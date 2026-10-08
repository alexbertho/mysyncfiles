//! Loopback bridge. Code execution requires its own one-use server authorization.
use super::Api;
use crate::{
    auth_protocol::{now, random_secret},
    web_status_protocol::*,
};
use anyhow::{Context, Result};
use axum::{
    Json,
    body::{Body, to_bytes},
    http::{HeaderMap, Method, Request, StatusCode},
    response::{IntoResponse, Response},
};
use hyper::{server::conn::http1, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::{HashMap, VecDeque},
    convert::Infallible,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    net::TcpListener,
    sync::Semaphore,
    task::{JoinHandle, JoinSet},
};

struct BridgeState {
    api: Arc<Api>,
    origin: String,
    instance_id: String,
    activity: Arc<Mutex<DaemonState>>,
    attempts: Mutex<VecDeque<Instant>>,
    used: Mutex<HashMap<String, i64>>,
    proof_limit: Semaphore,
    runner: super::runner::Runner,
    runner_limit: Semaphore,
}

/// Dropping this guard stops the bridge and all accepted connections.
pub struct LocalBridge {
    task: JoinHandle<()>,
}
impl Drop for LocalBridge {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn bind(address: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = Socket::new(
        Domain::for_address(address),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    socket.listen(8)?;
    TcpListener::from_std(socket.into())
}

fn optional_ipv6(result: std::io::Result<TcpListener>) -> std::io::Result<Option<TcpListener>> {
    match result {
        Ok(listener) => Ok(Some(listener)),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::Unsupported | std::io::ErrorKind::AddrNotAvailable
            ) || matches!(error.raw_os_error(), Some(92 | 93 | 97)) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

impl LocalBridge {
    pub fn start(api: Arc<Api>, activity: Arc<Mutex<DaemonState>>) -> Result<Self> {
        Self::start_on_port(api, activity, PORT)
    }

    fn start_on_port(api: Arc<Api>, activity: Arc<Mutex<DaemonState>>, port: u16) -> Result<Self> {
        let origin = api.web_origin()?;
        // Bind both before spawning anything: a collision disables the entire
        // bridge. Never fall back to an arbitrary port or a non-loopback address.
        let ipv4_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let v4 = bind(ipv4_address)
            .with_context(|| format!("cannot bind IPv4 loopback {ipv4_address}"))?;
        let port = v4.local_addr()?.port();
        let ipv6_address = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port);
        let v6 = optional_ipv6(bind(ipv6_address))
            .with_context(|| format!("cannot bind IPv6 loopback {ipv6_address}"))?;
        let state = Arc::new(BridgeState {
            api,
            origin,
            instance_id: random_secret()?,
            activity,
            attempts: Mutex::new(VecDeque::new()),
            used: Mutex::new(HashMap::new()),
            proof_limit: Semaphore::new(1),
            runner: super::runner::Runner::default(),
            runner_limit: Semaphore::new(2),
        });
        Ok(Self {
            task: tokio::spawn(serve(v4, v6, state)),
        })
    }
}

async fn serve(v4: TcpListener, v6: Option<TcpListener>, state: Arc<BridgeState>) {
    let mut connections = JoinSet::new();
    let limit = Arc::new(Semaphore::new(8));
    loop {
        let accepted = tokio::select! {
            result = v4.accept() => result,
            result = async { match &v6 { Some(listener) => listener.accept().await, None => std::future::pending().await } } => result,
            _ = connections.join_next(), if !connections.is_empty() => continue,
        };
        let Ok((socket, peer)) = accepted else {
            eprintln!("web status bridge stopped: loopback accept failed");
            return;
        };
        if !peer.ip().is_loopback() {
            continue;
        }
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            continue;
        };
        let Ok(address) = socket.local_addr() else {
            continue;
        };
        let host = address.to_string();
        let state = state.clone();
        let _ = socket.set_nodelay(true);
        connections.spawn(async move {
            let _permit = permit;
            let service =
                service_fn(move |request: Request<hyper::body::Incoming>| {
                    let state = state.clone();
                    let host = host.clone();
                    async move {
                        let result = tokio::time::timeout(
                            Duration::from_secs(10),
                            handle(state, &host, request.map(Body::new)),
                        )
                        .await;
                        Ok::<_, Infallible>(result.unwrap_or_else(|_| {
                            failure(StatusCode::GATEWAY_TIMEOUT, "status_timeout")
                        }))
                    }
                });
            let mut builder = http1::Builder::new();
            builder
                .keep_alive(false)
                .max_buf_size(8192)
                .max_headers(32)
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(5));
            // Also bound response writes to a client that stops reading.
            let _ = tokio::time::timeout(
                Duration::from_secs(15),
                builder.serve_connection(TokioIo::new(socket), service),
            )
            .await;
        });
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}

fn failure(status: StatusCode, code: &str) -> Response {
    let mut response = (status, Json(serde_json::json!({"error": code}))).into_response();
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response
}

fn cors(mut response: Response, origin: &str) -> Response {
    let headers = response.headers_mut();
    headers.insert("access-control-allow-origin", origin.parse().unwrap());
    headers.insert("vary", "Origin".parse().unwrap());
    headers.insert("cache-control", "no-store".parse().unwrap());
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    response
}

async fn handle(state: Arc<BridgeState>, host: &str, request: Request<Body>) -> Response {
    let headers = request.headers();
    if header(headers, "host") != Some(host)
        || header(headers, "origin") != Some(state.origin.as_str())
    {
        return failure(StatusCode::FORBIDDEN, "origin_refused");
    }
    let result = handle_allowed(&state, request).await;
    cors(result, &state.origin)
}

async fn handle_allowed(state: &BridgeState, request: Request<Body>) -> Response {
    if request.uri().path() == "/v1/editor" {
        return editor(state, request).await;
    }
    let headers = request.headers();
    if request.uri().scheme().is_some()
        || request.uri().authority().is_some()
        || request.uri().path() != "/v1/status"
        || request.uri().query().is_some()
        || headers.contains_key("upgrade")
        || headers.contains_key("transfer-encoding")
        || headers.contains_key("expect")
        || (headers.contains_key("content-length")
            && header(headers, "content-length") != Some("0"))
        || headers
            .iter()
            .map(|(k, v)| k.as_str().len() + v.len() + 4)
            .sum::<usize>()
            > 8192
    {
        return failure(StatusCode::BAD_REQUEST, "invalid_request");
    }
    if request.method() == Method::OPTIONS {
        let allowed = header(headers, "access-control-request-headers").is_some_and(|value| {
            let names: Vec<_> = value
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .collect();
            names.iter().any(|s| s == BRIDGE_HEADER)
                && names
                    .iter()
                    .all(|s| s == BRIDGE_HEADER || s == CHALLENGE_HEADER)
        });
        if header(headers, "access-control-request-method") != Some("GET") || !allowed {
            return failure(StatusCode::FORBIDDEN, "preflight_refused");
        }
        let mut response = StatusCode::NO_CONTENT.into_response();
        response.headers_mut().insert(
            "access-control-allow-methods",
            "GET, OPTIONS".parse().unwrap(),
        );
        response.headers_mut().insert(
            "access-control-allow-headers",
            "X-MySync-Bridge, X-MySync-Challenge".parse().unwrap(),
        );
        // Compatibility with older PNA clients; current LNA permission remains
        // the browser's responsibility and is never bypassed by this header.
        if header(headers, "access-control-request-private-network") == Some("true") {
            response.headers_mut().insert(
                "access-control-allow-private-network",
                "true".parse().unwrap(),
            );
        }
        return response;
    }
    if request.method() != Method::GET {
        return failure(StatusCode::METHOD_NOT_ALLOWED, "method_refused");
    }
    if header(headers, BRIDGE_HEADER) != Some("1") {
        return failure(StatusCode::FORBIDDEN, "bridge_header_required");
    }
    let ticket = match header(headers, CHALLENGE_HEADER) {
        Some(ticket) => ticket.to_owned(),
        None if !headers.contains_key(CHALLENGE_HEADER) => {
            return failure(StatusCode::UNAUTHORIZED, "challenge_required");
        }
        None => return failure(StatusCode::BAD_REQUEST, "invalid_challenge"),
    };
    if to_bytes(request.into_body(), 0).await.is_err() {
        return failure(StatusCode::BAD_REQUEST, "body_refused");
    }
    let Ok(_permit) = state.proof_limit.try_acquire() else {
        return failure(StatusCode::TOO_MANY_REQUESTS, "status_busy");
    };
    {
        let mut attempts = state.attempts.lock().unwrap();
        while attempts
            .front()
            .is_some_and(|t| t.elapsed() >= Duration::from_secs(60))
        {
            attempts.pop_front();
        }
        if attempts.len() >= 6 {
            return failure(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
        }
        attempts.push_back(Instant::now());
    }
    let claims = match state.api.verify_status_ticket(&ticket) {
        Ok(claims) => claims,
        Err(error) => {
            return failure(
                StatusCode::FORBIDDEN,
                match error.to_string().as_str() {
                    "files_read_disabled" => "files_read_disabled",
                    "files_write_disabled" => "files_write_disabled",
                    "files_manage_disabled" => "files_manage_disabled",
                    "files_edit_disabled" => "files_edit_disabled",
                    "code_run_disabled" => "code_run_disabled",
                    _ => "invalid_challenge",
                },
            );
        }
    };
    if claims.origin != state.origin {
        return failure(StatusCode::FORBIDDEN, "origin_refused");
    }
    {
        let mut used = state.used.lock().unwrap();
        used.retain(|_, expiry| *expiry > now());
        if used
            .insert(claims.challenge_id.clone(), claims.expires_at)
            .is_some()
        {
            return failure(StatusCode::CONFLICT, "challenge_used");
        }
    }
    let daemon_state = *state.activity.lock().unwrap();
    let (communication, last_authenticated_at) = state.api.communication();
    let status = LocalStatus {
        api_version: 1,
        client_version: env!("CARGO_PKG_VERSION").into(),
        daemon_state,
        communication,
        observed_at: now(),
        last_authenticated_at,
        error: if daemon_state == DaemonState::Error {
            Some(StatusError::SyncFailed)
        } else if communication == CommunicationState::Failed {
            Some(StatusError::CommunicationFailed)
        } else {
            None
        },
    };
    let proof = PresenceProof {
        ticket,
        observed_origin: state.origin.clone(),
        instance_id: state.instance_id.clone(),
        status: status.clone(),
    };
    match state.api.submit_presence(&proof).await {
        Ok(accepted) => {
            Json(serde_json::json!({"challenge_id": accepted.challenge_id, "status": status}))
                .into_response()
        }
        Err(_) => failure(StatusCode::BAD_GATEWAY, "verification_failed"),
    }
}

async fn editor(state: &BridgeState, request: Request<Body>) -> Response {
    let headers = request.headers();
    if request.uri().scheme().is_some()
        || request.uri().authority().is_some()
        || request.uri().query().is_some()
        || ["upgrade", "transfer-encoding", "expect"]
            .iter()
            .any(|name| headers.contains_key(*name))
    {
        return failure(StatusCode::BAD_REQUEST, "invalid_request");
    }
    if request.method() == Method::OPTIONS {
        let allowed = header(headers, "access-control-request-headers").is_some_and(|value| {
            let names: Vec<_> = value
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .collect();
            names.iter().any(|s| s == BRIDGE_HEADER)
                && names
                    .iter()
                    .all(|s| s == BRIDGE_HEADER || s == "content-type")
        });
        if header(headers, "access-control-request-method") != Some("POST") || !allowed {
            return failure(StatusCode::FORBIDDEN, "preflight_refused");
        }
        let mut response = StatusCode::NO_CONTENT.into_response();
        response.headers_mut().insert(
            "access-control-allow-methods",
            "POST, OPTIONS".parse().unwrap(),
        );
        response.headers_mut().insert(
            "access-control-allow-headers",
            "X-MySync-Bridge, Content-Type".parse().unwrap(),
        );
        if header(headers, "access-control-request-private-network") == Some("true") {
            response.headers_mut().insert(
                "access-control-allow-private-network",
                "true".parse().unwrap(),
            );
        }
        return response;
    }
    if request.method() != Method::POST
        || header(headers, BRIDGE_HEADER) != Some("1")
        || header(headers, "content-type") != Some("application/json")
    {
        return failure(StatusCode::FORBIDDEN, "invalid_request");
    }
    let Ok(_permit) = state.runner_limit.try_acquire() else {
        return failure(StatusCode::TOO_MANY_REQUESTS, "runner_busy");
    };
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        ticket: String,
    }
    let input = match to_bytes(request.into_body(), MAX_JSON_BYTES).await {
        Ok(bytes) => serde_json::from_slice::<Input>(&bytes).ok(),
        Err(_) => None,
    };
    let Some(input) = input.filter(|input| valid_secret(&input.ticket)) else {
        return failure(StatusCode::BAD_REQUEST, "invalid_ticket");
    };
    let authorization = match state
        .api
        .authorize_runner(input.ticket, state.instance_id.clone())
        .await
    {
        Ok(value) => value,
        Err(error) => {
            return failure(
                StatusCode::FORBIDDEN,
                if error.to_string() == "code_run_disabled" {
                    "code_run_disabled"
                } else {
                    "runner_authorization_refused"
                },
            );
        }
    };
    match state.runner.handle(authorization).await {
        Ok(value) => Json(value).into_response(),
        Err(error) => failure(
            StatusCode::CONFLICT,
            match error.to_string().as_str() {
                "tool_missing" => "tool_missing",
                "isolation_unavailable" => "isolation_unavailable",
                "runner_busy" => "runner_busy",
                "job_missing" => "job_missing",
                _ => "runner_failed",
            },
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn state() -> Result<Arc<BridgeState>> {
        let config: super::super::ClientConfig = serde_json::from_value(serde_json::json!({
            "server":"https://sync.example.com", "server_public_key":hex::encode(ed25519_dalek::SigningKey::from_bytes(&[7;32]).verifying_key().to_bytes()),
            "identity":{"device":"test", "public":"", "private":"", "ek_kind":"rsa", "tcti":"device:/no-tpm-for-probes"},
            "root":"/unused", "auto_update":false
        }))?;
        assert!(config.web_status_enabled);
        Ok(Arc::new(BridgeState {
            api: Arc::new(Api::new(&config)?),
            origin: config.server,
            instance_id: random_secret()?,
            activity: Arc::new(Mutex::new(DaemonState::Starting)),
            attempts: Mutex::new(VecDeque::new()),
            used: Mutex::new(HashMap::new()),
            proof_limit: Semaphore::new(1),
            runner: super::super::runner::Runner::default(),
            runner_limit: Semaphore::new(2),
        }))
    }

    fn request(method: &str) -> axum::http::request::Builder {
        Request::builder()
            .method(method)
            .uri("/v1/status")
            .header("host", "127.0.0.1:47831")
            .header("origin", "https://sync.example.com")
            .header(BRIDGE_HEADER, "1")
    }

    #[tokio::test]
    async fn probes_are_constant_and_http_policy_precedes_tpm() -> Result<()> {
        let state = state()?;
        let response = handle(
            state.clone(),
            "127.0.0.1:47831",
            request("GET").body(Body::empty())?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers()["access-control-allow-origin"],
            "https://sync.example.com"
        );
        assert_eq!(response.headers()["cache-control"], "no-store");
        let bytes = to_bytes(response.into_body(), 4096).await?;
        assert_eq!(bytes.as_ref(), b"{\"error\":\"challenge_required\"}");
        for origin in [
            None,
            Some("null"),
            Some("https://other.example.com"),
            Some("https://sync.example.com:444"),
        ] {
            let mut req = request("GET").body(Body::empty())?;
            req.headers_mut().remove("origin");
            if let Some(origin) = origin {
                req.headers_mut().insert("origin", origin.parse()?);
            }
            let response = handle(state.clone(), "127.0.0.1:47831", req).await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert!(
                !response
                    .headers()
                    .contains_key("access-control-allow-origin")
            );
        }
        for host in [
            "localhost:47831",
            "rebinding.example.com:47831",
            "[::1]:47831",
            "127.0.0.1",
        ] {
            let mut req = request("GET").body(Body::empty())?;
            req.headers_mut().insert("host", host.parse()?);
            assert_eq!(
                handle(state.clone(), "127.0.0.1:47831", req).await.status(),
                StatusCode::FORBIDDEN
            );
        }
        for duplicate in ["origin", "host"] {
            let mut req = request("GET").body(Body::empty())?;
            let value = req.headers()[duplicate].clone();
            req.headers_mut().append(duplicate, value);
            assert_eq!(
                handle(state.clone(), "127.0.0.1:47831", req).await.status(),
                StatusCode::FORBIDDEN
            );
        }
        for method in ["HEAD", "POST", "PUT", "DELETE", "CONNECT"] {
            assert_eq!(
                handle(
                    state.clone(),
                    "127.0.0.1:47831",
                    request(method).body(Body::empty())?
                )
                .await
                .status(),
                StatusCode::METHOD_NOT_ALLOWED
            );
        }
        for uri in [
            "http://127.0.0.1:47831/v1/status",
            "/v1/status?ticket=x",
            "/files",
        ] {
            assert_eq!(
                handle(
                    state.clone(),
                    "127.0.0.1:47831",
                    request("GET").uri(uri).body(Body::empty())?
                )
                .await
                .status(),
                StatusCode::BAD_REQUEST
            );
        }
        for (name, value) in [
            ("content-length", "1"),
            ("transfer-encoding", "chunked"),
            ("upgrade", "websocket"),
        ] {
            assert_eq!(
                handle(
                    state.clone(),
                    "127.0.0.1:47831",
                    request("GET").header(name, value).body(Body::empty())?
                )
                .await
                .status(),
                StatusCode::BAD_REQUEST
            );
        }
        let mut simple = request("GET").body(Body::empty())?;
        simple.headers_mut().remove(BRIDGE_HEADER);
        assert_eq!(
            handle(state.clone(), "127.0.0.1:47831", simple)
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        let options = request("OPTIONS")
            .header("access-control-request-method", "GET")
            .header(
                "access-control-request-headers",
                "x-mysync-bridge, x-mysync-challenge",
            )
            .body(Body::empty())?;
        assert_eq!(
            handle(state.clone(), "127.0.0.1:47831", options)
                .await
                .status(),
            StatusCode::NO_CONTENT
        );
        assert!(state.attempts.lock().unwrap().is_empty());
        assert_eq!(
            state.api.communication(),
            (CommunicationState::Unknown, None)
        );
        Ok(())
    }

    #[tokio::test]
    async fn invalid_tickets_are_rate_limited_without_using_tpm() -> Result<()> {
        let state = state()?;
        for i in 0..7 {
            let response = handle(
                state.clone(),
                "127.0.0.1:47831",
                request("GET")
                    .header(CHALLENGE_HEADER, "invalid")
                    .body(Body::empty())?,
            )
            .await;
            assert_eq!(
                response.status(),
                if i < 6 {
                    StatusCode::FORBIDDEN
                } else {
                    StatusCode::TOO_MANY_REQUESTS
                }
            );
        }
        assert_eq!(
            state.api.communication(),
            (CommunicationState::Unknown, None)
        );
        Ok(())
    }

    #[tokio::test]
    async fn listeners_confine_connections_bound_headers_and_close_on_drop() -> Result<()> {
        let state = state()?;
        let v4 = bind("127.0.0.1:0".parse()?)?;
        let address = v4.local_addr()?;
        let v6 = optional_ipv6(bind(SocketAddr::new(
            Ipv6Addr::LOCALHOST.into(),
            address.port(),
        )))?;
        let has_v6 = v6.is_some();
        assert!(address.ip().is_loopback());
        if let Some(ref listener) = v6 {
            assert!(listener.local_addr()?.ip().is_loopback());
        }
        let error = match LocalBridge::start_on_port(
            state.api.clone(),
            state.activity.clone(),
            address.port(),
        ) {
            Ok(_) => anyhow::bail!("the bridge must refuse an occupied port"),
            Err(error) => error,
        };
        assert!(error.to_string().contains(&address.to_string()));
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::AddrInUse
        );
        let bridge = LocalBridge {
            task: tokio::spawn(serve(v4, v6, state.clone())),
        };
        let http = reqwest::Client::builder().no_proxy().build()?;
        let response = http
            .get(format!("http://{address}/v1/status"))
            .header("origin", &state.origin)
            .header(BRIDGE_HEADER, "1")
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        if has_v6 {
            assert_eq!(
                http.get(format!("http://[::1]:{}/v1/status", address.port()))
                    .header("origin", &state.origin)
                    .header(BRIDGE_HEADER, "1")
                    .send()
                    .await?
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        }
        let mut stream = tokio::net::TcpStream::connect(address).await?;
        let oversized = format!(
            "GET /v1/status HTTP/1.1\r\nHost: {address}\r\nX-Large: {}\r\n\r\n",
            "x".repeat(9000)
        );
        stream.write_all(oversized.as_bytes()).await?;
        let mut response = String::new();
        stream.read_to_string(&mut response).await?;
        assert!(response.starts_with("HTTP/1.1 431"));
        // Slow headers are closed independently of all daemon/TPM operations.
        let mut slow = tokio::net::TcpStream::connect(address).await?;
        slow.write_all(b"GET /v1/status HTTP/1.1\r\n").await?;
        let mut response = String::new();
        tokio::time::timeout(Duration::from_secs(7), slow.read_to_string(&mut response)).await??;
        assert!(response.is_empty() || response.starts_with("HTTP/1.1 408"));
        let mut held = Vec::new();
        for _ in 0..8 {
            let mut socket = tokio::net::TcpStream::connect(address).await?;
            socket.write_all(b"GET ").await?;
            held.push(socket);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut excess = tokio::net::TcpStream::connect(address).await?;
        let mut reply = Vec::new();
        let read =
            tokio::time::timeout(Duration::from_secs(1), excess.read_to_end(&mut reply)).await?;
        assert!(read.is_err() || reply.is_empty());
        drop(held);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut unfinished = tokio::net::TcpStream::connect(address).await?;
        unfinished.write_all(b"GET ").await?;
        drop(bridge);
        tokio::task::yield_now().await;
        let mut bytes = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(1), unfinished.read_to_end(&mut bytes))
            .await?;
        assert!(tokio::net::TcpStream::connect(address).await.is_err());
        assert!(optional_ipv6(Err(std::io::ErrorKind::Unsupported.into()))?.is_none());
        assert!(optional_ipv6(Err(std::io::ErrorKind::AddrInUse.into())).is_err());
        Ok(())
    }
}
