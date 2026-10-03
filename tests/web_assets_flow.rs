use anyhow::Result;
use mysyncfiles::server;
use reqwest::{Client, StatusCode};
use std::{path::PathBuf, time::Duration};

struct Site {
    _temp: tempfile::TempDir,
    web: PathBuf,
    url: String,
    http: Client,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Site {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Site {
    async fn start() -> Result<Self> {
        let temp = tempfile::tempdir()?;
        let web = temp.path().join("public");
        std::fs::create_dir(&web)?;
        let data = temp.path().join("private");
        let state = server::open_with_web_dir(&data, None, web.clone())?;
        rusqlite::Connection::open(data.join("metadata.sqlite3"))?.execute(
            "INSERT INTO auth_settings(key,value) VALUES('public_url','https://sync.example.test')",
            [],
        )?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let task = tokio::spawn(async move {
            axum::serve(server::api_listener(listener), server::router(state))
                .await
                .unwrap();
        });
        Ok(Self {
            _temp: temp,
            web,
            url,
            http: Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(5))
                .build()?,
            task,
        })
    }

    async fn get(&self, path: &str) -> Result<reqwest::Response> {
        Ok(self.http.get(format!("{}{path}", self.url)).send().await?)
    }
}

#[tokio::test]
async fn html_and_assets_update_without_restart_and_keep_session_cookies() -> Result<()> {
    let site = Site::start().await?;
    for (file, route, content_type) in [
        ("index.html", "/", "text/html; charset=utf-8"),
        ("index.html", "/index.html", "text/html; charset=utf-8"),
        ("index.html", "/files", "text/html; charset=utf-8"),
        ("index.html", "/status", "text/html; charset=utf-8"),
        ("status.css", "/status.css", "text/css; charset=utf-8"),
        ("status.js", "/status.js", "text/javascript; charset=utf-8"),
        ("atlas.js", "/atlas.js", "text/javascript; charset=utf-8"),
        ("atlas-icons.svg", "/atlas-icons.svg", "image/svg+xml"),
        ("atlas-brand.png", "/atlas-brand.png", "image/png"),
        ("atlas-brand-dark.png", "/atlas-brand-dark.png", "image/png"),
    ] {
        std::fs::write(site.web.join(file), "before")?;
        let response = site.get(route).await?.error_for_status()?;
        assert_eq!(response.headers()["content-type"], content_type);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert!(
            response.headers()["content-security-policy"]
                .to_str()?
                .contains("frame-ancestors 'none'")
        );
        let cookie = response.headers().get("set-cookie").cloned();
        assert_eq!(response.text().await?, "before");

        // Editors commonly replace the file atomically. The running server
        // must reopen it instead of retaining the old inode or cached bytes.
        let replacement = site.web.join("replacement.tmp");
        std::fs::write(&replacement, "after")?;
        std::fs::rename(replacement, site.web.join(file))?;
        let mut request = site.http.get(format!("{}{route}", site.url));
        if let Some(cookie) = cookie {
            let cookie = cookie.to_str()?;
            let expected = if route == "/status" {
                "__Host-mysync-status="
            } else {
                "__Host-mysync-files="
            };
            assert!(cookie.starts_with(expected));
            assert!(cookie.contains("Secure; HttpOnly; SameSite=Strict; Path=/"));
            request = request.header("cookie", cookie.split(';').next().unwrap());
        } else {
            assert_ne!(file, "index.html");
        }
        let response = request.send().await?.error_for_status()?;
        assert!(!response.headers().contains_key("set-cookie"));
        assert_eq!(response.text().await?, "after");
    }
    // Serving the public shell never grants access to private file metadata.
    assert_eq!(
        site.http
            .get(format!("{}/v1/web/files/entries", site.url))
            .header("x-mysync-web", "1")
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    Ok(())
}

#[tokio::test]
async fn static_routes_refuse_unknown_files_symlinks_and_oversized_assets() -> Result<()> {
    let site = Site::start().await?;
    for name in [".env", "index.html.bak", "secret.key", "metadata.sqlite3"] {
        std::fs::write(site.web.join(name), "private fixture")?;
        assert_eq!(
            site.get(&format!("/{name}")).await?.status(),
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(
        site.get("/files/../.env").await?.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        site.get("/%2e%2e%2f.env").await?.status(),
        StatusCode::NOT_FOUND
    );

    let asset = site.web.join("index.html");
    assert_eq!(
        site.get("/").await?.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    std::os::unix::fs::symlink(site.web.join("secret.key"), &asset)?;
    let response = site.get("/files").await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key("set-cookie"));
    assert_eq!(
        response.json::<serde_json::Value>().await?,
        serde_json::json!({"error":"web_unavailable"})
    );
    std::fs::remove_file(&asset)?;
    std::fs::create_dir(&asset)?;
    assert_eq!(
        site.get("/status").await?.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    std::fs::remove_dir(&asset)?;
    std::fs::File::create(&asset)?.set_len(1024 * 1024 + 1)?;
    assert_eq!(
        site.get("/").await?.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    std::fs::write(asset, "repaired")?;
    assert_eq!(
        site.get("/").await?.error_for_status()?.text().await?,
        "repaired"
    );
    Ok(())
}
