//! Real authenticated CLI/server benchmark. See docs/operations.md.
use anyhow::{Result, ensure};
use clap::Parser;
use mysyncfiles::{client, server};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

#[path = "../tests/common/mod.rs"]
mod common;

#[derive(Parser)]
#[command(args_override_self = true)]
struct Options {
    // Cargo passes this to custom benchmark executables.
    #[arg(long, hide = true)]
    bench: bool,
    #[arg(long, default_value = "target/release/mysync")]
    binary: PathBuf,
    #[arg(long, default_value = "all", value_parser = ["all", "metadata", "transfer", "overwrite", "daemon", "concurrent"])]
    suite: String,
    #[arg(long, default_value_t = 3)]
    repetitions: usize,
    #[arg(long, default_value_t = 0)]
    delay_ms: u64,
    /// Parent of isolated temporary data. Choose a disk filesystem for I/O tests.
    #[arg(long)]
    work_dir: Option<PathBuf>,
}

struct Bench {
    options: Options,
    root: PathBuf,
    data: PathBuf,
    server: common::TestServer,
    key: mysyncfiles::tpm::Identity,
    requests: Arc<AtomicU64>,
    lag: Arc<AtomicU64>,
}

impl Bench {
    fn profile(&self, name: &str) -> Result<(PathBuf, PathBuf)> {
        let root = self.root.join(name).join("files");
        std::fs::create_dir_all(&root)?;
        let config = root.parent().unwrap().join("config.json");
        std::fs::write(
            &config,
            serde_json::to_vec(&common::config(&self.server.url, &root, self.key.clone()))?,
        )?;
        Ok((config, root))
    }

    fn reset(&self) -> Result<()> {
        let db = Connection::open(self.data.join("metadata.sqlite3"))?;
        db.execute_batch(
            "DELETE FROM entries; DELETE FROM uploads; DELETE FROM trash;
            UPDATE meta SET value=0 WHERE key='generation';",
        )?;
        for directory in ["blobs", "tmp"] {
            for entry in std::fs::read_dir(self.data.join(directory))? {
                std::fs::remove_file(entry?.path())?;
            }
        }
        Ok(())
    }

    fn seed(&self, config: &Path, n: usize, size: usize) -> Result<()> {
        let bytes = vec![0x5a; size];
        let sha = mysyncfiles::auth_protocol::hash(&bytes);
        std::fs::write(self.data.join("blobs/fixture"), bytes)?;
        let mut db = Connection::open(self.data.join("metadata.sqlite3"))?;
        let tx = db.transaction()?;
        let mut entries = serde_json::Map::new();
        {
            let mut query = tx.prepare("INSERT INTO entries VALUES(?1,?2,'fixture',?3,?4,0,1)")?;
            for i in 0..n {
                let path = filename(i);
                query.execute(params![path, (i + 1) as i64, sha, size as i64])?;
                entries.insert(path, json!({"revision":i+1,"sha256":sha}));
            }
        }
        tx.execute(
            "UPDATE meta SET value=?1 WHERE key='generation'",
            [n as i64],
        )?;
        tx.commit()?;
        std::fs::write(
            config.with_extension("state.json"),
            serde_json::to_vec(&json!({"entries":entries}))?,
        )?;
        Ok(())
    }

    fn command(&self, config: &Path, command: &str) -> std::process::Command {
        let mut child = std::process::Command::new("python3");
        child
            .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/benches/measure.py"))
            .arg(&self.options.binary)
            .arg("--config")
            .arg(config)
            .arg(command)
            .env("MYSYNC_BENCH_TIMINGS", "1");
        if command == "daemon" {
            child.env("MYSYNC_BENCH_DAEMON_SECONDS", "35");
        }
        child
    }

    fn cli(&self, case: &str, config: &Path, command: &str) -> Result<Value> {
        self.requests.store(0, Ordering::Relaxed);
        self.lag.store(0, Ordering::Relaxed);
        let before = process_io()?;
        // The main task runs outside Tokio's workers; the two workers serve HTTP.
        let output = self.command(config, command).output()?;
        ensure!(
            output.status.success(),
            "measurement failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut result: Value = serde_json::from_slice(&output.stdout)?;
        result["case"] = json!(case);
        result["http_requests"] = json!(self.requests.load(Ordering::Relaxed));
        result["server_max_timer_lag_ms"] = json!(self.lag.load(Ordering::Relaxed) as f64 / 1e6);
        // Linux includes waited-for children in these process I/O counters.
        // They describe the whole harness, not the server alone.
        result["harness_io_before"] = before;
        result["harness_io_after"] = process_io()?;
        println!("{result}");
        // Keep failed baseline cases measurable (notably the legacy pagination bug).
        Ok(result)
    }

    fn metadata(&self) -> Result<()> {
        for (n, size) in [(100, 4096), (10_000, 4096), (1, 512 * 1024 * 1024)] {
            self.reset()?;
            let (config, root) = self.profile(&format!("metadata-{n}-{size}"))?;
            fill(&root, n, size)?;
            self.seed(&config, n, size)?;
            for command in ["status", "sync"] {
                for _ in 0..self.options.repetitions {
                    self.cli(&format!("{command}-{n}x{size}"), &config, command)?;
                }
            }
            std::fs::remove_dir_all(root.parent().unwrap())?;
        }
        Ok(())
    }

    fn transfers(&self) -> Result<()> {
        for (n, size) in [(100, 4096), (1000, 4096), (3, 64 * 1024 * 1024)] {
            for repetition in 0..self.options.repetitions {
                self.reset()?;
                let (up, root) = self.profile(&format!("up-{n}-{repetition}"))?;
                fill(&root, n, size)?;
                self.cli(&format!("upload-{n}x{size}"), &up, "sync")?;
                let (down, down_root) = self.profile(&format!("down-{n}-{repetition}"))?;
                self.cli(&format!("download-{n}x{size}"), &down, "sync")?;
                if size > 4096 {
                    for (path, bytes) in [
                        (root.join(filename(0)), b"remote"),
                        (down_root.join(filename(0)), b"local!"),
                    ] {
                        std::fs::OpenOptions::new()
                            .write(true)
                            .open(path)?
                            .write_all(bytes)?;
                    }
                    self.cli("conflict-upload", &up, "sync")?;
                    self.cli("conflict-download", &down, "sync")?;
                    let content = std::fs::read(down_root.join(filename(0)))?;
                    ensure!(
                        content.starts_with(b"remote"),
                        "remote content was not applied"
                    );
                    ensure!(
                        walkdir::WalkDir::new(down_root.join(".mysync-conflicts"))
                            .into_iter()
                            .filter_map(Result::ok)
                            .any(|e| e.file_type().is_file()),
                        "conflict missing"
                    );
                }
                std::fs::remove_dir_all(root.parent().unwrap())?;
                std::fs::remove_dir_all(down_root.parent().unwrap())?;
            }
        }
        Ok(())
    }

    fn overwrites(&self) -> Result<()> {
        for (n, size) in [(100, 4096), (1, 128 * 1024 * 1024)] {
            for repetition in 0..self.options.repetitions {
                self.reset()?;
                let (config, root) = self.profile(&format!("overwrite-{n}-{repetition}"))?;
                fill(&root, n, size)?;
                self.seed(&config, n, size)?;
                // Advance the isolated fixture without including setup uploads
                // in this measurement of replacing unchanged local files.
                let bytes = vec![0x6b; size];
                let sha = mysyncfiles::auth_protocol::hash(&bytes);
                std::fs::write(self.data.join("blobs/replacement"), bytes)?;
                let db = Connection::open(self.data.join("metadata.sqlite3"))?;
                db.execute(
                    "UPDATE entries SET blob='replacement', sha256=?1, revision=revision+?2",
                    params![sha, n as i64],
                )?;
                db.execute(
                    "UPDATE meta SET value=?1 WHERE key='generation'",
                    [2 * n as i64],
                )?;
                let result = self.cli(&format!("overwrite-{n}x{size}"), &config, "sync")?;
                ensure!(result["returncode"] == 0, "replacement failed");
                ensure!(
                    !walkdir::WalkDir::new(root.join(".mysync-conflicts"))
                        .into_iter()
                        .filter_map(Result::ok)
                        .any(|entry| entry.file_type().is_file()),
                    "unchanged local content was retained as a conflict"
                );
                std::fs::remove_dir_all(root.parent().unwrap())?;
            }
        }
        Ok(())
    }

    fn daemon(&self) -> Result<()> {
        self.reset()?;
        let (config, root) = self.profile("daemon")?;
        fill(&root, 1, 512 * 1024 * 1024)?;
        self.seed(&config, 1, 512 * 1024 * 1024)?;
        self.cli("daemon-idle-512MiB-35s", &config, "daemon")?;
        Ok(())
    }

    async fn concurrent(&mut self) -> Result<()> {
        self.reset()?;
        let (_, root) = self.profile("concurrent")?;
        let mut apis = Vec::new();
        for i in 0..8 {
            let key = self.server.add_device(&format!("benchmark-{i}")).await?;
            let api = Arc::new(client::Api::new(&common::config(
                &self.server.url,
                &root,
                key,
            ))?);
            api.authenticate().await?;
            apis.push(api);
        }
        for n in [1, 4, 8, 16] {
            self.lag.store(0, Ordering::Relaxed);
            let start = Instant::now();
            let mut tasks = Vec::new();
            for i in 0..n {
                let api = apis[i % apis.len()].clone();
                tasks.push(tokio::spawn(async move {
                    let mut times = Vec::new();
                    for _ in 0..30 {
                        let start = Instant::now();
                        api.manifest().await?;
                        times.push(start.elapsed().as_secs_f64() * 1000.0);
                    }
                    Ok::<_, anyhow::Error>(times)
                }));
            }
            let mut times = Vec::new();
            for task in tasks {
                times.extend(task.await??);
            }
            times.sort_by(f64::total_cmp);
            println!(
                "{}",
                json!({"case":format!("concurrent-{n}"),"wall_ms":start.elapsed().as_secs_f64()*1000.0,
                "p50_ms":times[times.len()/2],"p95_ms":times[times.len()*95/100],"requests":times.len(),
                "server_max_timer_lag_ms":self.lag.load(Ordering::Relaxed) as f64/1e6})
            );
        }
        Ok(())
    }
}

fn filename(i: usize) -> String {
    format!("d{:04}/f{i:06}.bin", i / 1000)
}

fn fill(root: &Path, n: usize, size: usize) -> Result<()> {
    let bytes = vec![0x5a; size.min(1024 * 1024)];
    for i in 0..n {
        let path = root.join(filename(i));
        std::fs::create_dir_all(path.parent().unwrap())?;
        let mut file = std::fs::File::create(path)?;
        let mut remaining = size;
        while remaining > 0 {
            let length = remaining.min(bytes.len());
            file.write_all(&bytes[..length])?;
            remaining -= length;
        }
    }
    Ok(())
}

fn process_io() -> Result<Value> {
    let mut value = serde_json::Map::new();
    for line in std::fs::read_to_string("/proc/self/io")?.lines() {
        let (key, number) = line.split_once(':').unwrap();
        value.insert(key.to_owned(), json!(number.trim().parse::<u64>()?));
    }
    Ok(Value::Object(value))
}

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let mut options = Options::parse();
    ensure!(options.repetitions > 0, "repetitions must be positive");
    options.binary = std::fs::canonicalize(&options.binary)?;
    let temporary = match &options.work_dir {
        Some(path) => tempfile::tempdir_in(path)?,
        None => tempfile::tempdir()?,
    };
    let data = temporary.path().join("server");
    let mut server = common::TestServer::start(&data).await?;
    let key = server.add_device("benchmark-client").await?;
    server.task.abort();
    // Finish cancellation before reusing this isolated test listener.
    let _ = (&mut server.task).await;
    let listener =
        tokio::net::TcpListener::bind(server.url.strip_prefix("http://").unwrap()).await?;
    let requests = Arc::new(AtomicU64::new(0));
    let count = requests.clone();
    let delay = options.delay_ms;
    let app = server::router(server.state.clone()).layer(axum::middleware::from_fn(
        move |request: axum::extract::Request, next: axum::middleware::Next| {
            let count = count.clone();
            async move {
                count.fetch_add(1, Ordering::Relaxed);
                let response = next.run(request).await;
                if delay > 0 {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
                response
            }
        },
    ));
    server.task = tokio::spawn(async move {
        axum::serve(server::api_listener(listener), app)
            .await
            .unwrap();
    });
    let lag = Arc::new(AtomicU64::new(0));
    let observed = lag.clone();
    let monitor = tokio::spawn(async move {
        loop {
            let start = Instant::now();
            tokio::time::sleep(Duration::from_millis(10)).await;
            observed.fetch_max(
                start
                    .elapsed()
                    .saturating_sub(Duration::from_millis(10))
                    .as_nanos() as u64,
                Ordering::Relaxed,
            );
        }
    });
    let mut bench = Bench {
        options,
        root: temporary.path().to_owned(),
        data,
        server,
        key,
        requests,
        lag,
    };
    let suite = bench.options.suite.clone();
    if suite == "all" || suite == "metadata" {
        bench.metadata()?;
    }
    if suite == "all" || suite == "transfer" {
        bench.transfers()?;
    }
    if suite == "all" || suite == "overwrite" {
        bench.overwrites()?;
    }
    if suite == "all" || suite == "daemon" {
        bench.daemon()?;
    }
    if suite == "all" || suite == "concurrent" {
        bench.concurrent().await?;
    }
    monitor.abort();
    Ok(())
}
