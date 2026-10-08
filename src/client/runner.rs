//! Single-file runner. The child is gated until cgroup limits are verified;
//! Bubblewrap never exposes the mirror, profile, home directory or host network.
use crate::{
    auth_protocol::{hash, now},
    editor_protocol::*,
};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
    sync::watch,
    task::JoinHandle,
};

#[derive(Default)]
pub(super) struct Runner {
    job: tokio::sync::Mutex<Option<Job>>,
    tools: tokio::sync::Mutex<Option<(Instant, Tools)>>,
}

struct Job {
    owner: String,
    id: String,
    lease: Arc<Mutex<Instant>>,
    run: Arc<Mutex<Run>>,
    cancel: watch::Sender<bool>,
    task: JoinHandle<()>,
}
impl Drop for Job {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Runner {
    pub async fn handle(&self, authorization: Authorization) -> Result<Value> {
        ensure!(
            authorization.expires_at > now() && authorization.operation.valid(),
            "authorization_expired"
        );
        match authorization.operation {
            Operation::Tools => Ok(serde_json::to_value(self.detect().await)?),
            Operation::Start {
                path,
                revision: _,
                sha256,
                job_id,
            } => {
                let source = authorization.source.context("source_missing")?;
                ensure!(
                    source.len() <= CODE_BYTES && !source.contains('\0') && hash(&source) == sha256,
                    "invalid_source"
                );
                let tools = self.detect().await;
                ensure!(tools.isolation, "isolation_unavailable");
                let python = language(&path) == Some("python");
                ensure!(
                    if python {
                        tools.python
                    } else {
                        tools.compiler.is_some()
                    },
                    "tool_missing"
                );
                let mut current = self.job.lock().await;
                if let Some(job) = current.as_ref() {
                    ensure!(
                        job.owner != authorization.owner || job.id != job_id,
                        "job_already_started"
                    );
                    ensure!(job.task.is_finished(), "runner_busy");
                }
                let work = tempfile::tempdir()?;
                // The name is fixed by us. The browser path is never used by a command.
                std::fs::write(
                    work.path()
                        .join(if python { "source.py" } else { "source.c" }),
                    source,
                )?;
                let run = Arc::new(Mutex::new(Run {
                    job_id: job_id.clone(),
                    sha256,
                    state: "running".into(),
                    compilation: None,
                    execution: None,
                }));
                let lease = Arc::new(Mutex::new(Instant::now()));
                let (cancel, receiver) = watch::channel(false);
                let task = tokio::spawn(execute(
                    work,
                    python,
                    tools.compiler,
                    run.clone(),
                    lease.clone(),
                    receiver,
                    authorization.expires_at,
                ));
                let value = serde_json::to_value(&*run.lock().unwrap())?;
                *current = Some(Job {
                    owner: authorization.owner,
                    id: job_id,
                    lease,
                    run,
                    cancel,
                    task,
                });
                Ok(value)
            }
            operation => {
                let (id, stop) = match operation {
                    Operation::Poll { job_id } => (job_id, false),
                    Operation::Stop { job_id } => (job_id, true),
                    _ => unreachable!(),
                };
                let current = self.job.lock().await;
                let job = current.as_ref().context("job_missing")?;
                ensure!(
                    job.owner == authorization.owner && job.id == id,
                    "job_missing"
                );
                *job.lease.lock().unwrap() = Instant::now();
                if stop {
                    let _ = job.cancel.send(true);
                }
                Ok(serde_json::to_value(&*job.run.lock().unwrap())?)
            }
        }
    }

    async fn detect(&self) -> Tools {
        let mut cached = self.tools.lock().await;
        if let Some((time, tools)) = &*cached
            && time.elapsed() < Duration::from_secs(30)
        {
            return tools.clone();
        }
        let python = tool("python3").is_some();
        let compiler = ["gcc", "clang"]
            .into_iter()
            .find(|name| tool(name).is_some())
            .map(str::to_owned);
        let isolation = if let Ok(work) = tempfile::tempdir() {
            let run = Arc::new(Mutex::new(Run {
                job_id: String::new(),
                sha256: String::new(),
                state: "running".into(),
                compilation: None,
                execution: None,
            }));
            let (_cancel, mut receiver) = watch::channel(false);
            phase(
                work.path(),
                false,
                &["/usr/bin/true"],
                &run,
                false,
                &Arc::new(Mutex::new(Instant::now())),
                &mut receiver,
                now() + 10,
                3,
            )
            .await
            .is_ok_and(|state| state == "finished")
        } else {
            false
        };
        let tools = Tools {
            python,
            compiler,
            isolation,
        };
        *cached = Some((Instant::now(), tools.clone()));
        tools
    }
}

// System tools only: a writable PATH entry must not replace a sandbox helper.
fn tool(name: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let path = Path::new("/usr/bin").join(name);
    path.metadata()
        .ok()
        .filter(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .map(|_| path)
}

struct Sandbox {
    child: Child,
    unit: String,
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        // Scope cleanup also covers a compiler's descendants and early failures.
        if let Ok(mut cleanup) = std::process::Command::new("/usr/bin/systemctl")
            .args(["--user", "stop", "--no-block", &self.unit])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            // std::process::Child does not reap on drop.
            std::thread::spawn(move || {
                let _ = cleanup.wait();
            });
        }
    }
}

fn command(work: &Path, writable: bool, args: &[&str], unit: &str, seconds: u64) -> Command {
    let mut cmd = Command::new("/usr/bin/systemd-run");
    cmd.env_clear();
    for name in ["XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"] {
        if let Some(value) = std::env::var_os(name) {
            cmd.env(name, value);
        }
    }
    cmd.env("PATH", "/usr/bin:/bin").env("LANG", "C.UTF-8");
    cmd.args([
        "--user",
        "--scope",
        "--quiet",
        "--collect",
        "--unit",
        unit,
        "--property=MemoryMax=268435456",
        "--property=MemorySwapMax=0",
        "--property=TasksMax=32",
        "--property=CPUQuota=100%",
    ])
    .arg(format!("--property=RuntimeMaxSec={}s", seconds + 4))
    .args([
        "--",
        "/usr/bin/bwrap",
        "--unshare-all",
        "--unshare-user",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--clearenv",
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind-try",
        "/lib",
        "/lib",
        "--ro-bind-try",
        "/lib64",
        "/lib64",
        "--symlink",
        "usr/bin",
        "/bin",
        "--ro-bind-try",
        "/etc/ld.so.cache",
        "/etc/ld.so.cache",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--size",
        "16777216",
        "--tmpfs",
        "/tmp",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "HOME",
        "/tmp",
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--setenv",
        "TMPDIR",
        "/tmp",
        "--block-fd",
        "0",
    ])
    .arg(if writable { "--bind" } else { "--ro-bind" })
    .arg(work)
    .arg("/work")
    .args([
        "--chdir",
        "/tmp",
        "--",
        "/usr/bin/prlimit",
        "--as=268435456",
        "--fsize=16777216",
        "--nofile=64",
        "--core=0",
    ])
    .arg(format!("--cpu={seconds}"))
    .arg("--")
    .args(args)
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .kill_on_drop(true);
    cmd
}

// systemd can accept properties on a machine lacking delegated controllers.
// Do not release the Bubblewrap gate unless the kernel actually enforces them.
async fn limits(pid: u32, unit: &str) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let membership = tokio::fs::read_to_string(format!("/proc/{pid}/cgroup")).await?;
            if let Some(path) = membership.lines().find_map(|line| line.strip_prefix("0::"))
                && path.ends_with(unit)
                && !path.split('/').any(|part| part == "..")
            {
                let root = Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/'));
                ensure!(
                    tokio::fs::read_to_string(root.join("memory.max"))
                        .await?
                        .trim()
                        == "268435456",
                    "memory_limit_missing"
                );
                ensure!(
                    tokio::fs::read_to_string(root.join("memory.swap.max"))
                        .await?
                        .trim()
                        == "0",
                    "swap_limit_missing"
                );
                ensure!(
                    tokio::fs::read_to_string(root.join("pids.max"))
                        .await?
                        .trim()
                        == "32",
                    "process_limit_missing"
                );
                let cpu = tokio::fs::read_to_string(root.join("cpu.max")).await?;
                let mut values = cpu.split_whitespace();
                let quota: u64 = values.next().context("cpu_limit_missing")?.parse()?;
                let period: u64 = values.next().context("cpu_limit_missing")?.parse()?;
                ensure!(quota <= period && quota > 0, "cpu_limit_missing");
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("isolation_unavailable")?
}

fn output_size(run: &Run) -> usize {
    [&run.compilation, &run.execution]
        .into_iter()
        .flatten()
        .map(|p| p.stdout.len() + p.stderr.len())
        .sum()
}

#[allow(clippy::too_many_arguments)]
async fn phase(
    work: &Path,
    writable: bool,
    args: &[&str],
    run: &Arc<Mutex<Run>>,
    compile: bool,
    lease: &Arc<Mutex<Instant>>,
    cancel: &mut watch::Receiver<bool>,
    expires: i64,
    seconds: u64,
) -> Result<String> {
    let start = Instant::now();
    let unit = format!("mysync-code-{}.scope", uuid::Uuid::new_v4().simple());
    let child = command(work, writable, args, &unit, seconds).spawn()?;
    let mut sandbox = Sandbox { child, unit };
    let pid = sandbox.child.id().context("isolation_unavailable")?;
    limits(pid, &sandbox.unit).await?;
    let mut stdin = sandbox.child.stdin.take().context("stdin_missing")?;
    stdin.write_all(b"1").await?;
    drop(stdin);
    let mut stdout = sandbox.child.stdout.take().context("stdout_missing")?;
    let mut stderr = sandbox.child.stderr.take().context("stderr_missing")?;
    {
        let mut value = run.lock().unwrap();
        if compile {
            value.compilation = Some(Phase::default());
        } else {
            value.execution = Some(Phase::default());
        }
    }
    let mut out = [0u8; 4096];
    let mut err = [0u8; 4096];
    let mut out_decoder = OutputDecoder::default();
    let mut err_decoder = OutputDecoder::default();
    let mut out_open = true;
    let mut err_open = true;
    let mut exit: Option<std::process::ExitStatus> = None;
    let mut check = tokio::time::interval(Duration::from_millis(100));
    let state = loop {
        if !out_open
            && !err_open
            && let Some(status) = exit
        {
            break if status.success() {
                "finished"
            } else {
                "failed"
            };
        }
        tokio::select! {
            result = stdout.read(&mut out), if out_open => {
                let n = result?; out_open = n != 0;
                if append(run, compile, false, out_decoder.decode(&out[..n], n == 0).as_bytes()) { break "output_limit"; }
            }
            result = stderr.read(&mut err), if err_open => {
                let n = result?; err_open = n != 0;
                if append(run, compile, true, err_decoder.decode(&err[..n], n == 0).as_bytes()) { break "output_limit"; }
            }
            result = sandbox.child.wait(), if exit.is_none() => { exit = Some(result?); }
            _ = cancel.changed() => { break "stopped"; }
            _ = check.tick() => {
                if *cancel.borrow() { break "stopped"; }
                if now() >= expires || lease.lock().unwrap().elapsed() >= Duration::from_secs(6) { break "authorization_expired"; }
                if start.elapsed() >= Duration::from_secs(seconds) { break "timeout"; }
            }
        }
    };
    if exit.is_none() {
        let _ = sandbox.child.kill().await;
    }
    let mut value = run.lock().unwrap();
    let phase = if compile {
        value.compilation.as_mut()
    } else {
        value.execution.as_mut()
    }
    .unwrap();
    phase.exit_code = exit.and_then(|s| s.code());
    phase.duration_ms = Some(start.elapsed().as_millis() as u64);
    Ok(state.into())
}

#[derive(Default)]
struct OutputDecoder {
    pending: Vec<u8>,
}
impl OutputDecoder {
    fn decode(&mut self, bytes: &[u8], eof: bool) -> String {
        let mut buffer = std::mem::take(&mut self.pending);
        buffer.extend_from_slice(bytes);
        let mut rest = buffer.as_slice();
        let mut result = String::new();
        while !rest.is_empty() {
            match std::str::from_utf8(rest) {
                Ok(text) => {
                    result.push_str(text);
                    break;
                }
                Err(error) => {
                    result.push_str(std::str::from_utf8(&rest[..error.valid_up_to()]).unwrap());
                    rest = &rest[error.valid_up_to()..];
                    if let Some(count) = error.error_len() {
                        result.push('\u{fffd}');
                        rest = &rest[count..];
                    } else {
                        if eof {
                            result.push('\u{fffd}');
                        } else {
                            self.pending.extend_from_slice(rest);
                        }
                        break;
                    }
                }
            }
        }
        result
    }
}

fn append(run: &Arc<Mutex<Run>>, compile: bool, stderr: bool, bytes: &[u8]) -> bool {
    let mut value = run.lock().unwrap();
    let remaining = OUTPUT_BYTES.saturating_sub(output_size(&value));
    // Lossy UTF-8 can expand invalid bytes, so apply the bound after decoding.
    let text = String::from_utf8_lossy(bytes);
    let mut end = text.len().min(remaining);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let phase = if compile {
        value.compilation.as_mut()
    } else {
        value.execution.as_mut()
    }
    .unwrap();
    if stderr {
        phase.stderr.push_str(&text[..end]);
    } else {
        phase.stdout.push_str(&text[..end]);
    }
    text.len() > remaining || output_size(&value) >= OUTPUT_BYTES
}

async fn execute(
    work: tempfile::TempDir,
    python: bool,
    compiler: Option<String>,
    run: Arc<Mutex<Run>>,
    lease: Arc<Mutex<Instant>>,
    mut cancel: watch::Receiver<bool>,
    expires: i64,
) {
    let result: Result<String> = async {
        if !python {
            let compiler = format!("/usr/bin/{}", compiler.context("tool_missing")?);
            let state = phase(
                work.path(),
                true,
                &[
                    &compiler,
                    "-std=c17",
                    "-O0",
                    "-o",
                    "/work/program",
                    "/work/source.c",
                ],
                &run,
                true,
                &lease,
                &mut cancel,
                expires,
                10,
            )
            .await?;
            if state != "finished" {
                return Ok(if state == "failed" {
                    "compile_failed".into()
                } else {
                    state
                });
            }
        }
        let args: &[&str] = if python {
            &["/usr/bin/python3", "-I", "-B", "-u", "/work/source.py"]
        } else {
            &["/work/program"]
        };
        phase(
            work.path(),
            false,
            args,
            &run,
            false,
            &lease,
            &mut cancel,
            expires,
            5,
        )
        .await
    }
    .await;
    run.lock().unwrap().state = result.unwrap_or_else(|_| "isolation_failed".into());
}

#[cfg(test)]
mod tests;
