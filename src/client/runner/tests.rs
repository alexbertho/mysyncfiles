use super::*;

#[test]
fn unicode_output_survives_arbitrary_pipe_boundaries() {
    let mut decoder = OutputDecoder::default();
    let mut text = String::new();
    for byte in "été 🦀\n".as_bytes() {
        text.push_str(&decoder.decode(&[*byte], false));
    }
    text.push_str(&decoder.decode(&[], true));
    assert_eq!(text, "été 🦀\n");
    assert_eq!(decoder.decode(&[0xff, b'x', 0xc3], false), "�x");
    assert_eq!(decoder.decode(&[], true), "�");
}

#[test]
fn output_is_bounded_after_decoding_and_across_both_phases() {
    let run = Arc::new(Mutex::new(Run {
        job_id: String::new(),
        sha256: String::new(),
        state: "running".into(),
        compilation: Some(Phase::default()),
        execution: Some(Phase::default()),
    }));
    assert!(!append(&run, true, false, b"compiler"));
    assert!(append(&run, false, true, &vec![255; OUTPUT_BYTES]));
    assert!(output_size(&run.lock().unwrap()) <= OUTPUT_BYTES);
}

// These tests run on a Linux desktop with working user namespaces, systemd and
// delegated cgroup v2 controllers. CI without isolation must fail closed too.
#[tokio::test]
async fn runner_executes_only_with_enforced_isolation() -> Result<()> {
    let runner = Runner::default();
    let tools = runner.detect().await;
    if !tools.isolation {
        assert!(
            std::env::var_os("MYSYNC_REQUIRE_RUNNER").is_none(),
            "runner isolation required by this test environment"
        );
        eprintln!("sandbox execution unavailable; verified closed state");
        let result = runner
            .handle(Authorization {
                operation: Operation::Start {
                    path: "test.py".into(),
                    revision: 1,
                    sha256: hash(b"pass"),
                    job_id: uuid::Uuid::new_v4().to_string(),
                },
                owner: "owner".into(),
                source: Some("pass".into()),
                expires_at: now() + 60,
            })
            .await;
        assert!(result.is_err());
        return Ok(());
    }
    async fn run(runner: &Runner, path: &str, source: &str, stop: bool) -> Result<Run> {
        let job_id = uuid::Uuid::new_v4().to_string();
        let auth = |operation, source| Authorization {
            operation,
            owner: "owner".into(),
            source,
            expires_at: now() + 60,
        };
        runner
            .handle(auth(
                Operation::Start {
                    path: path.into(),
                    revision: 1,
                    sha256: hash(source),
                    job_id: job_id.clone(),
                },
                Some(source.into()),
            ))
            .await?;
        let foreign = runner
            .handle(Authorization {
                operation: Operation::Poll {
                    job_id: job_id.clone(),
                },
                owner: "foreign".into(),
                source: None,
                expires_at: now() + 60,
            })
            .await;
        assert!(foreign.is_err());
        for i in 0..150 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let operation = if stop && i == 5 {
                Operation::Stop {
                    job_id: job_id.clone(),
                }
            } else {
                Operation::Poll {
                    job_id: job_id.clone(),
                }
            };
            let value: Run = serde_json::from_value(runner.handle(auth(operation, None)).await?)?;
            if value.state != "running" {
                return Ok(value);
            }
        }
        anyhow::bail!("runner did not finish")
    }
    if tools.python {
        let good = run(&runner, "ok.py", "print(sum([4,8,15,16,23,42]))", false).await?;
        assert_eq!(good.state, "finished");
        assert_eq!(good.execution.unwrap().stdout, "108\n");
        let failed = run(&runner, "error.py", "raise ValueError('test')", false).await?;
        assert_eq!(failed.state, "failed");
        assert!(failed.execution.unwrap().stderr.contains("ValueError"));
        let exit = run(&runner, "exit.py", "raise SystemExit(7)", false).await?;
        assert_eq!(exit.execution.unwrap().exit_code, Some(7));
        assert_eq!(
            run(&runner, "wait.py", "while True: pass", true)
                .await?
                .state,
            "stopped"
        );
        assert_eq!(
            run(&runner, "wait.py", "import time; time.sleep(60)", false)
                .await?
                .state,
            "timeout"
        );
        assert_eq!(
            run(&runner, "noisy.py", "while True: print('x'*1000)", false)
                .await?
                .state,
            "output_limit"
        );
        let isolated = run(&runner,"isolation.py","import os, socket\nassert not os.path.exists('/home')\nassert not os.path.exists('/etc/passwd')\nassert 'SECRET' not in os.environ\ns=socket.socket()\ntry:\n s.connect(('1.1.1.1',80))\n raise Exception('network exposed')\nexcept OSError: pass\nprint('isolated')",false).await?;
        assert_eq!(isolated.state, "finished");
        let memory = run(
            &runner,
            "memory.py",
            "data = bytearray(300 * 1024 * 1024)",
            false,
        )
        .await?;
        assert_eq!(memory.state, "failed");
        let processes = run(&runner,"processes.py","import subprocess\nchildren=[]\ntry:\n for i in range(80): children.append(subprocess.Popen(['/usr/bin/sleep','60']))\nexcept OSError:\n print('limited')\nfinally:\n for p in children: p.kill()\n for p in children: p.wait()",false).await?;
        assert_eq!(processes.state, "finished");
        assert!(processes.execution.unwrap().stdout.contains("limited"));
        let marker = format!("mysync-child-{}", uuid::Uuid::new_v4().simple());
        let code = format!(
            "import subprocess, time\nsubprocess.Popen(['/usr/bin/python3','-c','import time; time.sleep(60)','{marker}'],start_new_session=True)\nprint('child started')\ntime.sleep(60)"
        );
        let child = run(&runner, "children.py", &code, true).await?;
        assert_eq!(child.state, "stopped");
        assert!(child.execution.unwrap().stdout.contains("child started"));
        let descendants = || -> Result<bool> {
            for entry in std::fs::read_dir("/proc")? {
                let path = entry?.path();
                if path
                    .file_name()
                    .is_some_and(|n| n.as_encoded_bytes().iter().all(u8::is_ascii_digit))
                    && let Ok(bytes) = std::fs::read(path.join("cmdline"))
                    && bytes
                        .windows(marker.len())
                        .any(|part| part == marker.as_bytes())
                {
                    return Ok(true);
                }
            }
            Ok(false)
        };
        for _ in 0..20 {
            if !descendants()? {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            !descendants()?,
            "stopping the runner must kill detached descendants"
        );
        let job_id = uuid::Uuid::new_v4().to_string();
        let source = "import time; time.sleep(60)";
        runner
            .handle(Authorization {
                operation: Operation::Start {
                    path: "expired.py".into(),
                    revision: 1,
                    sha256: hash(source),
                    job_id: job_id.clone(),
                },
                owner: "expiry".into(),
                source: Some(source.into()),
                expires_at: now() + 2,
            })
            .await?;
        tokio::time::sleep(Duration::from_secs(3)).await;
        let value: Run = serde_json::from_value(
            runner
                .handle(Authorization {
                    operation: Operation::Poll { job_id },
                    owner: "expiry".into(),
                    source: None,
                    expires_at: now() + 60,
                })
                .await?,
        )?;
        assert_eq!(value.state, "authorization_expired");
    }
    if tools.compiler.is_some() {
        let good = run(
            &runner,
            "ok.c",
            "#include <stdio.h>\nint main(void) { puts(\"hello\"); return 0; }",
            false,
        )
        .await?;
        assert_eq!(good.state, "finished");
        assert_eq!(good.execution.unwrap().stdout, "hello\n");
        assert!(good.compilation.unwrap().duration_ms.is_some());
        let bad = run(&runner, "bad.c", "invalid C code", false).await?;
        assert_eq!(bad.state, "compile_failed");
        assert!(bad.execution.is_none());
    }
    Ok(())
}
