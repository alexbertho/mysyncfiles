use anyhow::Result;
use fs2::FileExt;
use mysyncfiles::{client, tpm::Identity};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Output},
};

fn cli(config: &Path, args: &[&str]) -> Result<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_mysync"))
        .arg("--config")
        .arg(config)
        .args(args)
        .output()?)
}

#[test]
fn web_status_cli_defaults_to_enabled_and_changes_only_the_preference() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mirror = temp.path().join("mirror");
    fs::create_dir(&mirror)?;
    fs::write(mirror.join("keep"), b"local content")?;
    let config = temp.path().join("client.json");
    // No reachable server, origin key or TPM: these commands must stay local.
    let mut value = serde_json::json!({
        "server": "https://sync.example.test",
        "server_public_key": "not-used",
        "root": mirror,
        "auto_update": false,
        "update_public_key": "not-used",
        "identity": Identity {
            device: "existing-enrollment".into(), public: "opaque-public".into(),
            private: "opaque-wrapped-key".into(), ek_kind: "rsa".into(),
            tcti: "device:/not/a/tpm".into(),
        }
    });
    let original = serde_json::to_vec(&value)?;
    fs::write(&config, &original)?;
    fs::write(config.with_extension("state.json"), b"unchanged state")?;
    fs::write(config.with_extension("state.journal"), b"unchanged journal")?;
    for args in [vec!["web-status"], vec!["web-status", "status"]] {
        let result = cli(&config, &args)?;
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(result.stdout, b"web_status_enabled=true\n");
        assert_eq!(fs::read(&config)?, original);
    }
    for (action, enabled) in [("disable", false), ("enable", true)] {
        let result = cli(&config, &["web-status", action])?;
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(String::from_utf8_lossy(&result.stdout).contains("restart"));
        value["web_status_enabled"] = enabled.into();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&fs::read(&config)?)?,
            value
        );
        assert_eq!(client::load_config(&config)?.web_status_enabled, enabled);
        let result = cli(&config, &["web-status", "status"])?;
        assert!(result.status.success());
        assert_eq!(
            String::from_utf8(result.stdout)?,
            format!("web_status_enabled={enabled}\n")
        );
        assert_eq!(fs::metadata(&config)?.permissions().mode() & 0o777, 0o600);
    }
    assert_eq!(
        fs::read(config.with_extension("state.json"))?,
        b"unchanged state"
    );
    assert_eq!(
        fs::read(config.with_extension("state.journal"))?,
        b"unchanged journal"
    );
    assert_eq!(fs::read(mirror.join("keep"))?, b"local content");
    Ok(())
}

#[test]
fn web_status_changes_fail_promptly_when_the_profile_is_busy() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let config = temp.path().join("client.json");
    let original = serde_json::to_vec(&serde_json::json!({
        "server": "https://sync.example.test", "root": temp.path(), "web_status_enabled": false
    }))?;
    fs::write(&config, &original)?;
    let lock = fs::File::create(config.with_extension("lock"))?;
    lock.lock_exclusive()?;
    let result = cli(&config, &["web-status", "enable"])?;
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("profile is busy"));
    assert_eq!(fs::read(&config)?, original);
    Ok(())
}
