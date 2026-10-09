use anyhow::Result;
use mysyncfiles_server::server;
use std::process::Command;

#[test]
fn init_requires_and_persists_a_valid_display_name() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let run = |name: Option<&str>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_mysync-server"));
        command.args(["init", "--data-dir"]).arg(temp.path());
        if let Some(name) = name {
            command.args(["--name", name]);
        }
        command.stdin(std::process::Stdio::null()).output()
    };
    for name in [None, Some(" "), Some("line\nbreak")] {
        assert!(!run(name)?.status.success());
    }
    assert!(run(Some("  Home server  "))?.status.success());
    let state = server::open(temp.path())?;
    assert_eq!(
        mysyncfiles_server::device_auth::server_name(&state)?,
        "Home server"
    );
    Ok(())
}

#[test]
fn public_url_command_reads_the_administrator_setting() -> Result<()> {
    let temp = tempfile::tempdir()?;
    server::open(temp.path())?;

    let output = Command::new(env!("CARGO_BIN_EXE_mysync-server"))
        .args(["device", "public-url", "--data-dir"])
        .arg(temp.path())
        .output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("public URL is not configured"));

    rusqlite::Connection::open(temp.path().join("metadata.sqlite3"))?.execute(
        "INSERT INTO auth_settings(key, value) VALUES('public_url', ?1)",
        ["https://sync.example.test"],
    )?;
    let output = Command::new(env!("CARGO_BIN_EXE_mysync-server"))
        .args(["device", "public-url", "--data-dir"])
        .arg(temp.path())
        .output()?;
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout)?,
        "https://sync.example.test\n"
    );
    Ok(())
}
