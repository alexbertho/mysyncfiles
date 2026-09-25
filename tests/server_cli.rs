use anyhow::Result;
use mysyncfiles::server;
use std::process::Command;

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
