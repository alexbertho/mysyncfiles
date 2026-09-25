use anyhow::Result;
use mysyncfiles::release;
use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

struct InstallerFixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    releases: PathBuf,
    home: PathBuf,
    script: PathBuf,
    mocks: PathBuf,
}

fn executable(path: &Path, bytes: &str) -> Result<()> {
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    Ok(())
}

impl InstallerFixture {
    fn new(doctor_ok: bool) -> Result<Self> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().to_path_buf();
        let home = root.join("home");
        let mocks = root.join("mockbin");
        fs::create_dir(&home)?;
        fs::create_dir(&mocks)?;
        let key = root.join("signing.key");
        let public = release::generate_key(&key)?;
        let binary = root.join("source-client");
        executable(
            &binary,
            &format!(
                "#!/bin/sh\ncase \"$1\" in\n  --version) echo 'mysync 0.3.0';;\n  doctor) if [ \"${{MYSYNC_TEST_REQUIRE_EK_CERT:-}}\" = 1 ] && [ \"$2\" != --ek-cert ]; then echo 'EK cert missing' >&2; exit 1; fi; {};;\n  setup) test -t 0 || exit 23; printf '%s\\n' \"$*\" > \"$MYSYNC_TEST_SETUP_CALLED\"; exit \"${{MYSYNC_TEST_SETUP_EXIT:-0}}\";;\n  *) exit 1;;\nesac\n",
                if doctor_ok {
                    "echo 'TPM 2.0 is ready.'"
                } else {
                    "echo 'TPM unavailable' >&2; exit 1"
                }
            ),
        )?;
        let releases_root = root.join("releases");
        let target = release::current_target().unwrap();
        release::publish(&key, &binary, "0.3.0", target, &releases_root)?;
        let releases = releases_root.join(target);
        executable(
            &mocks.join("curl"),
            r##"#!/bin/sh
destination= url=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --output) destination=$2; shift 2 ;;
        --write-out|--proto|--max-redirs|--connect-timeout|--max-time|--max-filesize) shift 2 ;;
        --fail|--silent|--show-error) shift ;;
        *) url=$1; shift ;;
    esac
done
file=${url##*/}
if [ "${MYSYNC_TEST_HTTP_STATUS:-200}" != 200 ] && [ "$file" = latest.json ]; then
    printf '%s' "$MYSYNC_TEST_HTTP_STATUS"
    exit 0
fi
cp "$MYSYNC_TEST_RELEASES/$file" "$destination" || exit 22
printf 200
"##,
        )?;
        executable(&mocks.join("tpm2_getcap"), "#!/bin/sh\nexit 0\n")?;
        executable(
            &mocks.join("systemctl"),
            "#!/bin/sh\n: > \"$MYSYNC_TEST_SYSTEMCTL_CALLED\"\nexit \"${MYSYNC_TEST_SYSTEMCTL_STATUS:-99}\"\n",
        )?;
        let template = include_str!("../deploy/install.sh");
        let script = root.join("install.sh");
        fs::write(
            &script,
            template
                .replace("@MYSYNC_SERVER_URL@", "'https://sync.example.test'")
                .replace("@MYSYNC_PUBLIC_KEY@", &format!("'{public}'"))
                .replace(
                    "@MYSYNC_UNIT@",
                    include_str!("../deploy/mysync.service").trim_end_matches('\n'),
                ),
        )?;
        Ok(Self {
            _temp: temp,
            root,
            releases,
            home,
            script,
            mocks,
        })
    }

    fn run(&self, status: &str) -> Result<Output> {
        self.run_with_cert(status, None)
    }

    fn run_with_cert(&self, status: &str, certificate: Option<&Path>) -> Result<Output> {
        let mut command = Command::new("sh");
        command.arg(&self.script);
        if let Some(certificate) = certificate {
            command.env("MYSYNC_EK_CERT", certificate);
            command.env("MYSYNC_TEST_REQUIRE_EK_CERT", "1");
        }
        Ok(command
            .env("HOME", &self.home)
            .env("NO_COLOR", "1")
            .env("TERM", "dumb")
            .env("MYSYNC_TEST_RELEASES", &self.releases)
            .env("MYSYNC_TEST_HTTP_STATUS", status)
            .env("MYSYNC_TEST_SETUP_CALLED", self.root.join("setup-called"))
            .env(
                "MYSYNC_TEST_SYSTEMCTL_CALLED",
                self.root.join("systemctl-called"),
            )
            .env(
                "PATH",
                format!("{}:{}", self.mocks.display(), std::env::var("PATH")?),
            )
            .output()?)
    }

    fn run_interactive(&self, setup_exit: &str, piped: bool) -> Result<Output> {
        let command = if piped {
            format!("cat {} | sh", self.script.display())
        } else {
            format!("sh {}", self.script.display())
        };
        let mut child = Command::new("script")
            .args(["-q", "-e", "-c"])
            .arg(command)
            .arg("/dev/null")
            .env("HOME", &self.home)
            .env("NO_COLOR", "1")
            .env("TERM", "dumb")
            .env("MYSYNC_TEST_RELEASES", &self.releases)
            .env("MYSYNC_TEST_HTTP_STATUS", "200")
            .env("MYSYNC_TEST_SETUP_CALLED", self.root.join("setup-called"))
            .env("MYSYNC_TEST_SETUP_EXIT", setup_exit)
            .env("MYSYNC_SERVER_PUBLIC_KEY", "test-origin-public-key")
            .env("MYSYNC_TEST_SYSTEMCTL_STATUS", "0")
            .env(
                "MYSYNC_TEST_SYSTEMCTL_CALLED",
                self.root.join("systemctl-called"),
            )
            .env(
                "PATH",
                format!("{}:{}", self.mocks.display(), std::env::var("PATH")?),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        child.stdin.take().unwrap().write_all(b"\n")?;
        Ok(child.wait_with_output()?)
    }

    fn assert_not_installed(&self) {
        assert!(!self.home.join(".local/bin/mysync").exists());
        assert!(!self.root.join("systemctl-called").exists());
    }
}

#[test]
fn signed_installer_accepts_explicit_ek_certificate() -> Result<()> {
    let fixture = InstallerFixture::new(true)?;
    let certificate = fixture.root.join("ek.der");
    fs::write(&certificate, b"test certificate path")?;
    let output = fixture.run_with_cert("200", Some(&certificate))?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(fixture.home.join(".local/bin/mysync").exists());
    Ok(())
}

#[test]
fn signed_installer_stages_unit_but_does_not_start_service() -> Result<()> {
    let fixture = InstallerFixture::new(true)?;
    let output = fixture.run("200")?;
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(fixture.home.join(".local/bin/mysync").exists());
    assert_eq!(
        fs::read(fixture.home.join(".config/systemd/user/mysync.service"))?,
        include_bytes!("../deploy/mysync.service")
    );
    assert!(!fixture.root.join("systemctl-called").exists());
    assert!(!output.stdout.contains(&0x1b));
    assert!(String::from_utf8_lossy(&output.stdout).contains("mysync setup"));
    Ok(())
}

#[test]
fn interactive_installer_starts_service_only_after_setup_succeeds() -> Result<()> {
    let success = InstallerFixture::new(true)?;
    let output = success.run_interactive("0", false)?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let setup = fs::read_to_string(success.root.join("setup-called"))?;
    assert!(setup.contains("setup --server https://sync.example.test"));
    assert!(setup.contains("--dir"));
    assert!(setup.contains("--server-public-key test-origin-public-key"));
    assert!(success.root.join("systemctl-called").exists());

    let failed = InstallerFixture::new(true)?;
    let output = failed.run_interactive("2", false)?;
    assert!(!output.status.success());
    assert!(failed.root.join("setup-called").exists());
    assert!(!failed.root.join("systemctl-called").exists());

    let custom_unit = InstallerFixture::new(true)?;
    let unit_dir = custom_unit.home.join(".config/systemd/user");
    fs::create_dir_all(&unit_dir)?;
    fs::write(
        unit_dir.join("mysync.service"),
        "[Service]\nExecStart=/custom/client\n",
    )?;
    let output = custom_unit.run_interactive("0", false)?;
    assert!(output.status.success());
    assert!(custom_unit.root.join("setup-called").exists());
    assert!(!custom_unit.root.join("systemctl-called").exists());
    Ok(())
}

#[test]
fn piped_installer_still_pairs_in_an_interactive_terminal() -> Result<()> {
    let fixture = InstallerFixture::new(true)?;
    let output = fixture.run_interactive("0", true)?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(fixture.root.join("setup-called").exists());
    assert!(fixture.root.join("systemctl-called").exists());
    Ok(())
}

#[test]
fn signed_installer_rejects_bad_signature_binary_and_tpm() -> Result<()> {
    let invalid_signature = InstallerFixture::new(true)?;
    fs::write(
        invalid_signature.releases.join("latest.sig"),
        "00".repeat(64),
    )?;
    let output = invalid_signature.run("200")?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("signature is invalid"));
    invalid_signature.assert_not_installed();

    let invalid_binary = InstallerFixture::new(true)?;
    let artifact = format!("mysync-0.3.0-{}", release::current_target().unwrap());
    fs::write(invalid_binary.releases.join(artifact), "tampered")?;
    let output = invalid_binary.run("200")?;
    assert!(!output.status.success());
    invalid_binary.assert_not_installed();

    let no_tpm = InstallerFixture::new(false)?;
    let output = no_tpm.run("200")?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("TPM preflight failed"));
    no_tpm.assert_not_installed();
    Ok(())
}

#[test]
fn signed_installer_rejects_redirects_and_missing_releases() -> Result<()> {
    for status in ["302", "404"] {
        let fixture = InstallerFixture::new(true)?;
        let output = fixture.run(status)?;
        assert!(!output.status.success());
        fixture.assert_not_installed();
    }
    Ok(())
}

#[test]
fn signed_installer_does_not_replace_existing_client_or_follow_bin_symlink() -> Result<()> {
    let existing = InstallerFixture::new(true)?;
    fs::create_dir_all(existing.home.join(".local/bin"))?;
    let destination = existing.home.join(".local/bin/mysync");
    executable(&destination, "#!/bin/sh\necho 'mysync 9.0.0'\n")?;
    let output = existing.run("200")?;
    assert!(output.status.success());
    assert_eq!(
        fs::read_to_string(destination)?,
        "#!/bin/sh\necho 'mysync 9.0.0'\n"
    );

    let symlink = InstallerFixture::new(true)?;
    fs::create_dir(symlink.home.join(".local"))?;
    let outside = symlink.root.join("outside");
    fs::create_dir(&outside)?;
    std::os::unix::fs::symlink(&outside, symlink.home.join(".local/bin"))?;
    let output = symlink.run("200")?;
    assert!(!output.status.success());
    assert!(!outside.join("mysync").exists());
    Ok(())
}

#[test]
fn signed_installer_rejects_unsupported_architecture() -> Result<()> {
    let fixture = InstallerFixture::new(true)?;
    executable(
        &fixture.mocks.join("uname"),
        "#!/bin/sh\ncase \"$1\" in -s) echo Linux;; -m) echo mips64;; esac\n",
    )?;
    let output = fixture.run("200")?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Unsupported CPU architecture"));
    fixture.assert_not_installed();
    Ok(())
}
