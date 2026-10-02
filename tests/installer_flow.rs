use anyhow::Result;
use mysyncfiles::release;
use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::Mutex,
};

// A concurrent fork can inherit another test's writable executable descriptor
// until exec closes it, causing ETXTBSY even after fs::write has returned.
// Serialize executable writes and process creation, but not child execution.
static EXECUTABLE_IO: Mutex<()> = Mutex::new(());

struct InstallerFixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    releases: PathBuf,
    home: PathBuf,
    script: PathBuf,
    mocks: PathBuf,
}

fn executable(path: &Path, bytes: &str) -> Result<()> {
    let _guard = EXECUTABLE_IO.lock().unwrap();
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    Ok(())
}

fn spawn_command(command: &mut Command) -> Result<Child> {
    let _guard = EXECUTABLE_IO.lock().unwrap();
    Ok(command.spawn()?)
}

fn command_output(command: &mut Command) -> Result<Output> {
    let child = spawn_command(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    )?;
    Ok(child.wait_with_output()?)
}

impl InstallerFixture {
    fn new(doctor_ok: bool) -> Result<Self> {
        Self::new_with_setup(doctor_ok, true)
    }

    fn new_with_setup(doctor_ok: bool, setup_ok: bool) -> Result<Self> {
        Self::new_with_capabilities(doctor_ok, setup_ok, true)
    }

    fn new_with_capabilities(doctor_ok: bool, setup_ok: bool, web_status: bool) -> Result<Self> {
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
                "#!/bin/sh\ncase \"$1\" in\n  --version) echo 'mysync 0.3.0';;\n  doctor) if [ \"${{MYSYNC_TEST_REQUIRE_EK_CERT:-}}\" = 1 ] && [ \"$2\" != --ek-cert ]; then echo 'EK cert missing' >&2; exit 1; fi; {};;\n  setup) if [ \"$2\" = --help ]; then {}; fi; test -t 0 || exit 23; printf '%s\\n' \"$*\" > \"$MYSYNC_TEST_SETUP_CALLED\"; exit \"${{MYSYNC_TEST_SETUP_EXIT:-0}}\";;\n  *) exit 1;;\nesac\n",
                if doctor_ok {
                    "echo 'TPM 2.0 is ready.'"
                } else {
                    "echo 'TPM unavailable' >&2; exit 1"
                },
                if setup_ok {
                    if web_status {
                        "echo '--web-status <true|false>'; exit 0"
                    } else {
                        "exit 0"
                    }
                } else {
                    "case \"$0\" in */source-client) exit 0;; *) exit 2;; esac"
                }
            ),
        )?;
        let releases_root = root.join("releases");
        let target = release::current_target().unwrap();
        {
            // Publication spawns the client for both compatibility probes.
            let _guard = EXECUTABLE_IO.lock().unwrap();
            release::publish(&key, &binary, "0.3.0", target, &releases_root)?;
        }
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
if [ "${MYSYNC_TEST_HTTP_STATUS:-200}" != 200 ] && {
    [ "$file" = latest.signed.json ] || [ "$file" = latest.json ] || [ "$file" = latest.sig ];
}; then
    printf '%s' "$MYSYNC_TEST_HTTP_STATUS"
    exit 0
fi
if [ ! -e "$MYSYNC_TEST_RELEASES/$file" ]; then
    printf 404
    exit 0
fi
cp "$MYSYNC_TEST_RELEASES/$file" "$destination" || exit 22
printf 200
"##,
        )?;
        executable(&mocks.join("tpm2_getcap"), "#!/bin/sh\nexit 0\n")?;
        executable(
            &mocks.join("systemctl"),
            "#!/bin/sh\nif [ \"$2\" = is-active ]; then exit 3; fi\n: > \"$MYSYNC_TEST_SYSTEMCTL_CALLED\"\nexit \"${MYSYNC_TEST_SYSTEMCTL_STATUS:-99}\"\n",
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

    fn command(&self, program: &str) -> Result<Command> {
        let mut command = Command::new(program);
        command
            .env("HOME", &self.home)
            // Keep profiles and units private even when the runner exports XDG_CONFIG_HOME.
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("SHELL", "/bin/sh")
            .env("NO_COLOR", "1")
            .env("TERM", "dumb")
            .env_remove("MYSYNC_WEB_STATUS")
            .env("MYSYNC_TEST_RELEASES", &self.releases)
            .env("MYSYNC_TEST_HTTP_STATUS", "200")
            .env("MYSYNC_TEST_SETUP_CALLED", self.root.join("setup-called"))
            .env(
                "MYSYNC_TEST_SYSTEMCTL_CALLED",
                self.root.join("systemctl-called"),
            )
            .env(
                "PATH",
                format!("{}:{}", self.mocks.display(), std::env::var("PATH")?),
            );
        Ok(command)
    }

    fn run_with_cert(&self, status: &str, certificate: Option<&Path>) -> Result<Output> {
        let mut command = self.command("sh")?;
        command.arg(&self.script);
        if let Some(certificate) = certificate {
            command.env("MYSYNC_EK_CERT", certificate);
            command.env("MYSYNC_TEST_REQUIRE_EK_CERT", "1");
        }
        command_output(command.env("MYSYNC_TEST_HTTP_STATUS", status))
    }

    fn run_interactive(&self, setup_exit: &str, piped: bool) -> Result<Output> {
        self.run_interactive_with_input(setup_exit, piped, b"\n\n")
    }

    fn run_interactive_with_input(
        &self,
        setup_exit: &str,
        piped: bool,
        input: &[u8],
    ) -> Result<Output> {
        self.run_interactive_with_setting(setup_exit, piped, input, None)
    }

    fn run_interactive_with_setting(
        &self,
        setup_exit: &str,
        piped: bool,
        input: &[u8],
        setting: Option<&str>,
    ) -> Result<Output> {
        let command = if piped {
            format!("cat {} | sh", self.script.display())
        } else {
            format!("sh {}", self.script.display())
        };
        let mut process = self.command("script")?;
        if let Some(setting) = setting {
            process.env("MYSYNC_WEB_STATUS", setting);
        }
        let mut child = spawn_command(
            process
                .args(["-q", "-e", "-c"])
                .arg(command)
                .arg("/dev/null")
                .env("MYSYNC_TEST_SETUP_EXIT", setup_exit)
                .env("MYSYNC_SERVER_PUBLIC_KEY", "test-origin-public-key")
                .env("MYSYNC_TEST_SYSTEMCTL_STATUS", "0")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        )?;
        child.stdin.take().unwrap().write_all(input)?;
        Ok(child.wait_with_output()?)
    }

    fn assert_not_installed(&self) {
        assert!(!self.home.join(".local/bin/mysync").exists());
        assert!(!self.root.join("systemctl-called").exists());
    }
}

fn mock_inaccessible_tss_device(fixture: &InstallerFixture) -> Result<()> {
    let script = fs::read_to_string(&fixture.script)?;
    let guard = "if [ -e /dev/tpmrm0 ] && { [ ! -r /dev/tpmrm0 ] || [ ! -w /dev/tpmrm0 ]; }; then";
    assert!(script.contains(guard));
    // Force only the device access predicate; keep the installer decision path intact.
    fs::write(&fixture.script, script.replacen(guard, "if true; then", 1))?;
    executable(
        &fixture.mocks.join("stat"),
        "#!/bin/sh\ncase \"$2\" in %G) echo tss;; %A) echo crw-rw----;; *) exit 1;; esac\n",
    )?;
    executable(
        &fixture.mocks.join("id"),
        "#!/bin/sh\ncase \"$1\" in\n  -un) echo alex;;\n  -nG) if [ \"$#\" -eq 1 ]; then echo 'alex users'; elif [ \"${MYSYNC_TEST_TSS_ASSIGNED:-}\" = 1 ]; then echo 'alex users tss'; else echo 'alex users'; fi;;\nesac\n",
    )?;
    executable(
        &fixture.mocks.join("sudo"),
        "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$MYSYNC_TEST_SUDO_CALLED\"\n",
    )?;
    Ok(())
}

#[test]
fn installer_guides_tss_membership_without_an_interactive_terminal() -> Result<()> {
    let fixture = InstallerFixture::new(true)?;
    mock_inaccessible_tss_device(&fixture)?;
    let output = fixture.run("200")?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("sudo usermod -aG tss alex"), "{stderr}");
    assert!(!fixture.root.join("sudo-called").exists());
    fixture.assert_not_installed();

    let output = command_output(
        fixture
            .command("sh")?
            .arg(&fixture.script)
            .env("MYSYNC_TEST_TSS_ASSIGNED", "1"),
    )?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("sign out and back in"));
    assert!(!fixture.root.join("sudo-called").exists());
    Ok(())
}

#[test]
fn installer_offers_tss_group_update_in_a_terminal() -> Result<()> {
    let fixture = InstallerFixture::new(true)?;
    mock_inaccessible_tss_device(&fixture)?;
    let mut child = spawn_command(
        fixture
            .command("script")?
            .args(["-q", "-e", "-c"])
            .arg(format!("sh {}", fixture.script.display()))
            .arg("/dev/null")
            .env("MYSYNC_TEST_SUDO_CALLED", fixture.root.join("sudo-called"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    )?;
    child.stdin.take().unwrap().write_all(b"y\n")?;
    let output = child.wait_with_output()?;
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Add alex to the tss group with sudo?"),
        "{stdout}"
    );
    assert!(stdout.contains("Sign out and back in"), "{stdout}");
    assert_eq!(
        fs::read_to_string(fixture.root.join("sudo-called"))?,
        "usermod -aG tss alex\n"
    );
    fixture.assert_not_installed();
    Ok(())
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
fn installer_rejects_a_signed_client_without_setup() -> Result<()> {
    let fixture = InstallerFixture::new_with_setup(true, false)?;
    let output = fixture.run("200")?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("lacks the setup command"));
    fixture.assert_not_installed();
    Ok(())
}

#[test]
fn installer_backs_up_an_older_or_different_same_version_client() -> Result<()> {
    for previous_version in ["0.2.9", "0.3.0"] {
        let fixture = InstallerFixture::new(true)?;
        let bin_dir = fixture.home.join(".local/bin");
        fs::create_dir_all(&bin_dir)?;
        let old_binary = format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'mysync {previous_version}'; else exit 2; fi\n"
        );
        executable(&bin_dir.join("mysync"), &old_binary)?;

        let output = fixture.run("200")?;
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("Back up"));
        assert_eq!(fs::read_to_string(bin_dir.join("mysync"))?, old_binary);

        let output = fixture.run_interactive_with_input("0", false, b"y\n\n\n")?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(
            fs::read(bin_dir.join("mysync"))?,
            fs::read(fixture.root.join("source-client"))?
        );
        let backups: Vec<_> = fs::read_dir(&bin_dir)?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("mysync.backup.")
            })
            .collect();
        assert_eq!(backups.len(), 1);
        assert_eq!(fs::read_to_string(backups[0].join("mysync"))?, old_binary);
        assert!(fixture.root.join("setup-called").exists());
    }
    Ok(())
}

#[test]
fn installer_archives_a_legacy_token_profile_before_pairing() -> Result<()> {
    let fixture = InstallerFixture::new(true)?;
    let config_dir = fixture.home.join(".config/mysync");
    let mirror = fixture.home.join("Sync");
    fs::create_dir_all(&config_dir)?;
    fs::create_dir_all(&mirror)?;
    fs::write(mirror.join("local.txt"), "local content")?;
    let profile = serde_json::to_vec(&serde_json::json!({
        "server": "https://sync.example.test",
        "root": mirror,
        "token": "obsolete-secret"
    }))?;
    fs::write(config_dir.join("config.json"), &profile)?;
    fs::write(config_dir.join("config.state.json"), b"old state")?;
    fs::write(config_dir.join("config.state.journal"), b"old journal")?;

    let output = fixture.run_interactive_with_input("0", true, b"y\n\n\n")?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(!config_dir.join("config.json").exists());
    assert!(!config_dir.join("config.state.json").exists());
    assert!(!config_dir.join("config.state.journal").exists());
    let backups: Vec<_> = fs::read_dir(&config_dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("legacy-profile.")
        })
        .collect();
    assert_eq!(backups.len(), 1);
    assert_eq!(fs::read(backups[0].join("config.json"))?, profile);
    assert_eq!(
        fs::read(backups[0].join("config.state.json"))?,
        b"old state"
    );
    assert_eq!(
        fs::read(backups[0].join("config.state.journal"))?,
        b"old journal"
    );
    assert_eq!(
        fs::read_to_string(mirror.join("local.txt"))?,
        "local content"
    );
    assert!(fixture.root.join("setup-called").exists());
    assert!(fixture.root.join("systemctl-called").exists());
    Ok(())
}

#[test]
fn installer_leaves_legacy_profile_untouched_without_consent() -> Result<()> {
    let fixture = InstallerFixture::new(true)?;
    let config_dir = fixture.home.join(".config/mysync");
    fs::create_dir_all(&config_dir)?;
    fs::write(config_dir.join("config.json"), b"{\"token\":\"old\"}")?;
    fs::write(config_dir.join("config.state.json"), b"old state")?;

    let output = fixture.run_interactive_with_input("0", true, b"\n")?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("legacy token profile"));
    assert_eq!(
        fs::read(config_dir.join("config.json"))?,
        b"{\"token\":\"old\"}"
    );
    assert_eq!(
        fs::read(config_dir.join("config.state.json"))?,
        b"old state"
    );
    assert!(!fixture.root.join("setup-called").exists());
    assert!(!fixture.root.join("systemctl-called").exists());

    let output = fixture.run("200")?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Rerun this installer in a terminal"));
    assert_eq!(
        fs::read(config_dir.join("config.json"))?,
        b"{\"token\":\"old\"}"
    );
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
    assert!(setup.contains("--web-status true"));
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
fn installer_offers_web_status_and_preserves_saved_opt_out() -> Result<()> {
    for (input, setting) in [
        (b"\nn\n".as_slice(), None),
        (b"\n".as_slice(), Some("false")),
    ] {
        let fixture = InstallerFixture::new(true)?;
        let output = fixture.run_interactive_with_setting("0", true, input, setting)?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            fs::read_to_string(fixture.root.join("setup-called"))?.contains("--web-status false")
        );
        assert!(fixture.root.join("systemctl-called").exists());
    }
    // Both an active profile and a pairing awaiting approval keep their choice.
    for filename in ["config.json", "config.pairing.json"] {
        let fixture = InstallerFixture::new(true)?;
        let config_dir = fixture.home.join(".config/mysync");
        fs::create_dir_all(&config_dir)?;
        fs::write(config_dir.join(filename), b"{\"web_status_enabled\":false}")?;
        let output = fixture.run_interactive("0", false)?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("[y/N]"));
        assert!(
            fs::read_to_string(fixture.root.join("setup-called"))?.contains("--web-status false")
        );
    }
    Ok(())
}

#[test]
fn installer_checks_web_status_input_and_legacy_capability() -> Result<()> {
    let fixture = InstallerFixture::new(true)?;
    let output = command_output(
        fixture
            .command("sh")?
            .arg(&fixture.script)
            .env("MYSYNC_WEB_STATUS", "invalid"),
    )?;
    assert!(!output.status.success());
    fixture.assert_not_installed();

    let output = fixture.run_interactive_with_input("0", false, b"\ninvalid\nn\n")?;
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Please answer yes or no"));
    assert!(fs::read_to_string(fixture.root.join("setup-called"))?.contains("--web-status false"));

    let legacy = InstallerFixture::new_with_capabilities(true, true, false)?;
    let output = command_output(
        legacy
            .command("sh")?
            .arg(&legacy.script)
            .env("MYSYNC_WEB_STATUS", "false"),
    )?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("lacks --web-status"));
    legacy.assert_not_installed();
    let output = legacy.run_interactive_with_input("0", false, b"\n")?;
    assert!(output.status.success());
    assert!(!fs::read_to_string(legacy.root.join("setup-called"))?.contains("--web-status"));
    Ok(())
}

#[test]
fn noninteractive_installer_passes_web_status_to_the_next_setup_command() -> Result<()> {
    let fixture = InstallerFixture::new(true)?;
    let output = command_output(
        fixture
            .command("sh")?
            .arg(&fixture.script)
            .env("MYSYNC_WEB_STATUS", "false"),
    )?;
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("--web-status false"));
    assert!(!fixture.root.join("setup-called").exists());
    assert!(!fixture.root.join("systemctl-called").exists());
    Ok(())
}

#[test]
fn source_installer_applies_web_status_before_starting_service() -> Result<()> {
    let fixture = InstallerFixture::new(true)?;
    executable(&fixture.mocks.join("id"), "#!/bin/sh\necho test-user\n")?;
    let config = fixture.home.join(".config/mysync/config.json");
    fs::create_dir_all(config.parent().unwrap())?;
    fs::write(
        &config,
        serde_json::to_vec(&serde_json::json!({
            "server": "https://sync.example.test", "root": fixture.home
        }))?,
    )?;
    executable(&fixture.mocks.join("loginctl"), "#!/bin/sh\necho yes\n")?;
    // A service start checks that the selected preference was already saved.
    executable(
        &fixture.mocks.join("systemctl"),
        r##"#!/bin/sh
python3 - "$XDG_CONFIG_HOME/mysync/config.json" "$MYSYNC_TEST_EXPECT_WEB_STATUS" <<'PY'
import json, sys
with open(sys.argv[1]) as source:
    assert json.load(source)['web_status_enabled'] == (sys.argv[2] == 'true')
PY
"##,
    )?;
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("deploy/install-client.sh");
    for setting in ["false", "true"] {
        let output = command_output(
            fixture
                .command("bash")?
                .arg(&script)
                .arg(env!("CARGO_BIN_EXE_mysync"))
                .env("MYSYNC_WEB_STATUS", setting)
                .env("MYSYNC_TEST_EXPECT_WEB_STATUS", setting),
        )?;
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
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
    fs::remove_file(invalid_signature.releases.join("latest.signed.json"))?;
    fs::write(
        invalid_signature.releases.join("latest.sig"),
        "00".repeat(64),
    )?;
    let output = invalid_signature.run("200")?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("signature is invalid"));
    invalid_signature.assert_not_installed();

    let invalid_envelope = InstallerFixture::new(true)?;
    fs::write(
        invalid_envelope.releases.join("latest.signed.json"),
        serde_json::json!({"manifest": "", "signature": "00".repeat(64)}).to_string(),
    )?;
    let output = invalid_envelope.run("200")?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("signature is invalid"));
    invalid_envelope.assert_not_installed();

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
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing to downgrade"));
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
