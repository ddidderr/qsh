//! End-to-end tests: a real `qsh-server` on a loopback UDP port, driven by the
//! real `qsh` binary. These are the tests that would catch a regression in the
//! parts users actually touch — exit codes, binary transparency, `rsync -e
//! qsh`, and the authorisation rules.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const SERVER_BIN: &str = env!("CARGO_BIN_EXE_qsh-server");
const CLIENT_BIN: &str = env!("CARGO_BIN_EXE_qsh");

/// A running server plus the client configuration that may talk to it.
struct Fixture {
    _tmp: tempfile::TempDir,
    server_dir: PathBuf,
    client_dir: PathBuf,
    port: u16,
    server: Child,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.server.kill();
        let _ = self.server.wait();
    }
}

fn run(bin: &str, args: &[&str]) -> std::process::Output {
    let out = Command::new(bin)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("running {bin} {args:?}: {e}"));
    assert!(
        out.status.success(),
        "{bin} {args:?} failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn current_user() -> String {
    std::env::var("USER")
        .ok()
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| {
            nix::unistd::User::from_uid(nix::unistd::Uid::current())
                .unwrap()
                .unwrap()
                .name
        })
}

impl Fixture {
    /// Set up server and client identities, authorise the client, start the
    /// server and wait until it answers.
    fn start(extra_authorize: &[&str]) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let server_dir = tmp.path().join("server");
        let client_dir = tmp.path().join("client");

        run(
            SERVER_BIN,
            &["--dir", server_dir.to_str().unwrap(), "keygen"],
        );
        run(
            CLIENT_BIN,
            &["keygen", "--identity", client_dir.to_str().unwrap()],
        );

        let mut args = vec![
            "--dir".to_string(),
            server_dir.to_string_lossy().into_owned(),
            "authorize".to_string(),
            client_dir.join("id.crt").to_string_lossy().into_owned(),
            "--user".to_string(),
            current_user(),
            "--name".to_string(),
            "tester".to_string(),
        ];
        args.extend(extra_authorize.iter().map(|s| s.to_string()));
        run(
            SERVER_BIN,
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
        );

        // Let the kernel choose the port and learn it from the server's own
        // log line; picking a port up front would race with parallel tests.
        let log = tmp.path().join("server.log");
        let server = Command::new(SERVER_BIN)
            .args([
                "--dir",
                server_dir.to_str().unwrap(),
                "serve",
                "--listen",
                "127.0.0.1:0",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::from(std::fs::File::create(&log).unwrap()))
            .spawn()
            .expect("starting qsh-server");

        let port = wait_for_port(&log);
        Self {
            _tmp: tmp,
            server_dir,
            client_dir,
            port,
            server,
        }
    }

    fn client(&self) -> Command {
        let mut cmd = Command::new(CLIENT_BIN);
        cmd.args([
            "-i",
            self.client_dir.to_str().unwrap(),
            "-p",
            &self.port.to_string(),
            "--accept-new",
            "-q",
            "127.0.0.1",
        ]);
        cmd
    }

    /// Run a remote command and return (status, stdout, stderr).
    fn exec(&self, argv: &[&str]) -> (i32, String, String) {
        let out = self
            .client()
            .args(argv)
            .stdin(Stdio::null())
            .output()
            .expect("running qsh");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }
}

/// Read the port out of the server's `listening on 127.0.0.1:NNNNN` line.
fn wait_for_port(log: &Path) -> u16 {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(text) = std::fs::read_to_string(log) {
            if let Some(rest) = text.split("listening on ").nth(1) {
                if let Some(addr) = rest.split_whitespace().next() {
                    return addr
                        .rsplit(':')
                        .next()
                        .and_then(|p| p.parse().ok())
                        .unwrap_or_else(|| panic!("cannot parse address {addr}"));
                }
            }
        }
        assert!(
            Instant::now() < deadline,
            "server never reported a listening address"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn remote_command_reports_its_exit_status() {
    let f = Fixture::start(&[]);
    assert_eq!(f.exec(&["true"]).0, 0);
    assert_eq!(f.exec(&["sh", "-c", "exit 42"]).0, 42);
    // Killed by SIGTERM: 128 + 15, the shell convention.
    assert_eq!(f.exec(&["sh", "-c", "kill -TERM $$"]).0, 143);
}

#[test]
fn stdout_and_stderr_stay_separate() {
    let f = Fixture::start(&[]);
    let (code, out, err) = f.exec(&["sh", "-c", "printf out; printf err >&2"]);
    assert_eq!(code, 0);
    assert_eq!(out, "out");
    assert!(err.contains("err"), "stderr was {err:?}");
}

#[test]
fn arguments_are_passed_without_a_shell() {
    let f = Fixture::start(&[]);
    // If anything joined argv into a shell string, these would be mangled or,
    // worse, executed.
    let (code, out, err) = f.exec(&["printf", "%s\n", "a b", "c;d", "$HOME", "*"]);
    assert_eq!(code, 0, "stderr: {err}");
    assert_eq!(out, "a b\nc;d\n$HOME\n*\n");
}

#[test]
fn binary_data_survives_a_round_trip() {
    let f = Fixture::start(&[]);
    // Every byte value, including NUL, CR and LF, the ones a careless
    // transport would translate.
    let payload: Vec<u8> = (0..=255u8).cycle().take(256 * 400).collect();

    let mut child = f
        .client()
        .args(["cat"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        stdin.write_all(&payload).unwrap();
        drop(stdin);
    });
    let out = child.wait_with_output().unwrap();
    writer.join().unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let expected: Vec<u8> = (0..=255u8).cycle().take(256 * 400).collect();
    assert_eq!(out.stdout.len(), expected.len());
    assert_eq!(out.stdout, expected);
}

#[test]
fn environment_is_controlled_by_the_server() {
    let f = Fixture::start(&[]);
    let (_, out, _) = f.exec(&["sh", "-c", "echo \"${LD_PRELOAD:-none}\""]);
    assert_eq!(out.trim(), "none");

    // Allow-listed variables do come through.
    let out = Command::new(CLIENT_BIN)
        .args([
            "-i",
            f.client_dir.to_str().unwrap(),
            "-p",
            &f.port.to_string(),
            "--accept-new",
            "-q",
            "-E",
            "LC_ALL=C.UTF-8",
            "127.0.0.1",
            "sh",
            "-c",
            "echo $LC_ALL",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "C.UTF-8");
}

#[test]
fn a_restricted_key_can_only_run_what_it_was_given() {
    let f = Fixture::start(&["--no-shell", "--command", "echo"]);
    let (code, out, _) = f.exec(&["echo", "hello"]);
    assert_eq!(code, 0);
    assert_eq!(out.trim(), "hello");

    let (code, _, err) = f.exec(&["cat", "/etc/passwd"]);
    assert_eq!(code, 126, "stderr: {err}");
    assert!(err.contains("may not execute"), "stderr: {err}");
}

#[test]
fn an_unauthorized_key_is_refused() {
    let f = Fixture::start(&[]);
    let stranger = f._tmp.path().join("stranger");
    run(
        CLIENT_BIN,
        &["keygen", "--identity", stranger.to_str().unwrap()],
    );

    let out = Command::new(CLIENT_BIN)
        .args([
            "-i",
            stranger.to_str().unwrap(),
            "-p",
            &f.port.to_string(),
            "--accept-new",
            "127.0.0.1",
            "true",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
}

#[test]
fn revoking_a_key_takes_effect_without_a_restart() {
    let f = Fixture::start(&[]);
    assert_eq!(f.exec(&["true"]).0, 0);

    run(
        SERVER_BIN,
        &["--dir", f.server_dir.to_str().unwrap(), "revoke", "tester"],
    );
    assert_ne!(f.exec(&["true"]).0, 0, "revoked key still worked");
}

#[test]
fn a_changed_host_key_is_refused() {
    let f = Fixture::start(&[]);
    assert_eq!(f.exec(&["true"]).0, 0);

    // Pin a different key for the same host, as a MITM would present.
    let known_hosts = f.client_dir.join("known_hosts");
    let text = std::fs::read_to_string(&known_hosts).unwrap();
    let tampered = text.replace("sha256:0", "sha256:1").replace(
        &text
            .lines()
            .find(|l| l.contains("sha256:"))
            .unwrap()
            .to_string(),
        &format!("127.0.0.1:{} sha256:{}", f.port, "ab".repeat(32)),
    );
    std::fs::write(&known_hosts, tampered).unwrap();

    let out = Command::new(CLIENT_BIN)
        .args([
            "-i",
            f.client_dir.to_str().unwrap(),
            "-p",
            &f.port.to_string(),
            "127.0.0.1",
            "true",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "connection with a wrong pin succeeded"
    );
}

#[test]
fn rsync_can_use_qsh_as_its_transport() {
    if which("rsync").is_none() {
        eprintln!("skipping: rsync is not installed");
        return;
    }
    let f = Fixture::start(&[]);
    let src = f._tmp.path().join("src");
    let dst = f._tmp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(src.join("nested")).unwrap();
    std::fs::write(src.join("small.txt"), "hello rsync\n").unwrap();
    std::fs::write(
        src.join("nested/binary.bin"),
        (0..=255u8).cycle().take(300_000).collect::<Vec<_>>(),
    )
    .unwrap();

    let rsh = format!(
        "{CLIENT_BIN} -i {} -p {} --accept-new -q",
        f.client_dir.display(),
        f.port
    );
    let out = Command::new("rsync")
        .args([
            "-e",
            &rsh,
            "-a",
            &format!("{}/", src.display()),
            &format!("127.0.0.1:{}/", dst.display()),
        ])
        .output()
        .expect("running rsync");
    assert!(
        out.status.success(),
        "rsync failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    assert_eq!(
        std::fs::read_to_string(dst.join("small.txt")).unwrap(),
        "hello rsync\n"
    );
    assert_eq!(
        std::fs::read(dst.join("nested/binary.bin")).unwrap(),
        std::fs::read(src.join("nested/binary.bin")).unwrap()
    );
}

#[test]
fn several_sessions_share_one_server() {
    let f = Fixture::start(&[]);
    let handles: Vec<_> = (0..4)
        .map(|i| {
            let mut cmd = f.client();
            cmd.args(["sh", "-c", &format!("exit {}", i + 1)])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped());
            cmd.spawn().unwrap()
        })
        .collect();
    for (i, h) in handles.into_iter().enumerate() {
        let out = h.wait_with_output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(i as i32 + 1),
            "session {i}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

fn which(program: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(program))
            .find(|p| p.is_file() && is_executable(p))
    })
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}
