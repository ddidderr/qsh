//! End-to-end tests: a real `qsh-server` on a loopback UDP port, driven by the
//! real `qsh` binary. These are the tests that would catch a regression in the
//! parts users actually touch — exit codes, binary transparency, `rsync -e
//! qsh`, and the authorisation rules.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    reason = "a failing assertion should panic loudly; that is the point of a test"
)]

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const SERVER_BIN: &str = env!("CARGO_BIN_EXE_qsh-server");
const CLIENT_BIN: &str = env!("CARGO_BIN_EXE_qsh");

/// A running server plus the client configuration that may talk to it.
struct Fixture {
    tmp: tempfile::TempDir,
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
        Self::start_with(extra_authorize, None)
    }

    /// `idle_timeout_secs` overrides how quickly the server gives up on a
    /// silent peer, which is what bounds cleanup after a client is killed.
    fn start_with(extra_authorize: &[&str], idle_timeout_secs: Option<u64>) -> Self {
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
        args.extend(extra_authorize.iter().map(|s| (*s).to_owned()));
        run(
            SERVER_BIN,
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
        );

        if let Some(idle) = idle_timeout_secs {
            std::fs::write(
                server_dir.join("qsh-server.toml"),
                format!("idle_timeout_secs = {idle}\nkeepalive_secs = 1\n"),
            )
            .unwrap();
        }

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
            tmp,
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
    let stranger = f.tmp.path().join("stranger");
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
    // The server re-reads `authorized/` at most once a second, so that an
    // unauthenticated packet flood cannot make it parse the directory over and
    // over. Give it that long to notice.
    std::thread::sleep(Duration::from_millis(1_200));
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
fn a_restricted_key_cannot_run_a_lookalike_from_a_writable_path() {
    // The regression behind the review: matching an allow-list entry by
    // basename would let this key run anything it can drop on disk.
    let f = Fixture::start(&["--command", "echo"]);
    let planted = f.tmp.path().join("echo");
    std::fs::write(&planted, "#!/bin/sh\necho pwned\n").unwrap();
    std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o755)).unwrap();

    let (code, out, err) = f.exec(&[planted.to_str().unwrap(), "hello"]);
    assert_ne!(code, 0, "a planted `echo` was executed: {out}");
    assert!(
        !out.contains("pwned"),
        "a planted `echo` was executed: {out}"
    );
    assert!(err.contains("may not execute"), "stderr: {err}");

    // The legitimate bare name still works, resolved through the server's PATH.
    assert_eq!(f.exec(&["echo", "hi"]).1.trim(), "hi");
}

#[test]
fn a_disconnected_client_does_not_strand_the_remote_process() {
    // A killed client sends no close frame, so the server learns of it through
    // the QUIC idle timeout. Shorten it so the test does not sit for a minute.
    let f = Fixture::start_with(&[], Some(3));
    // A marker file lets us identify this exact process afterwards.
    let marker = f.tmp.path().join("victim");
    let mut child = f
        .client()
        .args([
            "sh",
            "-c",
            &format!("touch {}; sleep 300", marker.display()),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    while !marker.exists() {
        assert!(Instant::now() < deadline, "remote command never started");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        sleep_processes_exist(),
        "the remote sleep should be running"
    );

    // Kill the client the way a crash or a lost network would.
    child.kill().unwrap();
    child.wait().unwrap();

    let deadline = Instant::now() + Duration::from_secs(30);
    while sleep_processes_exist() {
        assert!(
            Instant::now() < deadline,
            "the remote process outlived its session"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Is any `sleep 300` (the one this test starts) still running?
fn sleep_processes_exist() -> bool {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        let cmdline = entry.path().join("cmdline");
        if let Ok(raw) = std::fs::read(&cmdline) {
            let parts: Vec<&[u8]> = raw.split(|b| *b == 0).collect();
            if parts.first().is_some_and(|p| p.ends_with(b"sleep"))
                && parts.get(1).is_some_and(|p| *p == b"300")
            {
                return true;
            }
        }
    }
    false
}

#[test]
fn output_is_never_truncated_behind_a_success_status() {
    let f = Fixture::start(&[]);
    // Far more than the frame channel or any socket buffer can hold, so the
    // pump only finishes if it is genuinely drained to EOF.
    let (code, out, err) = f.exec(&["sh", "-c", "yes abcdefghij | head -n 200000"]);
    assert_eq!(code, 0, "stderr: {err}");
    assert_eq!(out.lines().count(), 200_000, "output was truncated");
}

#[test]
fn a_forced_terminal_still_delivers_end_of_file() {
    let f = Fixture::start(&[]);
    // `-t` with redirected input: the PTY has to receive an EOF character,
    // because a terminal has no half to close.
    let mut child = Command::new(CLIENT_BIN)
        .args([
            "-i",
            f.client_dir.to_str().unwrap(),
            "-p",
            &f.port.to_string(),
            "--accept-new",
            "-q",
            "-t",
            "127.0.0.1",
            "cat",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(b"hello\n").unwrap();
    drop(stdin);

    let out = wait_with_deadline(child, Duration::from_secs(15))
        .expect("`qsh -t host cat < file` never saw end of file");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("hello"),
        "output was {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// Wait for a child, killing it and returning `None` if it overruns.
fn wait_with_deadline(mut child: Child, limit: Duration) -> Option<std::process::Output> {
    let deadline = Instant::now() + limit;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().ok(),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

#[test]
fn a_session_runs_as_the_authorized_account() {
    // Only meaningful as root, where the server actually switches user.
    if !nix::unistd::Uid::effective().is_root() {
        eprintln!("skipping: not running as root, no privilege drop to exercise");
        return;
    }
    let Some(target) = ["nobody", "daemon", "bin"]
        .into_iter()
        .find(|u| nix::unistd::User::from_name(u).ok().flatten().is_some())
    else {
        eprintln!("skipping: no unprivileged account to switch to");
        return;
    };

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
    run(
        SERVER_BIN,
        &[
            "--dir",
            server_dir.to_str().unwrap(),
            "authorize",
            client_dir.join("id.crt").to_str().unwrap(),
            "--user",
            target,
            "--name",
            "dropped",
        ],
    );

    let log = tmp.path().join("server.log");
    let mut server = Command::new(SERVER_BIN)
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
        .unwrap();
    let port = wait_for_port(&log);

    let out = Command::new(CLIENT_BIN)
        .args([
            "-i",
            client_dir.to_str().unwrap(),
            "-p",
            &port.to_string(),
            "--accept-new",
            "-q",
            "127.0.0.1",
            "id",
            "-un",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let _ = server.kill();
    let _ = server.wait();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        target,
        "the session did not run as the authorized account"
    );
}

#[test]
fn an_expired_authorization_stops_working() {
    let f = Fixture::start(&["--expires-in-days", "30"]);
    assert_eq!(f.exec(&["true"]).0, 0, "should work before the deadline");

    // Move the recorded deadline into the past. This is the administrator's
    // deadline, so it must bite regardless of the certificate the client holds.
    let meta_path = f.server_dir.join("authorized/tester.toml");
    let meta = std::fs::read_to_string(&meta_path).unwrap();
    assert!(
        meta.contains("expires_at_unix"),
        "no deadline recorded: {meta}"
    );
    let rewritten: String = meta
        .lines()
        .map(|l| {
            if l.starts_with("expires_at_unix") {
                "expires_at_unix = 1".to_owned()
            } else {
                l.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&meta_path, rewritten).unwrap();
    std::thread::sleep(Duration::from_millis(1_200));

    let (code, _, err) = f.exec(&["true"]);
    assert_ne!(code, 0, "an expired authorization still worked");
    assert!(err.contains("expired"), "stderr: {err}");
}

#[test]
fn revoke_cannot_escape_the_authorized_directory() {
    let f = Fixture::start(&[]);
    let host_key = f.server_dir.join("server.crt");
    assert!(host_key.exists());

    let out = Command::new(SERVER_BIN)
        .args([
            "--dir",
            f.server_dir.to_str().unwrap(),
            "revoke",
            "../server",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "a traversing name was accepted");
    assert!(host_key.exists(), "revoke deleted the host key");
}

#[test]
fn rsync_can_use_qsh_as_its_transport() {
    if which("rsync").is_none() {
        eprintln!("skipping: rsync is not installed");
        return;
    }
    let f = Fixture::start(&[]);
    let src = f.tmp.path().join("src");
    let dst = f.tmp.path().join("dst");
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
