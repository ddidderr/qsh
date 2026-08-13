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
    // `exec` makes the sleep inherit the shell's pid, so the marker names the
    // exact process to watch. Matching on process names instead would also
    // match unrelated sleeps and make this test depend on what else is running.
    let marker = f.tmp.path().join("victim.pid");
    let mut child = f
        .client()
        .args([
            "sh",
            "-c",
            &format!("echo $$ > {}; exec sleep 300", marker.display()),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let victim = wait_for_pid(&marker);
    assert!(
        process_alive(victim),
        "the remote process should be running"
    );

    // Kill the client the way a crash or a lost network would.
    child.kill().unwrap();
    child.wait().unwrap();

    let deadline = Instant::now() + Duration::from_secs(30);
    while process_alive(victim) {
        assert!(
            Instant::now() < deadline,
            "remote process {victim} outlived its session"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Is this exact process still alive?
fn process_alive(pid: i32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// Wait for a remote command to report its pid through a marker file.
fn wait_for_pid(marker: &Path) -> i32 {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(text) = std::fs::read_to_string(marker) {
            if let Ok(pid) = text.trim().parse::<i32>() {
                return pid;
            }
        }
        assert!(Instant::now() < deadline, "remote command never started");
        std::thread::sleep(Duration::from_millis(50));
    }
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
fn a_forced_terminal_delivers_eof_without_a_trailing_newline() {
    let f = Fixture::start(&[]);
    // A terminal in canonical mode needs one EOF character to flush a partial
    // line and another to signal end of file, so input that does not end in a
    // newline used to hang here forever.
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
    stdin.write_all(b"hello").unwrap();
    drop(stdin);

    let out = wait_with_deadline(child, Duration::from_secs(15))
        .expect("`printf hello | qsh -t host cat` never saw end of file");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("hello"),
        "output was {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn a_background_descendant_does_not_outlive_a_disconnected_client() {
    // The leader exits immediately while a descendant keeps the session's
    // stdout open. Reaping the leader is not the end of the session, so the
    // disconnect watch has to stay up through the drain.
    let f = Fixture::start_with(&[], Some(3));
    let marker = f.tmp.path().join("descendant.pid");
    let mut child = f
        .client()
        .args([
            "sh",
            "-c",
            // `$!` is the background job's pid; `$$` inside a subshell would
            // still be the leader's.
            &format!("sleep 300 & echo $! > {}; exit 0", marker.display()),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let victim = wait_for_pid(&marker);
    assert!(process_alive(victim), "the descendant should be running");

    // The session is now parked draining a pipe the descendant holds open.
    child.kill().unwrap();
    child.wait().unwrap();

    let deadline = Instant::now() + Duration::from_secs(30);
    while process_alive(victim) {
        assert!(
            Instant::now() < deadline,
            "background descendant {victim} outlived its disconnected session"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Every identity fact the kernel will tell us about a remote session.
struct RemoteIdentity {
    account: String,
    fields: std::collections::HashMap<String, Vec<String>>,
    root_file_denied: bool,
}

impl RemoteIdentity {
    fn field(&self, name: &str) -> &[String] {
        self.fields
            .get(name)
            .unwrap_or_else(|| panic!("no `{name}` line in the remote /proc/self/status"))
    }
}

/// Ask a session who it is, in every sense the kernel exposes.
///
/// `id -un` alone would pass even if the gid or the supplementary groups had
/// been left at 0, so this reads /proc/self/status as well.
fn remote_identity(client_dir: &Path, port: u16) -> RemoteIdentity {
    let out = Command::new(CLIENT_BIN)
        .args([
            "-i",
            client_dir.to_str().unwrap(),
            "-p",
            &port.to_string(),
            "--accept-new",
            "-q",
            "127.0.0.1",
            "sh",
            "-c",
            "id -un; cat /proc/self/status; \
             cat /proc/1/environ >/dev/null 2>&1 && echo ROOTFILE_READABLE || echo ROOTFILE_DENIED",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut fields = std::collections::HashMap::new();
    for line in stdout.lines() {
        if let Some((name, rest)) = line.split_once(':') {
            fields.insert(
                format!("{name}:"),
                rest.split_whitespace().map(str::to_owned).collect(),
            );
        }
    }
    RemoteIdentity {
        account: stdout.lines().next().unwrap_or_default().to_owned(),
        fields,
        root_file_denied: stdout.contains("ROOTFILE_DENIED"),
    }
}

/// Run the client with its stdio on a real terminal, drive it, and return
/// `(exit status, everything it printed)`.
///
/// A pty is the only way to reach the interactive path: the client only asks
/// for a remote terminal when it has a local one, and the remote shell only
/// turns on job control when it is interactive.
#[allow(
    unsafe_code,
    reason = "raw read/write on a pty the test itself opened; there is no safe wrapper"
)]
fn interactive_session(f: &Fixture, script: &[&str], limit: Duration) -> (Option<i32>, String) {
    use std::os::fd::AsRawFd;

    let pair = nix::pty::openpty(None, None).expect("allocating a pty");
    let (master, slave) = (pair.master, pair.slave);

    let mut child = Command::new(CLIENT_BIN)
        .args([
            "-i",
            f.client_dir.to_str().unwrap(),
            "-p",
            &f.port.to_string(),
            "--accept-new",
            "-q",
            "127.0.0.1",
        ])
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave))
        .spawn()
        .expect("starting qsh on a pty");

    // Read continuously, or the terminal buffer would fill and block the
    // remote shell before it ever reaches the script.
    let fd = master.as_raw_fd();
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            // SAFETY: reading into a buffer we own from a pty we opened.
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            let Ok(n) = usize::try_from(n) else { break };
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        String::from_utf8_lossy(&out).into_owned()
    });

    for line in script {
        std::thread::sleep(Duration::from_millis(400));
        let bytes = format!("{line}\n");
        // SAFETY: writing a local buffer to a pty we opened.
        let written =
            unsafe { libc::write(master.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
        assert!(written > 0, "could not write to the pty");
    }

    let status = wait_with_deadline_status(&mut child, limit);
    drop(master);
    let text = reader.join().unwrap_or_default();
    (status, text)
}

/// Wait for a child, killing it and returning `None` if it overruns.
fn wait_with_deadline_status(child: &mut Child, limit: Duration) -> Option<i32> {
    let deadline = Instant::now() + limit;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.code(),
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
fn an_interactive_session_ends_even_with_a_job_left_on_the_terminal() {
    let f = Fixture::start(&[]);

    // Sanity first: a plain interactive session exits with the shell's status.
    let (status, text) = interactive_session(&f, &["exit 3"], Duration::from_secs(20));
    assert_eq!(status, Some(3), "plain interactive session: {text}");

    // Now the real case. An interactive shell has job control, so the
    // backgrounded job gets its own process group and does not receive the
    // hangup the kernel sends when the shell exits — it keeps the terminal
    // open indefinitely. A PTY has no last-writer guarantee, so without a
    // deadline the session would wait for that terminal forever and the
    // client would never receive an exit status.
    //
    // What is asserted here is only that: the client gets its status back. The
    // backgrounded job is expected to STILL BE RUNNING afterwards — qsh does
    // not kill jobs that have left the session's process group, the same as
    // ssh — so this test deliberately says nothing about it.
    let (status, text) =
        interactive_session(&f, &["sleep 300 &", "exit 4"], Duration::from_secs(25));
    assert_eq!(
        status,
        Some(4),
        "the client never got an exit status past a job left on the terminal: {text}"
    );
}

#[test]
fn a_revoked_key_loses_an_established_connection() {
    let f = Fixture::start(&[]);
    assert_eq!(f.exec(&["true"]).0, 0);

    // Hold a connection open across the revocation. Each session opens its own
    // stream, and the policy has to be re-read for every one of them.
    run(
        SERVER_BIN,
        &["--dir", f.server_dir.to_str().unwrap(), "revoke", "tester"],
    );
    std::thread::sleep(Duration::from_millis(1_200));
    assert_ne!(
        f.exec(&["true"]).0,
        0,
        "a revoked key still opened a session"
    );
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

    let who = remote_identity(&client_dir, port);
    let _ = server.kill();
    let _ = server.wait();

    let account = nix::unistd::User::from_name(target).unwrap().unwrap();
    let uid = account.uid.as_raw().to_string();
    let gid = account.gid.as_raw().to_string();

    assert_eq!(
        who.account, target,
        "the session did not run as the authorized account"
    );

    // Real, effective, saved-set and filesystem uid must all be the target's.
    // A saved-set uid of 0 is the one way `setuid(0)` could still succeed, so
    // this is the portable proof that root cannot be regained.
    let uids = who.field("Uid:");
    assert_eq!(uids.len(), 4, "unexpected Uid line: {uids:?}");
    assert!(
        uids.iter().all(|u| *u == uid),
        "not every uid was dropped to {target} ({uid}): {uids:?}"
    );

    let gids = who.field("Gid:");
    assert_eq!(gids.len(), 4, "unexpected Gid line: {gids:?}");
    assert!(
        gids.iter().all(|g| *g == gid),
        "not every gid was dropped to {gid}: {gids:?}"
    );

    // Compare token-wise: a substring check would accept "1000" as a zero.
    let groups = who.field("Groups:");
    assert!(
        !groups.iter().any(|g| g == "0"),
        "root's supplementary groups survived: {groups:?}"
    );

    // Any lingering capability would make the uid change cosmetic.
    for cap in ["CapPrm:", "CapEff:"] {
        let bits = who.field(cap);
        assert!(
            bits.iter().all(|b| b.chars().all(|c| c == '0')),
            "{cap} is not empty: {bits:?}"
        );
    }

    assert!(
        who.root_file_denied,
        "a root-only file was still readable from the session"
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
    std::fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
}
