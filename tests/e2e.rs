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
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;

const SERVER_BIN: &str = env!("CARGO_BIN_EXE_qsh-server");
const CLIENT_BIN: &str = env!("CARGO_BIN_EXE_qsh");

#[test]
fn explicitly_missing_server_config_fails_before_startup() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("missing.toml");
    let output = Command::new(SERVER_BIN)
        .arg("--dir")
        .arg(dir.path())
        .args(["serve", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("reading"), "{stderr}");
    assert!(stderr.contains("missing.toml"), "{stderr}");
}

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
        self.client_as(&self.client_dir)
    }

    /// The same, for a client identity other than the fixture's own.
    fn client_as(&self, identity: &Path) -> Command {
        let mut cmd = Command::new(CLIENT_BIN);
        cmd.args([
            "-i",
            identity.to_str().unwrap(),
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
        self.exec_as(&self.client_dir, argv)
    }

    fn exec_as(&self, identity: &Path, argv: &[&str]) -> (i32, String, String) {
        let out = self
            .client_as(identity)
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

// ---------------------------------------------------------------- raw client
//
// Some behaviour can only be reached below the CLI: the `qsh` binary makes one
// connection and one session per run, so nothing it can be asked to do covers
// "two sessions on the same QUIC connection". These helpers speak the protocol
// directly for those cases.

/// Accepts whatever certificate the server offers.
///
/// The tests are not verifying host-key pinning here — `a_changed_host_key_is_refused`
/// does that through the real client — they are verifying server behaviour
/// after the handshake.
#[derive(Debug)]
struct AcceptAnyServer;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServer {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A verifier that stops the handshake dead just before it would finish.
///
/// rustls calls this on the client once the server's flight has arrived, so a
/// connection parked in here has already had its address validated and is
/// occupying a handshake slot on the server — which is the state a pre-auth
/// flood needs to reach, and the only one worth defending against.
#[derive(Debug)]
struct StallingVerifier {
    hold: Duration,
}

impl rustls::client::danger::ServerCertVerifier for StallingVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Blocking, deliberately: it also stops this connection's driver from
        // sending anything further, which is what the server has to survive.
        std::thread::sleep(self.hold);
        Err(rustls::Error::General("stalled on purpose".into()))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("stalled on purpose".into()))
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("stalled on purpose".into()))
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build a client endpoint that authenticates as `client_dir`'s key.
fn raw_endpoint(
    client_dir: &Path,
    bind: &str,
    verifier: Arc<dyn rustls::client::danger::ServerCertVerifier>,
) -> quinn::Endpoint {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let identity =
        qsh::crypto::load_identity(&client_dir.join("id.crt"), &client_dir.join("id.key"))
            .expect("loading the test identity");

    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_client_auth_cert(vec![identity.cert.clone()], identity.key.clone_key())
    .expect("installing the client certificate");
    tls.alpn_protocols = vec![qsh::proto::ALPN.to_vec()];

    let mut endpoint = quinn::Endpoint::client(bind.parse().unwrap()).unwrap();
    let mut cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
    ));
    cfg.transport_config(Arc::new(
        qsh::net::transport_config(Duration::from_secs(60), Duration::from_secs(5)).unwrap(),
    ));
    endpoint.set_default_client_config(cfg);
    endpoint
}

/// Open one QUIC connection to the fixture's server, as the authorized key.
async fn raw_connect(client_dir: &Path, port: u16) -> quinn::Connection {
    let endpoint = raw_endpoint(client_dir, "0.0.0.0:0", Arc::new(AcceptAnyServer));
    let conn = endpoint
        .connect(std::net::SocketAddr::from(([127, 0, 0, 1], port)), "qsh")
        .expect("starting the handshake")
        .await
        .expect("connecting");
    // The endpoint has to outlive the connection.
    std::mem::forget(endpoint);
    conn
}

/// Park `count` handshakes from a single source address, each for `hold`.
///
/// Every one gets its own thread: the stall is a blocking one inside rustls,
/// so a connection that is parked also stops its endpoint's driver, and they
/// have to be independent of each other to all be in flight at once.
///
/// Returns once they are all far enough along to be occupying a slot.
fn stall_handshakes(client_dir: &Path, source: &str, port: u16, count: usize, hold: Duration) {
    for _ in 0..count {
        let dir = client_dir.to_path_buf();
        let bind = format!("{source}:0");
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let endpoint = raw_endpoint(&dir, &bind, Arc::new(StallingVerifier { hold }));
                if let Ok(connecting) =
                    endpoint.connect(std::net::SocketAddr::from(([127, 0, 0, 1], port)), "qsh")
                {
                    let _ = connecting.await;
                }
            });
        });
    }
    // Long enough for the retry round trip and the server's flight; the stall
    // itself is much longer, so this only has to be generous, not exact.
    std::thread::sleep(Duration::from_millis(750));
}

/// Open a session stream and send its request, without reading anything back.
async fn raw_request(
    conn: &quinn::Connection,
    argv: &[&str],
    pty: bool,
) -> Option<(quinn::SendStream, quinn::RecvStream)> {
    let (mut send, recv) = conn.open_bi().await.ok()?;
    qsh::proto::write_frame(
        &mut send,
        &qsh::proto::Frame::Request(qsh::proto::Request {
            version: qsh::proto::PROTOCOL_VERSION,
            user: None,
            command: Some(argv.iter().map(|a| (*a).to_owned()).collect()),
            pty: pty.then(|| qsh::proto::PtyRequest {
                term: "dumb".to_owned(),
                size: qsh::proto::PtySize::default(),
            }),
            env: Vec::new(),
        }),
    )
    .await
    .ok()?;
    Some((send, recv))
}

/// Run one command on an existing connection; `None` if the server refused to
/// start a session at all.
async fn raw_session(conn: &quinn::Connection, argv: &[&str]) -> Option<i32> {
    let (_send, mut recv) = raw_request(conn, argv, false).await?;
    loop {
        match qsh::proto::read_frame(&mut recv).await {
            Ok(Some(qsh::proto::Frame::Exit(status))) => return Some(status.wait_status()),
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => return None,
        }
    }
}

/// What a peer saw after it stopped reading in the middle of a session.
#[derive(Debug)]
struct Stalled {
    /// How many bytes of output reached this peer in the end.
    bytes: usize,
    /// The exit status the server reported, if it managed to report one.
    exit: Option<i32>,
    /// The diagnostic that came with it, if any.
    error: Option<String>,
    /// Whether the server tore the stream down instead of ending it cleanly.
    reset: bool,
}

/// Start a session, read only until the process has started, stop reading for
/// `stall`, then read whatever is left.
///
/// This is the peer the drain logic exists for: one that is authenticated and
/// keeps the connection alive, but stops consuming output while the remote
/// process is still producing it.
async fn stalled_session(conn: &quinn::Connection, argv: &[&str], stall: Duration) -> Stalled {
    let (_send, mut recv) = raw_request(conn, argv, true)
        .await
        .expect("opening a session stream");

    loop {
        match qsh::proto::read_frame(&mut recv).await {
            Ok(Some(qsh::proto::Frame::Started)) => break,
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => panic!("the session ended before it started"),
        }
    }

    // Nothing is read here. The server's frame channel fills, the writer
    // blocks on QUIC flow control, and the pump ends up parked holding a chunk
    // it cannot hand over — which is the state the drain has to classify.
    tokio::time::sleep(stall).await;

    let mut out = Stalled {
        bytes: 0,
        exit: None,
        error: None,
        reset: false,
    };
    let collect = async {
        loop {
            match qsh::proto::read_frame(&mut recv).await {
                Ok(Some(qsh::proto::Frame::Exit(status))) => {
                    out.exit = Some(status.wait_status());
                    return;
                }
                Ok(Some(qsh::proto::Frame::Stdout(d))) => out.bytes += d.len(),
                Ok(Some(qsh::proto::Frame::Error(e))) => out.error = Some(e),
                Ok(Some(_)) => {}
                Ok(None) => return,
                Err(_) => {
                    out.reset = true;
                    return;
                }
            }
        }
    };
    assert!(
        tokio::time::timeout(Duration::from_secs(30), collect)
            .await
            .is_ok(),
        "the server neither finished nor reset the session"
    );
    out
}

/// How the server ended a session stream.
#[derive(Debug, PartialEq, Eq)]
enum StreamEnd {
    /// A clean end of stream, with this much delivered.
    Finished(usize),
    /// Torn down with this application error code.
    Reset(u64),
}

/// Start a session, read only until it has started, stop reading for `stall`,
/// then report how the server ended the stream.
///
/// The difference from `stalled_session` is what it looks at: not the frames,
/// but the ending. A peer has to be able to tell "I have everything" from "the
/// server gave up on me", and those are a clean finish and a reset — which is
/// why this reads the stream raw rather than through the frame codec.
async fn stalled_until_teardown(
    conn: &quinn::Connection,
    argv: &[&str],
    stall: Duration,
) -> StreamEnd {
    let (_send, mut recv) = raw_request(conn, argv, true)
        .await
        .expect("opening a session stream");
    loop {
        match qsh::proto::read_frame(&mut recv).await {
            Ok(Some(qsh::proto::Frame::Started)) => break,
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => panic!("the session ended before it started"),
        }
    }
    // `read_frame` reads exactly the bytes of a frame and no more, so nothing
    // is stranded in a buffer by switching to raw reads here.
    tokio::time::sleep(stall).await;

    let mut buf = vec![0u8; 64 * 1024];
    let mut bytes = 0usize;
    let collect = async {
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(n)) => bytes += n,
                Ok(None) => return StreamEnd::Finished(bytes),
                Err(quinn::ReadError::Reset(code)) => return StreamEnd::Reset(code.into_inner()),
                Err(e) => panic!("unexpected read error: {e}"),
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(30), collect)
        .await
        .expect("the server neither finished nor reset the session")
}

/// Is `pid` still a live process running the command we started?
///
/// Matching the marker matters: a bare `kill(pid, 0)` would be satisfied by an
/// unrelated process that reused the pid, and by a zombie — whose `cmdline` is
/// empty, so it correctly reads as gone here.
fn running_with_marker(pid: i32, marker: &str) -> bool {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .is_ok_and(|c| String::from_utf8_lossy(&c).contains(marker))
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
fn child_stdin_closing_does_not_discard_output_or_exit_status() {
    let f = Fixture::start(&[]);
    let ready = f.tmp.path().join("child-closed-stdin");
    let script = "trap 'printf after-broken-pipe; printf stderr-marker >&2; exit 42' USR1; \
                  exec 0<&-; printf ready > \"$1\"; sleep 8; exit 99";
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let conn = raw_connect(&f.client_dir, f.port).await;
        let (mut send, mut recv) = raw_request(
            &conn,
            &["sh", "-c", script, "sh", ready.to_str().unwrap()],
            false,
        )
        .await
        .expect("opening the session");
        wait_for_started(&mut recv).await;

        // The marker is written only after the child closes fd 0. Sending a
        // Stdin frame after this point guarantees a broken child pipe, then
        // the Signal frame tests that control input is still handled.
        tokio::time::timeout(Duration::from_secs(5), async {
            while !ready.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the child never closed stdin");
        qsh::proto::write_frame(&mut send, &qsh::proto::Frame::Stdin(vec![b'x'; 64 * 1024]))
            .await
            .unwrap();
        qsh::proto::write_frame(&mut send, &qsh::proto::Frame::Signal("USR1".into()))
            .await
            .unwrap();

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let status = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match qsh::proto::read_frame(&mut recv).await {
                    Ok(Some(qsh::proto::Frame::Stdout(bytes))) => stdout.extend(bytes),
                    Ok(Some(qsh::proto::Frame::Stderr(bytes))) => stderr.extend(bytes),
                    Ok(Some(qsh::proto::Frame::Exit(exit))) => break exit.wait_status(),
                    Ok(Some(qsh::proto::Frame::Error(error))) => panic!("{error}"),
                    Ok(Some(other)) => panic!("unexpected frame: {other:?}"),
                    Ok(None) | Err(_) => panic!("session ended without an exit status"),
                }
            }
        })
        .await
        .expect("closed child stdin stopped the control stream");

        assert_eq!(status, 42, "the signal was not delivered after EPIPE");
        assert_eq!(stdout, b"after-broken-pipe");
        assert_eq!(stderr, b"stderr-marker");
    });
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
fn an_invalid_first_frame_cannot_expand_into_a_large_log_line() {
    let f = Fixture::start(&[]);
    let log = f.tmp.path().join("server.log");
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let conn = raw_connect(&f.client_dir, f.port).await;
        let before = std::fs::metadata(&log).unwrap().len() as usize;
        let (mut send, _recv) = conn.open_bi().await.unwrap();
        qsh::proto::write_frame(
            &mut send,
            &qsh::proto::Frame::Stdin(vec![b'x'; qsh::proto::MAX_FRAME]),
        )
        .await
        .unwrap();
        send.finish().unwrap();

        // Wait for the newline, not just the start of the message: the old
        // Debug formatting wrote several MiB of decimal payload bytes after
        // this text, and sampling mid-write would miss the amplification.
        let marker = b"expected a request frame first";
        let logged_tail = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let contents = std::fs::read(&log).unwrap();
                let complete = contents.get(before..).and_then(|after| {
                    let start = after
                        .windows(marker.len())
                        .position(|window| window == marker.as_slice())?;
                    after.get(start..)?.iter().position(|byte| *byte == b'\n')
                });
                if let Some(end) = complete {
                    break end;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("the server did not report the invalid first frame");
        assert!(
            logged_tail < 4 * 1024,
            "one invalid frame expanded into a {logged_tail}-byte log line"
        );
    });
}

#[test]
fn a_disallowed_large_request_cannot_expand_into_a_large_log_line() {
    let f = Fixture::start(&[]);
    let log = f.tmp.path().join("server.log");
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let conn = raw_connect(&f.client_dir, f.port).await;
        // Wait for the authenticated-connection diagnostic before measuring
        // what the rejected request itself adds to the log.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if std::fs::read_to_string(&log)
                    .unwrap()
                    .contains("authenticated as")
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("the connection was not authenticated");
        let before = std::fs::metadata(&log).unwrap().len() as usize;

        // A valid Request can be almost as large as MAX_FRAME while asking
        // for an account this key is not allowed to use. The server must deny
        // it without copying that attacker-controlled value into its log.
        let request = qsh::proto::Request {
            version: qsh::proto::PROTOCOL_VERSION,
            user: Some("x".repeat(qsh::proto::MAX_FRAME - 1024)),
            command: Some(vec!["true".into()]),
            pty: None,
            env: Vec::new(),
        };
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        qsh::proto::write_frame(&mut send, &qsh::proto::Frame::Request(request))
            .await
            .unwrap();
        send.finish().unwrap();

        let (saw_error, exit) = tokio::time::timeout(Duration::from_secs(10), async {
            let mut saw_error = false;
            loop {
                match qsh::proto::read_frame(&mut recv).await {
                    Ok(Some(qsh::proto::Frame::Error(_))) => saw_error = true,
                    Ok(Some(qsh::proto::Frame::Exit(status))) => {
                        break (saw_error, status.wait_status());
                    }
                    Ok(Some(qsh::proto::Frame::Started)) => {
                        panic!("a disallowed account started a process")
                    }
                    Ok(Some(_)) => {}
                    Ok(None) | Err(_) => panic!("the invalid request did not receive a refusal"),
                }
            }
        })
        .await
        .expect("the disallowed request was not answered");
        assert!(saw_error, "the client received no refusal diagnostic");
        assert_eq!(exit, 126);

        let marker = b"session from";
        let line_len = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let contents = std::fs::read(&log).unwrap();
                let complete = contents.get(before..).and_then(|after| {
                    after
                        .split_inclusive(|byte| *byte == b'\n')
                        .find(|line| {
                            line.ends_with(b"\n")
                                && line
                                    .windows(marker.len())
                                    .any(|window| window == marker.as_slice())
                        })
                        .map(<[u8]>::len)
                });
                if let Some(len) = complete {
                    break len;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("the server did not log the refused request");
        assert!(
            line_len < 4 * 1024,
            "one disallowed request expanded into a {line_len}-byte log line"
        );
    });
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
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("host key for") && err.contains("has changed"),
        "{err}"
    );
    assert!(
        err.contains("known-hosts -i") && err.contains(f.client_dir.to_str().unwrap()),
        "{err}"
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
fn disconnect_is_observed_while_child_stdin_is_blocked() {
    let f = Fixture::start(&[]);
    let pidfile = f.tmp.path().join("blocked-stdin.pid");
    let marker = f.tmp.path().join("blocked-stdin-job");
    let script = idle_job_script(&pidfile, &marker);
    let marker = marker.to_string_lossy().into_owned();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let conn = raw_connect(&f.client_dir, f.port).await;
        let (mut send, mut recv) = raw_request(&conn, &["sh", "-c", &script], false)
            .await
            .expect("opening the stdin session");
        wait_for_started(&mut recv).await;
        let pid = tokio::task::block_in_place(|| wait_for_pid(&pidfile));
        tokio::task::block_in_place(|| wait_for_running_marker(pid, &marker));

        // The child never reads stdin. Two maximal frames exceed a Linux pipe
        // by a wide margin, leaving the server's stdin writer backpressured.
        let input = qsh::proto::Frame::Stdin(vec![b'x'; qsh::proto::MAX_FRAME]);
        for _ in 0..2 {
            tokio::time::timeout(
                Duration::from_secs(10),
                qsh::proto::write_frame(&mut send, &input),
            )
            .await
            .expect("sending stdin exceeded the QUIC flow-control window")
            .expect("sending stdin failed");
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(running_with_marker(pid, &marker));
        conn.close(0u32.into(), b"disconnect while stdin is blocked");

        let deadline = Instant::now() + Duration::from_secs(8);
        while running_with_marker(pid, &marker) {
            assert!(
                Instant::now() < deadline,
                "blocked child stdin hid the disconnect; process {pid} survived"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });
}

async fn wait_for_started(recv: &mut quinn::RecvStream) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match qsh::proto::read_frame(recv).await {
                Ok(Some(qsh::proto::Frame::Started)) => return,
                Ok(Some(qsh::proto::Frame::Error(error))) => {
                    panic!("session was refused before starting: {error}")
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => panic!("session ended before starting"),
            }
        }
    })
    .await
    .expect("session did not start in time");
}

/// Wait until the recorded process has exec'd the command unique to this test.
fn wait_for_running_marker(pid: i32, marker: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !running_with_marker(pid, marker) {
        assert!(
            Instant::now() < deadline,
            "remote command {pid} never started"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// An idle job that keeps the session alive without reading stdin.
fn idle_job_script(pidfile: &Path, marker: &Path) -> String {
    format!(
        "echo $$ > {}; exec sh -c 'while :; do sleep 300; done' {}",
        pidfile.display(),
        marker.display()
    )
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

/// A `qsh` client whose stdio is a real terminal that this process owns.
///
/// A pty is the only way to reach the interactive path: the client only asks
/// for a remote terminal when it has a local one, and the remote shell only
/// turns on job control when it is interactive. It is also the only way to
/// observe what the client does to the terminal, which is what
/// `a_fatal_signal_puts_the_terminal_back` needs.
struct PtyClient {
    master: std::os::fd::OwnedFd,
    /// A spare handle on the same terminal. It is what lets the test read the
    /// termios the client has installed, and it is deliberately closed before
    /// the reader is joined: the reader's `read` on the master only returns
    /// (with `EIO`) once *every* slave descriptor is gone.
    terminal: Option<std::os::fd::OwnedFd>,
    child: Child,
    reader: Option<std::thread::JoinHandle<String>>,
}

#[allow(
    unsafe_code,
    reason = "raw read/write on a pty the test itself opened; there is no safe wrapper"
)]
impl PtyClient {
    fn start(f: &Fixture) -> Self {
        use std::os::fd::AsRawFd;

        let pair = nix::pty::openpty(None, None).expect("allocating a pty");
        let (master, slave) = (pair.master, pair.slave);

        let child = Command::new(CLIENT_BIN)
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
            .stderr(Stdio::from(slave.try_clone().unwrap()))
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

        Self {
            master,
            terminal: Some(slave),
            child,
            reader: Some(reader),
        }
    }

    fn write_line(&self, line: &str) {
        use std::os::fd::AsRawFd;
        let bytes = format!("{line}\n");
        // SAFETY: writing a local buffer to a pty we opened.
        let written =
            unsafe { libc::write(self.master.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
        assert!(written > 0, "could not write to the pty");
    }

    /// The terminal settings currently in force, as the client left them.
    fn termios(&self) -> nix::sys::termios::Termios {
        let fd = self
            .terminal
            .as_ref()
            .expect("the terminal handle is still open");
        nix::sys::termios::tcgetattr(fd).expect("reading the pty's termios")
    }

    fn pid(&self) -> nix::unistd::Pid {
        nix::unistd::Pid::from_raw(self.child.id() as i32)
    }

    fn wait_status(&mut self, limit: Duration) -> Option<i32> {
        wait_with_deadline_status(&mut self.child, limit)
    }

    /// Close the terminal and collect everything the client printed.
    fn finish(mut self) -> String {
        drop(self.terminal.take());
        self.reader
            .take()
            .map(|r| r.join().unwrap_or_default())
            .unwrap_or_default()
    }
}

/// Run the client on a real terminal, feed it a script, and return
/// `(exit status, everything it printed)`.
fn interactive_session(f: &Fixture, script: &[&str], limit: Duration) -> (Option<i32>, String) {
    let mut client = PtyClient::start(f);
    for line in script {
        std::thread::sleep(Duration::from_millis(400));
        client.write_line(line);
    }
    let status = client.wait_status(limit);
    (status, client.finish())
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
fn one_source_cannot_monopolize_the_handshake_pool() {
    let f = Fixture::start(&[]);

    // More stalled handshakes than the whole global budget (32), all from one
    // address. Address validation has already happened for each — a retry
    // makes sure of that — so these are the attempts that actually cost the
    // server something, not spoofable packets.
    stall_handshakes(
        &f.client_dir,
        "127.0.0.2",
        f.port,
        40,
        Duration::from_secs(12),
    );

    // A key holder arriving from a different address must not have to wait for
    // that to burn itself out. The server's handshake grace is five seconds,
    // so without a per-source reservation this is what would be lost: the pool
    // is fully occupied and a new client is dropped until the flood times out.
    let started = Instant::now();
    let (code, _, err) = f.exec(&["true"]);
    let waited = started.elapsed();
    assert_eq!(code, 0, "a key holder was locked out by the flood: {err}");
    assert!(
        waited < Duration::from_secs(4),
        "a key holder waited {waited:?} behind another address's half-open attempts"
    );
}

#[test]
fn a_torn_authorize_cannot_pair_a_new_key_with_a_legacy_policy() {
    let f = Fixture::start(&[]);
    let authorized = f.server_dir.join("authorized");
    let policy_path = authorized.join("tester.toml");
    let cert_path = authorized.join("tester.crt");

    // Age the policy into one written before `key_fingerprint` existed. Those
    // are deliberately still accepted — failing them closed would lock out
    // every deployment that upgrades — and that acceptance is exactly what
    // makes the order of the two writes a security property rather than a
    // detail.
    let legacy: String = std::fs::read_to_string(&policy_path)
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with("key_fingerprint"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !legacy.contains("key_fingerprint"),
        "the policy still names its key"
    );
    std::fs::write(&policy_path, legacy).unwrap();
    std::thread::sleep(Duration::from_millis(1_200));
    assert_eq!(
        f.exec(&["true"]).0,
        0,
        "a legacy policy should still be honoured"
    );

    // Now replace that authorization with a different key under the same name.
    let second = f.tmp.path().join("second");
    run(
        CLIENT_BIN,
        &["keygen", "--identity", second.to_str().unwrap()],
    );
    run(
        SERVER_BIN,
        &[
            "--dir",
            f.server_dir.to_str().unwrap(),
            "authorize",
            second.join("id.crt").to_str().unwrap(),
            "--user",
            &current_user(),
            "--name",
            "tester",
            "--force",
        ],
    );

    // The policy has to be committed first. That is the whole fix: it fixes
    // which half-written state is reachable. Writing the certificate first
    // would leave the new key sitting next to the legacy policy above — a key
    // running under a policy that was written for a different one, and with
    // no fingerprint in it to catch that.
    //
    // The two writes are separated by two `fsync`s, so the gap is milliseconds
    // on any filesystem that timestamps finer than a second.
    let policy_written = std::fs::metadata(&policy_path).unwrap().modified().unwrap();
    let cert_written = std::fs::metadata(&cert_path).unwrap().modified().unwrap();
    assert!(
        policy_written < cert_written,
        "the certificate was published before the policy that names it \
         ({policy_written:?} vs {cert_written:?})"
    );

    // And the state that order does leave reachable fails closed. Rebuild it:
    // the new policy, still paired with the certificate it replaced.
    std::fs::copy(f.client_dir.join("id.crt"), &cert_path).unwrap();
    std::thread::sleep(Duration::from_millis(1_200));
    assert_ne!(
        f.exec(&["true"]).0,
        0,
        "the superseded key still worked against a policy written for another key"
    );
    assert_ne!(
        f.exec_as(&second, &["true"]).0,
        0,
        "the new key worked without its certificate being published"
    );

    // Finish the interrupted publication and it works again — the residual is
    // an authorization that is refused until `authorize` is re-run, not one
    // that quietly does the wrong thing.
    std::fs::copy(second.join("id.crt"), &cert_path).unwrap();
    std::thread::sleep(Duration::from_millis(1_200));
    assert_eq!(
        f.exec_as(&second, &["true"]).0,
        0,
        "the completed authorization did not work"
    );
}

#[test]
fn a_peer_that_never_reads_gets_the_stream_reset() {
    let f = Fixture::start(&[]);

    // Same shape as the slow-reader case — a leader that exits leaving a
    // descendant writing to the terminal — but this peer never comes back at
    // all. It stops reading and stays gone past the server's *entire*
    // shutdown budget: the drain deadline, then the exit-status send, then the
    // writer. By the end of that there is still output the server holds and
    // cannot deliver, and it has to give up.
    //
    // How it gives up is the point. quinn treats a dropped `SendStream` as a
    // graceful *finish* and goes on retransmitting, so a peer that came back
    // later would eventually see a clean end of stream and have no way to know
    // it had been abandoned mid-session. A reset is the honest ending, and
    // this asserts that is what actually goes on the wire.
    let pidfile = f.tmp.path().join("writer.pid");
    let marker = f.tmp.path().join("abandoned-writer");
    let script = format!(
        "sh -c 'trap \"\" HUP; echo $$ > {pid}; exec cat /dev/zero {marker}' & \
         until [ -s {pid} ]; do sleep 0.1; done; exit 0",
        pid = pidfile.display(),
        marker = marker.display(),
    );

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let ended = rt.block_on(async {
        let conn = raw_connect(&f.client_dir, f.port).await;
        stalled_until_teardown(&conn, &["sh", "-c", &script], Duration::from_secs(12)).await
    });

    assert_eq!(
        ended,
        StreamEnd::Reset(u64::from(qsh::proto::RESET_ABANDONED)),
        "the server did not reset a stream it had given up on"
    );
}

#[test]
fn a_peer_that_stops_reading_never_gets_a_successful_exit() {
    let f = Fixture::start(&[]);

    // A leader that exits at once, leaving a descendant writing to the
    // terminal. That is the shape the PTY drain deadline exists for: a
    // terminal has no last-writer guarantee, so the pump can never see EOF,
    // and the deadline has to decide what the silence means.
    //
    // `trap "" HUP` is load-bearing. The leader is the session leader with
    // this pty as its controlling terminal, so the kernel hangs up the
    // foreground process group when it exits — without the trap the writer
    // dies immediately, nothing ever backs up, and the session drains cleanly.
    // The disposition survives `exec`, so `cat` inherits it. It stays in the
    // leader's process group, which is what teardown is supposed to reach.
    //
    // It records its pid and carries a unique path in its argv, so the test
    // can tell it apart from any other `cat` on the machine.
    let pidfile = f.tmp.path().join("writer.pid");
    let marker = f.tmp.path().join("stalled-writer");
    //
    // The leader waits for the pid file before exiting. Without that wait the
    // hangup can arrive while the descendant is still starting up, before its
    // trap is installed, and the whole setup evaporates.
    let script = format!(
        "sh -c 'trap \"\" HUP; echo $$ > {pid}; exec cat /dev/zero {marker}' & \
         until [ -s {pid} ]; do sleep 0.1; done; exit 0",
        pid = pidfile.display(),
        marker = marker.display(),
    );

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let stalled = rt.block_on(async {
        let conn = raw_connect(&f.client_dir, f.port).await;
        // Comfortably longer than the server's two-second drain deadline, so
        // the decision is already made by the time this peer starts reading
        // again — and short enough that reading resumes while the server is
        // still tearing the session down, so its verdict can reach us.
        stalled_session(&conn, &["sh", "-c", &script], Duration::from_secs(4)).await
    });

    // The scenario really did produce a backlog. Without this the rest could
    // pass on a session that never wrote anything at all, which is how the
    // first version of this test quietly measured nothing.
    assert!(
        stalled.bytes > 1024 * 1024,
        "the session did not produce enough output to back up: {stalled:?}"
    );

    // The point of the whole drain path: output that could not be delivered
    // must never be dressed up as a successful run. The leader exited 0, so a
    // server that forwards its status verbatim reports 0 here — and a caller
    // redirecting to a file would keep a truncated copy and believe it.
    assert_ne!(
        stalled.exit,
        Some(0),
        "a truncated -t session reported success: {stalled:?}"
    );
    assert!(
        stalled.exit.is_some() || stalled.reset,
        "the session neither reported a status nor reset the stream: {stalled:?}"
    );
    if let Some(exit) = stalled.exit {
        assert_eq!(exit, 255, "unexpected failure status: {stalled:?}");
    }
    // The diagnostic is best-effort by design: it is queued without blocking,
    // precisely because the usual way to get here is a queue nobody is
    // draining. So it is checked when it arrives and not required.
    if let Some(error) = &stalled.error {
        assert!(
            error.contains("could not be delivered in full"),
            "unexpected diagnostic: {error}"
        );
    }

    // And the job does not get to outlive the session that failed. This is the
    // half that does not depend on whether the exit status made it back: a
    // server that treated the timeout as a clean drain would disarm the guard
    // and leave this process writing into a terminal nobody owns.
    let pid: i32 = std::fs::read_to_string(&pidfile)
        .expect("the descendant never recorded its pid")
        .trim()
        .parse()
        .expect("unparseable pid");
    let marker = marker.to_string_lossy().into_owned();
    let deadline = Instant::now() + Duration::from_secs(15);
    while running_with_marker(pid, &marker) {
        assert!(
            Instant::now() < deadline,
            "the descendant survived the session it belonged to (pid {pid})"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn a_fatal_signal_puts_the_terminal_back() {
    use nix::sys::termios::LocalFlags;

    let f = Fixture::start(&[]);
    let mut client = PtyClient::start(&f);

    let before = client.termios();
    assert!(
        before.local_flags.contains(LocalFlags::ECHO),
        "the test's own pty did not start in cooked mode"
    );

    // Wait until the client has actually taken the terminal into raw mode.
    // Without this the rest of the test would pass on a client that never
    // touched the terminal at all, which is the vacuous version of it.
    let deadline = Instant::now() + Duration::from_secs(20);
    while client.termios().local_flags.contains(LocalFlags::ECHO) {
        assert!(
            Instant::now() < deadline,
            "the client never put the terminal into raw mode"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // SIGTERM, not SIGKILL: the whole point is that a signal whose default
    // action would kill the process outright gets handled first. Nothing but
    // an installed handler can put the terminal back afterwards, because the
    // process that changed it is the one going away.
    nix::sys::signal::kill(client.pid(), nix::sys::signal::Signal::SIGTERM)
        .expect("signalling the client");

    let status = client.wait_status(Duration::from_secs(20));
    let after = client.termios();
    let text = client.finish();

    assert_eq!(
        status,
        Some(128 + libc::SIGTERM),
        "the client did not report the signal it died from: {text}"
    );
    assert!(
        after.local_flags.contains(LocalFlags::ECHO),
        "the terminal was left without echo after SIGTERM: {text}"
    );
    assert!(
        after.local_flags.contains(LocalFlags::ICANON),
        "the terminal was left in raw mode after SIGTERM: {text}"
    );
    // Every flag word, not just the two obvious ones — `cfmakeraw` touches
    // input, output and control flags as well, and leaving any of them behind
    // is the same bug.
    assert_eq!(after.input_flags, before.input_flags, "input flags");
    assert_eq!(after.output_flags, before.output_flags, "output flags");
    assert_eq!(after.control_flags, before.control_flags, "control flags");
    assert_eq!(after.local_flags, before.local_flags, "local flags");
}

#[test]
fn a_revoked_key_loses_an_established_connection() {
    let f = Fixture::start(&[]);

    // This has to be one QUIC connection with two streams on it, not two runs
    // of the client: the bug being guarded against is the server caching the
    // policy it resolved at handshake time, and a fresh connection re-resolves
    // it either way. So the CLI cannot express this test — it makes one
    // connection per run — and it is driven through the raw helpers above.
    //
    // Everything except the revocation happens on the same `quinn::Connection`
    // value, which is what makes the second session a *second stream* rather
    // than a second handshake.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let conn = raw_connect(&f.client_dir, f.port).await;
        assert_eq!(
            raw_session(&conn, &["true"]).await,
            Some(0),
            "the first session on the connection should have run"
        );

        let dir = f.server_dir.clone();
        tokio::task::spawn_blocking(move || {
            run(
                SERVER_BIN,
                &["--dir", dir.to_str().unwrap(), "revoke", "tester"],
            );
        })
        .await
        .unwrap();
        // The server re-reads the authorized directory on a timer; give it more
        // than one interval so this is testing the policy, not the clock.
        tokio::time::sleep(Duration::from_secs(2)).await;

        assert_eq!(
            raw_session(&conn, &["true"]).await,
            None,
            "a second stream on the same connection still ran after revoke"
        );
    });
}

#[test]
fn revocation_stops_a_running_session_on_an_established_connection() {
    let f = Fixture::start(&[]);
    let pidfile = f.tmp.path().join("revoked-live.pid");
    let marker = f.tmp.path().join("revoked-live-job");
    let script = idle_job_script(&pidfile, &marker);
    let marker = marker.to_string_lossy().into_owned();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let conn = raw_connect(&f.client_dir, f.port).await;
        let (_send, mut recv) = raw_request(&conn, &["sh", "-c", &script], false)
            .await
            .expect("opening the live session");
        wait_for_started(&mut recv).await;
        let pid = tokio::task::block_in_place(|| wait_for_pid(&pidfile));
        tokio::task::block_in_place(|| wait_for_running_marker(pid, &marker));

        let server_dir = f.server_dir.clone();
        tokio::task::spawn_blocking(move || {
            run(
                SERVER_BIN,
                &["--dir", server_dir.to_str().unwrap(), "revoke", "tester"],
            );
        })
        .await
        .unwrap();

        tokio::time::timeout(Duration::from_secs(8), conn.closed())
            .await
            .expect("revocation did not close the established connection");
        let deadline = Instant::now() + Duration::from_secs(10);
        while running_with_marker(pid, &marker) {
            assert!(
                Instant::now() < deadline,
                "the revoked session's process survived (pid {pid})"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });
}

#[test]
fn a_preopened_stream_uses_the_policy_when_its_request_arrives() {
    let f = Fixture::start(&[]);
    let ran = f.tmp.path().join("staged-request-ran");
    let script = format!("echo ran > {}", ran.display());
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let conn = raw_connect(&f.client_dir, f.port).await;
        assert_eq!(raw_session(&conn, &["true"]).await, Some(0));

        // Send only the Request kind. The server can accept this stream, but
        // cannot finish decoding its first frame until the policy changes.
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(&[1]).await.unwrap();
        send.flush().await.unwrap();
        assert_eq!(
            raw_session(&conn, &["true"]).await,
            Some(0),
            "the server did not accept a later stream while this one was staged"
        );

        let policy_path = f.server_dir.join("authorized/tester.toml");
        let policy = std::fs::read_to_string(&policy_path).unwrap();
        assert!(policy.contains("allow_exec = true"), "{policy}");
        std::fs::write(
            &policy_path,
            policy.replace("allow_exec = true", "allow_exec = false"),
        )
        .unwrap();

        // A fresh request is a reload barrier, so the staged request is not
        // completed against a policy the server has not read yet.
        let deadline = Instant::now() + Duration::from_secs(6);
        loop {
            let (code, _, error) = tokio::task::block_in_place(|| f.exec(&["true"]));
            if code == 126 {
                assert!(error.contains("may not execute"), "{error}");
                break;
            }
            assert!(
                Instant::now() < deadline,
                "server did not load the narrower policy"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let request = qsh::proto::Request {
            version: qsh::proto::PROTOCOL_VERSION,
            user: None,
            command: Some(vec!["sh".into(), "-c".into(), script]),
            pty: None,
            env: Vec::new(),
        };
        let payload = postcard::to_stdvec(&request).unwrap();
        send.write_all(&u32::try_from(payload.len()).unwrap().to_be_bytes())
            .await
            .unwrap();
        send.write_all(&payload).await.unwrap();
        send.flush().await.unwrap();

        // Closing the connection or refusing in-band are both safe outcomes.
        // Starting the command is not, even if the connection closes later.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match qsh::proto::read_frame(&mut recv).await {
                    Ok(Some(qsh::proto::Frame::Started)) => {
                        panic!("the staged request started under its old policy")
                    }
                    Ok(Some(qsh::proto::Frame::Exit(status))) => {
                        assert_ne!(status.wait_status(), 0);
                        break;
                    }
                    Ok(Some(_)) => {}
                    Ok(None) | Err(_) => break,
                }
            }
        })
        .await
        .expect("the staged request was never rejected");
        assert!(
            !ran.exists(),
            "the staged request ran after exec was forbidden"
        );
    });
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
fn an_expired_key_cannot_keep_or_open_an_idle_connection() {
    let f = Fixture::start(&["--expires-in-days", "30"]);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        // No session stream is opened: request-time expiry checks cannot make
        // this pass. The already admitted connection must release its slot.
        let conn = raw_connect(&f.client_dir, f.port).await;
        let log = f.tmp.path().join("server.log");
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if std::fs::read_to_string(&log)
                    .unwrap()
                    .contains("authenticated as")
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("the idle connection was not admitted before expiry");
        let policy_path = f.server_dir.join("authorized/tester.toml");
        let policy = std::fs::read_to_string(&policy_path).unwrap();
        assert!(policy.contains("expires_at_unix"), "{policy}");
        let expired = policy
            .lines()
            .map(|line| {
                if line.starts_with("expires_at_unix") {
                    "expires_at_unix = 1"
                } else {
                    line
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&policy_path, expired).unwrap();

        tokio::time::timeout(Duration::from_secs(8), conn.closed())
            .await
            .expect("an expired key kept its already admitted idle connection");

        // A new expired-key connection may be rejected during TLS or closed
        // just after the handshake. It must not remain idle and admitted.
        let endpoint = raw_endpoint(&f.client_dir, "0.0.0.0:0", Arc::new(AcceptAnyServer));
        let connecting = endpoint
            .connect(std::net::SocketAddr::from(([127, 0, 0, 1], f.port)), "qsh")
            .unwrap();
        if let Ok(new_conn) = tokio::time::timeout(Duration::from_secs(5), connecting)
            .await
            .expect("expired-key admission did not finish")
        {
            tokio::time::timeout(Duration::from_secs(5), new_conn.closed())
                .await
                .expect("an expired key kept a new idle connection");
        }
        // TLS may also refuse the expired key before the handshake completes.
    });
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

#[test]
fn one_key_cannot_occupy_every_established_connection_slot() {
    const KEY_LIMIT: usize = 32;

    let f = Fixture::start(&[]);
    let other = f.tmp.path().join("other-client");
    run(
        CLIENT_BIN,
        &["keygen", "--identity", other.to_str().unwrap()],
    );
    run(
        SERVER_BIN,
        &[
            "--dir",
            f.server_dir.to_str().unwrap(),
            "authorize",
            other.join("id.crt").to_str().unwrap(),
            "--user",
            &current_user(),
            "--name",
            "other",
        ],
    );
    let deadline = Instant::now() + Duration::from_secs(6);
    while f.exec_as(&other, &["true"]).0 != 0 {
        assert!(Instant::now() < deadline, "the second key was never loaded");
        std::thread::sleep(Duration::from_millis(100));
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], f.port));
        let endpoint = raw_endpoint(&f.client_dir, "0.0.0.0:0", Arc::new(AcceptAnyServer));
        let mut held = Vec::new();
        for _ in 0..KEY_LIMIT {
            let conn = tokio::time::timeout(
                Duration::from_secs(5),
                endpoint.connect(addr, "qsh").unwrap(),
            )
            .await
            .expect("an allowed connection timed out")
            .expect("an allowed connection was refused");
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(5), raw_session(&conn, &["true"]))
                    .await
                    .expect("an allowed session timed out"),
                Some(0),
                "a connection within the per-key limit was refused"
            );
            held.push(conn);
        }

        let excess = tokio::time::timeout(
            Duration::from_secs(5),
            endpoint.connect(addr, "qsh").unwrap(),
        )
        .await
        .expect("the over-limit handshake did not finish");
        if let Ok(conn) = excess {
            assert_ne!(
                tokio::time::timeout(Duration::from_secs(5), raw_session(&conn, &["true"]))
                    .await
                    .expect("the over-limit connection stayed open"),
                Some(0),
                "one key exceeded its established-connection limit"
            );
        }

        let other_conn = raw_connect(&other, f.port).await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), raw_session(&other_conn, &["true"]))
                .await
                .expect("the other key's session timed out"),
            Some(0),
            "one key's quota prevented a different key from connecting"
        );
        for conn in held {
            conn.close(0u32.into(), b"test complete");
        }
    });
}

#[test]
fn root_target_login_with_a_different_server_group() {
    use std::os::unix::process::CommandExt;

    const CHILD_MARKER: &str = "QSH_TEST_ROOT_DIFFERENT_GROUP";
    if !nix::unistd::Uid::effective().is_root() {
        eprintln!("skipping: requires root to change the server group");
        return;
    }
    if std::env::var_os(CHILD_MARKER).is_none() {
        let root = qsh::child::resolve_user("root").unwrap();
        let other_gid = if root.gid.as_raw() == 1 { 2 } else { 1 };
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "root_target_login_with_a_different_server_group",
                "--nocapture",
            ])
            .env(CHILD_MARKER, "1")
            .gid(other_gid)
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }

    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        use tokio::io::AsyncReadExt;

        let root = qsh::child::resolve_user("root").unwrap();
        assert_ne!(nix::unistd::Gid::current(), root.gid);
        for pty in [false, true] {
            let req = qsh::proto::Request {
                version: qsh::proto::PROTOCOL_VERSION,
                user: None,
                command: Some(vec!["sh".into(), "-c".into(), "id -u; id -g".into()]),
                pty: pty.then(|| qsh::proto::PtyRequest {
                    term: "xterm".into(),
                    size: qsh::proto::PtySize::default(),
                }),
                env: Vec::new(),
            };
            let mut spawned = qsh::child::spawn(&root, &req).unwrap();
            let mut output = String::new();
            match &mut spawned.io {
                qsh::child::ChildIo::Pty(master) => {
                    master.read_to_string(&mut output).await.unwrap()
                }
                qsh::child::ChildIo::Pipes { stdout, .. } => {
                    stdout.read_to_string(&mut output).await.unwrap()
                }
            };
            assert!(spawned.child.wait().await.unwrap().success());
            assert_eq!(
                output.replace('\r', ""),
                format!("0\n{}\n", root.gid.as_raw())
            );
        }
    });
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

#[test]
fn no_stdin_leaves_the_local_input_unread() {
    use std::io::Read;
    let f = Fixture::start(&[]);
    let input = f.tmp.path().join("hosts.txt");
    std::fs::write(&input, b"host-one\nhost-two\n").unwrap();
    let mut file = std::fs::File::open(input).unwrap();
    let out = Command::new(CLIENT_BIN)
        .args([
            "-i",
            f.client_dir.to_str().unwrap(),
            "-p",
            &f.port.to_string(),
            "--accept-new",
            "-n",
            "127.0.0.1",
            "cat",
        ])
        .stdin(Stdio::from(file.try_clone().unwrap()))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stdout.is_empty());
    let mut unread = String::new();
    file.read_to_string(&mut unread).unwrap();
    assert_eq!(unread, "host-one\nhost-two\n");
}

#[test]
fn forced_pty_does_not_interpret_piped_tildes() {
    let f = Fixture::start(&[]);
    let mut child = Command::new(CLIENT_BIN)
        .args([
            "-i",
            f.client_dir.to_str().unwrap(),
            "-p",
            &f.port.to_string(),
            "--accept-new",
            "-t",
            "127.0.0.1",
            "head",
            "-n",
            "3",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"~~hello\nx\n~.\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("~~hello") && stdout.contains("~."),
        "{stdout}"
    );
}

#[test]
fn forced_pty_with_piped_stdin_relays_sigint() {
    let f = Fixture::start(&[]);
    let pidfile = f.tmp.path().join("ready.pid");
    let child = Command::new(CLIENT_BIN)
        .args([
            "-i",
            f.client_dir.to_str().unwrap(),
            "-p",
            &f.port.to_string(),
            "--accept-new",
            "-t",
            "127.0.0.1",
            "sh",
            "-c",
            "trap 'exit 42' INT; echo $$ > \"$1\"; while :; do sleep 1; done",
            "sh",
            pidfile.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_pid(&pidfile);
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id() as i32),
        nix::sys::signal::Signal::SIGINT,
    )
    .unwrap();
    let out = wait_with_deadline(child, Duration::from_secs(10))
        .expect("client did not forward SIGINT to the forced PTY");
    assert_eq!(
        out.status.code(),
        Some(42),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn forced_pty_with_piped_stdin_uses_the_output_terminal_size() {
    let f = Fixture::start(&[]);
    let sizefile = f.tmp.path().join("terminal-size");
    let size = nix::pty::Winsize {
        ws_row: 45,
        ws_col: 123,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let terminal = nix::pty::openpty(Some(&size), None).unwrap();
    let out = Command::new(CLIENT_BIN)
        .args([
            "-i",
            f.client_dir.to_str().unwrap(),
            "-p",
            &f.port.to_string(),
            "--accept-new",
            "-t",
            "127.0.0.1",
            "sh",
            "-c",
            "stty size > \"$1\"",
            "sh",
            sizefile.to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::from(terminal.slave))
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read_to_string(sizefile).unwrap().trim(), "45 123");
    drop(terminal.master);
}
