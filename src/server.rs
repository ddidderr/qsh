//! The qsh server: accept QUIC connections, authenticate them against the
//! authorisation store and run one process per session stream.

use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::os::unix::process::ExitStatusExt;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::child::{self, ChildIo, Spawned};
use crate::config::{AuthEntry, AuthStore, ServerConfig, ServerPaths};
use crate::crypto::{self, AuthorizedClientVerifier, Fingerprint};
use crate::net::transport_config;
use crate::proto::{
    read_frame, signal_number, write_frame, ExitStatus, Frame, PtySize, Request, CHUNK,
    PROTOCOL_VERSION,
};
use crate::pty;

/// How long to keep reading a PTY after the remote process has exited.
const DRAIN_GRACE: Duration = Duration::from_secs(2);

/// How long to wait for the job to die before escalating to the next signal.
const TERMINATE_GRACE: Duration = Duration::from_secs(2);

/// How long to wait for the peer to acknowledge the final frames.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// `Ctrl-D`: what a terminal's line discipline turns into end of file.
const EOT: u8 = 0x04;

/// Shortest gap between two reloads of the authorisation store.
const RELOAD_INTERVAL: Duration = Duration::from_secs(1);

/// Run the server until the process is stopped.
///
/// # Errors
/// Fails if the host identity is missing, the authorisation store cannot be
/// read, the TLS configuration is invalid, or the socket cannot be bound.
pub async fn serve(
    paths: &ServerPaths,
    cfg: &ServerConfig,
    listen_override: Option<SocketAddr>,
) -> Result<()> {
    let identity = crypto::load_identity(&paths.cert(), &paths.key()).with_context(|| {
        format!(
            "loading the server identity from {} (run `qsh-server keygen` first)",
            paths.dir.display()
        )
    })?;

    let store = Arc::new(RwLock::new(AuthStore::load(&paths.authorized())?));
    if crate::sync::read(&store).is_empty() {
        eprintln!(
            "qsh-server: warning: no authorized clients in {} — every connection will be refused",
            paths.authorized().display()
        );
    }

    let verifier = {
        let store = Arc::clone(&store);
        AuthorizedClientVerifier::new(Arc::new(move |fp: &Fingerprint| {
            crate::sync::read(&store).lookup(fp).is_some()
        }))
    };

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("configuring TLS 1.3")?
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![identity.cert.clone()], identity.key.clone_key())
        .context("installing the server certificate")?;
    tls.alpn_protocols = vec![crate::proto::ALPN.to_vec()];

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(tls).context("building the QUIC crypto configuration")?,
    ));
    server_config.transport_config(Arc::new(transport_config(
        Duration::from_secs(cfg.idle_timeout_secs),
        Duration::from_secs(cfg.keepalive_secs),
    )?));

    let addr = match listen_override {
        Some(a) => a,
        None => cfg.listen_addr()?,
    };
    let endpoint = quinn::Endpoint::server(server_config, addr)
        .with_context(|| format!("binding UDP {addr}"))?;

    eprintln!(
        "qsh-server: listening on {} ({} authorized client(s))",
        endpoint.local_addr()?,
        crate::sync::read(&store).entries().count()
    );

    let mut last_reload = tokio::time::Instant::now();
    while let Some(incoming) = endpoint.accept().await {
        // Make the peer prove it can receive at its claimed address before we
        // spend anything on it. Without this, a spoofed-source flood would
        // reach the work below on every packet.
        if !incoming.remote_address_validated() {
            incoming.retry().ok();
            continue;
        }

        // Pick up `authorize`/`revoke` changes without a restart, but at most
        // once a second: re-reading and parsing the whole directory for every
        // arriving Initial is a denial-of-service lever, since this runs
        // before the handshake has authenticated anybody.
        if last_reload.elapsed() >= RELOAD_INTERVAL {
            last_reload = tokio::time::Instant::now();
            match AuthStore::load(&paths.authorized()) {
                Ok(fresh) => *crate::sync::write(&store) = fresh,
                Err(e) => eprintln!("qsh-server: keeping previous authorizations: {e:#}"),
            }
        }

        let store = Arc::clone(&store);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(incoming, store).await {
                eprintln!("qsh-server: connection closed: {e:#}");
            }
        });
    }
    Ok(())
}

/// Seconds since the Unix epoch, saturating rather than failing.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(i64::MAX)
}

/// Which authorised client is on the other end of this connection?
fn identify(conn: &quinn::Connection, store: &Arc<RwLock<AuthStore>>) -> Result<AuthEntry> {
    let identity = conn
        .peer_identity()
        .ok_or_else(|| anyhow!("client presented no certificate"))?;
    let certs = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| anyhow!("unexpected peer identity type"))?;
    let end_entity = certs
        .first()
        .ok_or_else(|| anyhow!("client presented an empty certificate chain"))?;
    let fp = Fingerprint::of_cert(end_entity)?;
    crate::sync::read(store)
        .lookup(&fp)
        .cloned()
        .ok_or_else(|| anyhow!("client key {fp} is not authorized"))
}

async fn handle_connection(incoming: quinn::Incoming, store: Arc<RwLock<AuthStore>>) -> Result<()> {
    let conn = incoming.await.context("QUIC handshake failed")?;
    let peer = conn.remote_address();
    let entry = identify(&conn, &store)?;
    eprintln!(
        "qsh-server: {peer} authenticated as `{}` (key `{}`)",
        entry.meta.user, entry.name
    );

    loop {
        let stream = match conn.accept_bi().await {
            Ok(s) => s,
            Err(
                quinn::ConnectionError::ApplicationClosed(_)
                | quinn::ConnectionError::ConnectionClosed(_)
                | quinn::ConnectionError::LocallyClosed,
            ) => return Ok(()),
            Err(e) => return Err(e).context("accepting a session stream"),
        };
        let entry = entry.clone();
        tokio::spawn(async move {
            let (send, recv) = stream;
            if let Err(e) = handle_session(send, recv, entry).await {
                eprintln!("qsh-server: session from {peer} ended: {e:#}");
            }
        });
    }
}

/// Validate a request against what this key is allowed to do.
fn authorize_request(entry: &AuthEntry, req: &Request, now_unix: i64) -> Result<()> {
    if entry.meta.is_expired(now_unix) {
        bail!(
            "the authorization for key `{}` has expired; ask an administrator to renew it",
            entry.name
        );
    }
    if req.version != PROTOCOL_VERSION {
        bail!(
            "protocol version mismatch: client speaks {}, server speaks {}",
            req.version,
            PROTOCOL_VERSION
        );
    }
    if let Some(requested) = &req.user {
        if requested != &entry.meta.user {
            bail!(
                "key `{}` is authorized for `{}`, not `{requested}`",
                entry.name,
                entry.meta.user
            );
        }
    }
    match &req.command {
        None => {
            if !entry.meta.allow_shell {
                bail!("key `{}` may not open an interactive shell", entry.name);
            }
        }
        Some(argv) => {
            if argv.is_empty() {
                bail!("empty command");
            }
            if !entry.meta.allow_exec {
                bail!("key `{}` may not execute commands", entry.name);
            }
            if !entry.meta.command_allowed(argv) {
                bail!(
                    "key `{}` may not execute `{}`; permitted: {}",
                    entry.name,
                    argv.first().map_or("", String::as_str),
                    entry.meta.allowed_commands.join(", ")
                );
            }
        }
    }
    Ok(())
}

async fn handle_session(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    entry: AuthEntry,
) -> Result<()> {
    let req = match read_frame(&mut recv).await? {
        Some(Frame::Request(r)) => r,
        Some(other) => bail!("expected a request frame first, got {other:?}"),
        None => return Ok(()),
    };

    let start = (|| -> Result<Spawned> {
        authorize_request(&entry, &req, unix_now())?;
        let user = child::resolve_user(&entry.meta.user)?;
        child::spawn(&user, &req)
    })();

    let spawned = match start {
        Ok(s) => s,
        Err(e) => {
            // Report the refusal in-band so the client can print it, then end
            // the session with a shell-like "cannot execute" status.
            let _ = write_frame(&mut send, &Frame::Error(format!("{e:#}"))).await;
            let _ = write_frame(
                &mut send,
                &Frame::Exit(ExitStatus {
                    code: 126,
                    signal: None,
                }),
            )
            .await;
            let _ = send.finish();
            return Err(e);
        }
    };

    run_session(send, recv, spawned).await
}

/// Kills the remote process group if the session goes away.
///
/// Tokio deliberately leaves a child running when its handle is dropped, so
/// without this a client that is killed — or a server that is shutting down —
/// would leave `sleep 3600` behind forever. The guard fires on every exit path
/// including task cancellation, which is the one path an `async` cleanup step
/// could never cover.
struct ProcessGroupGuard {
    pid: Option<u32>,
}

impl ProcessGroupGuard {
    fn new(pid: Option<u32>) -> Self {
        Self { pid }
    }

    /// The child was reaped normally; nothing left to kill.
    fn disarm(&mut self) {
        self.pid = None;
    }

    /// Ask the job to go away, escalating if it will not.
    async fn terminate(&mut self) {
        let Some(pid) = self.pid.take() else { return };
        for sig in [libc::SIGHUP, libc::SIGTERM] {
            child::signal_process_group(pid, sig);
            // Anything that is going to exit on a hangup does so promptly.
            if tokio::time::timeout(TERMINATE_GRACE, wait_for_exit(pid))
                .await
                .is_ok()
            {
                return;
            }
        }
        child::signal_process_group(pid, libc::SIGKILL);
    }
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        if let Some(pid) = self.pid {
            // No async available here, so skip straight to the signal that
            // cannot be ignored.
            child::signal_process_group(pid, libc::SIGKILL);
        }
    }
}

/// Poll until the process group has no members left.
async fn wait_for_exit(pid: u32) {
    loop {
        if !child::process_group_alive(pid) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Why the session stopped.
enum Outcome {
    /// The remote process exited on its own.
    Exited(std::process::ExitStatus),
    /// The client vanished; the remote process is still running.
    Disconnected,
}

async fn run_session(
    mut send: quinn::SendStream,
    recv: quinn::RecvStream,
    spawned: Spawned,
) -> Result<()> {
    let Spawned { mut child, io } = spawned;
    let pid = child.id();
    // Armed before anything that can fail, so no error path can leak the job.
    let mut guard = ProcessGroupGuard::new(pid);

    let (tx, mut rx) = mpsc::channel::<Frame>(64);

    // Single writer for the stream: stdout, stderr and the exit status all
    // funnel through here, so frames never interleave.
    let writer = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if write_frame(&mut send, &frame).await.is_err() {
                break;
            }
        }
        let _ = send.finish();
        send
    });

    if tx.send(Frame::Started).await.is_err() {
        guard.terminate().await;
        bail!("client closed the session before it started");
    }

    let mut outputs = Vec::new();
    let stdin_sink: Box<dyn AsyncWrite + Unpin + Send>;
    let pty_fd: Option<RawFd>;

    match io {
        ChildIo::Pty(master) => {
            pty_fd = Some(master.as_raw_fd());
            let (r, w) = tokio::io::split(master);
            stdin_sink = Box::new(w);
            outputs.push(tokio::spawn(pump(r, tx.clone(), Frame::Stdout)));
        }
        ChildIo::Pipes {
            stdin,
            stdout,
            stderr,
        } => {
            pty_fd = None;
            stdin_sink = Box::new(stdin);
            outputs.push(tokio::spawn(pump(stdout, tx.clone(), Frame::Stdout)));
            outputs.push(tokio::spawn(pump(stderr, tx.clone(), Frame::Stderr)));
        }
    }

    let mut control = tokio::spawn(control_loop(recv, stdin_sink, pid, pty_fd));

    // Race the process against the client going away. Waiting only on the
    // child would let a killed client strand a `sleep` here forever.
    let outcome = tokio::select! {
        status = child.wait() => Outcome::Exited(status.context("waiting for the remote process")?),
        _ = &mut control => Outcome::Disconnected,
    };

    if matches!(outcome, Outcome::Disconnected) {
        guard.terminate().await;
        let _ = child.wait().await;
        return Ok(());
    }
    guard.disarm();
    control.abort();

    let drained = drain(outputs, pty_fd.is_some()).await;

    let exit = match (&outcome, drained) {
        (Outcome::Exited(status), Drained::Fully) => ExitStatus {
            code: status.code().unwrap_or(0),
            signal: status.signal(),
        },
        // Never hand back a successful status over a truncated stream: a
        // caller redirecting our stdout to a file would silently keep a short
        // copy and believe it.
        (_, Drained::Incomplete(why)) => {
            let _ = tx
                .send(Frame::Error(format!(
                    "the remote output could not be delivered in full: {why}"
                )))
                .await;
            ExitStatus {
                code: 255,
                signal: None,
            }
        }
        (Outcome::Disconnected, _) => return Ok(()),
    };

    let _ = tx.send(Frame::Exit(exit)).await;
    drop(tx);

    if let Ok(Ok(mut send)) = tokio::time::timeout(SHUTDOWN_GRACE, writer).await {
        // Make sure the peer sees everything before the stream disappears.
        let _ = send.flush().await;
        let _ = tokio::time::timeout(SHUTDOWN_GRACE, send.stopped()).await;
    }
    Ok(())
}

/// Did every byte of the child's output make it onto the wire?
enum Drained {
    Fully,
    Incomplete(&'static str),
}

/// Collect the output pumps once the remote process has exited.
///
/// Pipes have a definite end: the kernel reports EOF once the last writer
/// closes them, so they are drained without a deadline and back-pressure from
/// the frame channel keeps memory bounded. A PTY master has no such guarantee —
/// a background job holding the terminal open would keep it readable forever —
/// so those get a grace period instead.
async fn drain(outputs: Vec<tokio::task::JoinHandle<PumpEnd>>, is_pty: bool) -> Drained {
    let mut result = Drained::Fully;
    for mut task in outputs {
        let end = if is_pty {
            if let Ok(joined) = tokio::time::timeout(DRAIN_GRACE, &mut task).await {
                joined.ok()
            } else {
                task.abort();
                // Expected for an interactive session that leaves a background
                // job attached to the terminal.
                None
            }
        } else {
            task.await.ok()
        };
        match end {
            Some(PumpEnd::Eof) | None if is_pty => {}
            Some(PumpEnd::Eof) => {}
            Some(PumpEnd::ReadError) => result = Drained::Incomplete("read error"),
            Some(PumpEnd::ClientGone) => result = Drained::Incomplete("client stopped reading"),
            None => result = Drained::Incomplete("output task failed"),
        }
    }
    result
}

/// How an output pump finished.
enum PumpEnd {
    /// The stream reached a real end of file; everything was forwarded.
    Eof,
    /// Reading the child's output failed part way through.
    ReadError,
    /// Nobody is left to receive the frames.
    ClientGone,
}

/// Forward one output stream of the child into frames.
async fn pump<R: AsyncRead + Unpin>(
    mut src: R,
    tx: mpsc::Sender<Frame>,
    wrap: fn(Vec<u8>) -> Frame,
) -> PumpEnd {
    let mut buf = vec![0u8; CHUNK];
    loop {
        match src.read(&mut buf).await {
            Ok(0) => return PumpEnd::Eof,
            Err(_) => return PumpEnd::ReadError,
            Ok(n) => {
                let Some(chunk) = buf.get(..n) else {
                    return PumpEnd::ReadError;
                };
                // `send` awaits when the channel is full, which is the
                // back-pressure that stops a slow client ballooning memory.
                if tx.send(wrap(chunk.to_vec())).await.is_err() {
                    return PumpEnd::ClientGone;
                }
            }
        }
    }
}

/// Handle everything the client sends after the request.
async fn control_loop(
    mut recv: quinn::RecvStream,
    stdin_sink: Box<dyn AsyncWrite + Unpin + Send>,
    pid: Option<u32>,
    pty_fd: Option<RawFd>,
) {
    let mut stdin_sink = Some(stdin_sink);
    loop {
        match read_frame(&mut recv).await {
            Ok(Some(Frame::Stdin(data))) => {
                if let Some(sink) = stdin_sink.as_mut() {
                    if sink.write_all(&data).await.is_err() {
                        stdin_sink = None;
                    }
                }
            }
            Ok(Some(Frame::StdinEof)) => {
                if pty_fd.is_some() {
                    // A terminal has no "close one end": dropping our write
                    // half would leave the read half owning the same master,
                    // so the child would never see EOF and `qsh -t host cat
                    // < file` would hang. Send the line discipline's EOF
                    // character instead, as ssh does.
                    if let Some(sink) = stdin_sink.as_mut() {
                        let _ = sink.write_all(&[EOT]).await;
                        let _ = sink.flush().await;
                    }
                } else {
                    // Dropping the writer closes the pipe, which the child
                    // sees as EOF.
                    stdin_sink = None;
                }
            }
            Ok(Some(Frame::Resize(size))) => resize(pty_fd, pid, size),
            Ok(Some(Frame::Signal(name))) => {
                if let (Some(pid), Some(sig)) = (pid, signal_number(&name)) {
                    child::signal_process_group(pid, sig);
                }
            }
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
        }
    }
}

fn resize(pty_fd: Option<RawFd>, pid: Option<u32>, size: PtySize) {
    let Some(fd) = pty_fd else { return };
    if pty::set_size(fd, size).is_ok() {
        if let Some(pid) = pid {
            child::signal_process_group(pid, libc::SIGWINCH);
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a failing assertion should panic loudly; that is the point of a test"
)]
mod tests {
    use super::*;
    use crate::config::AuthMeta;

    fn entry(meta: AuthMeta) -> AuthEntry {
        let (pem, _) = crypto::generate_identity("t", &["t".into()], 30).unwrap();
        AuthEntry {
            name: "test".into(),
            fingerprint: Fingerprint::of_cert(&crypto::cert_from_pem(&pem).unwrap()).unwrap(),
            meta,
        }
    }

    fn request(command: Option<&[&str]>) -> Request {
        Request {
            version: PROTOCOL_VERSION,
            user: None,
            command: command.map(|c| c.iter().map(|s| (*s).to_owned()).collect()),
            pty: None,
            env: Vec::new(),
        }
    }

    #[test]
    fn shell_can_be_forbidden_while_exec_is_allowed() {
        let e = entry(AuthMeta {
            user: "alice".into(),
            allow_shell: false,
            allow_exec: true,
            allowed_commands: vec!["rsync".into()],
            expires_at_unix: None,
        });
        assert!(authorize_request(&e, &request(None), 0).is_err());
        assert!(authorize_request(&e, &request(Some(&["rsync", "--server"])), 0).is_ok());
        assert!(authorize_request(&e, &request(Some(&["sh"])), 0).is_err());
    }

    #[test]
    fn exec_can_be_forbidden_while_shell_is_allowed() {
        let e = entry(AuthMeta {
            user: "alice".into(),
            allow_shell: true,
            allow_exec: false,
            allowed_commands: vec![],
            expires_at_unix: None,
        });
        assert!(authorize_request(&e, &request(None), 0).is_ok());
        assert!(authorize_request(&e, &request(Some(&["ls"])), 0).is_err());
    }

    #[test]
    fn version_mismatch_is_rejected() {
        let e = entry(AuthMeta {
            user: "alice".into(),
            ..Default::default()
        });
        let mut req = request(Some(&["ls"]));
        req.version = PROTOCOL_VERSION + 1;
        assert!(authorize_request(&e, &req, 0).is_err());
    }

    #[test]
    fn empty_command_is_rejected() {
        let e = entry(AuthMeta {
            user: "alice".into(),
            ..Default::default()
        });
        assert!(authorize_request(&e, &request(Some(&[])), 0).is_err());
    }

    #[test]
    fn an_expired_authorization_is_refused() {
        let e = entry(AuthMeta {
            user: "alice".into(),
            expires_at_unix: Some(1_000),
            ..Default::default()
        });
        assert!(authorize_request(&e, &request(Some(&["ls"])), 999).is_ok());
        let err = authorize_request(&e, &request(Some(&["ls"])), 1_001).unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
        // A shell is refused for the same reason, not just exec.
        assert!(authorize_request(&e, &request(None), 1_001).is_err());
    }
}
