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

/// How long to keep draining output after the remote process has exited.
const DRAIN_GRACE: Duration = Duration::from_secs(2);

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

    while let Some(incoming) = endpoint.accept().await {
        // Pick up `authorize`/`revoke` changes without a restart.
        match AuthStore::load(&paths.authorized()) {
            Ok(fresh) => *crate::sync::write(&store) = fresh,
            Err(e) => eprintln!("qsh-server: keeping previous authorizations: {e:#}"),
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
fn authorize_request(entry: &AuthEntry, req: &Request) -> Result<()> {
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
        authorize_request(&entry, &req)?;
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

    write_frame(&mut send, &Frame::Started).await?;
    run_session(send, recv, spawned).await
}

async fn run_session(
    mut send: quinn::SendStream,
    recv: quinn::RecvStream,
    spawned: Spawned,
) -> Result<()> {
    let Spawned { mut child, io } = spawned;
    let pid = child.id();
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

    let control = tokio::spawn(control_loop(recv, stdin_sink, pid, pty_fd));

    let status = child
        .wait()
        .await
        .context("waiting for the remote process")?;

    // Give the output pumps a moment to drain whatever is still buffered. A
    // background job can hold the PTY open forever, so they do not get to
    // outlive the grace period — otherwise the exit status would never be
    // written.
    for mut task in outputs {
        if tokio::time::timeout(DRAIN_GRACE, &mut task).await.is_err() {
            task.abort();
        }
    }
    control.abort();

    let _ = tx
        .send(Frame::Exit(ExitStatus {
            code: status.code().unwrap_or(0),
            signal: status.signal(),
        }))
        .await;
    drop(tx);

    if let Ok(Ok(mut send)) = tokio::time::timeout(DRAIN_GRACE, writer).await {
        // Make sure the peer sees everything before the stream disappears.
        let _ = send.flush().await;
        let _ = tokio::time::timeout(DRAIN_GRACE, send.stopped()).await;
    }
    Ok(())
}

/// Forward one output stream of the child into frames.
async fn pump<R: AsyncRead + Unpin>(
    mut src: R,
    tx: mpsc::Sender<Frame>,
    wrap: fn(Vec<u8>) -> Frame,
) {
    let mut buf = vec![0u8; CHUNK];
    loop {
        match src.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let Some(chunk) = buf.get(..n) else { break };
                if tx.send(wrap(chunk.to_vec())).await.is_err() {
                    break;
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
                // Dropping the writer closes the pipe, which the child sees as EOF.
                stdin_sink = None;
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
        });
        assert!(authorize_request(&e, &request(None)).is_err());
        assert!(authorize_request(&e, &request(Some(&["rsync", "--server"]))).is_ok());
        assert!(authorize_request(&e, &request(Some(&["sh"]))).is_err());
    }

    #[test]
    fn exec_can_be_forbidden_while_shell_is_allowed() {
        let e = entry(AuthMeta {
            user: "alice".into(),
            allow_shell: true,
            allow_exec: false,
            allowed_commands: vec![],
        });
        assert!(authorize_request(&e, &request(None)).is_ok());
        assert!(authorize_request(&e, &request(Some(&["ls"]))).is_err());
    }

    #[test]
    fn version_mismatch_is_rejected() {
        let e = entry(AuthMeta {
            user: "alice".into(),
            ..Default::default()
        });
        let mut req = request(Some(&["ls"]));
        req.version = PROTOCOL_VERSION + 1;
        assert!(authorize_request(&e, &req).is_err());
    }

    #[test]
    fn empty_command_is_rejected() {
        let e = entry(AuthMeta {
            user: "alice".into(),
            ..Default::default()
        });
        assert!(authorize_request(&e, &request(Some(&[]))).is_err());
    }
}
