//! The qsh client: connect, verify the host key, run one session.

use std::io::{IsTerminal, Write as _};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::config::{ClientPaths, KnownHosts};
use crate::crypto::{self, Fingerprint, PinnedServerVerifier};
use crate::net::transport_config;
use crate::proto::{
    read_frame, write_frame, ExitStatus, Frame, PtyRequest, Request, CHUNK,
    PROTOCOL_VERSION,
};
use crate::pty::{self, RawMode};

/// What to do when the host is not in `known_hosts` yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyPolicy {
    /// Ask on the terminal (the default).
    Ask,
    /// Pin silently. Convenient for scripts, trusting the first connection.
    AcceptNew,
    /// Never pin automatically.
    Refuse,
}

/// Whether the session should get a terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtyPolicy {
    /// A terminal for interactive shells, none for commands — like ssh.
    Auto,
    Force,
    Never,
}

/// Everything needed to run one client session.
#[derive(Debug, Clone)]
pub struct Options {
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    pub command: Option<Vec<String>>,
    pub pty: PtyPolicy,
    pub env: Vec<(String, String)>,
    pub host_key_policy: HostKeyPolicy,
    pub paths_dir: Option<std::path::PathBuf>,
    pub quiet: bool,
}

impl Options {
    fn host_key(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Records the certificate the server presented without judging it, so the
/// caller can apply trust-on-first-use afterwards. Nothing is sent over a
/// connection verified this way until the fingerprint has been accepted.
#[derive(Debug)]
struct CaptureVerifier {
    seen: Mutex<Option<Fingerprint>>,
}

impl CaptureVerifier {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            seen: Mutex::new(None),
        })
    }
}

impl ServerCertVerifier for CaptureVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        let fp = Fingerprint::of_cert(end_entity)
            .map_err(|_| TlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
        *self.seen.lock().unwrap() = Some(fp);
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Run a session and return the status the local shell should report.
pub async fn run(opts: Options) -> Result<i32> {
    let paths = match &opts.paths_dir {
        Some(dir) => ClientPaths::new(dir.clone()),
        None => ClientPaths::discover()?,
    };
    let identity = crypto::load_identity(&paths.cert(), &paths.key()).with_context(|| {
        format!(
            "loading your identity from {} (run `qsh keygen` first)",
            paths.dir.display()
        )
    })?;

    let host_key = opts.host_key();
    let mut known = KnownHosts::load(&paths.known_hosts())?;
    let pinned = known.get(&host_key);

    let capture = CaptureVerifier::new();
    let verifier: Arc<dyn ServerCertVerifier> = match pinned {
        Some(fp) => PinnedServerVerifier::new(fp),
        None => Arc::clone(&capture) as Arc<dyn ServerCertVerifier>,
    };

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("configuring TLS 1.3")?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![identity.cert.clone()], identity.key.clone_key())
        .context("installing your client certificate")?;
    tls.alpn_protocols = vec![crate::proto::ALPN.to_vec()];

    let addr = resolve(&opts.host, opts.port)?;
    let bind: SocketAddr = if addr.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let mut endpoint = quinn::Endpoint::client(bind).context("opening a local UDP socket")?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls).context("building the QUIC crypto configuration")?,
    ));
    client_config.transport_config(Arc::new(transport_config(
        Duration::from_secs(600),
        Duration::from_secs(15),
    )?));
    endpoint.set_default_client_config(client_config);

    let conn = endpoint
        .connect(addr, sni_name(&opts.host))
        .context("starting the QUIC handshake")?
        .await
        .map_err(|e| connect_error(e, &opts, addr))?;

    // Trust on first use: the handshake is complete but nothing has been sent.
    if pinned.is_none() {
        let fp = capture
            .seen
            .lock()
            .unwrap()
            .ok_or_else(|| anyhow!("server presented no certificate"))?;
        if !accept_new_host(&host_key, fp, opts.host_key_policy)? {
            conn.close(1u32.into(), b"host key rejected");
            bail!("host key for {host_key} was not accepted");
        }
        known.set(&host_key, fp)?;
        if !opts.quiet {
            eprintln!("qsh: permanently added {host_key} ({fp}) to known hosts");
        }
    }

    let status = session(&conn, &opts).await;
    conn.close(0u32.into(), b"bye");
    endpoint.wait_idle().await;
    status
}

/// Turn a connection failure into a message that says what to do next.
fn connect_error(e: quinn::ConnectionError, opts: &Options, addr: SocketAddr) -> anyhow::Error {
    let base = anyhow!("cannot connect to {} ({addr}): {e}", opts.host);
    match &e {
        quinn::ConnectionError::TransportError(te)
            if te.to_string().contains("host key mismatch") =>
        {
            anyhow!(
                "{}\n\nThe host key for {} has changed. If this is expected, remove the old \
                 entry with `qsh known-hosts remove {}`; otherwise someone may be \
                 impersonating the server.",
                te,
                opts.host_key(),
                opts.host_key()
            )
        }
        quinn::ConnectionError::TimedOut => anyhow!(
            "{base}\n\nNo response. Check that qsh-server is running and that UDP port {} is \
             reachable — QUIC needs UDP, not TCP.",
            opts.port
        ),
        _ => base,
    }
}

fn sni_name(host: &str) -> &str {
    // The certificate is pinned by public key, so the SNI value is cosmetic;
    // it just has to be a syntactically valid DNS name.
    if host.parse::<std::net::IpAddr>().is_ok() || host.is_empty() {
        "qsh"
    } else {
        host
    }
}

fn resolve(host: &str, port: u16) -> Result<SocketAddr> {
    let trimmed = host.trim_start_matches('[').trim_end_matches(']');
    (trimmed, port)
        .to_socket_addrs()
        .with_context(|| format!("resolving `{host}`"))?
        .next()
        .ok_or_else(|| anyhow!("`{host}` did not resolve to any address"))
}

/// Trust-on-first-use decision for an unknown host.
fn accept_new_host(host_key: &str, fp: Fingerprint, policy: HostKeyPolicy) -> Result<bool> {
    match policy {
        HostKeyPolicy::AcceptNew => return Ok(true),
        HostKeyPolicy::Refuse => {
            bail!(
                "host {host_key} is not known and --refuse-new-hosts is in effect\n\
                 Its key is {fp}. Add it with `qsh known-hosts add {host_key} {fp}`."
            );
        }
        HostKeyPolicy::Ask => {}
    }

    // stdin may be a pipe (rsync!), so ask the terminal directly.
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty");
    let Ok(mut tty) = tty else {
        bail!(
            "host {host_key} is not known and there is no terminal to ask on.\n\
             Its key is {fp}.\n\
             Connect once interactively, or run: qsh known-hosts add {host_key} {fp}"
        );
    };
    write!(
        tty,
        "The authenticity of host '{host_key}' cannot be established.\n\
         Key fingerprint is {fp}.\n\
         Are you sure you want to continue connecting (yes/no)? "
    )?;
    tty.flush()?;
    let mut answer = String::new();
    std::io::BufRead::read_line(&mut std::io::BufReader::new(&tty), &mut answer)?;
    Ok(matches!(answer.trim(), "yes" | "y"))
}

/// Should this session allocate a remote terminal?
fn want_pty(opts: &Options) -> bool {
    match opts.pty {
        PtyPolicy::Force => true,
        PtyPolicy::Never => false,
        // Same rule as ssh: interactive login gets a terminal, a command does not.
        PtyPolicy::Auto => opts.command.is_none() && std::io::stdin().is_terminal(),
    }
}

async fn session(conn: &quinn::Connection, opts: &Options) -> Result<i32> {
    let use_pty = want_pty(opts);
    let stdin_fd = libc::STDIN_FILENO;

    let pty_req = use_pty.then(|| {
        let size = pty::get_size(stdin_fd).unwrap_or_default();
        PtyRequest {
            term: std::env::var("TERM").unwrap_or_else(|_| "xterm".into()),
            size,
        }
    });

    let mut env = opts.env.clone();
    for name in ["LANG", "LC_ALL", "LC_CTYPE", "COLORTERM"] {
        if let Ok(v) = std::env::var(name) {
            if !env.iter().any(|(k, _)| k == name) {
                env.push((name.to_string(), v));
            }
        }
    }

    let (mut send, mut recv) = conn.open_bi().await.context("opening the session stream")?;

    write_frame(
        &mut send,
        &Frame::Request(Request {
            version: PROTOCOL_VERSION,
            user: opts.user.clone(),
            command: opts.command.clone(),
            pty: pty_req,
            env,
        }),
    )
    .await
    .context("sending the session request")?;

    // Wait for the server's verdict before touching the local terminal.
    match read_frame(&mut recv).await? {
        Some(Frame::Started) => {}
        Some(Frame::Error(msg)) => {
            eprintln!("qsh: {msg}");
            // Drain the exit status the server sends after an error.
            if let Ok(Some(Frame::Exit(s))) = read_frame(&mut recv).await {
                return Ok(s.wait_status());
            }
            return Ok(126);
        }
        Some(other) => bail!("unexpected reply from server: {other:?}"),
        None => bail!("server closed the session without a reply"),
    }

    let raw = if use_pty && std::io::stdin().is_terminal() {
        Some(RawMode::enable(stdin_fd).context("switching the terminal to raw mode")?)
    } else {
        None
    };

    let result = pump(send, recv, use_pty).await;
    drop(raw);
    result
}

/// Frames the input tasks want to put on the wire.
type Outbound = mpsc::Sender<Frame>;

/// Drive the session to completion.
///
/// Reading and writing each live in their own task. Frame codecs are not
/// cancellation-safe, so they must never sit in a `select!` arm — a cancelled
/// half-read would desynchronise the stream.
async fn pump(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    use_pty: bool,
) -> Result<i32> {
    let (tx, mut rx) = mpsc::channel::<Frame>(64);

    let writer = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if write_frame(&mut send, &frame).await.is_err() {
                break;
            }
        }
        let _ = send.finish();
    });

    let stdin_task = tokio::spawn(forward_stdin(tx.clone(), use_pty));
    let winch_task = use_pty.then(|| tokio::spawn(forward_winch(tx.clone())));
    let signal_task = (!use_pty).then(|| tokio::spawn(forward_signals(tx.clone())));
    drop(tx);

    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    let mut exit: Option<ExitStatus> = None;

    while let Some(frame) = read_frame(&mut recv).await? {
        if let Some(status) = apply(frame, &mut stdout, &mut stderr).await? {
            exit = Some(status);
            break;
        }
    }

    stdin_task.abort();
    if let Some(t) = winch_task {
        t.abort();
    }
    if let Some(t) = signal_task {
        t.abort();
    }
    writer.abort();
    stdout.flush().await.ok();
    stderr.flush().await.ok();

    // No exit status means the stream ended early — never report that as a
    // successful run.
    exit.map(|s| s.wait_status()).ok_or_else(|| {
        anyhow!("the connection closed before the remote process reported an exit status")
    })
}

/// Apply one server frame; returns the exit status once the session ends.
async fn apply(
    frame: Frame,
    stdout: &mut tokio::io::Stdout,
    stderr: &mut tokio::io::Stderr,
) -> Result<Option<ExitStatus>> {
    match frame {
        Frame::Stdout(data) => {
            stdout.write_all(&data).await?;
            stdout.flush().await?;
        }
        Frame::Stderr(data) => {
            stderr.write_all(&data).await?;
            stderr.flush().await?;
        }
        Frame::Error(msg) => eprintln!("qsh: {msg}"),
        Frame::Exit(status) => return Ok(Some(status)),
        _ => {}
    }
    Ok(None)
}

/// Read local stdin and forward it, honouring the `~.` escape on a terminal.
async fn forward_stdin(tx: Outbound, use_pty: bool) {
    let mut stdin = tokio::io::stdin();
    let mut buf = vec![0u8; CHUNK];
    let mut escape = EscapeState::new(use_pty);

    loop {
        match stdin.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let (data, disconnect) = escape.filter(&buf[..n]);
                if !data.is_empty() && tx.send(Frame::Stdin(data)).await.is_err() {
                    break;
                }
                if disconnect {
                    let _ = tx.send(Frame::Signal("HUP".into())).await;
                    break;
                }
            }
        }
    }
    let _ = tx.send(Frame::StdinEof).await;
}

/// The `~.` escape sequence, recognised only at the start of a line.
struct EscapeState {
    enabled: bool,
    at_line_start: bool,
    after_tilde: bool,
}

impl EscapeState {
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            at_line_start: true,
            after_tilde: false,
        }
    }

    /// Returns the bytes to forward and whether the user asked to disconnect.
    fn filter(&mut self, input: &[u8]) -> (Vec<u8>, bool) {
        if !self.enabled {
            return (input.to_vec(), false);
        }
        let mut out = Vec::with_capacity(input.len());
        for &b in input {
            if self.after_tilde {
                self.after_tilde = false;
                match b {
                    b'.' => return (out, true),
                    // `~~` sends a literal tilde.
                    b'~' => out.push(b'~'),
                    other => {
                        out.push(b'~');
                        out.push(other);
                    }
                }
                self.at_line_start = false;
                continue;
            }
            if self.at_line_start && b == b'~' {
                self.after_tilde = true;
                continue;
            }
            self.at_line_start = matches!(b, b'\r' | b'\n');
            out.push(b);
        }
        (out, false)
    }
}

/// Forward terminal resizes.
async fn forward_winch(tx: Outbound) {
    let Ok(mut winch) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
    else {
        return;
    };
    let mut last = pty::get_size(libc::STDIN_FILENO).unwrap_or_default();
    while winch.recv().await.is_some() {
        let size = pty::get_size(libc::STDIN_FILENO).unwrap_or_default();
        if size != last {
            last = size;
            if tx.send(Frame::Resize(size)).await.is_err() {
                break;
            }
        }
    }
}

/// Without a terminal, local Ctrl-C must be relayed as a signal.
async fn forward_signals(tx: Outbound) {
    let mut int = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()) {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(s) => s,
        Err(_) => return,
    };
    loop {
        let name = tokio::select! {
            _ = int.recv() => "INT",
            _ = term.recv() => "TERM",
        };
        if tx.send(Frame::Signal(name.into())).await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filtered(chunks: &[&[u8]]) -> (Vec<u8>, bool) {
        let mut st = EscapeState::new(true);
        let mut out = Vec::new();
        for c in chunks {
            let (data, disconnect) = st.filter(c);
            out.extend_from_slice(&data);
            if disconnect {
                return (out, true);
            }
        }
        (out, false)
    }

    #[test]
    fn escape_disconnects_only_at_line_start() {
        assert_eq!(filtered(&[b"~."]), (b"".to_vec(), true));
        assert_eq!(filtered(&[b"ls~."]), (b"ls~.".to_vec(), false));
        // Split across reads, as a real terminal delivers it.
        assert_eq!(filtered(&[b"\n", b"~", b"."]), (b"\n".to_vec(), true));
    }

    #[test]
    fn double_tilde_is_a_literal_tilde() {
        assert_eq!(filtered(&[b"~~cd\n"]), (b"~cd\n".to_vec(), false));
    }

    #[test]
    fn unknown_escape_is_passed_through() {
        assert_eq!(filtered(&[b"~x"]), (b"~x".to_vec(), false));
    }

    #[test]
    fn escape_is_off_without_a_terminal() {
        // rsync's binary stream must never be interpreted.
        let mut st = EscapeState::new(false);
        let payload: Vec<u8> = (0u8..=255).collect();
        let (out, disconnect) = st.filter(&payload);
        assert_eq!(out, payload);
        assert!(!disconnect);
    }

    #[test]
    fn sni_falls_back_for_addresses() {
        assert_eq!(sni_name("192.0.2.1"), "qsh");
        assert_eq!(sni_name("example.com"), "example.com");
    }

    #[test]
    fn pty_is_off_for_remote_commands() {
        let base = Options {
            host: "h".into(),
            port: 2222,
            user: None,
            command: Some(vec!["rsync".into()]),
            pty: PtyPolicy::Auto,
            env: vec![],
            host_key_policy: HostKeyPolicy::Ask,
            paths_dir: None,
            quiet: false,
        };
        assert!(!want_pty(&base));
        assert!(want_pty(&Options {
            pty: PtyPolicy::Force,
            ..base.clone()
        }));
        assert!(!want_pty(&Options {
            pty: PtyPolicy::Never,
            command: None,
            ..base
        }));
    }
}
