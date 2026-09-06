//! The qsh client: connect, verify the host key, run one session.

use std::io::{IsTerminal, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
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
    read_frame, write_frame, ExitStatus, Frame, PtyRequest, Request, CHUNK, PROTOCOL_VERSION,
};
use std::os::fd::RawFd;

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

/// Which IP families the client may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AddressFamily {
    #[default]
    Any,
    V4,
    V6,
}

impl AddressFamily {
    fn accepts(self, addr: &SocketAddr) -> bool {
        match self {
            Self::Any => true,
            Self::V4 => addr.is_ipv4(),
            Self::V6 => addr.is_ipv6(),
        }
    }
}

impl std::fmt::Display for AddressFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Any => "usable",
            Self::V4 => "IPv4",
            Self::V6 => "IPv6",
        })
    }
}

/// Idle timeout for an established session. QUIC uses the lower of the two
/// peers' values, so this only matters if the server's is higher.
const IDLE_TIMEOUT_SECS: u64 = 60;
/// Keep-alive interval for an established session.
const KEEPALIVE_SECS: u64 = 15;
/// Default deadline for reaching one address.
pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;

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
    pub no_stdin: bool,
    pub family: AddressFamily,
    pub connect_timeout_secs: u64,
}

impl Options {
    fn known_hosts_command(&self) -> String {
        self.paths_dir.as_ref().map_or_else(
            || "qsh known-hosts".into(),
            |dir| format!("qsh known-hosts -i {}", shell_quote(&dir.to_string_lossy())),
        )
    }

    fn host_key(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

// Commands in diagnostics must preserve spaces and apostrophes in identity paths.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

/// An anonymous probe verifies the server's validity and proof of possession,
/// records its fingerprint, then deliberately stops before client authentication.
/// The caller must reconnect with a pinned verifier after accepting that key.
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
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        // Trust-on-first-use decides *which* key to trust; it does not excuse
        // an expired or not-yet-valid certificate. Skipping this would mean
        // expiry never applied to exactly the clients that have no pin yet.
        crypto::check_validity(end_entity, now)?;
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
        )?;
        let fp = Fingerprint::of_cert(cert)
            .map_err(|_| TlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
        *crate::sync::mutex(&self.seen) = Some(fp);
        Err(TlsError::General(
            "anonymous host-key probe complete".into(),
        ))
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Run a session and return the status the local shell should report.
///
/// # Errors
/// Fails if the identity is missing, the host key is unknown and not
/// accepted, the connection cannot be established, or the session ends
/// without an exit status.
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
    let addrs = resolve(&opts.host, opts.port, opts.family)?;
    let pinned = if let Some(fp) = known.get(&host_key) {
        fp
    } else {
        // Refusal needs no contact with an unknown server at all.
        if opts.host_key_policy == HostKeyPolicy::Refuse {
            let command = opts.known_hosts_command();
            bail!(
                "host {host_key} is not known and the host-key policy refuses new hosts (--refuse-new)\n\
                 Obtain the host key fingerprint through a trusted channel, then add it with \
                 `{command} add {host_key} <verified-fingerprint>`."
            );
        }
        let fp = probe_host_key(&addrs, &opts).await?;
        if !accept_new_host(&host_key, fp, &opts)? {
            bail!("host key for {host_key} was not accepted");
        }
        known.set_if_new(&host_key, fp)?;
        if !opts.quiet {
            eprintln!("qsh: permanently added {host_key} ({fp}) to known hosts");
        }
        fp
    };
    let config = client_config(PinnedServerVerifier::new(pinned), Some(&identity))?;
    let (endpoint, conn) = connect_any(&addrs, &config, &opts).await?;

    let status = session(&conn, &opts).await;
    conn.close(0u32.into(), b"bye");
    endpoint.wait_idle().await;
    status
}

/// Client credentials are installed only for a host key that has been accepted.
fn client_config(
    verifier: Arc<dyn ServerCertVerifier>,
    identity: Option<&crypto::Identity>,
) -> Result<quinn::ClientConfig> {
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .context("configuring TLS 1.3")?
    .dangerous()
    .with_custom_certificate_verifier(verifier);
    let mut tls = match identity {
        Some(identity) => builder
            .with_client_auth_cert(vec![identity.cert.clone()], identity.key.clone_key())
            .context("installing your client certificate")?,
        None => builder.with_no_client_auth(),
    };
    tls.alpn_protocols = vec![crate::proto::ALPN.to_vec()];
    let mut config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls).context("building the QUIC crypto configuration")?,
    ));
    config.transport_config(Arc::new(transport_config(
        Duration::from_secs(IDLE_TIMEOUT_SECS),
        Duration::from_secs(KEEPALIVE_SECS),
    )?));
    Ok(config)
}

async fn probe_host_key(addrs: &[SocketAddr], opts: &Options) -> Result<Fingerprint> {
    race_addresses(addrs, |addr| {
        let opts = opts.clone();
        async move {
            // Capture state belongs to exactly one address, never the race.
            let capture = CaptureVerifier::new();
            let config = client_config(capture.clone(), None)?;
            let result = connect_one(addr, &config, &opts).await;
            // Only a verified CertificateVerify populates this state. The
            // anonymous probe then aborts before client authentication.
            let seen = *crate::sync::mutex(&capture.seen);
            seen.ok_or_else(|| {
                result
                    .err()
                    .unwrap_or_else(|| anyhow!("server presented no verified certificate"))
            })
        }
    })
    .await
}

const ADDRESS_STAGGER: Duration = Duration::from_millis(250);
const MAX_PARALLEL_ATTEMPTS: usize = 2;

/// Start another address after a short delay without cutting the earlier
/// address's timeout short. At most two endpoints exist concurrently.
async fn race_addresses<T, F, Fut>(addrs: &[SocketAddr], mut attempt: F) -> Result<T>
where
    T: Send + 'static,
    F: FnMut(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = Result<T>> + Send + 'static,
{
    let mut remaining = addrs.iter().copied().peekable();
    let mut pending = tokio::task::JoinSet::<Result<T>>::new();
    let mut next_start = tokio::time::Instant::now();
    let mut last = anyhow!("host did not resolve to any address");
    loop {
        if pending.is_empty() && remaining.peek().is_none() {
            return Err(last);
        }
        tokio::select! {
            // Process a ready identity failure before launching another attempt.
            biased;
            joined = pending.join_next(), if !pending.is_empty() => {
                match joined {
                    Some(Ok(Ok(value))) => {
                        // Cancellation drops each attempt's endpoint. Await
                        // cancellation so no detached handshake survives us.
                        pending.shutdown().await;
                        return Ok(value);
                    }
                    Some(Ok(Err(error))) if error.is::<HostKeyRejected>() => {
                        pending.shutdown().await;
                        return Err(error);
                    }
                    Some(Ok(Err(error))) => last = error,
                    Some(Err(error)) => last = error.into(),
                    None => {}
                }
                // A failed attempt need not consume the rest of its stagger.
                next_start = tokio::time::Instant::now();
            }
            () = tokio::time::sleep_until(next_start),
                if pending.len() < MAX_PARALLEL_ATTEMPTS && remaining.peek().is_some() => {
                if let Some(addr) = remaining.next() {
                    pending.spawn(attempt(addr));
                    next_start = tokio::time::Instant::now() + ADDRESS_STAGGER;
                }
            }
        }
    }
}

#[derive(Debug)]
struct HostKeyRejected;

impl std::fmt::Display for HostKeyRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("host key rejected")
    }
}

impl std::error::Error for HostKeyRejected {}

/// Race the resolved addresses with an independent deadline for each one.
async fn connect_any(
    addrs: &[SocketAddr],
    client_config: &quinn::ClientConfig,
    opts: &Options,
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    race_addresses(addrs, |addr| {
        let config = client_config.clone();
        let opts = opts.clone();
        async move { connect_one(addr, &config, &opts).await }
    })
    .await
}

async fn connect_one(
    addr: SocketAddr,
    client_config: &quinn::ClientConfig,
    opts: &Options,
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    let bind = SocketAddr::new(
        if addr.is_ipv6() {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        },
        0,
    );
    let mut endpoint = quinn::Endpoint::client(bind).context("opening a local UDP socket")?;
    endpoint.set_default_client_config(client_config.clone());
    let connecting = endpoint
        .connect(addr, sni_name(&opts.host))
        .context("starting the QUIC handshake")?;
    match tokio::time::timeout(Duration::from_secs(opts.connect_timeout_secs), connecting).await {
        Ok(Ok(conn)) => Ok((endpoint, conn)),
        Ok(Err(error)) => {
            let fatal = matches!(&error, quinn::ConnectionError::TransportError(te)
                if te.to_string().contains("HostKeyMismatch"));
            let error = connect_error(&error, opts, addr);
            if fatal {
                Err(error.context(HostKeyRejected))
            } else {
                Err(error)
            }
        }
        Err(_) => Err(anyhow!(
            "connecting to {} ({addr}) timed out after {}s",
            opts.host,
            opts.connect_timeout_secs
        )),
    }
}

/// Turn a connection failure into a message that says what to do next.
fn connect_error(e: &quinn::ConnectionError, opts: &Options, addr: SocketAddr) -> anyhow::Error {
    let base = anyhow!("cannot connect to {} ({addr}): {e}", opts.host);
    match e {
        quinn::ConnectionError::TransportError(te)
            if te.to_string().contains("HostKeyMismatch") =>
        {
            anyhow!(
                "{}\n\nThe host key for {} has changed. If this is expected, remove the old \
                 entry with `{} remove {}`; otherwise someone may be \
                 impersonating the server.",
                te,
                opts.host_key(),
                opts.known_hosts_command(),
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

/// Every address the host resolves to, filtered by the requested family.
///
/// Returning only the first result would make a perfectly reachable host fail
/// on resolver order alone — `localhost` yielding `::1` first while the server
/// listens on `0.0.0.0` is the everyday case.
fn resolve(host: &str, port: u16, family: AddressFamily) -> Result<Vec<SocketAddr>> {
    let trimmed = host.trim_start_matches('[').trim_end_matches(']');
    let mut addrs: Vec<SocketAddr> = (trimmed, port)
        .to_socket_addrs()
        .with_context(|| format!("resolving `{host}`"))?
        .filter(|a| family.accepts(a))
        .collect();
    // Interleave the families so an IPv4 fallback is the second attempt,
    // even when DNS returns several IPv6 addresses first.
    addrs.sort_unstable();
    addrs.dedup();
    let (v6, v4): (Vec<_>, Vec<_>) = addrs.into_iter().partition(SocketAddr::is_ipv6);
    let mut addrs = Vec::with_capacity(v6.len() + v4.len());
    for i in 0..v6.len().max(v4.len()) {
        addrs.extend(v6.get(i));
        addrs.extend(v4.get(i));
    }
    if addrs.is_empty() {
        bail!("`{host}` did not resolve to any {family} address");
    }
    Ok(addrs)
}

/// Trust-on-first-use decision for an unknown host.
fn accept_new_host(host_key: &str, fp: Fingerprint, opts: &Options) -> Result<bool> {
    let command = opts.known_hosts_command();
    match opts.host_key_policy {
        HostKeyPolicy::AcceptNew => return Ok(true),
        HostKeyPolicy::Refuse => {
            bail!(
                "host {host_key} is not known and the host-key policy refuses new hosts (--refuse-new)\n\
                 Its key is {fp}. Add it with `{command} add {host_key} {fp}`."
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
             Connect once interactively, or run: {command} add {host_key} {fp}"
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
        PtyPolicy::Auto => {
            opts.command.is_none() && !opts.no_stdin && std::io::stdin().is_terminal()
        }
    }
}

async fn session(conn: &quinn::Connection, opts: &Options) -> Result<i32> {
    let use_pty = want_pty(opts);
    let stdin_fd = libc::STDIN_FILENO;

    let pty_req = use_pty.then(|| {
        let size = terminal_size();
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

    let raw = if use_pty && !opts.no_stdin && std::io::stdin().is_terminal() {
        // Register the handlers *before* touching the terminal. `Drop` covers
        // the ordinary paths, but a fatal signal does not unwind, and a signal
        // arriving between changing the termios and the handler being ready
        // would take the default action and leave the terminal raw — no echo,
        // no line editing, and no obvious way back.
        let signals = FatalSignals::install()?;
        let guard = RawMode::enable(stdin_fd).context("switching the terminal to raw mode")?;
        tokio::spawn(signals.restore_on_fire(stdin_fd, guard.saved()));
        Some(guard)
    } else {
        None
    };

    let result = pump(send, recv, use_pty, opts.no_stdin).await;
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
    no_stdin: bool,
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

    let terminal_input = use_pty && !no_stdin && std::io::stdin().is_terminal();
    let stdin_task = if no_stdin {
        let _ = tx.send(Frame::StdinEof).await;
        None
    } else {
        Some(tokio::spawn(forward_stdin(tx.clone(), terminal_input)))
    };
    let winch_task = use_pty.then(|| tokio::spawn(forward_winch(tx.clone())));
    let signal_task = (!terminal_input).then(|| tokio::spawn(forward_signals(tx.clone())));
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

    if let Some(t) = stdin_task {
        t.abort();
    }
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
async fn forward_stdin(tx: Outbound, terminal_input: bool) {
    let mut stdin = tokio::io::stdin();
    let mut buf = vec![0u8; CHUNK];
    let mut escape = EscapeState::new(terminal_input);

    loop {
        match stdin.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let Some(chunk) = buf.get(..n) else { break };
                let (data, disconnect) = escape.filter(chunk);
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
                self.at_line_start = matches!(b, b'\r' | b'\n');
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

/// The signals that would otherwise kill the client without unwinding.
///
/// `SIGINT` is deliberately absent: in a PTY session Ctrl-C is just a byte for
/// the remote terminal, and the local process should not act on it.
struct FatalSignals {
    term: tokio::signal::unix::Signal,
    hup: tokio::signal::unix::Signal,
    quit: tokio::signal::unix::Signal,
}

impl FatalSignals {
    /// Start listening. Registration happens here, synchronously, so that by
    /// the time this returns the disposition is already installed — waiting
    /// for a spawned task to be polled would leave a window with the terminal
    /// already in raw mode and nothing watching.
    fn install() -> Result<Self> {
        use tokio::signal::unix::{signal, SignalKind};
        Ok(Self {
            term: signal(SignalKind::terminate()).context("listening for SIGTERM")?,
            hup: signal(SignalKind::hangup()).context("listening for SIGHUP")?,
            quit: signal(SignalKind::quit()).context("listening for SIGQUIT")?,
        })
    }

    /// Put the terminal back and exit when one of them arrives.
    async fn restore_on_fire(mut self, fd: RawFd, saved: nix::sys::termios::Termios) {
        let sig = tokio::select! {
            _ = self.term.recv() => libc::SIGTERM,
            _ = self.hup.recv() => libc::SIGHUP,
            _ = self.quit.recv() => libc::SIGQUIT,
        };
        pty::restore_termios(fd, &saved);
        let mut stdout = tokio::io::stdout();
        let _ = stdout.flush().await;
        std::process::exit(128 + sig);
    }
}

/// A forced PTY may receive piped input while output still goes to a terminal.
fn terminal_size() -> crate::proto::PtySize {
    [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO]
        .into_iter()
        .find_map(|fd| pty::get_size(fd).ok())
        .unwrap_or_default()
}

/// Forward terminal resizes.
async fn forward_winch(tx: Outbound) {
    let Ok(mut winch) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
    else {
        return;
    };
    let mut last = terminal_size();
    while winch.recv().await.is_some() {
        let size = terminal_size();
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
    let Ok(mut int) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
    else {
        return;
    };
    let Ok(mut term) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    else {
        return;
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
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a failing assertion should panic loudly; that is the point of a test"
)]
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
    fn escaped_newline_still_starts_a_new_line() {
        assert_eq!(filtered(&[b"~\r~."]), (b"~\r".to_vec(), true));
        assert_eq!(
            filtered(&[b"~", b"\n", b"~", b"."]),
            (b"~\n".to_vec(), true)
        );
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

    fn verify(pem: &str) -> std::result::Result<ServerCertVerified, TlsError> {
        let der = crypto::cert_from_pem(pem).unwrap();
        let now = UnixTime::since_unix_epoch(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap(),
        );
        CaptureVerifier::new().verify_server_cert(
            &der,
            &[],
            &ServerName::try_from("qsh").unwrap(),
            &[],
            now,
        )
    }

    #[test]
    fn first_contact_still_rejects_a_certificate_outside_its_validity() {
        // Trust on first use picks which key to trust; it is not a licence to
        // accept an expired one. Getting this wrong would mean expiry never
        // applied to precisely the clients that have no pin yet.
        let (expired, _) = crypto::generate_identity_outside_validity(true).unwrap();
        assert!(
            verify(&expired).is_err(),
            "an expired host key was accepted"
        );

        let (future, _) = crypto::generate_identity_outside_validity(false).unwrap();
        assert!(
            verify(&future).is_err(),
            "a not-yet-valid host key was accepted"
        );

        let (good, _) = crypto::generate_identity("host", &["localhost".into()], 30).unwrap();
        assert!(verify(&good).is_ok(), "a valid host key was rejected");
    }

    #[tokio::test]
    async fn address_race_cancels_a_stalled_loser_and_honours_fatal_errors() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Active(Arc<AtomicUsize>);
        impl Drop for Active {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let active = Arc::new(AtomicUsize::new(0));
        let addrs = [
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.1:2".parse().unwrap(),
        ];
        let winner = tokio::time::timeout(
            Duration::from_secs(2),
            race_addresses(&addrs, |addr| {
                let active = Arc::clone(&active);
                async move {
                    active.fetch_add(1, Ordering::SeqCst);
                    let _active = Active(active);
                    if addr.port() == 1 {
                        std::future::pending::<()>().await;
                    }
                    Ok(addr.port())
                }
            }),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(winner, 2);
        assert_eq!(
            active.load(Ordering::SeqCst),
            0,
            "a cancelled attempt remained live"
        );

        let started = Arc::new(AtomicUsize::new(0));
        let result = race_addresses(&addrs, |_| {
            let started = Arc::clone(&started);
            async move {
                started.fetch_add(1, Ordering::SeqCst);
                Err::<(), _>(anyhow!("changed key").context(HostKeyRejected))
            }
        })
        .await;
        assert!(result.unwrap_err().is::<HostKeyRejected>());
        assert_eq!(started.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn address_race_bounds_concurrency_and_keeps_trying_after_failures() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let addrs: Vec<SocketAddr> = (1..=5)
            .map(|port| SocketAddr::from(([127, 0, 0, 1], port)))
            .collect();
        let result = race_addresses(&addrs, |addr| {
            let active = Arc::clone(&active);
            let maximum = Arc::clone(&maximum);
            async move {
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                maximum.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(300)).await;
                active.fetch_sub(1, Ordering::SeqCst);
                if addr.port() == 5 {
                    Ok(5)
                } else {
                    bail!("address unavailable")
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(result, 5);
        assert!(maximum.load(Ordering::SeqCst) <= MAX_PARALLEL_ATTEMPTS);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    fn test_identity(dir: &std::path::Path) -> crypto::Identity {
        let (cert, key) =
            crypto::generate_identity("user@private-host", &["qsh".into()], 30).unwrap();
        crypto::write_public(&dir.join("id.crt"), &cert).unwrap();
        crypto::write_private(&dir.join("id.key"), &key).unwrap();
        crypto::load_identity(&dir.join("id.crt"), &dir.join("id.key")).unwrap()
    }

    #[tokio::test]
    async fn refusing_unknown_hosts_preserves_identity_guidance_without_network_contact() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("client's identity dir");
        std::fs::create_dir(&dir).unwrap();
        let _identity = test_identity(&dir);
        let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let opts = Options {
            host: "127.0.0.1".into(),
            port: addr.port(),
            user: None,
            command: None,
            pty: PtyPolicy::Never,
            env: vec![],
            host_key_policy: HostKeyPolicy::Refuse,
            paths_dir: Some(dir.clone()),
            quiet: true,
            no_stdin: true,
            family: AddressFamily::V4,
            connect_timeout_secs: 2,
        };
        let expected_command = opts.known_hosts_command();
        let error = run(opts).await.unwrap_err().to_string();
        assert!(
            error.contains("--refuse-new") && error.contains("trusted channel"),
            "{error}"
        );
        assert!(
            error.contains(&format!(
                "{expected_command} add {addr} <verified-fingerprint>"
            )),
            "{error}"
        );
        assert!(!dir.join("known_hosts").exists());
        let mut packet = [0u8; 2048];
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.recv_from(&mut packet))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn anonymous_probe_and_changed_key_never_disclose_the_client_identity() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let server_dir = tempfile::tempdir().unwrap();
        let client_dir = tempfile::tempdir().unwrap();
        let server_id = test_identity(server_dir.path());
        let client_id = test_identity(client_dir.path());
        let observed = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&observed);
        let verifier = crypto::AuthorizedClientVerifier::new(Arc::new(move |_| {
            count.fetch_add(1, Ordering::SeqCst);
            true
        }));
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![server_id.cert.clone()], server_id.key.clone_key())
        .unwrap();
        tls.alpn_protocols = vec![crate::proto::ALPN.to_vec()];
        let config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
        ));
        let server = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let opts = Options {
            host: "127.0.0.1".into(),
            port: addr.port(),
            user: None,
            command: None,
            pty: PtyPolicy::Never,
            env: vec![],
            host_key_policy: HostKeyPolicy::AcceptNew,
            paths_dir: None,
            quiet: true,
            no_stdin: false,
            family: AddressFamily::V4,
            connect_timeout_secs: 2,
        };
        // Keep a UDP address bound but silent, ahead of the healthy server.
        // Both anonymous first contact and pinned reconnect must bypass it
        // without waiting for the full per-address timeout.
        let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addrs = [blackhole.local_addr().unwrap(), addr];
        let opts = Options {
            connect_timeout_secs: 10,
            ..opts
        };
        let started = std::time::Instant::now();
        let (probe, rejected) = tokio::join!(probe_host_key(&addrs, &opts), async {
            server.accept().await.unwrap().await
        },);
        let pin = probe.unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "probe waited for the dead first address"
        );
        assert_eq!(pin, Fingerprint::of_cert(&server_id.cert).unwrap());
        assert!(rejected.is_err());
        assert_eq!(observed.load(Ordering::SeqCst), 0);

        // A key swapped after approval fails at the pinned verifier before
        // the legitimate client certificate can be sent.
        let wrong_pin = Fingerprint::of_cert(&client_id.cert).unwrap();
        let changed =
            client_config(PinnedServerVerifier::new(wrong_pin), Some(&client_id)).unwrap();
        let (client, peer) = tokio::join!(connect_any(&addrs, &changed, &opts), async {
            server.accept().await.unwrap().await
        },);
        assert!(client.is_err() && peer.is_err());
        assert_eq!(observed.load(Ordering::SeqCst), 0);

        // Once the probed key is accepted, ordinary mandatory mutual TLS works.
        let trusted = client_config(PinnedServerVerifier::new(pin), Some(&client_id)).unwrap();
        let started = std::time::Instant::now();
        let (client, peer) = tokio::join!(connect_any(&addrs, &trusted, &opts), async {
            server.accept().await.unwrap().await
        },);
        let (endpoint, conn) = client.unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "connection waited for the dead first address"
        );
        let peer = peer.unwrap();
        assert_eq!(observed.load(Ordering::SeqCst), 1);
        conn.close(0u32.into(), b"done");
        peer.close(0u32.into(), b"done");
        endpoint.close(0u32.into(), b"done");
        server.close(0u32.into(), b"done");
    }

    #[test]
    fn resolution_honours_the_requested_family() {
        let v4 = resolve("127.0.0.1", 2222, AddressFamily::Any).unwrap();
        assert!(v4.iter().all(SocketAddr::is_ipv4));
        assert!(resolve("127.0.0.1", 2222, AddressFamily::V6).is_err());

        // A dual-stack name must offer every address, not just the first.
        if let Ok(all) = resolve("localhost", 2222, AddressFamily::Any) {
            assert!(!all.is_empty());
            for addr in &all {
                assert_eq!(addr.port(), 2222);
            }
        }
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
            no_stdin: false,
            family: AddressFamily::Any,
            connect_timeout_secs: DEFAULT_CONNECT_TIMEOUT_SECS,
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
