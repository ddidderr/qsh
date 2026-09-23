//! The qsh server: accept QUIC connections, authenticate them against the
//! authorisation store and run one process per session stream.

use std::future::Future;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::ExitStatusExt;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context as TaskContext, Poll};
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
    PROTOCOL_VERSION, RESET_ABANDONED,
};
use crate::pty;

/// How long to keep reading a PTY once the leader has exited.
///
/// A pipe ends when its last writer closes it, so that case needs no deadline.
/// A PTY master has no such guarantee: a job backgrounded from an interactive
/// shell keeps the slave open after the shell exits, and without a bound the
/// session would never finish — `sleep 300 &` then `exit` would hang the
/// client forever.
const DRAIN_GRACE: Duration = Duration::from_secs(2);

/// How long to wait for the job to die before escalating to the next signal.
const TERMINATE_GRACE: Duration = Duration::from_secs(2);

/// How long to wait for the peer to acknowledge the final frames.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// `Ctrl-D`: what a terminal's line discipline turns into end of file.
const EOT: u8 = 0x04;

/// Shortest gap between two reloads of the authorisation store.
const RELOAD_INTERVAL: Duration = Duration::from_secs(1);

/// Connections being served at once. Reached only under attack: a legitimate
/// deployment has a handful.
const MAX_CONNECTIONS: usize = 256;

/// Established connections one client key may keep at once. This leaves room
/// for other authorized keys even when a client opens idle connections.
const MAX_CONNECTIONS_PER_KEY: usize = 32;

/// A program path longer than this cannot be executed on the supported Unix
/// hosts. This also bounds what a live session retains for policy rechecks.
const MAX_PROGRAM_LEN: usize = 4096;

/// Handshakes in flight at once.
///
/// Deliberately a separate, smaller budget: sharing one pool with established
/// sessions would let a stream of half-open connections — none of which can
/// authenticate — hold every slot for the length of the handshake deadline and
/// lock out the people with keys.
const MAX_HANDSHAKES: usize = 32;

/// Handshakes in flight from any single address.
///
/// The global budget alone is not fairness: one reachable source can hold all
/// of it for the length of the handshake deadline, over and over, and no new
/// client gets in — even though established sessions are unaffected. Capping
/// each address leaves room for at least `MAX_HANDSHAKES / MAX_HANDSHAKES_PER_SOURCE`
/// distinct clients to be starting at once.
const MAX_HANDSHAKES_PER_SOURCE: usize = 4;

/// How long an accepted connection may take to finish its handshake. The idle
/// timeout is far too generous for this — it would let half-open attempts hold
/// admission slots for a minute each.
const HANDSHAKE_GRACE: Duration = Duration::from_secs(5);

/// How long an opened session stream may take to say what it wants.
const FIRST_FRAME_GRACE: Duration = Duration::from_secs(10);

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

    let mut warnings = Vec::new();
    let store = Arc::new(RwLock::new(AuthStore::load_with_warnings(
        &paths.authorized(),
        |warning| warnings.push(warning),
    )?));
    for warning in &warnings {
        eprintln!("{warning}");
    }
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

    let counters = Arc::new(AdmissionCounters::default());
    let refresher = spawn_store_refresher(
        Arc::clone(&store),
        paths.authorized(),
        warnings,
        Arc::clone(&counters),
    );

    // Everything below runs before any client has authenticated, so all of it
    // has to be bounded.
    let connections = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let handshakes = Arc::new(tokio::sync::Semaphore::new(MAX_HANDSHAKES));
    let per_source = Arc::new(PerSourceHandshakes::default());
    let per_key = Arc::new(PerKeyConnections::default());

    while let Some(incoming) = endpoint.accept().await {
        // Make the peer prove it can receive at its claimed address before we
        // spend anything on it. Without this, a spoofed-source flood would
        // reach the work below on every packet.
        if !incoming.remote_address_validated() {
            incoming.retry().ok();
            continue;
        }

        // Over any of the limits: drop it silently. Refusing would send a
        // packet per attempt, which is a reflection lever of its own.
        let source = incoming.remote_address().ip();
        let (Ok(permit), Ok(handshake_permit), Some(source_slot)) = (
            Arc::clone(&connections).try_acquire_owned(),
            Arc::clone(&handshakes).try_acquire_owned(),
            per_source.try_acquire(source),
        ) else {
            counters
                .rejected
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            incoming.ignore();
            continue;
        };

        let store = Arc::clone(&store);
        let counters = Arc::clone(&counters);
        let per_key = Arc::clone(&per_key);
        tokio::spawn(async move {
            // The permit lives as long as the connection does.
            let _permit = permit;
            let outcome =
                handle_connection(incoming, store, per_key, (handshake_permit, source_slot)).await;
            record_connection_outcome(&counters, outcome);
        });
    }
    refresher.abort();
    Ok(())
}

fn record_connection_outcome(counters: &AdmissionCounters, outcome: Result<Authenticated>) {
    match outcome {
        // Only reachable once a client has authenticated; anyone can provoke
        // pre-authentication failures, so count those instead of logging each.
        Err(e) => eprintln!("qsh-server: {}", bounded_diagnostic(&e)),
        Ok(Authenticated::No) => {
            counters
                .unauthenticated
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(Authenticated::OverLimit) => {
            counters
                .rejected
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(Authenticated::Yes) => {}
    }
}

/// Counts handshakes in flight per source address.
///
/// Deliberately not a rate limiter: nothing is remembered once an attempt
/// finishes, so there is no table to grow and nothing to expire. It only stops
/// one address from occupying the whole handshake budget at any instant.
#[derive(Debug, Default)]
struct PerSourceHandshakes {
    in_flight: std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, usize>>,
}

/// Releases the slot when the handshake finishes, however it finishes.
struct SourceSlot {
    limiter: Arc<PerSourceHandshakes>,
    source: std::net::IpAddr,
}

impl PerSourceHandshakes {
    fn try_acquire(self: &Arc<Self>, source: std::net::IpAddr) -> Option<SourceSlot> {
        let mut in_flight = crate::sync::mutex(&self.in_flight);
        let count = in_flight.entry(source).or_insert(0);
        if *count >= MAX_HANDSHAKES_PER_SOURCE {
            return None;
        }
        *count += 1;
        Some(SourceSlot {
            limiter: Arc::clone(self),
            source,
        })
    }
}

impl Drop for SourceSlot {
    fn drop(&mut self) {
        let mut in_flight = crate::sync::mutex(&self.limiter.in_flight);
        if let Some(count) = in_flight.get_mut(&self.source) {
            *count -= 1;
            if *count == 0 {
                in_flight.remove(&self.source);
            }
        }
    }
}

/// Established connection slots are counted by proved client key, not IP.
#[derive(Debug, Default)]
struct PerKeyConnections {
    established: std::sync::Mutex<std::collections::HashMap<Fingerprint, usize>>,
}

struct KeySlot {
    limiter: Arc<PerKeyConnections>,
    fingerprint: Fingerprint,
}

impl PerKeyConnections {
    fn try_acquire(self: &Arc<Self>, fingerprint: Fingerprint) -> Option<KeySlot> {
        let mut established = crate::sync::mutex(&self.established);
        let count = established.entry(fingerprint).or_insert(0);
        if *count >= MAX_CONNECTIONS_PER_KEY {
            return None;
        }
        *count += 1;
        Some(KeySlot {
            limiter: Arc::clone(self),
            fingerprint,
        })
    }
}

impl Drop for KeySlot {
    fn drop(&mut self) {
        let mut established = crate::sync::mutex(&self.limiter.established);
        if let Some(count) = established.get_mut(&self.fingerprint) {
            *count -= 1;
            if *count == 0 {
                established.remove(&self.fingerprint);
            }
        }
    }
}

#[derive(Default)]
struct AdmissionCounters {
    rejected: std::sync::atomic::AtomicU64,
    unauthenticated: std::sync::atomic::AtomicU64,
}

impl AdmissionCounters {
    /// Batch reports independently of incoming traffic, including after a flood stops.
    fn report(&self) {
        use std::sync::atomic::Ordering;

        let rejected = self.rejected.swap(0, Ordering::Relaxed);
        if rejected > 0 {
            eprintln!("qsh-server: refused {rejected} connection(s) over the concurrency limit");
        }
        let failed = self.unauthenticated.swap(0, Ordering::Relaxed);
        if failed > 0 {
            eprintln!("qsh-server: {failed} connection(s) failed to authenticate");
        }
    }
}

struct ReloadDiagnostics {
    warnings: Vec<String>,
    failure: Option<String>,
}

impl ReloadDiagnostics {
    fn reload(&mut self, store: &RwLock<AuthStore>, dir: &std::path::Path) -> Vec<String> {
        let mut warnings = Vec::new();
        match AuthStore::load_with_warnings(dir, |warning| warnings.push(warning)) {
            Ok(fresh) => {
                *crate::sync::write(store) = fresh;
                let mut messages: Vec<_> = warnings
                    .iter()
                    .filter(|warning| !self.warnings.contains(warning))
                    .cloned()
                    .collect();
                self.warnings = warnings;
                if self.failure.take().is_some() {
                    messages.push("qsh-server: authorization reload recovered".into());
                }
                messages
            }
            Err(e) => {
                let failure = format!(
                    "qsh-server: cannot reload authorizations; keeping previous authorizations: {e:#}"
                );
                if self.failure.as_ref() == Some(&failure) {
                    Vec::new()
                } else {
                    self.failure = Some(failure.clone());
                    vec![failure]
                }
            }
        }
    }
}

/// Re-read `authorized/` and report admission counters on a timer.
///
/// Revocation has to reach connections that are already open, and those do not
/// necessarily bring new ones with them: reloading only when someone connects
/// would let a client that keeps one connection, and keeps opening sessions on
/// it, hold the rights it started with for as long as nobody else arrives.
fn spawn_store_refresher(
    store: Arc<RwLock<AuthStore>>,
    dir: std::path::PathBuf,
    warnings: Vec<String>,
    counters: Arc<AdmissionCounters>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut diagnostics = ReloadDiagnostics {
            warnings,
            failure: None,
        };
        let mut ticker = tokio::time::interval(RELOAD_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            counters.report();
            for message in diagnostics.reload(&store, &dir) {
                eprintln!("{message}");
            }
        }
    })
}

/// Seconds since the Unix epoch, saturating rather than failing.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(i64::MAX)
}

/// The public key the handshake proved possession of.
fn peer_key(conn: &quinn::Connection) -> Result<Fingerprint> {
    let identity = conn
        .peer_identity()
        .ok_or_else(|| anyhow!("client presented no certificate"))?;
    let certs = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| anyhow!("unexpected peer identity type"))?;
    let end_entity = certs
        .first()
        .ok_or_else(|| anyhow!("client presented an empty certificate chain"))?;
    Fingerprint::of_cert(end_entity)
}

/// Did the peer get as far as proving who it was?
enum Authenticated {
    Yes,
    No,
    OverLimit,
}

async fn handle_connection(
    incoming: quinn::Incoming,
    store: Arc<RwLock<AuthStore>>,
    per_key: Arc<PerKeyConnections>,
    handshake_permit: (tokio::sync::OwnedSemaphorePermit, SourceSlot),
) -> Result<Authenticated> {
    // An unauthenticated peer must not be able to sit on an admission slot.
    let Ok(handshake) = tokio::time::timeout(HANDSHAKE_GRACE, incoming).await else {
        return Ok(Authenticated::No);
    };
    // Anything up to here is provokable by anyone who can send a packet, so it
    // ends quietly rather than writing a log line per attempt.
    let Ok(conn) = handshake else {
        return Ok(Authenticated::No);
    };
    // The handshake is over; stop occupying that budget.
    drop(handshake_permit);

    let peer = conn.remote_address();
    let Ok(fingerprint) = peer_key(&conn) else {
        return Ok(Authenticated::No);
    };
    let Some(entry) = crate::sync::read(&store).lookup(&fingerprint).cloned() else {
        return Ok(Authenticated::No);
    };
    if entry.meta.is_expired(unix_now()) {
        conn.close(1u32.into(), b"authorization expired");
        return Ok(Authenticated::No);
    }
    let Some(_key_slot) = per_key.try_acquire(fingerprint) else {
        conn.close(1u32.into(), b"key connection limit reached");
        return Ok(Authenticated::OverLimit);
    };
    eprintln!(
        "qsh-server: {peer} authenticated as `{}` (key `{}`)",
        entry.meta.user, entry.name
    );

    let mut policy_tick = tokio::time::interval(RELOAD_INTERVAL);
    policy_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let stream = match tokio::select! {
            _ = policy_tick.tick() => {
                let current = crate::sync::read(&store);
                if current
                    .lookup(&fingerprint)
                    .is_none_or(|entry| entry.meta.is_expired(unix_now()))
                {
                    conn.close(1u32.into(), b"authorization withdrawn or expired");
                    return Ok(Authenticated::Yes);
                }
                continue;
            }
            accepted = conn.accept_bi() => accepted,
        } {
            Ok(s) => s,
            Err(
                quinn::ConnectionError::ApplicationClosed(_)
                | quinn::ConnectionError::ConnectionClosed(_)
                | quinn::ConnectionError::LocallyClosed,
            ) => return Ok(Authenticated::Yes),
            Err(e) => return Err(e).context("accepting a session stream"),
        };
        // Refuse a withdrawn key promptly; handle_session checks again after
        // its request arrives so a pending first frame cannot keep old rights.
        let current = crate::sync::read(&store);
        let allowed = current
            .lookup(&fingerprint)
            .is_some_and(|entry| !entry.meta.is_expired(unix_now()));
        drop(current);
        if !allowed {
            eprintln!("qsh-server: {peer} is no longer authorized; dropping the connection");
            conn.close(1u32.into(), b"authorization withdrawn");
            return Ok(Authenticated::Yes);
        }
        let session_store = Arc::clone(&store);
        let session_conn = conn.clone();
        tokio::spawn(async move {
            let (send, recv) = stream;
            if let Err(e) =
                handle_session(send, recv, session_conn, session_store, fingerprint).await
            {
                eprintln!(
                    "qsh-server: session from {peer} ended: {}",
                    bounded_diagnostic(&e)
                );
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
            if argv
                .first()
                .is_some_and(|program| program.len() > MAX_PROGRAM_LEN)
            {
                bail!("program name is too long");
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
    conn: quinn::Connection,
    store: Arc<RwLock<AuthStore>>,
    fingerprint: Fingerprint,
) -> Result<()> {
    // A stream that never says what it wants must not hold resources open.
    // Only the first frame is on a clock; `control_loop` has to stay
    // deadline-free or an idle interactive shell would be cut off.
    let first = tokio::time::timeout(FIRST_FRAME_GRACE, read_frame(&mut recv))
        .await
        .map_err(|_| anyhow!("client opened a session but sent no request"))?;
    let req = match first? {
        Some(Frame::Request(r)) => r,
        Some(_) => bail!("expected a request frame first"),
        None => return Ok(()),
    };

    let start = (|| -> Result<(Spawned, String, RequestGrant)> {
        let current = crate::sync::read(&store);
        let entry = current
            .lookup(&fingerprint)
            .ok_or_else(|| anyhow!("client authorization was withdrawn"))?;
        authorize_request(entry, &req, unix_now())?;
        let grant = RequestGrant::from_request(&req)?;
        let user = child::resolve_user(&entry.meta.user)?;
        Ok((child::spawn(&user, &req)?, entry.meta.user.clone(), grant))
    })();

    let (spawned, authorized_user, grant) = match start {
        Ok(s) => s,
        Err(e) => {
            // Report the refusal in-band so the client can print it, then end
            // the session with a shell-like "cannot execute" status.
            let _ = write_frame(&mut send, &Frame::Error(bounded_diagnostic(&e))).await;
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

    // Child spawn has consumed the request; keep only the command identity
    // needed to detect a later policy change, not its potentially large argv,
    // environment and terminal metadata for the lifetime of the process.
    drop(req);

    let authorization = LiveAuthorization {
        store,
        fingerprint,
        grant,
        authorized_user,
    };
    run_session(send, recv, conn, authorization, spawned).await
}

/// Diagnostics can contain client-supplied request fields. Keep each message
/// short and single-line for both the server log and the in-band refusal.
fn bounded_diagnostic(error: &anyhow::Error) -> String {
    const MAX_CHARS: usize = 512;
    let mut bounded = String::new();
    for (index, ch) in format!("{error:#}").chars().enumerate() {
        if index == MAX_CHARS {
            bounded.push('…');
            break;
        }
        bounded.push(if ch.is_control() { ' ' } else { ch });
    }
    bounded
}

#[derive(Debug)]
enum RequestGrant {
    Shell,
    Exec(String),
}

struct LiveAuthorization {
    store: Arc<RwLock<AuthStore>>,
    fingerprint: Fingerprint,
    grant: RequestGrant,
    authorized_user: String,
}

impl RequestGrant {
    fn from_request(request: &Request) -> Result<Self> {
        match &request.command {
            None => Ok(Self::Shell),
            Some(argv) => argv
                .first()
                .cloned()
                .map(Self::Exec)
                .ok_or_else(|| anyhow!("empty command")),
        }
    }
}

fn request_still_authorized(auth: &LiveAuthorization) -> bool {
    let current = crate::sync::read(&auth.store);
    current.lookup(&auth.fingerprint).is_some_and(|entry| {
        entry.meta.user == auth.authorized_user
            && !entry.meta.is_expired(unix_now())
            && match &auth.grant {
                RequestGrant::Shell => entry.meta.allow_shell,
                RequestGrant::Exec(program) => {
                    entry.meta.allow_exec
                        && (entry.meta.allowed_commands.is_empty()
                            || entry
                                .meta
                                .allowed_commands
                                .iter()
                                .any(|allowed| allowed == program))
                }
            }
    })
}

/// Kills the remote process group if the session goes away.
///
/// Tokio deliberately leaves a child running when its handle is dropped, so
/// without this a client that is killed — or a server that is shutting down —
/// would leave `sleep 3600` behind forever. The guard fires on every exit path
/// including task cancellation, which is the one path an `async` cleanup step
/// could never cover.
///
/// Its reach is the session's initial process group. PTY job control can put
/// foreground or background work in a different group; `setsid` does likewise.
/// Closing the PTY sends a hangup to its foreground group, but an ignoring
/// process can survive. Full containment requires a session cgroup or a
/// different job-control policy.
struct ProcessGroupGuard {
    pid: Option<u32>,
}

impl ProcessGroupGuard {
    fn new(pid: Option<u32>) -> Self {
        Self { pid }
    }

    /// Stop guarding the group.
    ///
    /// Only correct once the leader has exited *and* its output has drained
    /// to end of file. Nothing left is attached to this session, and reaping
    /// the leader after disarming cannot race a later group signal.
    fn disarm(&mut self) {
        self.pid = None;
    }

    /// Ask the job to go away, escalating if it will not.
    ///
    /// The pid stays in place across both grace periods. Taking it up front
    /// would disarm the guard for the several seconds this spends awaiting,
    /// and a cancellation in that window — daemon shutdown, say — would then
    /// drop the child handle without killing anything, which is precisely the
    /// case a job that ignores `SIGHUP` and `SIGTERM` survives.
    async fn terminate(&mut self) {
        let Some(pid) = self.pid else { return };
        for sig in [libc::SIGHUP, libc::SIGTERM] {
            child::signal_process_group(pid, sig);
            // Keep the leader waitable so its PID cannot be reused. Once it
            // exits, kill any stragglers still in its process group.
            if matches!(
                tokio::time::timeout(TERMINATE_GRACE, wait_for_leader_exit(Some(pid))).await,
                Ok(Ok(()))
            ) {
                child::signal_process_group(pid, libc::SIGKILL);
                self.pid = None;
                return;
            }
        }
        child::signal_process_group(pid, libc::SIGKILL);
        self.pid = None;
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

/// Observe leader exit without reaping it. The reserved PID prevents later
/// group and terminal signals from targeting an unrelated process.
#[allow(
    unsafe_code,
    reason = "waitid with WNOWAIT preserves the child PID until cleanup"
)]
async fn wait_for_leader_exit(pid: Option<u32>) -> Result<()> {
    let pid = pid.ok_or_else(|| anyhow!("remote child has no PID"))?;
    let id = libc::id_t::try_from(pid).context("remote child PID is out of range")?;
    loop {
        // SAFETY: zeroed siginfo_t is the writable output buffer for waitid.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                id,
                &raw mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error()).context("observing remote process exit");
        }
        if unsafe { info.si_pid() } != 0 {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the session lifecycle keeps the unreaped child and signal guard in one owner"
)]
async fn run_session(
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    conn: quinn::Connection,
    authorization: LiveAuthorization,
    spawned: Spawned,
) -> Result<()> {
    let Spawned { mut child, io } = spawned;
    let pid = child.id();
    // Armed before anything that can fail, so no error path can leak the job.
    let mut guard = ProcessGroupGuard::new(pid);

    let (tx, mut rx) = mpsc::channel::<Frame>(64);

    // Single writer for the stream: stdout, stderr and the exit status all
    // funnel through here, so frames never interleave.
    let mut writer = AbortOnDrop(tokio::spawn(async move {
        let mut stream = SessionStream::new(send);
        while let Some(frame) = rx.recv().await {
            if stream.write(&frame).await.is_err() {
                break;
            }
        }
        stream.finish().await;
    }));

    if tx.send(Frame::Started).await.is_err() {
        guard.terminate().await;
        let _ = child.wait().await;
        bail!("client closed the session before it started");
    }

    let mut outputs = Vec::new();
    let stdin_sink: Box<dyn AsyncWrite + Unpin + Send>;
    let pty_fd: Option<OwnedFd>;

    match io {
        ChildIo::Pty(master) => {
            pty_fd = match master.try_clone_fd() {
                Ok(fd) => Some(fd),
                Err(e) => {
                    writer.abort();
                    guard.terminate().await;
                    let _ = child.wait().await;
                    return Err(e).context("duplicating PTY descriptor for resize");
                }
            };
            let (r, w) = tokio::io::split(master);
            stdin_sink = Box::new(w);
            outputs.push(spawn_pump(r, tx.clone(), Frame::Stdout));
        }
        ChildIo::Pipes {
            stdin,
            stdout,
            stderr,
        } => {
            pty_fd = None;
            stdin_sink = Box::new(stdin);
            outputs.push(spawn_pump(stdout, tx.clone(), Frame::Stdout));
            outputs.push(spawn_pump(stderr, tx.clone(), Frame::Stderr));
        }
    }

    // Keep control alive through output drain. Connection closure and policy
    // changes are watched independently, even if control blocks on child stdin.
    let is_pty = pty_fd.is_some();
    let (events_tx, mut events_rx) = mpsc::channel::<ControlEvent>(32);
    let mut control = AbortOnDrop(tokio::spawn(control_loop(
        recv, stdin_sink, is_pty, events_tx,
    )));
    let mut policy_tick = tokio::time::interval(RELOAD_INTERVAL);
    policy_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Observe exit without reaping: a zombie keeps the leader's PID reserved
    // until every possible process-group signal has been sent.
    let leader_exited = loop {
        tokio::select! {
            exited = wait_for_leader_exit(pid) => {
                if let Err(error) = exited {
                    eprintln!("qsh-server: could not observe child exit: {error:#}");
                    break None;
                }
                break Some(());
            }
            _ = &mut control => break None,
            _ = conn.closed() => break None,
            event = events_rx.recv() => {
                if let Some(event) = event {
                    apply_control_event(event, pty_fd.as_ref(), pid);
                } else {
                    break None;
                }
            }
            _ = policy_tick.tick() => {
                if !request_still_authorized(&authorization) {
                    break None;
                }
            }
        }
    };
    if leader_exited.is_none() {
        control.abort();
        let _ = control.await;
        writer.abort();
        let _ = writer.await;
        return abandon(&mut guard, &mut child, outputs).await;
    }

    // The leader is gone, but its descendants may still hold the output open.
    // Drain with disconnect and policy watches still running. Pin the drain
    // future so a timer tick never restarts a partly completed drain.
    let drained = {
        let pending = drain(&mut outputs, is_pty);
        tokio::pin!(pending);
        loop {
            tokio::select! {
                result = &mut pending => break Some(result),
                _ = &mut control => break None,
                _ = conn.closed() => break None,
                event = events_rx.recv() => {
                    if let Some(event) = event {
                        apply_control_event(event, pty_fd.as_ref(), pid);
                    } else {
                        break None;
                    }
                }
                _ = policy_tick.tick() => {
                    if !request_still_authorized(&authorization) {
                        break None;
                    }
                }
            }
        }
    };
    let Some(drained) = drained else {
        control.abort();
        let _ = control.await;
        writer.abort();
        let _ = writer.await;
        return abandon(&mut guard, &mut child, outputs).await;
    };
    control.abort();
    let _ = control.await;

    let exit = match drained {
        Drained::Fully => {
            // Everything the session produced has been delivered, so nothing
            // left in the group is attached to it any more: whatever survives
            // has deliberately detached, and killing it would be wrong.
            guard.disarm();
            let status = child.wait().await.context("reaping the remote process")?;
            ExitStatus {
                code: status.code().unwrap_or(0),
                signal: status.signal(),
            }
        }
        // Never hand back a successful status over a truncated stream: a
        // caller redirecting our stdout to a file would silently keep a short
        // copy and believe it. The job does not get to survive this either —
        // it is still wired to a session that is ending badly.
        Drained::Incomplete(why) => {
            // Deliberately non-blocking. The usual way to get here is a writer
            // stuck on a peer that has stopped reading, and awaiting this send
            // would wait for exactly that blockage to clear.
            let _ = tx.try_send(Frame::Error(format!(
                "the remote output could not be delivered in full: {why}"
            )));
            ExitStatus {
                code: 255,
                signal: None,
            }
        }
    };

    // Kill the job before trying to talk to a peer that may never answer.
    if matches!(drained, Drained::Incomplete(_)) {
        guard.terminate().await;
        let _ = child.wait().await;
    }

    let _ = tokio::time::timeout(SHUTDOWN_GRACE, tx.send(Frame::Exit(exit))).await;
    drop(tx);

    // The writer finishes the stream itself once the channel closes. If it is
    // still stuck on a peer that is not reading, cancel it and wait for that
    // to take effect: dropping the handle would detach a task that still owns
    // the stream, and quinn treats a dropped `SendStream` as a graceful finish
    // that goes on retransmitting. `SessionStream` resets it on the way out
    // instead, which is the honest ending for a session nobody is listening to.
    if tokio::time::timeout(SHUTDOWN_GRACE, &mut writer)
        .await
        .is_err()
    {
        writer.abort();
        let _ = writer.await;
    }
    Ok(())
}

/// The client is gone: kill the job, reap it, and stop.
///
/// There is nobody left to send an exit status to, so this is not an error.
async fn abandon(
    guard: &mut ProcessGroupGuard,
    child: &mut tokio::process::Child,
    outputs: Vec<Pump>,
) -> Result<()> {
    for pump in &outputs {
        pump.task.abort();
    }
    // Reap only after the last signal; otherwise this PID can be recycled
    // while a descendant still holds output or the guard is escalating.
    guard.terminate().await;
    let _ = child.wait().await;
    Ok(())
}

/// Did every byte of the child's output make it onto the wire?
enum Drained {
    Fully,
    Incomplete(&'static str),
}

/// Collect the output pumps once the remote process has exited.
///
/// A pipe is drained without a deadline: the kernel reports EOF when its last
/// writer closes it, so waiting is exactly as long as there is still output to
/// deliver, and cutting that short on a timer is what turned a slow reader
/// into a truncated file with a successful exit status.
///
/// A PTY gets a deadline, because it has no last-writer guarantee — a job
/// backgrounded from an interactive shell holds the slave open indefinitely.
/// The pump reports whether cutoff discarded a chunk already read from the
/// PTY. A pending send means output is lost, even when the client is reading
/// steadily; it does not by itself establish that the client stopped reading.
/// This preserves the existing bounded drain policy and its incomplete-output
/// status while making cancellation outcomes explicit.
///
/// The handles stay borrowed so that a cancelled drain leaves them intact for
/// the caller to abort.
async fn drain(tasks: &mut [Pump], is_pty: bool) -> Drained {
    let mut result = Drained::Fully;
    for pump in tasks.iter_mut() {
        let end = if is_pty {
            if let Ok(joined) = tokio::time::timeout(DRAIN_GRACE, &mut pump.task).await {
                joined.unwrap_or(PumpEnd::Failed)
            } else {
                if let Some(cancel) = pump.cancel.take() {
                    let _ = cancel.send(());
                }
                (&mut pump.task).await.unwrap_or(PumpEnd::Failed)
            }
        } else {
            (&mut pump.task).await.unwrap_or(PumpEnd::Failed)
        };
        match end {
            PumpEnd::Eof | PumpEnd::CutoffIdle => {}
            PumpEnd::ReadError => result = Drained::Incomplete("read error"),
            PumpEnd::ClientGone => result = Drained::Incomplete("client stopped reading"),
            PumpEnd::CutoffPending => {
                result = Drained::Incomplete("output remained buffered at the PTY drain deadline");
            }
            PumpEnd::Failed => result = Drained::Incomplete("output task failed"),
        }
    }
    result
}

/// How an output pump finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PumpEnd {
    /// The stream reached a real end of file; everything was forwarded.
    Eof,
    /// Reading the child's output failed part way through.
    ReadError,
    /// Nobody is left to receive the frames.
    ClientGone,
    /// The PTY drain deadline arrived while waiting for more output.
    CutoffIdle,
    /// The PTY drain deadline arrived with a chunk still awaiting delivery.
    CutoffPending,
    /// The forwarding task itself did not finish.
    Failed,
}

/// The session's send stream, which is never simply dropped.
///
/// A `SendStream` that goes out of scope is *finished* by quinn, which keeps
/// retransmitting whatever is buffered. That is the wrong ending for a session
/// being abandoned because the peer stopped reading: the point is to stop.
/// This resets it instead, unless it was finished deliberately.
struct SessionStream {
    send: Option<quinn::SendStream>,
}

impl SessionStream {
    fn new(send: quinn::SendStream) -> Self {
        Self { send: Some(send) }
    }

    async fn write(&mut self, frame: &Frame) -> std::io::Result<()> {
        match self.send.as_mut() {
            Some(send) => write_frame(send, frame).await,
            None => Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)),
        }
    }

    /// End the stream properly and wait for the peer to acknowledge it.
    ///
    /// The stream stays inside the guard across every await here, and the
    /// guard is disarmed only once the peer has acknowledged the whole thing.
    /// Taking it out first would mean a cancellation during `flush` or
    /// `stopped` — the caller bounds both with a timeout — dropped a bare
    /// `SendStream`, which quinn implicitly *finishes* and goes on
    /// retransmitting: precisely the ending this type exists to remove. quinn
    /// allows `reset` after `finish`, abandoning whatever is still buffered,
    /// so staying armed through all of this costs nothing and an error on any
    /// step leaves it armed on purpose.
    async fn finish(&mut self) {
        let Some(send) = self.send.as_mut() else {
            return;
        };
        if send.flush().await.is_err() {
            return;
        }
        if send.finish().is_err() {
            return;
        }
        if send.stopped().await.is_err() {
            return;
        }
        // Acknowledged in full; there is nothing left to reset.
        self.send = None;
    }
}

impl Drop for SessionStream {
    fn drop(&mut self) {
        if let Some(mut send) = self.send.take() {
            let _ = send.reset(RESET_ABANDONED.into());
        }
    }
}

/// One output stream being forwarded, with a cooperative drain cutoff.
struct Pump {
    task: AbortOnDrop<PumpEnd>,
    cancel: Option<tokio::sync::oneshot::Sender<()>>,
}

/// Spawned session tasks must stop when their parent is canceled. A bare
/// `JoinHandle` detaches on drop and could keep I/O alive after cleanup.
#[derive(Debug)]
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> AbortOnDrop<T> {
    fn abort(&self) {
        self.0.abort();
    }
}

impl<T> Future for AbortOnDrop<T> {
    type Output = std::result::Result<T, tokio::task::JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Start forwarding one output stream of the child into frames.
fn spawn_pump<R: AsyncRead + Unpin + Send + 'static>(
    src: R,
    tx: mpsc::Sender<Frame>,
    wrap: fn(Vec<u8>) -> Frame,
) -> Pump {
    let (cancel, cancelled) = tokio::sync::oneshot::channel();
    Pump {
        task: AbortOnDrop(tokio::spawn(pump(src, tx, wrap, cancelled))),
        cancel: Some(cancel),
    }
}

async fn pump<R: AsyncRead + Unpin>(
    mut src: R,
    tx: mpsc::Sender<Frame>,
    wrap: fn(Vec<u8>) -> Frame,
    mut cancelled: tokio::sync::oneshot::Receiver<()>,
) -> PumpEnd {
    let mut buf = vec![0u8; CHUNK];
    loop {
        // `read` is cancel-safe. Only this branch can stop without owing a chunk.
        let read = tokio::select! {
            biased;
            _ = &mut cancelled => return PumpEnd::CutoffIdle,
            read = src.read(&mut buf) => read,
        };
        match read {
            Ok(0) => return PumpEnd::Eof,
            Err(_) => return PumpEnd::ReadError,
            Ok(n) => {
                let Some(chunk) = buf.get(..n) else {
                    return PumpEnd::ReadError;
                };
                // Cancelling a pending send discards this chunk, so the pump
                // itself reports incomplete output. No shared flag or task
                // cancellation timing is needed to reconstruct that fact.
                let sent = tokio::select! {
                    biased;
                    _ = &mut cancelled => return PumpEnd::CutoffPending,
                    sent = tx.send(wrap(chunk.to_vec())) => sent,
                };
                if sent.is_err() {
                    return PumpEnd::ClientGone;
                }
            }
        }
    }
}

/// Handle everything the client sends after the request.
#[derive(Debug, Clone, Copy)]
enum ControlEvent {
    Resize(PtySize),
    Signal(i32),
}

fn apply_control_event(event: ControlEvent, pty_fd: Option<&OwnedFd>, pid: Option<u32>) {
    match event {
        ControlEvent::Resize(size) => resize(pty_fd, pid, size),
        ControlEvent::Signal(sig) => {
            if let Some(pid) = pid {
                child::signal_process_group(pid, sig);
            }
        }
    }
}

async fn control_loop(
    mut recv: quinn::RecvStream,
    stdin_sink: Box<dyn AsyncWrite + Unpin + Send>,
    is_pty: bool,
    events: mpsc::Sender<ControlEvent>,
) {
    let mut stdin_sink = Some(stdin_sink);
    loop {
        match read_frame(&mut recv).await {
            Ok(Some(Frame::Stdin(data))) => {
                if let Some(sink) = stdin_sink.as_mut() {
                    if !write_stdin_or_peer_closed(&mut recv, sink.as_mut(), &data).await {
                        break;
                    }
                }
            }
            Ok(Some(Frame::StdinEof)) => {
                if is_pty {
                    // A terminal has no "close one end": dropping our write
                    // half would leave the read half owning the same master,
                    // so the child would never see EOF.
                    //
                    // Two EOTs, not one. In canonical mode `^D` makes the
                    // pending input readable, and only yields a zero-length
                    // read — the actual end of file — when the queue is
                    // already empty. Input that does not end in a newline
                    // therefore consumes the first one just to flush the last
                    // partial line, and `printf hello | qsh -t host cat`
                    // would hang waiting for a second. Sending both is
                    // harmless when the queue was already empty: the reader
                    // has stopped by then.
                    if let Some(sink) = stdin_sink.as_mut() {
                        if !write_stdin_or_peer_closed(&mut recv, sink.as_mut(), &[EOT, EOT]).await
                        {
                            break;
                        }
                        tokio::select! {
                            _ = recv.received_reset() => break,
                            result = sink.flush() => {
                                if result.is_err() { break; }
                            }
                        }
                    }
                } else {
                    // Dropping the writer closes the pipe, which the child
                    // sees as EOF.
                    stdin_sink = None;
                }
            }
            Ok(Some(Frame::Resize(size))) => {
                if events.send(ControlEvent::Resize(size)).await.is_err() {
                    break;
                }
            }
            Ok(Some(Frame::Signal(name))) => {
                if let Some(sig) = signal_number(&name) {
                    if events.send(ControlEvent::Signal(sig)).await.is_err() {
                        break;
                    }
                }
            }
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
        }
    }
}

/// Child stdin can block forever when the program stops reading. A peer reset
/// or FIN must still end the control task so the session guard can clean up.
async fn write_stdin_or_peer_closed(
    recv: &mut quinn::RecvStream,
    sink: &mut (dyn AsyncWrite + Unpin + Send),
    data: &[u8],
) -> bool {
    tokio::select! {
        _ = recv.received_reset() => false,
        result = sink.write_all(data) => result.is_ok(),
    }
}

fn resize(pty_fd: Option<&OwnedFd>, pid: Option<u32>, size: PtySize) {
    let Some(fd) = pty_fd else { return };
    if pty::set_size(fd.as_raw_fd(), size).is_ok() {
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

    use std::os::unix::process::CommandExt as _;

    fn entry(meta: AuthMeta) -> AuthEntry {
        let (pem, _) = crypto::generate_identity("t", &["t".into()], 30).unwrap();
        AuthEntry {
            name: "test".into(),
            fingerprint: Fingerprint::of_cert(&crypto::cert_from_pem(&pem).unwrap()).unwrap(),
            meta,
        }
    }

    #[test]
    fn per_key_connection_limit_preserves_other_keys_and_releases_slots() {
        let limiter = Arc::new(PerKeyConnections::default());
        let first = entry(AuthMeta::default()).fingerprint;
        let second = entry(AuthMeta::default()).fingerprint;
        let mut held = (0..MAX_CONNECTIONS_PER_KEY)
            .map(|_| limiter.try_acquire(first).unwrap())
            .collect::<Vec<_>>();
        assert!(limiter.try_acquire(first).is_none());
        assert!(limiter.try_acquire(second).is_some());
        held.pop();
        assert!(limiter.try_acquire(first).is_some());
    }

    #[tokio::test]
    async fn observing_leader_exit_keeps_it_waitable() {
        let mut child = tokio::process::Command::new("sh")
            .args(["-c", "exit 7"])
            .spawn()
            .unwrap();
        let pid = child.id();
        tokio::time::timeout(Duration::from_secs(5), wait_for_leader_exit(pid))
            .await
            .unwrap()
            .unwrap();
        // WNOWAIT reports the same completed child again: it was not reaped.
        wait_for_leader_exit(pid).await.unwrap();
        assert_eq!(child.wait().await.unwrap().code(), Some(7));
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
    fn reload_warnings_follow_entry_changes_and_recover_from_errors() {
        let dir = tempfile::tempdir().unwrap();
        let authorized = dir.path().join("authorized");
        std::fs::create_dir(&authorized).unwrap();
        let cert = authorized.join("client.crt");
        std::fs::write(&cert, "broken certificate").unwrap();
        let store = RwLock::new(AuthStore::default());
        let mut diagnostics = ReloadDiagnostics {
            warnings: Vec::new(),
            failure: None,
        };

        let first = diagnostics.reload(&store, &authorized);
        assert_eq!(first.len(), 1);
        assert!(first[0].contains("ignoring authorization"));
        assert!(diagnostics.reload(&store, &authorized).is_empty());
        std::fs::remove_file(&cert).unwrap();
        assert!(diagnostics.reload(&store, &authorized).is_empty());
        std::fs::write(&cert, "broken certificate").unwrap();
        assert_eq!(diagnostics.reload(&store, &authorized), first);

        // A file cannot be listed as an authorization directory, even as root.
        let saved = dir.path().join("saved");
        std::fs::rename(&authorized, &saved).unwrap();
        std::fs::write(&authorized, "not a directory").unwrap();
        let failure = diagnostics.reload(&store, &authorized);
        assert_eq!(failure.len(), 1);
        assert!(failure[0].contains("keeping previous authorizations"));
        assert!(diagnostics.reload(&store, &authorized).is_empty());
        std::fs::remove_file(&authorized).unwrap();
        std::fs::rename(saved, &authorized).unwrap();
        assert_eq!(
            diagnostics.reload(&store, &authorized),
            ["qsh-server: authorization reload recovered"]
        );
        assert!(diagnostics.reload(&store, &authorized).is_empty());
    }

    #[tokio::test]
    async fn rejection_counts_are_reported_without_another_connection() {
        use std::sync::atomic::Ordering;

        let dir = tempfile::tempdir().unwrap();
        let counters = Arc::new(AdmissionCounters::default());
        let refresher = spawn_store_refresher(
            Arc::new(RwLock::new(AuthStore::default())),
            dir.path().to_owned(),
            Vec::new(),
            Arc::clone(&counters),
        );
        counters.rejected.store(12, Ordering::Relaxed);
        counters.unauthenticated.store(3, Ordering::Relaxed);
        tokio::time::timeout(Duration::from_secs(5), async {
            while counters.rejected.load(Ordering::Relaxed) != 0
                || counters.unauthenticated.load(Ordering::Relaxed) != 0
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("timer did not report the counters without traffic");
        refresher.abort();
        let _ = refresher.await;
    }

    #[test]
    fn shell_can_be_forbidden_while_exec_is_allowed() {
        let e = entry(AuthMeta {
            user: "alice".into(),
            allow_shell: false,
            allow_exec: true,
            allowed_commands: vec!["rsync".into()],
            key_fingerprint: None,
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
            key_fingerprint: None,
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

    /// Start a job that ignores the polite signals, in its own process group.
    ///
    /// It blocks on a shell builtin rather than on `sleep`, so the group has
    /// exactly one member: a grandchild would be reparented to init on death,
    /// and whether init reaps it promptly is not something a test can rely on.
    async fn stubborn_job() -> (tokio::process::Child, u32, tokio::process::ChildStdin) {
        let mut cmd = tokio::process::Command::new("sh");
        // It announces itself once the traps are installed, so the test can
        // wait for that rather than guessing at a sleep that a loaded machine
        // would outrun.
        cmd.arg("-c")
            .arg("trap '' HUP TERM; echo ready; read line")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());
        // SAFETY: setsid is async-signal-safe; mirrors what child::spawn does.
        #[allow(unsafe_code, reason = "the test needs its own process group")]
        unsafe {
            cmd.as_std_mut().pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().unwrap();
        let pid = child.id().unwrap();
        // The caller keeps stdin open, which is what keeps the shell blocked.
        let stdin = child.stdin.take().unwrap();

        let mut stdout = child.stdout.take().unwrap();
        let mut ready = [0u8; 6];
        tokio::time::timeout(Duration::from_secs(10), stdout.read_exact(&mut ready))
            .await
            .expect("the test job never started")
            .expect("the test job never reported readiness");
        (child, pid, stdin)
    }

    #[tokio::test]
    async fn a_cancelled_terminate_still_kills_the_group() {
        let (mut child, pid, _stdin) = stubborn_job().await;
        assert!(child::process_group_alive(pid));

        // Cancel the guard mid-escalation, exactly as a daemon shutdown would.
        let task = tokio::spawn(async move {
            ProcessGroupGuard::new(Some(pid)).terminate().await;
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        task.abort();
        let _ = task.await;

        // `Drop` must have delivered SIGKILL even though the escalation never
        // finished, because the guard stayed armed across the awaits.
        tokio::time::timeout(Duration::from_secs(5), wait_for_leader_exit(Some(pid)))
            .await
            .expect("a job ignoring HUP and TERM survived a cancelled terminate")
            .unwrap();
        let _ = child.wait().await;
        assert!(!child::process_group_alive(pid));
    }

    #[tokio::test]
    async fn terminate_escalates_to_kill_when_signals_are_ignored() {
        let (mut child, pid, _stdin) = stubborn_job().await;
        let mut guard = ProcessGroupGuard::new(Some(pid));
        let started = tokio::time::Instant::now();
        guard.terminate().await;
        let _ = child.wait().await;
        assert!(!child::process_group_alive(pid));
        // It should have taken both grace periods to get there.
        assert!(started.elapsed() >= TERMINATE_GRACE);
    }

    #[tokio::test]
    async fn terminate_returns_promptly_for_a_job_that_takes_the_hint() {
        // Observing without reaping lets termination return promptly while
        // reserving the PID through its final group signal.
        let mut cmd = tokio::process::Command::new("sleep");
        cmd.arg("60");
        // SAFETY: setsid is async-signal-safe; mirrors what child::spawn does.
        #[allow(unsafe_code, reason = "the test needs its own process group")]
        unsafe {
            cmd.as_std_mut().pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().unwrap();
        let pid = child.id().unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        let mut guard = ProcessGroupGuard::new(Some(pid));
        let started = tokio::time::Instant::now();
        guard.terminate().await;
        let _ = child.wait().await;
        let elapsed = started.elapsed();

        assert!(!child::process_group_alive(pid));
        assert!(
            elapsed < TERMINATE_GRACE,
            "SIGHUP should have been enough, but termination took {elapsed:?}"
        );
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

    #[tokio::test]
    async fn pump_cutoff_reports_idle_read_without_losing_queued_output() {
        let (mut source, reader) = tokio::io::duplex(64);
        let (tx, mut rx) = mpsc::channel(1);
        let mut pump = spawn_pump(reader, tx, Frame::Stdout);
        source.write_all(b"hello").await.unwrap();
        assert!(matches!(rx.recv().await, Some(Frame::Stdout(data)) if data == b"hello"));
        pump.cancel.take().unwrap().send(()).unwrap();
        assert_eq!(pump.task.await.unwrap(), PumpEnd::CutoffIdle);
    }

    #[tokio::test]
    async fn pump_cutoff_reports_a_chunk_parked_on_a_full_channel() {
        let (mut source, reader) = tokio::io::duplex(1);
        let (tx, _rx) = mpsc::channel(1);
        tx.send(Frame::Started).await.unwrap();
        let mut pump = spawn_pump(reader, tx, Frame::Stdout);
        // With a one-byte pipe, writing the second byte proves the pump read
        // the first and reached its send to the already-full channel.
        source.write_all(b"ab").await.unwrap();
        pump.cancel.take().unwrap().send(()).unwrap();
        assert_eq!(pump.task.await.unwrap(), PumpEnd::CutoffPending);
    }

    #[tokio::test]
    async fn pump_preserves_eof_and_receiver_loss_results() {
        let (tx, _rx) = mpsc::channel(1);
        let pump = spawn_pump(tokio::io::empty(), tx, Frame::Stdout);
        assert_eq!(pump.task.await.unwrap(), PumpEnd::Eof);

        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let pump = spawn_pump(&b"output"[..], tx, Frame::Stdout);
        assert_eq!(pump.task.await.unwrap(), PumpEnd::ClientGone);
    }

    #[test]
    fn a_source_cannot_take_more_than_its_share_of_handshakes() {
        let limiter = Arc::new(PerSourceHandshakes::default());
        let one: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        let two: std::net::IpAddr = "203.0.113.8".parse().unwrap();

        let held: Vec<_> = (0..MAX_HANDSHAKES_PER_SOURCE)
            .map(|_| limiter.try_acquire(one).expect("within the per-source cap"))
            .collect();
        assert!(
            limiter.try_acquire(one).is_none(),
            "one address got past its cap"
        );
        // Which is the whole point: the next address is unaffected.
        let other = limiter.try_acquire(two).expect("a different source");

        drop(held);
        assert!(
            limiter.try_acquire(one).is_some(),
            "slots were not released when the handshakes ended"
        );
        drop(other);
        // Nothing is remembered once the attempts are over, so there is no
        // table to grow and nothing to expire.
        assert!(crate::sync::mutex(&limiter.in_flight).is_empty());
    }
}
