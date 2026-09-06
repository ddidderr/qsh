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

    let refresher = spawn_store_refresher(Arc::clone(&store), paths.authorized());

    // Everything below runs before any client has authenticated, so all of it
    // has to be bounded.
    let unauthenticated = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let connections = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let handshakes = Arc::new(tokio::sync::Semaphore::new(MAX_HANDSHAKES));
    let per_source = Arc::new(PerSourceHandshakes::default());
    let mut rejected: u64 = 0;
    let mut last_reload = tokio::time::Instant::now();

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
            rejected = rejected.saturating_add(1);
            incoming.ignore();
            continue;
        };

        // Report in batches on a timer. Logging one line per attempt would let
        // anyone who can send a packet flood the log, since this runs before
        // the handshake has authenticated anybody.
        if last_reload.elapsed() >= RELOAD_INTERVAL {
            last_reload = tokio::time::Instant::now();
            // Report refusals on this already-throttled tick rather than once
            // per attempt, so a flood cannot also flood the log.
            if rejected > 0 {
                eprintln!(
                    "qsh-server: refused {rejected} connection(s) over the concurrency limit"
                );
                rejected = 0;
            }
            let failed = unauthenticated.swap(0, std::sync::atomic::Ordering::Relaxed);
            if failed > 0 {
                eprintln!("qsh-server: {failed} connection(s) failed to authenticate");
            }
        }

        let store = Arc::clone(&store);
        let failures = Arc::clone(&unauthenticated);
        tokio::spawn(async move {
            // The permit lives as long as the connection does.
            let _permit = permit;
            match handle_connection(incoming, store, (handshake_permit, source_slot)).await {
                // Only reachable once a client has authenticated; anyone can
                // provoke the failures before that, so they are counted and
                // reported in batches instead of logged one per attempt.
                Err(e) => eprintln!("qsh-server: {e:#}"),
                Ok(Authenticated::No) => {
                    failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                Ok(Authenticated::Yes) => {}
            }
        });
    }
    refresher.abort();
    Ok(())
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

/// Re-read `authorized/` on a timer.
///
/// Revocation has to reach connections that are already open, and those do not
/// necessarily bring new ones with them: reloading only when someone connects
/// would let a client that keeps one connection, and keeps opening sessions on
/// it, hold the rights it started with for as long as nobody else arrives.
fn spawn_store_refresher(
    store: Arc<RwLock<AuthStore>>,
    dir: std::path::PathBuf,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(RELOAD_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if let Ok(fresh) = AuthStore::load(&dir) {
                *crate::sync::write(&store) = fresh;
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
}

async fn handle_connection(
    incoming: quinn::Incoming,
    store: Arc<RwLock<AuthStore>>,
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
            ) => return Ok(Authenticated::Yes),
            Err(e) => return Err(e).context("accepting a session stream"),
        };
        // Re-resolve the policy for every session rather than reusing the one
        // captured at handshake time. Otherwise a long-lived connection would
        // keep the rights it started with, and `revoke` would not reach it.
        let Some(entry) = crate::sync::read(&store).lookup(&fingerprint).cloned() else {
            eprintln!("qsh-server: {peer} is no longer authorized; dropping the connection");
            conn.close(1u32.into(), b"authorization withdrawn");
            return Ok(Authenticated::Yes);
        };
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
    // A stream that never says what it wants must not hold resources open.
    // Only the first frame is on a clock; `control_loop` has to stay
    // deadline-free or an idle interactive shell would be cut off.
    let first = tokio::time::timeout(FIRST_FRAME_GRACE, read_frame(&mut recv))
        .await
        .map_err(|_| anyhow!("client opened a session but sent no request"))?;
    let req = match first? {
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
///
/// Its reach is the session's process group and no further. A job the user
/// backgrounded with `&` in an interactive shell is in a group of its own —
/// that is what job control does — and so are `setsid` and `nohup` children;
/// none of them are signalled here. That matches ssh, and it is the behaviour
/// people rely on to leave work running after logging out. Killing them anyway
/// would need the session in its own cgroup, which is a bigger and more
/// intrusive design than this tool wants.
struct ProcessGroupGuard {
    pid: Option<u32>,
}

impl ProcessGroupGuard {
    fn new(pid: Option<u32>) -> Self {
        Self { pid }
    }

    /// Stop guarding the group.
    ///
    /// Only correct once the leader has been reaped *and* its output drained
    /// to end of file: at that point nothing in the group still holds our
    /// stdio, so whatever is left has deliberately detached — a `nohup`ed
    /// daemon — and killing it would be wrong. Every other exit path must go
    /// through `terminate` instead.
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
            // Anything that is going to exit on a hangup does so promptly.
            if tokio::time::timeout(TERMINATE_GRACE, wait_for_exit(pid))
                .await
                .is_ok()
            {
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

/// Poll until the process group has no members left.
///
/// The caller must be reaping the leader concurrently: an exited but unreaped
/// child is a zombie, and a zombie still answers `kill(pid, 0)`, so without a
/// concurrent `wait` this can never observe the group going away.
async fn wait_for_exit(pid: u32) {
    loop {
        if !child::process_group_alive(pid) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn run_session(
    send: quinn::SendStream,
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
    let mut writer = tokio::spawn(async move {
        let mut stream = SessionStream::new(send);
        while let Some(frame) = rx.recv().await {
            if stream.write(&frame).await.is_err() {
                break;
            }
        }
        stream.finish().await;
    });

    if tx.send(Frame::Started).await.is_err() {
        // Reap while terminating: the escalation watches for the group to go
        // away, and a zombie would keep it looking alive.
        let ((), _) = tokio::join!(guard.terminate(), child.wait());
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

    // `control` is the only thing watching for the client going away, so it
    // has to stay alive right up to the end of the session — including
    // through the drain below, which can take arbitrarily long.
    let mut control = tokio::spawn(control_loop(recv, stdin_sink, pid, pty_fd));

    // Race the process against the client. Waiting only on the child would
    // let a killed client strand a `sleep` here forever.
    let status = tokio::select! {
        status = child.wait() => Some(status.context("waiting for the remote process")?),
        _ = &mut control => None,
    };
    let Some(status) = status else {
        return abandon(&mut guard, &mut child, outputs).await;
    };

    // The leader is gone, but its descendants may still hold the output open.
    // Drain with the disconnect watch still running, so a client that dies
    // mid-drain takes the whole job down with it.
    let drained = tokio::select! {
        drained = drain(&mut outputs, pty_fd.is_some()) => drained,
        _ = &mut control => return abandon(&mut guard, &mut child, outputs).await,
    };
    control.abort();

    let exit = match drained {
        Drained::Fully => {
            // Everything the session produced has been delivered, so nothing
            // left in the group is attached to it any more: whatever survives
            // has deliberately detached, and killing it would be wrong.
            guard.disarm();
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
        let ((), _) = tokio::join!(guard.terminate(), child.wait());
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
    // Reaping has to run alongside the escalation, not after it: until the
    // leader is reaped it lingers as a zombie, which still answers
    // `kill(pid, 0)`, and the polite signals would look like they had no
    // effect.
    let ((), _) = tokio::join!(guard.terminate(), child.wait());
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
/// Which of the two things a timeout means is decided by whether frames are
/// still backed up: an empty channel means everything read has been handed to
/// the writer and the pump is simply parked on a terminal nobody is using any
/// more, while a full one means the client is not keeping up and output really
/// would be lost.
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
                // Order matters here. `abort` only *requests* cancellation, so
                // reading the flag first would be sampling a pump that is
                // still running and can still pick up a chunk — an await that
                // is immediately ready does not have to yield. Awaiting the
                // handle is what establishes that the task has stopped; only
                // then is anything about it a settled fact.
                pump.task.abort();
                let joined = (&mut pump.task).await;
                cutoff(
                    joined,
                    pump.holding.load(std::sync::atomic::Ordering::Acquire),
                )
            }
        } else {
            (&mut pump.task).await.unwrap_or(PumpEnd::Failed)
        };
        match end {
            PumpEnd::Eof => {}
            PumpEnd::ReadError => result = Drained::Incomplete("read error"),
            PumpEnd::ClientGone => result = Drained::Incomplete("client stopped reading"),
            PumpEnd::Failed => result = Drained::Incomplete("output task failed"),
        }
    }
    result
}

/// Decide what a pump's ending means once the drain deadline has passed.
///
/// `abort` is a request, not a result: Tokio is explicit that an aborted task
/// may have completed anyway, in which case the handle still yields its value.
/// That value is the truth and has to win. A pump that returned `ReadError` or
/// `ClientGone` in the gap between the deadline expiring and the abort landing
/// has already cleared `holding` on its way out, so deciding from the flag
/// would read a failed transfer as a clean end of file — and forward the
/// child's successful status over it, which is the whole thing this path
/// exists to prevent.
///
/// The flag only means anything for a task that really was cancelled, because
/// only then is there no return value to ask.
fn cutoff(joined: std::result::Result<PumpEnd, tokio::task::JoinError>, holding: bool) -> PumpEnd {
    match joined {
        Ok(end) => end,
        Err(e) if e.is_panic() => PumpEnd::Failed,
        // Cancelled mid-handover: that chunk is gone.
        Err(_) if holding => PumpEnd::ClientGone,
        // Cancelled parked on the read, owing nothing. Whatever it did send is
        // already queued ahead of the exit status.
        Err(_) => PumpEnd::Eof,
    }
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

/// One output stream being forwarded, and whether it is mid-handover.
struct Pump {
    task: tokio::task::JoinHandle<PumpEnd>,
    /// True exactly while the pump holds a chunk it has read but not yet
    /// passed on. Only these two states exist at an await point, so aborting
    /// while it is false cannot lose data.
    holding: Arc<std::sync::atomic::AtomicBool>,
}

/// Start forwarding one output stream of the child into frames.
fn spawn_pump<R: AsyncRead + Unpin + Send + 'static>(
    src: R,
    tx: mpsc::Sender<Frame>,
    wrap: fn(Vec<u8>) -> Frame,
) -> Pump {
    let holding = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&holding);
    Pump {
        task: tokio::spawn(pump(src, tx, wrap, flag)),
        holding,
    }
}

async fn pump<R: AsyncRead + Unpin>(
    mut src: R,
    tx: mpsc::Sender<Frame>,
    wrap: fn(Vec<u8>) -> Frame,
    holding: Arc<std::sync::atomic::AtomicBool>,
) -> PumpEnd {
    use std::sync::atomic::Ordering;

    let mut buf = vec![0u8; CHUNK];
    loop {
        match src.read(&mut buf).await {
            Ok(0) => return PumpEnd::Eof,
            Err(_) => return PumpEnd::ReadError,
            Ok(n) => {
                let Some(chunk) = buf.get(..n) else {
                    return PumpEnd::ReadError;
                };
                // Set before the next await and cleared after it, with no
                // await point in between, so an observer that finds it false
                // knows the pump is parked on the read and owes nothing.
                holding.store(true, Ordering::Release);
                // `send` awaits when the channel is full, which is the
                // back-pressure that stops a slow client ballooning memory.
                let sent = tx.send(wrap(chunk.to_vec())).await;
                holding.store(false, Ordering::Release);
                if sent.is_err() {
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
                        let _ = sink.write_all(&[EOT, EOT]).await;
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

    use std::os::unix::process::CommandExt as _;

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
        let reaper = tokio::spawn(async move { child.wait().await });

        // Cancel the guard mid-escalation, exactly as a daemon shutdown would.
        let task = tokio::spawn(async move {
            ProcessGroupGuard::new(Some(pid)).terminate().await;
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        task.abort();
        let _ = task.await;

        // `Drop` must have delivered SIGKILL even though the escalation never
        // finished, because the guard stayed armed across the awaits.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while child::process_group_alive(pid) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "a job ignoring HUP and TERM survived a cancelled terminate"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let _ = reaper.await;
    }

    #[tokio::test]
    async fn terminate_escalates_to_kill_when_signals_are_ignored() {
        let (mut child, pid, _stdin) = stubborn_job().await;
        let mut guard = ProcessGroupGuard::new(Some(pid));
        let started = tokio::time::Instant::now();
        let ((), _) = tokio::join!(guard.terminate(), child.wait());
        assert!(!child::process_group_alive(pid));
        // It should have taken both grace periods to get there.
        assert!(started.elapsed() >= TERMINATE_GRACE);
    }

    #[tokio::test]
    async fn terminate_returns_promptly_for_a_job_that_takes_the_hint() {
        // Without a concurrent reap this would sit through both grace periods
        // even for a job that died instantly, because the unreaped leader is a
        // zombie and a zombie still answers `kill(pid, 0)`.
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
        let ((), _) = tokio::join!(guard.terminate(), child.wait());
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

    /// A `JoinError` of the cancelled kind, which cannot be constructed
    /// directly.
    async fn cancelled_join_error() -> tokio::task::JoinError {
        let task = tokio::spawn(std::future::pending::<PumpEnd>());
        task.abort();
        task.await.unwrap_err()
    }

    #[tokio::test]
    async fn a_pump_that_finished_keeps_its_verdict_past_the_cutoff() {
        // The race this guards: the drain deadline expires, and the pump
        // finishes — with a failure — before the abort lands. Tokio then hands
        // back the value rather than a cancellation, and the pump has already
        // cleared `holding` on its way out. Deciding from the flag would call
        // that a clean end of file and forward the child's exit status over a
        // transfer that failed.
        let mut task = tokio::spawn(async { PumpEnd::ReadError });
        // Let it run to completion, then abort anyway, exactly as `drain` does.
        tokio::time::sleep(Duration::from_millis(50)).await;
        task.abort();
        let joined = (&mut task).await;
        assert_eq!(
            joined.as_ref().ok(),
            Some(&PumpEnd::ReadError),
            "aborting a finished task should still yield its value"
        );
        assert_eq!(cutoff(joined, false), PumpEnd::ReadError);

        // Same for the other failure a pump can return on its own.
        let mut task = tokio::spawn(async { PumpEnd::ClientGone });
        tokio::time::sleep(Duration::from_millis(50)).await;
        task.abort();
        assert_eq!(cutoff((&mut task).await, false), PumpEnd::ClientGone);
    }

    #[tokio::test]
    async fn the_cutoff_reads_the_flag_only_for_a_real_cancellation() {
        // Genuinely cancelled: the flag is the only evidence there is.
        assert_eq!(
            cutoff(Err(cancelled_join_error().await), true),
            PumpEnd::ClientGone
        );
        assert_eq!(
            cutoff(Err(cancelled_join_error().await), false),
            PumpEnd::Eof
        );

        // A pump that reached the end of its stream is complete even if the
        // deadline expired first — a PTY nobody is writing to any more.
        assert_eq!(cutoff(Ok(PumpEnd::Eof), false), PumpEnd::Eof);

        // A panicking pump is never a clean drain, whatever the flag says.
        let panicked = tokio::spawn(async { panic!("boom") }).await.unwrap_err();
        assert_eq!(cutoff(Err(panicked), false), PumpEnd::Failed);
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
