//! On-disk layout, configuration files and the authorisation store.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::crypto::{load_cert, write_public, Fingerprint};

/// Default UDP port. QUIC is UDP, so this does not collide with sshd.
pub const DEFAULT_PORT: u16 = 2222;

/// Environment variables a client may ask the server to set. Anything else is
/// dropped, so a client cannot smuggle in `LD_PRELOAD` or `PATH`.
pub const ENV_ALLOWLIST: &[&str] = &["TERM", "LANG", "COLORTERM"];

/// Is `name` an environment variable clients are allowed to set?
#[must_use]
pub fn env_allowed(name: &str) -> bool {
    ENV_ALLOWLIST.contains(&name) || name.starts_with("LC_") || name.starts_with("QSH_")
}

/// `~/.config/qsh`, or `$QSH_HOME` when set.
///
/// # Errors
/// Fails if no configuration directory can be determined.
pub fn client_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("QSH_HOME") {
        return Ok(PathBuf::from(dir));
    }
    Ok(dirs::config_dir()
        .ok_or_else(|| anyhow!("cannot determine your config directory; set QSH_HOME"))?
        .join("qsh"))
}

/// `/etc/qsh` when running as root, `~/.config/qsh-server` otherwise, or
/// `$QSH_SERVER_HOME` when set.
///
/// # Errors
/// Fails if no configuration directory can be determined.
pub fn server_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("QSH_SERVER_HOME") {
        return Ok(PathBuf::from(dir));
    }
    if nix::unistd::Uid::effective().is_root() {
        return Ok(PathBuf::from("/etc/qsh"));
    }
    Ok(dirs::config_dir()
        .ok_or_else(|| anyhow!("cannot determine your config directory; set QSH_SERVER_HOME"))?
        .join("qsh-server"))
}

/// Paths inside the client's configuration directory.
#[derive(Debug, Clone)]
pub struct ClientPaths {
    pub dir: PathBuf,
}

impl ClientPaths {
    #[must_use]
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }
    /// Locate the client directory from the environment.
    ///
    /// # Errors
    /// Fails if no configuration directory can be determined.
    pub fn discover() -> Result<Self> {
        Ok(Self::new(client_dir()?))
    }
    #[must_use]
    pub fn cert(&self) -> PathBuf {
        self.dir.join("id.crt")
    }
    #[must_use]
    pub fn key(&self) -> PathBuf {
        self.dir.join("id.key")
    }
    #[must_use]
    pub fn known_hosts(&self) -> PathBuf {
        self.dir.join("known_hosts")
    }
}

/// Paths inside the server's configuration directory.
#[derive(Debug, Clone)]
pub struct ServerPaths {
    pub dir: PathBuf,
}

impl ServerPaths {
    #[must_use]
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }
    /// Locate the server directory from the environment.
    ///
    /// # Errors
    /// Fails if no configuration directory can be determined.
    pub fn discover() -> Result<Self> {
        Ok(Self::new(server_dir()?))
    }
    #[must_use]
    pub fn cert(&self) -> PathBuf {
        self.dir.join("server.crt")
    }
    #[must_use]
    pub fn key(&self) -> PathBuf {
        self.dir.join("server.key")
    }
    #[must_use]
    pub fn config(&self) -> PathBuf {
        self.dir.join("qsh-server.toml")
    }
    #[must_use]
    pub fn authorized(&self) -> PathBuf {
        self.dir.join("authorized")
    }
}

/// `qsh-server.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Address to listen on, e.g. `0.0.0.0:2222` or `[::]:2222`.
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Drop a connection after this many seconds without traffic.
    /// QUIC uses the smaller peer timeout; the qsh client currently caps it at 60 seconds.
    #[serde(default = "default_idle")]
    pub idle_timeout_secs: u64,
    /// Interval at which the server sends QUIC keep-alives.
    #[serde(default = "default_keepalive")]
    pub keepalive_secs: u64,
}

fn default_listen() -> String {
    format!("0.0.0.0:{DEFAULT_PORT}")
}
fn default_idle() -> u64 {
    // Four missed keep-alives. This is also the backstop that reclaims a
    // session whose client was killed outright: a dead peer sends no close
    // frame, so nothing else tells the server the client is gone.
    60
}
fn default_keepalive() -> u64 {
    15
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            idle_timeout_secs: default_idle(),
            keepalive_secs: default_keepalive(),
        }
    }
}

impl ServerConfig {
    /// Read the configuration, falling back to defaults when absent.
    ///
    /// # Errors
    /// Fails if the file exists but cannot be read or parsed.
    pub fn load(path: &Path) -> Result<Self> {
        match Self::load_required(path) {
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                Ok(Self::default())
            }
            result => result,
        }
    }

    /// Read an explicitly selected configuration file without a default fallback.
    ///
    /// # Errors
    /// Fails if the file is missing, cannot be read, or cannot be parsed.
    pub fn load_required(path: &Path) -> Result<Self> {
        let text =
            fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    /// The address to bind.
    ///
    /// # Errors
    /// Fails if `listen` is not a socket address.
    pub fn listen_addr(&self) -> Result<SocketAddr> {
        self.listen
            .parse()
            .with_context(|| format!("`listen` is not a socket address: {}", self.listen))
    }
}

/// Metadata stored next to an authorised client certificate
/// (`authorized/<name>.toml`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthMeta {
    /// Local Unix account this certificate may log in as.
    pub user: String,
    /// May this certificate request an interactive shell?
    #[serde(default = "yes")]
    pub allow_shell: bool,
    /// May this certificate run non-interactive commands?
    #[serde(default = "yes")]
    pub allow_exec: bool,
    /// If non-empty, only these exact `argv[0]` values may be executed.
    /// Arguments and programs spawned by that executable are not inspected;
    /// `allow_shell` is governed separately.
    #[serde(default)]
    pub allowed_commands: Vec<String>,
    /// The public key this policy was written for.
    ///
    /// A certificate and its policy live in two files, so a crash or a reload
    /// landing between the two writes could otherwise pair a new certificate
    /// with a stale, possibly broader policy. Recording the fingerprint lets
    /// the loader detect that and fail closed.
    #[serde(default)]
    pub key_fingerprint: Option<String>,
    /// Unix timestamp after which this authorization stops being accepted.
    ///
    /// This is the administrator's deadline, recorded when the key was
    /// authorized. It is deliberately independent of the certificate the
    /// client presents: whoever holds the private key can always mint a fresh
    /// certificate for the same public key with a later expiry, so the
    /// presented certificate's own validity window cannot bound access.
    #[serde(default)]
    pub expires_at_unix: Option<i64>,
    /// Kill all processes remaining in each session cgroup when that session
    /// ends. This opt-in policy requires a Linux cgroup v2 delegated to the
    /// root-owned server and a non-root target account.
    #[serde(default)]
    pub kill_session_processes: bool,
}

fn yes() -> bool {
    true
}

impl Default for AuthMeta {
    fn default() -> Self {
        Self {
            user: String::new(),
            allow_shell: true,
            allow_exec: true,
            allowed_commands: Vec::new(),
            key_fingerprint: None,
            expires_at_unix: None,
            kill_session_processes: false,
        }
    }
}

impl AuthMeta {
    /// Is `argv` permitted by `allowed_commands`?
    ///
    /// The comparison is against the whole of `argv[0]`, never its basename.
    /// Matching a basename would be a hole rather than a convenience: the
    /// authorized account can write an executable to a path it controls and
    /// ask for `/tmp/tool`, bypassing an entry that names a trusted `tool`.
    ///
    /// A bare name such as `tool` therefore permits that exact name, which the
    /// server resolves through its own fixed `PATH`. It does not constrain the
    /// tool's arguments or subprocesses. To allow a program elsewhere,
    /// authorize its absolute path.
    #[must_use]
    pub fn command_allowed(&self, argv: &[String]) -> bool {
        if self.allowed_commands.is_empty() {
            return true;
        }
        let Some(program) = argv.first() else {
            return false;
        };
        self.allowed_commands
            .iter()
            .any(|allowed| allowed == program)
    }

    /// Has the administrator's deadline for this authorization passed?
    #[must_use]
    pub fn is_expired(&self, now_unix: i64) -> bool {
        self.expires_at_unix.is_some_and(|limit| now_unix > limit)
    }
}

/// One authorised client.
#[derive(Debug, Clone)]
pub struct AuthEntry {
    pub name: String,
    pub fingerprint: Fingerprint,
    pub meta: AuthMeta,
}

/// All authorised clients, loaded from `authorized/`.
///
/// Entries retain their administrator-visible names. A second name for the
/// same public key is retained for management and diagnostics, but the
/// fingerprint is not exposed through [`Self::lookup`] until the conflict is
/// repaired. Silently choosing either policy would let removing one name
/// reactivate the other.
#[derive(Debug, Clone, Default)]
pub struct AuthStore {
    entries: Vec<AuthEntry>,
    names_by_fingerprint: BTreeMap<Fingerprint, Vec<String>>,
    fingerprints_by_name: BTreeMap<String, Fingerprint>,
    denied_fingerprints: BTreeSet<Fingerprint>,
}

const AUTH_DENIAL_PREFIX: &str = ".qsh-deny-sha256-";

impl AuthStore {
    /// Load every `<name>.crt` in `dir` together with its `<name>.toml`.
    ///
    /// A certificate without metadata is ignored with a warning rather than
    /// failing the whole server: one broken file must not lock everyone out.
    ///
    /// # Errors
    /// Fails if the shared store lock cannot be acquired or the directory
    /// cannot be listed.
    pub fn load(dir: &Path) -> Result<Self> {
        let lock_path = authorization_lock_target(dir)?;
        let _lock = FileLock::acquire(&lock_path, nix::fcntl::FlockArg::LockShared)?;
        Self::load_unlocked(dir, |warning| eprintln!("{warning}"))
    }

    /// Let a long-running caller deduplicate diagnostics across reloads.
    pub(crate) fn load_with_warnings(dir: &Path, warn: impl FnMut(String)) -> Result<Self> {
        let lock_path = authorization_lock_target(dir)?;
        let _lock = FileLock::acquire(&lock_path, nix::fcntl::FlockArg::LockShared)?;
        Self::load_unlocked(dir, warn)
    }

    fn load_unlocked(dir: &Path, mut warn: impl FnMut(String)) -> Result<Self> {
        let mut entries = Vec::new();
        let mut names_by_fingerprint: BTreeMap<Fingerprint, Vec<String>> = BTreeMap::new();
        let mut fingerprints_by_name = BTreeMap::new();
        let directory = match fs::read_dir(dir) {
            Ok(directory) => directory,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
        };
        let mut paths: Vec<_> = directory
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .map(|e| e.path())
            .collect();
        paths.sort();
        let denied_fingerprints = load_denial_markers(&paths, &mut warn);

        let names = paths
            .into_iter()
            .filter(|p| p.extension().is_some_and(|e| e == "crt"))
            .collect::<Vec<_>>();

        for cert_path in names {
            let utf8_name = cert_path
                .file_stem()
                .and_then(|s| s.to_str())
                .map(str::to_owned);
            let name = utf8_name.clone().unwrap_or_else(|| "?".to_owned());
            let cert = match load_cert(&cert_path) {
                Ok(cert) => cert,
                Err(error) => {
                    warn(format!(
                        "qsh-server: ignoring authorization `{name}`: {error:#}"
                    ));
                    continue;
                }
            };
            let fingerprint = Fingerprint::of_cert(&cert)?;
            names_by_fingerprint
                .entry(fingerprint)
                .or_default()
                .push(name.clone());
            if let Some(name) = utf8_name {
                fingerprints_by_name.insert(name, fingerprint);
            }

            match load_auth_entry(&cert_path, name.clone(), fingerprint, &mut warn) {
                Ok(entry) => entries.push(entry),
                Err(e) => warn(format!(
                    "qsh-server: ignoring authorization `{name}`: {e:#}"
                )),
            }
        }
        for (fingerprint, names) in &names_by_fingerprint {
            if names.len() > 1 {
                warn(format!(
                    "qsh-server: refusing duplicate authorizations for {fingerprint}: {}; \
                     revoke the duplicates or repair them with `qsh-server authorize --force`",
                    names.join(", ")
                ));
            }
        }
        for fingerprint in &denied_fingerprints {
            if names_by_fingerprint.contains_key(fingerprint) {
                warn(format!(
                    "qsh-server: refusing {fingerprint}: an authorization mutation was \
                     interrupted; rerun `authorize --force` to enable it or `revoke` to \
                     finish removing it"
                ));
            }
        }
        Ok(Self {
            entries,
            names_by_fingerprint,
            fingerprints_by_name,
            denied_fingerprints,
        })
    }

    #[must_use]
    pub fn fingerprints(&self) -> Vec<Fingerprint> {
        self.names_by_fingerprint
            .keys()
            .filter(|fingerprint| self.lookup(fingerprint).is_some())
            .copied()
            .collect()
    }

    #[must_use]
    pub fn lookup(&self, fp: &Fingerprint) -> Option<&AuthEntry> {
        if self.denied_fingerprints.contains(fp) {
            return None;
        }
        let names = self.names_by_fingerprint.get(fp)?;
        let [_name] = names.as_slice() else {
            return None;
        };
        self.entries.iter().find(|entry| entry.fingerprint == *fp)
    }

    pub fn entries(&self) -> impl Iterator<Item = &AuthEntry> {
        self.entries
            .iter()
            .filter(|entry| self.lookup(&entry.fingerprint).is_some())
    }

    /// Every valid on-disk entry, including entries refused due to a duplicate
    /// fingerprint. Management commands use this to make conflicts visible.
    pub fn stored_entries(&self) -> impl Iterator<Item = &AuthEntry> {
        self.entries.iter()
    }

    /// All administrator-visible names holding this public key.
    #[must_use]
    pub fn names_for_fingerprint(&self, fingerprint: &Fingerprint) -> &[String] {
        self.names_by_fingerprint
            .get(fingerprint)
            .map_or(&[], Vec::as_slice)
    }

    /// The public key stored under `name`, even when duplicate names make it
    /// ineligible for authentication.
    #[must_use]
    pub fn fingerprint_for_name(&self, name: &str) -> Option<Fingerprint> {
        self.fingerprints_by_name.get(name).copied()
    }

    #[must_use]
    pub fn has_fingerprint_conflict(&self, fingerprint: &Fingerprint) -> bool {
        self.names_for_fingerprint(fingerprint).len() > 1
    }

    #[must_use]
    pub fn is_fingerprint_denied(&self, fingerprint: &Fingerprint) -> bool {
        self.denied_fingerprints.contains(fingerprint)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries().next().is_none()
    }

    /// Serialize `qsh-server` mutations of one authorization directory.
    ///
    /// Runtime reloads take the matching shared lock so they observe either the
    /// old state or the completed mutation, never a mixture of both.
    ///
    /// # Errors
    /// Fails if the sidecar lock cannot be created or acquired.
    pub fn lock_directory(dir: &Path) -> Result<AuthorizationLock> {
        let lock_path = authorization_lock_target(dir)?;
        FileLock::acquire(&lock_path, nix::fcntl::FlockArg::LockExclusive).map(|lock| {
            AuthorizationLock {
                dir: dir.to_owned(),
                _lock: lock,
            }
        })
    }
}

fn load_denial_markers(paths: &[PathBuf], warn: &mut impl FnMut(String)) -> BTreeSet<Fingerprint> {
    let mut denied = BTreeSet::new();
    for path in paths {
        let Some(result) = denial_fingerprint(path) else {
            continue;
        };
        match result {
            Ok(fingerprint) => {
                denied.insert(fingerprint);
            }
            Err(error) => warn(format!(
                "qsh-server: ignoring malformed authorization denial marker {}: {error:#}",
                path.display()
            )),
        }
    }
    denied
}

fn load_auth_entry(
    cert_path: &Path,
    name: String,
    fingerprint: Fingerprint,
    warn: &mut impl FnMut(String),
) -> Result<AuthEntry> {
    let meta_path = cert_path.with_extension("toml");
    let text = fs::read_to_string(&meta_path)
        .with_context(|| format!("reading {}", meta_path.display()))?;
    let meta: AuthMeta =
        toml::from_str(&text).with_context(|| format!("parsing {}", meta_path.display()))?;
    if meta.user.is_empty() {
        bail!("{} does not name a user", meta_path.display());
    }
    if !meta.allowed_commands.is_empty() {
        warn(format!(
            "qsh-server: warning: authorization `{name}` uses an executable-name \
             filter; its arguments and subprocesses remain unrestricted"
        ));
    }
    // Refuse a policy that was written for a different key rather than
    // applying it to this one.
    match &meta.key_fingerprint {
        Some(expected) if expected != &fingerprint.to_string() => bail!(
            "{} was written for key {expected}, but {} holds {fingerprint}",
            meta_path.display(),
            cert_path.display()
        ),
        Some(_) => {}
        // Written before this field existed. Accepted so an upgrade does not
        // lock everyone out, but it cannot be checked, so say so.
        None => warn(format!(
            "qsh-server: warning: {} does not record which key it is for; \
             re-run `qsh-server authorize` for `{name}` to fix that",
            meta_path.display()
        )),
    }
    Ok(AuthEntry {
        name,
        fingerprint,
        meta,
    })
}

/// Exclusive authorization-directory mutation guard.
#[derive(Debug)]
pub struct AuthorizationLock {
    dir: PathBuf,
    _lock: FileLock,
}

impl AuthorizationLock {
    /// Load the store while this guard already holds its exclusive lock.
    ///
    /// # Errors
    /// Fails if the authorization directory cannot be listed.
    pub fn load(&self) -> Result<AuthStore> {
        AuthStore::load_unlocked(&self.dir, |warning| eprintln!("{warning}"))
    }

    /// Deny a fingerprint before beginning a multi-file mutation. The marker
    /// survives process interruption and keeps any remaining alias fail-closed.
    ///
    /// # Errors
    /// Fails if the marker cannot be published atomically.
    pub fn deny_fingerprint(&self, fingerprint: Fingerprint) -> Result<()> {
        write_public(
            &denial_path(&self.dir, fingerprint),
            &format!("deny {fingerprint}\n"),
        )
    }

    /// Clear a completed mutation's denial marker.
    ///
    /// # Errors
    /// Fails if an existing marker cannot be removed.
    pub fn clear_fingerprint_denial(&self, fingerprint: Fingerprint) -> Result<()> {
        let path = denial_path(&self.dir, fingerprint);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
        }
    }
}

fn denial_path(dir: &Path, fingerprint: Fingerprint) -> PathBuf {
    let fingerprint = fingerprint.to_string();
    let digest = fingerprint.strip_prefix("sha256:").unwrap_or(&fingerprint);
    dir.join(format!("{AUTH_DENIAL_PREFIX}{digest}"))
}

fn denial_fingerprint(path: &Path) -> Option<Result<Fingerprint>> {
    let digest = path
        .file_name()?
        .to_str()?
        .strip_prefix(AUTH_DENIAL_PREFIX)?;
    Some(Fingerprint::parse(&format!("sha256:{digest}")))
}

fn authorization_lock_target(dir: &Path) -> Result<PathBuf> {
    match fs::canonicalize(dir) {
        Ok(path) => Ok(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let Some(parent) = dir.parent() else {
                return Ok(dir.to_owned());
            };
            match fs::canonicalize(parent) {
                Ok(parent) => Ok(dir
                    .file_name()
                    .map_or(parent.clone(), |name| parent.join(name))),
                Err(parent_error) if parent_error.kind() == std::io::ErrorKind::NotFound => {
                    Ok(dir.to_owned())
                }
                Err(parent_error) => {
                    Err(parent_error).with_context(|| format!("resolving {}", parent.display()))
                }
            }
        }
        Err(error) => Err(error).with_context(|| format!("resolving {}", dir.display())),
    }
}

/// Whether an existing pin may be replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Trust {
    Replace,
    OnlyIfAbsentOrEqual,
}

/// An advisory lock held for a read-modify-write of a shared file.
///
/// The lock lives on a sidecar so that the file itself can still be replaced
/// by an atomic rename underneath it.
#[derive(Debug)]
struct FileLock {
    /// Holding the `Flock` is what holds the lock; it releases on drop.
    _flock: nix::fcntl::Flock<fs::File>,
}

impl FileLock {
    fn acquire(path: &Path, operation: nix::fcntl::FlockArg) -> Result<Self> {
        let lock_path = path.with_extension("lock");
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .with_context(|| format!("opening {}", lock_path.display()))?;
        nix::fcntl::Flock::lock(file, operation)
            .map(|flock| Self { _flock: flock })
            .map_err(|(_, e)| anyhow!("locking {}: {e}", lock_path.display()))
    }
}

pub(crate) mod host;

/// A `known_hosts` file: `host:port sha256:<hex>`, one per line.
#[derive(Debug, Default)]
pub struct KnownHosts {
    path: PathBuf,
    entries: Vec<(String, Fingerprint)>,
}

impl KnownHosts {
    /// Read a `known_hosts` file, tolerating a missing one.
    ///
    /// # Errors
    /// Fails on a malformed entry or an unparseable fingerprint.
    pub fn load(path: &Path) -> Result<Self> {
        let mut entries: Vec<(String, Fingerprint)> = Vec::new();
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
        };
        for (lineno, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let (Some(host), Some(fp)) = (parts.next(), parts.next()) else {
                bail!("{}:{}: malformed entry", path.display(), lineno + 1);
            };
            let fp = Fingerprint::parse(fp)
                .with_context(|| format!("{}:{}", path.display(), lineno + 1))?;
            let host = host::canonical_key(host)
                .with_context(|| format!("{}:{}", path.display(), lineno + 1))?;
            if let Some((_, old)) = entries.iter().find(|(name, _)| *name == host) {
                if *old != fp {
                    bail!(
                        "{}:{}: conflicting pins for {host}",
                        path.display(),
                        lineno + 1
                    );
                }
            } else {
                entries.push((host, fp));
            }
        }
        Ok(Self {
            path: path.to_path_buf(),
            entries,
        })
    }

    #[must_use]
    pub fn get(&self, host_key: &str) -> Option<Fingerprint> {
        let host_key = host::canonical_key(host_key).ok()?;
        self.entries
            .iter()
            .find(|(h, _)| *h == host_key)
            .map(|(_, fp)| *fp)
    }

    /// Add or replace the entry for `host_key` and persist the file.
    ///
    /// # Errors
    /// Fails if the file cannot be written.
    pub fn set(&mut self, host_key: &str, fp: Fingerprint) -> Result<()> {
        self.update(host_key, fp, Trust::Replace)
    }

    /// Pin `host_key` only if it is unpinned, or already pinned to `fp`.
    ///
    /// This is what trust on first use must use. Plain `set` would happily
    /// overwrite a pin another process wrote a moment earlier, which is the
    /// one thing a pin exists to prevent — silently replacing a conflicting
    /// key reopens exactly the question the pin had already answered.
    ///
    /// # Errors
    /// Fails if the host is already pinned to a different key, or if the file
    /// cannot be written.
    pub fn set_if_new(&mut self, host_key: &str, fp: Fingerprint) -> Result<()> {
        self.update(host_key, fp, Trust::OnlyIfAbsentOrEqual)
    }

    fn update(&mut self, host_key: &str, fp: Fingerprint, trust: Trust) -> Result<()> {
        let host_key = host::canonical_key(host_key)?;
        // Everything from here to the rename happens under the lock, so a
        // concurrent client cannot read the old file, decide, and write back a
        // snapshot that drops what we just added.
        let _lock = FileLock::acquire(&self.path, nix::fcntl::FlockArg::LockExclusive)?;
        self.refresh()?;
        if trust == Trust::OnlyIfAbsentOrEqual {
            if let Some(existing) = self.get(&host_key) {
                if existing != fp {
                    bail!(
                        "{host_key} was pinned to {existing} while we were connecting, \
                         but the server offered {fp}"
                    );
                }
                return Ok(());
            }
        }
        self.entries.retain(|(h, _)| *h != host_key);
        self.entries.push((host_key, fp));
        self.save()
    }

    /// Refuse to overwrite a file that became unreadable or has conflicting pins.
    fn refresh(&mut self) -> Result<()> {
        self.entries = Self::load(&self.path)?.entries;
        Ok(())
    }

    /// Remove every entry for `host_key`. Returns how many were removed.
    ///
    /// # Errors
    /// Fails if the file cannot be written.
    pub fn remove(&mut self, host_key: &str) -> Result<usize> {
        let host_key = host::canonical_key(host_key)?;
        let _lock = FileLock::acquire(&self.path, nix::fcntl::FlockArg::LockExclusive)?;
        self.refresh()?;
        let before = self.entries.len();
        self.entries.retain(|(h, _)| *h != host_key);
        let removed = before - self.entries.len();
        if removed > 0 {
            self.save()?;
        }
        Ok(removed)
    }

    #[must_use]
    pub fn entries(&self) -> &[(String, Fingerprint)] {
        &self.entries
    }

    fn save(&self) -> Result<()> {
        let mut out = String::from("# qsh known hosts: <host>:<port> sha256:<public key hash>\n");
        for (host, fp) in &self.entries {
            out.push_str(host);
            out.push(' ');
            out.push_str(&fp.to_string());
            out.push('\n');
        }
        crate::crypto::write_private(&self.path, &out)
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

    fn fp(seed: &str) -> Fingerprint {
        let (pem, _) = crate::crypto::generate_identity(seed, &[seed.into()], 30).unwrap();
        Fingerprint::of_cert(&crate::crypto::cert_from_pem(&pem).unwrap()).unwrap()
    }

    #[test]
    fn env_allowlist_blocks_dangerous_variables() {
        assert!(env_allowed("TERM"));
        assert!(env_allowed("LC_ALL"));
        assert!(env_allowed("QSH_TAG"));
        assert!(!env_allowed("LD_PRELOAD"));
        assert!(!env_allowed("PATH"));
        assert!(!env_allowed("IFS"));
    }

    #[test]
    fn empty_allowed_commands_permits_everything() {
        let meta = AuthMeta {
            user: "alice".into(),
            ..Default::default()
        };
        assert!(meta.command_allowed(&["anything".into()]));
    }

    #[test]
    fn allowed_commands_match_argv0_exactly() {
        let meta = AuthMeta {
            user: "alice".into(),
            allowed_commands: vec!["rsync".into()],
            ..Default::default()
        };
        assert!(meta.command_allowed(&["rsync".into(), "--server".into()]));
        assert!(!meta.command_allowed(&["rm".into(), "-rf".into(), "/".into()]));
        assert!(!meta.command_allowed(&["rsyncevil".into()]));
        assert!(!meta.command_allowed(&[]));
    }

    #[test]
    fn a_basename_match_cannot_smuggle_in_another_executable() {
        // Exact argv[0] matching prevents a writable lookalike from satisfying
        // an entry that names the trusted PATH-resolved executable.
        let meta = AuthMeta {
            user: "alice".into(),
            allowed_commands: vec!["rsync".into()],
            ..Default::default()
        };
        for evil in [
            "/tmp/rsync",
            "./rsync",
            "../rsync",
            "/home/alice/bin/rsync",
            "/usr/bin/rsync",
        ] {
            assert!(
                !meta.command_allowed(&[evil.into()]),
                "`{evil}` must not satisfy an allow-list entry of `rsync`"
            );
        }
    }

    #[test]
    fn an_absolute_path_can_be_authorized_explicitly() {
        let meta = AuthMeta {
            user: "alice".into(),
            allowed_commands: vec!["/usr/bin/rsync".into()],
            ..Default::default()
        };
        assert!(meta.command_allowed(&["/usr/bin/rsync".into()]));
        assert!(!meta.command_allowed(&["rsync".into()]));
        assert!(!meta.command_allowed(&["/tmp/rsync".into()]));
    }

    #[test]
    fn authorization_expiry_is_independent_of_any_certificate() {
        let mut meta = AuthMeta {
            user: "alice".into(),
            ..Default::default()
        };
        assert!(!meta.is_expired(i64::MAX), "no deadline means no expiry");
        meta.expires_at_unix = Some(1_000);
        assert!(!meta.is_expired(999));
        assert!(!meta.is_expired(1_000));
        assert!(meta.is_expired(1_001));
    }

    #[test]
    fn session_cgroup_policy_is_opt_in_and_round_trips() {
        let legacy: AuthMeta = toml::from_str("user = 'guest'").unwrap();
        assert!(!legacy.kill_session_processes);
        let restricted: AuthMeta =
            toml::from_str("user = 'guest'\nkill_session_processes = true\n").unwrap();
        assert!(restricted.kill_session_processes);
        let encoded = toml::to_string(&restricted).unwrap();
        assert!(encoded.contains("kill_session_processes = true"));
    }

    #[test]
    fn known_hosts_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let a = fp("a");
        let b = fp("b");

        let mut kh = KnownHosts::load(&path).unwrap();
        assert!(kh.get("h:2222").is_none());
        kh.set("h:2222", a).unwrap();

        let kh = KnownHosts::load(&path).unwrap();
        assert_eq!(kh.get("h:2222"), Some(a));

        // Re-pinning replaces rather than appends.
        let mut kh = kh;
        kh.set("h:2222", b).unwrap();
        let kh = KnownHosts::load(&path).unwrap();
        assert_eq!(kh.entries().len(), 1);
        assert_eq!(kh.get("h:2222"), Some(b));

        let mut kh = kh;
        assert_eq!(kh.remove("h:2222").unwrap(), 1);
        assert_eq!(KnownHosts::load(&path).unwrap().entries().len(), 0);
    }

    #[test]
    fn trust_on_first_use_refuses_to_replace_a_conflicting_pin() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let (a, b) = (fp("a"), fp("b"));

        let mut kh = KnownHosts::load(&path).unwrap();
        kh.set_if_new("h:2222", a).unwrap();

        // Another process pinned this host in the meantime. Silently replacing
        // it would undo the answer the pin already recorded.
        let mut other = KnownHosts::load(&path).unwrap();
        let err = other.set_if_new("h:2222", b).unwrap_err().to_string();
        assert!(err.contains("was pinned to"), "{err}");
        assert_eq!(KnownHosts::load(&path).unwrap().get("h:2222"), Some(a));

        // Re-pinning the same key is not a conflict.
        other.set_if_new("h:2222", a).unwrap();
    }

    #[test]
    fn concurrent_writers_do_not_lose_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let hosts: Vec<String> = (0..8).map(|i| format!("host{i}:2222")).collect();

        std::thread::scope(|scope| {
            for host in &hosts {
                let path = path.clone();
                scope.spawn(move || {
                    let mut kh = KnownHosts::load(&path).unwrap();
                    kh.set(host, fp(host)).unwrap();
                });
            }
        });

        let kh = KnownHosts::load(&path).unwrap();
        for host in &hosts {
            assert!(
                kh.get(host).is_some(),
                "{host} was lost by a concurrent write"
            );
        }
    }

    #[test]
    fn known_hosts_rejects_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        fs::write(&path, "host sha256:not-hex\n").unwrap();
        assert!(KnownHosts::load(&path).is_err());
    }

    #[test]
    fn legacy_pins_are_canonicalized_at_every_entry_point() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let a = fp("a");
        fs::write(
            &path,
            format!("EXAMPLE.com:02222 {a}\n2001:0DB8::1:2222 {a}\n"),
        )
        .unwrap();
        let mut kh = KnownHosts::load(&path).unwrap();
        assert_eq!(kh.get("example.COM:2222"), Some(a));
        assert_eq!(kh.get("[2001:db8:0:0::1]:2222"), Some(a));
        kh.set_if_new("Example.Com:2222", a).unwrap();
        assert!(kh.set_if_new("example.com:2222", fp("b")).is_err());
        assert_eq!(kh.remove("EXAMPLE.COM:2222").unwrap(), 1);
        assert_eq!(kh.remove("[2001:DB8::1]:2222").unwrap(), 1);
        assert!(KnownHosts::load(&path).unwrap().entries().is_empty());
    }

    #[test]
    fn conflicting_aliases_and_refresh_errors_never_overwrite_pins() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let (a, b) = (fp("a"), fp("b"));
        let mut stale = KnownHosts::load(&path).unwrap();
        stale.set("example.com:2222", a).unwrap();

        for replacement in [
            format!("example.com:2222 {a}\nEXAMPLE.COM:2222 {b}\n"),
            format!("[2001:db8::1]:2222 {a}\n2001:0DB8::1:2222 {b}\n"),
            "malformed entry\n".to_owned(),
        ] {
            fs::write(&path, &replacement).unwrap();
            assert!(KnownHosts::load(&path).is_err());
            assert!(stale.set_if_new("example.com:2222", a).is_err());
            assert!(stale.set("example.com:2222", b).is_err());
            assert!(stale.remove("example.com:2222").is_err());
            assert_eq!(fs::read_to_string(&path).unwrap(), replacement);
        }

        fs::write(
            &path,
            format!("example.com:2222 {a}\nEXAMPLE.COM:2222 {a}\n"),
        )
        .unwrap();
        assert_eq!(KnownHosts::load(&path).unwrap().entries().len(), 1);
    }

    #[test]
    fn auth_store_skips_incomplete_entries() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_pem, _) =
            crate::crypto::generate_identity("laptop", &["laptop".into()], 30).unwrap();
        let (orphan_pem, _) =
            crate::crypto::generate_identity("orphan", &["orphan".into()], 30).unwrap();
        fs::write(dir.path().join("laptop.crt"), &cert_pem).unwrap();
        fs::write(dir.path().join("laptop.toml"), "user = \"alice\"\n").unwrap();
        // A distinct certificate with no .toml companion is ignored without
        // affecting valid keys. A same-key orphan is deliberately a conflict.
        fs::write(dir.path().join("orphan.crt"), &orphan_pem).unwrap();

        let store = AuthStore::load(dir.path()).unwrap();
        assert_eq!(store.entries().count(), 1);
        assert_eq!(store.entries().next().unwrap().meta.user, "alice");
    }

    #[test]
    fn auth_store_refuses_duplicate_fingerprints_without_hiding_names() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_pem, _) =
            crate::crypto::generate_identity("laptop", &["laptop".into()], 30).unwrap();
        let cert = crate::crypto::cert_from_pem(&cert_pem).unwrap();
        let fingerprint = Fingerprint::of_cert(&cert).unwrap();
        let policy = format!("user = \"alice\"\nkey_fingerprint = \"{fingerprint}\"\n");
        for name in ["alpha", "beta"] {
            fs::write(dir.path().join(format!("{name}.crt")), &cert_pem).unwrap();
            fs::write(dir.path().join(format!("{name}.toml")), &policy).unwrap();
        }

        let mut warnings = Vec::new();
        let store =
            AuthStore::load_with_warnings(dir.path(), |warning| warnings.push(warning)).unwrap();
        assert!(store.lookup(&fingerprint).is_none());
        assert!(store.is_empty());
        assert!(store.has_fingerprint_conflict(&fingerprint));
        assert_eq!(
            store.names_for_fingerprint(&fingerprint),
            &["alpha".to_owned(), "beta".to_owned()]
        );
        assert_eq!(store.stored_entries().count(), 2);
        assert!(warnings.iter().any(|warning| {
            warning.contains("refusing duplicate authorizations")
                && warning.contains("alpha")
                && warning.contains("beta")
        }));
    }

    #[test]
    fn malformed_policy_alias_still_blocks_and_identifies_its_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_pem, _) =
            crate::crypto::generate_identity("laptop", &["laptop".into()], 30).unwrap();
        let cert = crate::crypto::cert_from_pem(&cert_pem).unwrap();
        let fingerprint = Fingerprint::of_cert(&cert).unwrap();
        fs::write(dir.path().join("alpha.crt"), &cert_pem).unwrap();
        fs::write(
            dir.path().join("alpha.toml"),
            format!("user = \"alice\"\nkey_fingerprint = \"{fingerprint}\"\n"),
        )
        .unwrap();
        fs::write(dir.path().join("broken.crt"), &cert_pem).unwrap();
        fs::write(dir.path().join("broken.toml"), "not valid TOML").unwrap();

        let store = AuthStore::load(dir.path()).unwrap();
        assert!(store.lookup(&fingerprint).is_none());
        assert_eq!(
            store.names_for_fingerprint(&fingerprint),
            &["alpha".to_owned(), "broken".to_owned()]
        );
        assert_eq!(store.fingerprint_for_name("broken"), Some(fingerprint));
    }

    #[test]
    fn interrupted_mutation_marker_keeps_a_unique_entry_denied() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_pem, _) =
            crate::crypto::generate_identity("laptop", &["laptop".into()], 30).unwrap();
        let cert = crate::crypto::cert_from_pem(&cert_pem).unwrap();
        let fingerprint = Fingerprint::of_cert(&cert).unwrap();
        fs::write(dir.path().join("laptop.crt"), &cert_pem).unwrap();
        fs::write(
            dir.path().join("laptop.toml"),
            format!("user = \"alice\"\nkey_fingerprint = \"{fingerprint}\"\n"),
        )
        .unwrap();

        let lock = AuthStore::lock_directory(dir.path()).unwrap();
        lock.deny_fingerprint(fingerprint).unwrap();
        drop(lock);
        let store = AuthStore::load(dir.path()).unwrap();
        assert!(store.is_fingerprint_denied(&fingerprint));
        assert!(store.lookup(&fingerprint).is_none());

        let lock = AuthStore::lock_directory(dir.path()).unwrap();
        lock.clear_fingerprint_denial(fingerprint).unwrap();
        drop(lock);
        assert!(AuthStore::load(dir.path())
            .unwrap()
            .lookup(&fingerprint)
            .is_some());
    }

    #[cfg(unix)]
    #[test]
    fn unique_non_utf8_authorization_name_remains_usable() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let dir = tempfile::tempdir().unwrap();
        let (cert_pem, _) =
            crate::crypto::generate_identity("laptop", &["laptop".into()], 30).unwrap();
        let cert = crate::crypto::cert_from_pem(&cert_pem).unwrap();
        let fingerprint = Fingerprint::of_cert(&cert).unwrap();
        let cert_name = OsString::from_vec(b"laptop-\xff.crt".to_vec());
        let meta_name = OsString::from_vec(b"laptop-\xff.toml".to_vec());
        fs::write(dir.path().join(cert_name), &cert_pem).unwrap();
        fs::write(
            dir.path().join(meta_name),
            format!("user = \"alice\"\nkey_fingerprint = \"{fingerprint}\"\n"),
        )
        .unwrap();

        let store = AuthStore::load(dir.path()).unwrap();
        assert_eq!(
            store.lookup(&fingerprint).map(|entry| entry.name.as_str()),
            Some("?")
        );
    }

    #[test]
    fn authorization_directory_lock_serializes_writers() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("shared");
        let first_home = dir.path().join("first");
        let second_home = dir.path().join("second");
        fs::create_dir(&target).unwrap();
        fs::create_dir(&first_home).unwrap();
        fs::create_dir(&second_home).unwrap();
        std::os::unix::fs::symlink(&target, first_home.join("authorized")).unwrap();
        std::os::unix::fs::symlink(&target, second_home.join("authorized")).unwrap();
        let first = AuthStore::lock_directory(&first_home.join("authorized")).unwrap();
        let path = second_home.join("authorized");
        let (attempting, started) = std::sync::mpsc::channel();
        let (acquired, finished) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            attempting.send(()).unwrap();
            let _second = AuthStore::lock_directory(&path).unwrap();
            acquired.send(()).unwrap();
        });

        started
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        assert!(finished
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_err());
        drop(first);
        finished
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        writer.join().unwrap();
    }

    #[test]
    fn server_config_defaults_apply_to_missing_file() {
        let cfg = ServerConfig::load(Path::new("/nonexistent/qsh-server.toml")).unwrap();
        assert_eq!(cfg.listen, format!("0.0.0.0:{DEFAULT_PORT}"));
        assert!(cfg.listen_addr().is_ok());
    }

    #[test]
    fn explicit_server_config_must_exist() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.toml");
        let error = ServerConfig::load_required(&path).unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::NotFound
        );
    }

    #[test]
    fn both_config_loaders_preserve_values_and_report_invalid_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.toml");
        fs::write(
            &path,
            "listen = \"127.0.0.1:3333\"\nidle_timeout_secs = 300\n",
        )
        .unwrap();
        for cfg in [
            ServerConfig::load(&path),
            ServerConfig::load_required(&path),
        ] {
            let cfg = cfg.unwrap();
            assert_eq!(cfg.listen, "127.0.0.1:3333");
            assert_eq!(cfg.idle_timeout_secs, 300);
        }
        fs::write(&path, "invalid configuration").unwrap();
        assert!(ServerConfig::load(&path).is_err());
        assert!(ServerConfig::load_required(&path).is_err());
        assert!(ServerConfig::load(dir.path()).is_err());
        assert!(ServerConfig::load_required(dir.path()).is_err());
    }
}
