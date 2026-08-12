//! On-disk layout, configuration files and the authorisation store.

use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::crypto::{load_cert, Fingerprint};

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
    600
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
        if !path.exists() {
            return Ok(Self::default());
        }
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
    /// If non-empty, only these program names (argv[0], basename compared)
    /// may be executed. `allow_shell` is governed separately.
    #[serde(default)]
    pub allowed_commands: Vec<String>,
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
        }
    }
}

impl AuthMeta {
    /// Is `argv` permitted by `allowed_commands`?
    #[must_use]
    pub fn command_allowed(&self, argv: &[String]) -> bool {
        if self.allowed_commands.is_empty() {
            return true;
        }
        let Some(program) = argv.first() else {
            return false;
        };
        let base = Path::new(program)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(program);
        self.allowed_commands
            .iter()
            .any(|allowed| allowed == program || allowed == base)
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
#[derive(Debug, Clone, Default)]
pub struct AuthStore {
    entries: BTreeMap<Fingerprint, AuthEntry>,
}

impl AuthStore {
    /// Load every `<name>.crt` in `dir` together with its `<name>.toml`.
    ///
    /// A certificate without metadata is ignored with a warning rather than
    /// failing the whole server: one broken file must not lock everyone out.
    ///
    /// # Errors
    /// Fails only if the directory itself cannot be listed.
    pub fn load(dir: &Path) -> Result<Self> {
        let mut entries = BTreeMap::new();
        if !dir.exists() {
            return Ok(Self { entries });
        }
        let mut names: Vec<_> = fs::read_dir(dir)
            .with_context(|| format!("reading {}", dir.display()))?
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "crt"))
            .collect();
        names.sort();

        for cert_path in names {
            let name = cert_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("?")
                .to_string();
            let meta_path = cert_path.with_extension("toml");
            let load = || -> Result<AuthEntry> {
                let cert = load_cert(&cert_path)?;
                let fingerprint = Fingerprint::of_cert(&cert)?;
                let text = fs::read_to_string(&meta_path)
                    .with_context(|| format!("reading {}", meta_path.display()))?;
                let meta: AuthMeta = toml::from_str(&text)
                    .with_context(|| format!("parsing {}", meta_path.display()))?;
                if meta.user.is_empty() {
                    bail!("{} does not name a user", meta_path.display());
                }
                Ok(AuthEntry {
                    name: name.clone(),
                    fingerprint,
                    meta,
                })
            };
            match load() {
                Ok(entry) => {
                    entries.insert(entry.fingerprint, entry);
                }
                Err(e) => eprintln!("qsh-server: ignoring authorization `{name}`: {e:#}"),
            }
        }
        Ok(Self { entries })
    }

    #[must_use]
    pub fn fingerprints(&self) -> Vec<Fingerprint> {
        self.entries.keys().copied().collect()
    }

    #[must_use]
    pub fn lookup(&self, fp: &Fingerprint) -> Option<&AuthEntry> {
        self.entries.get(fp)
    }

    pub fn entries(&self) -> impl Iterator<Item = &AuthEntry> {
        self.entries.values()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

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
        let mut entries = Vec::new();
        if path.exists() {
            let text =
                fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
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
                entries.push((host.to_string(), fp));
            }
        }
        Ok(Self {
            path: path.to_path_buf(),
            entries,
        })
    }

    #[must_use]
    pub fn get(&self, host_key: &str) -> Option<Fingerprint> {
        self.entries
            .iter()
            .find(|(h, _)| h == host_key)
            .map(|(_, fp)| *fp)
    }

    /// Add or replace the entry for `host_key` and persist the file.
    ///
    /// # Errors
    /// Fails if the file cannot be written.
    pub fn set(&mut self, host_key: &str, fp: Fingerprint) -> Result<()> {
        self.entries.retain(|(h, _)| h != host_key);
        self.entries.push((host_key.to_string(), fp));
        self.save()
    }

    /// Remove every entry for `host_key`. Returns how many were removed.
    ///
    /// # Errors
    /// Fails if the file cannot be written.
    pub fn remove(&mut self, host_key: &str) -> Result<usize> {
        let before = self.entries.len();
        self.entries.retain(|(h, _)| h != host_key);
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
    fn allowed_commands_match_by_name_or_path() {
        let meta = AuthMeta {
            user: "alice".into(),
            allowed_commands: vec!["rsync".into()],
            ..Default::default()
        };
        assert!(meta.command_allowed(&["rsync".into(), "--server".into()]));
        assert!(meta.command_allowed(&["/usr/bin/rsync".into()]));
        assert!(!meta.command_allowed(&["rm".into(), "-rf".into(), "/".into()]));
        assert!(!meta.command_allowed(&["rsyncevil".into()]));
        assert!(!meta.command_allowed(&[]));
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
    fn known_hosts_rejects_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        fs::write(&path, "host sha256:not-hex\n").unwrap();
        assert!(KnownHosts::load(&path).is_err());
    }

    #[test]
    fn auth_store_skips_incomplete_entries() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_pem, _) =
            crate::crypto::generate_identity("laptop", &["laptop".into()], 30).unwrap();
        fs::write(dir.path().join("laptop.crt"), &cert_pem).unwrap();
        fs::write(dir.path().join("laptop.toml"), "user = \"alice\"\n").unwrap();
        // No .toml companion: must be ignored, not fatal.
        fs::write(dir.path().join("orphan.crt"), &cert_pem).unwrap();

        let store = AuthStore::load(dir.path()).unwrap();
        assert_eq!(store.entries().count(), 1);
        assert_eq!(store.entries().next().unwrap().meta.user, "alice");
    }

    #[test]
    fn server_config_defaults_apply_to_missing_file() {
        let cfg = ServerConfig::load(Path::new("/nonexistent/qsh-server.toml")).unwrap();
        assert_eq!(cfg.listen, format!("0.0.0.0:{DEFAULT_PORT}"));
        assert!(cfg.listen_addr().is_ok());
    }
}
