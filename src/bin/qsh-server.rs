//! `qsh-server` — the daemon plus its key-management subcommands.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use qsh::config::{AuthMeta, AuthStore, ServerConfig, ServerPaths};
use qsh::crypto::{self, Fingerprint};

#[derive(Parser)]
#[command(
    name = "qsh-server",
    version,
    about = "qsh server: remote shell, remote exec and rsync transport over QUIC",
    subcommand_required = true,
    arg_required_else_help = true
)]
struct Cli {
    /// Configuration directory (default: /etc/qsh as root, else ~/.config/qsh-server)
    #[arg(long, global = true, value_name = "DIR")]
    dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the server.
    Serve(Serve),
    /// Create the server's host identity.
    Keygen(Keygen),
    /// Allow a client certificate to log in as a local user.
    Authorize(Authorize),
    /// Withdraw a previously authorized client.
    Revoke(Revoke),
    /// List authorized clients.
    List,
    /// Print the server's host key fingerprint (for `qsh known-hosts add`).
    Fingerprint,
}

#[derive(Args)]
struct Serve {
    /// Address to listen on, overriding the configuration file.
    #[arg(long, value_name = "ADDR")]
    listen: Option<SocketAddr>,
    /// Configuration file (default: <dir>/qsh-server.toml)
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
}

#[derive(Args)]
struct Keygen {
    /// Validity in days.
    #[arg(long, default_value_t = 3650)]
    days: u32,
    /// Replace an existing host identity.
    #[arg(long)]
    force: bool,
    /// Host names to embed as subject alternative names (cosmetic: clients
    /// pin the public key, not the name).
    #[arg(long = "host", value_name = "NAME")]
    hosts: Vec<String>,
}

#[derive(Args)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "these are independent Clap switches, not program state"
)]
struct Authorize {
    /// The client's `id.crt`.
    certificate: PathBuf,
    /// Local account this key may log in as.
    #[arg(long)]
    user: String,
    /// Short name for the entry (default: the certificate's file stem).
    #[arg(long)]
    name: Option<String>,
    /// Refuse interactive shells for this key.
    #[arg(long)]
    no_shell: bool,
    /// Refuse remote command execution for this key.
    #[arg(long)]
    no_exec: bool,
    /// Filter the executable name; repeatable. All arguments and subprocesses
    /// remain allowed. Without it, any program is allowed.
    #[arg(long = "command", value_name = "PROGRAM")]
    commands: Vec<String>,
    /// Stop accepting this key after N days. The deadline is recorded here on
    /// the server and enforced regardless of what certificate the client
    /// later presents.
    #[arg(long, value_name = "DAYS")]
    expires_in_days: Option<u32>,
    /// Kill processes still in this key's session cgroup when each session
    /// ends. Requires Linux cgroup v2 and a root daemon serving a non-root user.
    #[arg(long)]
    kill_session_processes: bool,
    /// Overwrite an existing entry with the same name.
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
struct Revoke {
    /// Entry name as shown by `qsh-server list`.
    name: String,
}

/// Seconds since the Unix epoch, saturating rather than failing.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(i64::MAX)
}

/// Entry names become file names under a root-owned directory, so they must
/// not be able to escape it.
fn validate_entry_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("entry name must not be empty");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        || name.starts_with('.')
    {
        bail!(
            "entry name `{name}` must be alphanumeric with `-`, `_` or `.`, \
             and may not start with `.`"
        );
    }
    Ok(())
}

fn main() -> ExitCode {
    qsh::install_crypto_provider();
    let cli = Cli::parse();
    let paths = match cli.dir {
        Some(dir) => Ok(ServerPaths::new(dir)),
        None => ServerPaths::discover(),
    };
    let result = paths.and_then(|paths| run(&paths, cli.command));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("qsh-server: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(paths: &ServerPaths, command: Command) -> Result<()> {
    match command {
        Command::Serve(args) => serve(paths, args),
        Command::Keygen(args) => keygen(paths, args),
        Command::Authorize(args) => authorize(paths, args),
        Command::Revoke(args) => revoke(paths, &args),
        Command::List => list(paths),
        Command::Fingerprint => fingerprint(paths),
    }
}

fn serve(paths: &ServerPaths, args: Serve) -> Result<()> {
    let cfg = match args.config {
        Some(path) => ServerConfig::load_required(&path)?,
        None => ServerConfig::load(&paths.config())?,
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")?;
    runtime.block_on(async {
        tokio::select! {
            result = qsh::server::serve(paths, &cfg, args.listen) => result,
            () = shutdown_signal() => {
                eprintln!("qsh-server: shutting down");
                Ok(())
            }
        }
    })
}

async fn shutdown_signal() {
    let Ok(mut term) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    else {
        return;
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

fn keygen(paths: &ServerPaths, args: Keygen) -> Result<()> {
    if paths.cert().exists() && !args.force {
        bail!(
            "{} already exists; pass --force to replace the host identity \
             (every client would have to re-pin it)",
            paths.cert().display()
        );
    }
    let mut sans = args.hosts;
    if sans.is_empty() {
        sans.push(hostname());
        sans.push("localhost".into());
    }
    let (cert_pem, key_pem) = crypto::generate_identity(&hostname(), &sans, args.days)?;
    crypto::write_private(&paths.key(), &key_pem)?;
    crypto::write_public(&paths.cert(), &cert_pem)?;

    if !paths.config().exists() {
        let default = toml::to_string_pretty(&ServerConfig::default())?;
        crypto::write_public(
            &paths.config(),
            &format!("# qsh-server configuration\n{default}"),
        )?;
        println!("Wrote {}", paths.config().display());
    }
    std::fs::create_dir_all(paths.authorized())?;

    let fp = Fingerprint::of_cert(&crypto::load_cert(&paths.cert())?)?;
    println!("Wrote {}", paths.key().display());
    println!("Wrote {}", paths.cert().display());
    println!("Host key: {fp}");
    println!("Valid for {} days.", args.days);
    println!();
    println!("Clients can pin this key without a prompt:");
    println!(
        "  qsh known-hosts add <host>:{} {fp}",
        qsh::config::DEFAULT_PORT
    );
    Ok(())
}

fn authorize(paths: &ServerPaths, args: Authorize) -> Result<()> {
    let cert = crypto::load_cert(&args.certificate)?;
    let fp = Fingerprint::of_cert(&cert)?;

    // Fail early rather than at first login.
    let target = qsh::child::resolve_user(&args.user)?;
    if args.kill_session_processes && target.uid.is_root() {
        bail!("--kill-session-processes cannot constrain root; authorize a non-root account");
    }

    let name = args
        .name
        .or_else(|| {
            args.certificate
                .file_stem()
                .and_then(|s| s.to_str())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "client".into());
    validate_entry_name(&name)?;

    let dir = paths.authorized();
    let lock = AuthStore::lock_directory(&dir)?;
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let cert_path = dir.join(format!("{name}.crt"));
    if cert_path.exists() && !args.force {
        bail!(
            "{} already exists; pass --force to replace it",
            cert_path.display()
        );
    }

    let existing = lock.load()?;
    let replacement = replacement_plan(&existing, fp, &name, args.force)?;
    for fingerprint in &replacement.denied_fingerprints {
        lock.deny_fingerprint(*fingerprint)?;
    }

    let expires = args
        .expires_in_days
        .map(|days| unix_now().saturating_add(i64::from(days).saturating_mul(86_400)));

    let meta = AuthMeta {
        user: args.user.clone(),
        allow_shell: !args.no_shell,
        allow_exec: !args.no_exec,
        allowed_commands: args.commands.clone(),
        key_fingerprint: Some(fp.to_string()),
        expires_at_unix: expires,
        kill_session_processes: args.kill_session_processes,
    };

    // Policy first, certificate second — the order matters for what a reload
    // landing between the two writes can see.
    //
    // The new policy names the new key. So in the window, the directory holds
    // the *old* certificate against a policy written for a different one: a
    // mismatch, which the loader refuses. Once the certificate lands the pair
    // agrees again.
    //
    // The other order is not safe, and this used to have it. Replacing an
    // entry whose old policy predates `key_fingerprint` would put the new
    // certificate next to a policy with nothing to check it against — and
    // since those are deliberately still accepted, the new key would be
    // authorized under the old policy, which may grant more than intended.
    crypto::write_public(
        &dir.join(format!("{name}.toml")),
        &format!(
            "# authorized qsh client `{name}`\n{}",
            toml::to_string_pretty(&meta)?
        ),
    )?;
    crypto::write_certificate(&cert_path, &cert)?;

    // Duplicate fingerprints are denied by AuthStore, so publishing the new
    // pair before deleting every alias is fail-closed if this process stops.
    for old in &replacement.aliases {
        remove_entry(&dir, old)?;
    }
    // Displaced fingerprints stay tombstoned after their files are removed.
    // Only this explicitly authorized key is made live again.
    lock.clear_fingerprint_denial(fp)?;

    println!("Authorized `{name}` ({fp}) as user `{}`.", args.user);
    if !replacement.aliases.is_empty() {
        println!(
            "Removed previous authorization aliases: {}.",
            replacement
                .aliases
                .iter()
                .map(|old| format!("`{old}`"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if let Some(days) = args.expires_in_days {
        println!("Expires in {days} days; after that the key is refused.");
    }
    if !meta.allowed_commands.is_empty() {
        println!(
            "Executable filter (arguments unrestricted): {}",
            meta.allowed_commands.join(", ")
        );
    }
    if !meta.allow_shell {
        println!("Interactive shells are refused for this key.");
    }
    if !meta.allow_exec {
        println!("Remote commands are refused for this key.");
    }
    if meta.kill_session_processes {
        println!("Session descendants are killed at session end (Linux cgroup v2 required).");
    }
    println!("The change takes effect within a second; no restart needed.");
    Ok(())
}

struct ReplacementPlan {
    aliases: Vec<String>,
    denied_fingerprints: Vec<Fingerprint>,
}

fn replacement_plan(
    existing: &AuthStore,
    fingerprint: Fingerprint,
    name: &str,
    force: bool,
) -> Result<ReplacementPlan> {
    let aliases: Vec<_> = existing
        .names_for_fingerprint(&fingerprint)
        .iter()
        .filter(|old| old.as_str() != name)
        .cloned()
        .collect();
    if !aliases.is_empty() && !force {
        bail!(
            "that key is already authorized as {}; revoke it first or pass --force",
            aliases
                .iter()
                .map(|old| format!("`{old}`"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let mut replaced = if force { aliases } else { Vec::new() };
    let mut denied = Vec::new();
    let mut deny_target = existing.is_fingerprint_denied(&fingerprint);
    // Replacing a name that belongs to a conflicted old fingerprint must not
    // make one of its formerly hidden aliases active. Treat those invalid
    // aliases as part of the forced repair as well.
    if force {
        deny_target |= !replaced.is_empty() || existing.fingerprint_for_name(name).is_some();
        if let Some(old_fingerprint) = existing.fingerprint_for_name(name) {
            if old_fingerprint != fingerprint {
                denied.push(old_fingerprint);
                replaced.extend(
                    existing
                        .names_for_fingerprint(&old_fingerprint)
                        .iter()
                        .filter(|old| old.as_str() != name)
                        .cloned(),
                );
            }
        }
        replaced.sort();
        replaced.dedup();
    }
    denied.sort();
    denied.dedup();
    if deny_target {
        denied.retain(|old| old != &fingerprint);
        // Clear the target marker last, after displaced keys are already safe.
        denied.push(fingerprint);
    }
    Ok(ReplacementPlan {
        aliases: replaced,
        denied_fingerprints: denied,
    })
}

fn revoke(paths: &ServerPaths, args: &Revoke) -> Result<()> {
    // Without this, `revoke ../server` would delete the host key, and an
    // absolute name could reach any .crt/.toml on the filesystem.
    validate_entry_name(&args.name)?;
    let dir = paths.authorized();
    let lock = AuthStore::lock_directory(&dir)?;
    let store = lock.load()?;
    let fingerprint = store.fingerprint_for_name(&args.name);
    if let Some(fingerprint) = fingerprint {
        lock.deny_fingerprint(fingerprint)?;
    }
    let mut names = store.fingerprint_for_name(&args.name).map_or_else(
        || vec![args.name.clone()],
        |fingerprint| store.names_for_fingerprint(&fingerprint).to_vec(),
    );
    // Remove aliases first and the explicitly requested name last. If the
    // process stops midway, no hidden alternate policy can become the winner.
    names.retain(|name| name != &args.name);
    names.push(args.name.clone());
    let mut removed = 0;
    for name in &names {
        removed += remove_entry(&dir, name)?;
    }
    if removed == 0 {
        bail!("no authorization named `{}`", args.name);
    }
    println!("Revoked `{}`.", args.name);
    let aliases = names
        .get(..names.len().saturating_sub(1))
        .unwrap_or_default();
    if !aliases.is_empty() {
        println!(
            "Also removed duplicate aliases: {}.",
            aliases
                .iter()
                .map(|name| format!("`{name}`"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(())
}

/// Delete both files backing one authorization. Returns how many existed.
fn remove_entry(dir: &Path, name: &str) -> Result<usize> {
    validate_entry_name(name)?;
    let mut removed = 0;
    for ext in ["crt", "toml"] {
        let path = dir.join(format!("{name}.{ext}"));
        if path.exists() {
            std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
            removed += 1;
        }
    }
    Ok(removed)
}

fn list(paths: &ServerPaths) -> Result<()> {
    let store = AuthStore::load(&paths.authorized())?;
    if store.stored_entries().next().is_none() {
        println!("no authorized clients in {}", paths.authorized().display());
        return Ok(());
    }
    for entry in store.stored_entries() {
        let mut notes = Vec::new();
        if store.has_fingerprint_conflict(&entry.fingerprint) {
            notes.push("CONFLICT: duplicate fingerprint; refused".to_owned());
        }
        if store.is_fingerprint_denied(&entry.fingerprint) {
            notes.push("DENIED: interrupted mutation".to_owned());
        }
        if !entry.meta.allow_shell {
            notes.push("no-shell".to_string());
        }
        if !entry.meta.allow_exec {
            notes.push("no-exec".to_string());
        }
        if !entry.meta.allowed_commands.is_empty() {
            notes.push(format!(
                "commands={}",
                entry.meta.allowed_commands.join("+")
            ));
        }
        if entry.meta.kill_session_processes {
            notes.push("kill-session-processes".to_owned());
        }
        if let Some(deadline) = entry.meta.expires_at_unix {
            let now = unix_now();
            notes.push(if now > deadline {
                "EXPIRED".to_owned()
            } else {
                format!("expires in {}d", (deadline - now).saturating_div(86_400))
            });
        }
        let suffix = if notes.is_empty() {
            String::new()
        } else {
            format!("  [{}]", notes.join(" "))
        };
        println!(
            "{:<16} {:<12} {}{suffix}",
            entry.name, entry.meta.user, entry.fingerprint
        );
    }
    Ok(())
}

fn fingerprint(paths: &ServerPaths) -> Result<()> {
    let cert = crypto::load_cert(&paths.cert()).with_context(|| {
        format!(
            "no host identity in {} (run `qsh-server keygen`)",
            paths.dir.display()
        )
    })?;
    println!("{}", Fingerprint::of_cert(&cert)?);
    Ok(())
}

fn hostname() -> String {
    nix::unistd::gethostname()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "localhost".into())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test failures should identify violated invariants"
)]
mod tests {
    use super::*;

    fn current_user_name() -> String {
        nix::unistd::User::from_uid(nix::unistd::getuid())
            .unwrap()
            .unwrap()
            .name
    }

    fn authorize_args(certificate: &Path, name: &str, force: bool) -> Authorize {
        Authorize {
            certificate: certificate.to_path_buf(),
            user: current_user_name(),
            name: Some(name.to_owned()),
            no_shell: false,
            no_exec: false,
            commands: Vec::new(),
            expires_in_days: None,
            kill_session_processes: false,
            force,
        }
    }

    fn copy_entry(dir: &Path, from: &str, to: &str) {
        for extension in ["crt", "toml"] {
            std::fs::copy(
                dir.join(format!("{from}.{extension}")),
                dir.join(format!("{to}.{extension}")),
            )
            .unwrap();
        }
    }

    #[test]
    fn authorize_publishes_only_the_certificate_bound_to_its_policy() {
        let dir = tempfile::tempdir().unwrap();
        let paths = ServerPaths::new(dir.path().join("server"));
        let source = dir.path().join("submitted.crt");
        let (cert_pem, key_pem) =
            crypto::generate_identity("client", &["localhost".into()], 30).unwrap();
        crypto::write_private(
            &source,
            &format!("{cert_pem}{key_pem}\nprivate trailing text\n"),
        )
        .unwrap();
        let original = crypto::load_cert(&source).unwrap();
        let fingerprint = Fingerprint::of_cert(&original).unwrap();
        let user = current_user_name();

        authorize(
            &paths,
            Authorize {
                certificate: source,
                user: user.clone(),
                name: Some("client".into()),
                no_shell: false,
                no_exec: false,
                commands: Vec::new(),
                expires_in_days: None,
                kill_session_processes: false,
                force: false,
            },
        )
        .unwrap();

        let published = std::fs::read_to_string(paths.authorized().join("client.crt")).unwrap();
        assert_eq!(published, cert_pem);
        let sections = pem::parse_many(published).unwrap();
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].tag(), "CERTIFICATE");
        assert_eq!(sections[0].contents(), original.as_ref());
        let store = AuthStore::load(&paths.authorized()).unwrap();
        let entry = store.lookup(&fingerprint).unwrap();
        assert_eq!(entry.meta.user, user);
        assert_eq!(entry.meta.key_fingerprint, Some(fingerprint.to_string()));
    }

    #[test]
    fn force_authorize_repairs_every_alias_for_one_key() {
        let dir = tempfile::tempdir().unwrap();
        let paths = ServerPaths::new(dir.path().join("server"));
        let source = dir.path().join("submitted.crt");
        let (cert_pem, _) = crypto::generate_identity("client", &["localhost".into()], 30).unwrap();
        crypto::write_public(&source, &cert_pem).unwrap();

        authorize(&paths, authorize_args(&source, "alpha", false)).unwrap();
        copy_entry(&paths.authorized(), "alpha", "beta");
        copy_entry(&paths.authorized(), "alpha", "gamma");
        let fingerprint = Fingerprint::of_cert(&crypto::load_cert(&source).unwrap()).unwrap();
        assert!(AuthStore::load(&paths.authorized())
            .unwrap()
            .lookup(&fingerprint)
            .is_none());

        authorize(&paths, authorize_args(&source, "current", true)).unwrap();

        let store = AuthStore::load(&paths.authorized()).unwrap();
        assert_eq!(
            store.lookup(&fingerprint).map(|entry| entry.name.as_str()),
            Some("current")
        );
        assert_eq!(store.stored_entries().count(), 1);
        for old in ["alpha", "beta", "gamma"] {
            assert!(!paths.authorized().join(format!("{old}.crt")).exists());
            assert!(!paths.authorized().join(format!("{old}.toml")).exists());
        }
    }

    #[test]
    fn revoke_removes_every_alias_for_one_key() {
        let dir = tempfile::tempdir().unwrap();
        let paths = ServerPaths::new(dir.path().join("server"));
        let source = dir.path().join("submitted.crt");
        let (cert_pem, _) = crypto::generate_identity("client", &["localhost".into()], 30).unwrap();
        crypto::write_public(&source, &cert_pem).unwrap();

        authorize(&paths, authorize_args(&source, "alpha", false)).unwrap();
        copy_entry(&paths.authorized(), "alpha", "beta");
        revoke(
            &paths,
            &Revoke {
                name: "beta".into(),
            },
        )
        .unwrap();

        assert!(AuthStore::load(&paths.authorized()).unwrap().is_empty());
        for name in ["alpha", "beta"] {
            assert!(!paths.authorized().join(format!("{name}.crt")).exists());
            assert!(!paths.authorized().join(format!("{name}.toml")).exists());
        }
    }

    #[test]
    fn interrupted_revoke_cannot_reactivate_the_remaining_alias() {
        let dir = tempfile::tempdir().unwrap();
        let paths = ServerPaths::new(dir.path().join("server"));
        let source = dir.path().join("submitted.crt");
        let (cert_pem, _) = crypto::generate_identity("client", &["localhost".into()], 30).unwrap();
        crypto::write_public(&source, &cert_pem).unwrap();
        authorize(&paths, authorize_args(&source, "alpha", false)).unwrap();
        copy_entry(&paths.authorized(), "alpha", "beta");
        let fingerprint = Fingerprint::of_cert(&crypto::load_cert(&source).unwrap()).unwrap();

        let lock = AuthStore::lock_directory(&paths.authorized()).unwrap();
        lock.deny_fingerprint(fingerprint).unwrap();
        remove_entry(&paths.authorized(), "alpha").unwrap();
        drop(lock); // Simulate the management process stopping before `beta`.

        let interrupted = AuthStore::load(&paths.authorized()).unwrap();
        assert_eq!(
            interrupted.names_for_fingerprint(&fingerprint),
            &["beta".to_owned()]
        );
        assert!(interrupted.lookup(&fingerprint).is_none());
        revoke(
            &paths,
            &Revoke {
                name: "beta".into(),
            },
        )
        .unwrap();
        assert!(AuthStore::load(&paths.authorized()).unwrap().is_empty());
    }

    #[test]
    fn revocation_tombstone_blocks_stale_files_until_reauthorization() {
        let dir = tempfile::tempdir().unwrap();
        let paths = ServerPaths::new(dir.path().join("server"));
        let source = dir.path().join("submitted.crt");
        let (cert_pem, _) = crypto::generate_identity("client", &["localhost".into()], 30).unwrap();
        crypto::write_public(&source, &cert_pem).unwrap();
        authorize(&paths, authorize_args(&source, "client", false)).unwrap();
        let cert = std::fs::read(paths.authorized().join("client.crt")).unwrap();
        let policy = std::fs::read(paths.authorized().join("client.toml")).unwrap();
        let fingerprint = Fingerprint::of_cert(&crypto::load_cert(&source).unwrap()).unwrap();

        revoke(
            &paths,
            &Revoke {
                name: "client".into(),
            },
        )
        .unwrap();
        std::fs::write(paths.authorized().join("client.crt"), cert).unwrap();
        std::fs::write(paths.authorized().join("client.toml"), policy).unwrap();
        assert!(AuthStore::load(&paths.authorized())
            .unwrap()
            .lookup(&fingerprint)
            .is_none());

        authorize(&paths, authorize_args(&source, "client", true)).unwrap();
        assert!(AuthStore::load(&paths.authorized())
            .unwrap()
            .lookup(&fingerprint)
            .is_some());
    }

    #[test]
    fn interrupted_force_replacement_cannot_reactivate_the_old_alias() {
        let dir = tempfile::tempdir().unwrap();
        let paths = ServerPaths::new(dir.path().join("server"));
        let old_source = dir.path().join("old.crt");
        let new_source = dir.path().join("new.crt");
        let (old_pem, _) = crypto::generate_identity("old", &["localhost".into()], 30).unwrap();
        let (new_pem, _) = crypto::generate_identity("new", &["localhost".into()], 30).unwrap();
        crypto::write_public(&old_source, &old_pem).unwrap();
        crypto::write_public(&new_source, &new_pem).unwrap();
        authorize(&paths, authorize_args(&old_source, "alpha", false)).unwrap();
        copy_entry(&paths.authorized(), "alpha", "beta");
        let old_fingerprint =
            Fingerprint::of_cert(&crypto::load_cert(&old_source).unwrap()).unwrap();
        let new_fingerprint =
            Fingerprint::of_cert(&crypto::load_cert(&new_source).unwrap()).unwrap();

        let lock = AuthStore::lock_directory(&paths.authorized()).unwrap();
        lock.deny_fingerprint(old_fingerprint).unwrap();
        let new_policy = AuthMeta {
            user: current_user_name(),
            key_fingerprint: Some(new_fingerprint.to_string()),
            ..Default::default()
        };
        crypto::write_public(
            &paths.authorized().join("alpha.toml"),
            &toml::to_string(&new_policy).unwrap(),
        )
        .unwrap();
        drop(lock); // Stop after policy replacement but before certificate replacement.

        let interrupted = AuthStore::load(&paths.authorized()).unwrap();
        assert!(interrupted.lookup(&old_fingerprint).is_none());
        assert!(interrupted.lookup(&new_fingerprint).is_none());

        authorize(&paths, authorize_args(&new_source, "alpha", true)).unwrap();
        let repaired = AuthStore::load(&paths.authorized()).unwrap();
        assert!(repaired.lookup(&old_fingerprint).is_none());
        assert_eq!(
            repaired
                .lookup(&new_fingerprint)
                .map(|entry| entry.name.as_str()),
            Some("alpha")
        );
        assert!(!paths.authorized().join("beta.crt").exists());
        assert!(!paths.authorized().join("beta.toml").exists());
    }
}
