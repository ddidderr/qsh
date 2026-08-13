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
    /// Restrict execution to these programs; repeatable. Without it, any
    /// program is allowed.
    #[arg(long = "command", value_name = "PROGRAM")]
    commands: Vec<String>,
    /// Stop accepting this key after N days. The deadline is recorded here on
    /// the server and enforced regardless of what certificate the client
    /// later presents.
    #[arg(long, value_name = "DAYS")]
    expires_in_days: Option<u32>,
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
    let config_path = args.config.unwrap_or_else(|| paths.config());
    let cfg = ServerConfig::load(&config_path)?;
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
    qsh::child::resolve_user(&args.user)?;

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
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let cert_path = dir.join(format!("{name}.crt"));
    if cert_path.exists() && !args.force {
        bail!(
            "{} already exists; pass --force to replace it",
            cert_path.display()
        );
    }

    let existing = AuthStore::load(&dir)?;
    let mut replaced: Option<String> = None;
    if let Some(other) = existing.lookup(&fp) {
        if other.name != name {
            if !args.force {
                bail!(
                    "that key is already authorized as `{}`; revoke it first or pass --force",
                    other.name
                );
            }
            // The old files have to go — two entries for one key would be
            // resolved by file name order, so the policy that actually applied
            // would be a coin toss, and revoking the new name would quietly
            // reinstate the old one. Removing them only after the new pair is
            // on disk means a failure in between leaves the old authorization
            // working rather than leaving the key locked out.
            replaced = Some(other.name.clone());
        }
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
    };

    let pem = std::fs::read_to_string(&args.certificate)
        .with_context(|| format!("reading {}", args.certificate.display()))?;
    // Certificate first, policy second. Each write is atomic on its own, and
    // an entry is only usable once both exist — the policy names the key it
    // belongs to, so a half-finished pair is refused rather than guessed at.
    crypto::write_public(&cert_path, &pem)?;
    crypto::write_public(
        &dir.join(format!("{name}.toml")),
        &format!(
            "# authorized qsh client `{name}`\n{}",
            toml::to_string_pretty(&meta)?
        ),
    )?;

    if let Some(old) = &replaced {
        remove_entry(&dir, old)?;
    }

    println!("Authorized `{name}` ({fp}) as user `{}`.", args.user);
    if let Some(old) = replaced {
        println!("Removed the previous authorization `{old}` for the same key.");
    }
    if let Some(days) = args.expires_in_days {
        println!("Expires in {days} days; after that the key is refused.");
    }
    if !meta.allowed_commands.is_empty() {
        println!("Restricted to: {}", meta.allowed_commands.join(", "));
    }
    if !meta.allow_shell {
        println!("Interactive shells are refused for this key.");
    }
    if !meta.allow_exec {
        println!("Remote commands are refused for this key.");
    }
    println!("The change takes effect within a second; no restart needed.");
    Ok(())
}

fn revoke(paths: &ServerPaths, args: &Revoke) -> Result<()> {
    // Without this, `revoke ../server` would delete the host key, and an
    // absolute name could reach any .crt/.toml on the filesystem.
    validate_entry_name(&args.name)?;
    let dir = paths.authorized();
    if remove_entry(&dir, &args.name)? == 0 {
        bail!("no authorization named `{}`", args.name);
    }
    println!("Revoked `{}`.", args.name);
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
    if store.is_empty() {
        println!("no authorized clients in {}", paths.authorized().display());
        return Ok(());
    }
    for entry in store.entries() {
        let mut notes = Vec::new();
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
