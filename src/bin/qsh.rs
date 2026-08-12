//! `qsh` — the client.
//!
//! The command line is deliberately ssh-shaped so that `rsync -e qsh` and
//! `scp`-style muscle memory keep working:
//!
//! ```text
//! qsh [options] [user@]host [command [args...]]
//! ```
//!
//! Options are parsed only up to the host argument; everything after it is
//! the remote command and is passed through as a structured argument list,
//! never re-joined into a shell string.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use qsh::client::{AddressFamily, HostKeyPolicy, Options, PtyPolicy, DEFAULT_CONNECT_TIMEOUT_SECS};
use qsh::config::{ClientPaths, KnownHosts, DEFAULT_PORT};
use qsh::crypto::{self, Fingerprint};

const USAGE: &str = "\
qsh — a small SSH replacement over QUIC

Usage:
  qsh [options] [user@]host [command [args...]]
  qsh keygen [--days N] [--force]
  qsh fingerprint
  qsh known-hosts list
  qsh known-hosts add <host:port> <sha256:...>
  qsh known-hosts remove <host:port>

Options:
  -p, --port PORT        Server port (default 2222, UDP)
  -l USER                Log in as USER (must match what the server authorized)
  -i, --identity DIR     Directory holding id.crt and id.key
  -t                     Force a remote terminal
  -T                     Never allocate a remote terminal
  -E, --setenv K=V       Send an environment variable (TERM, LANG, LC_*, QSH_*)
      --accept-new       Pin an unknown host key without asking
      --refuse-new       Never pin automatically
  -o OPTION              Accepted for ssh compatibility; only
                         StrictHostKeyChecking=accept-new|yes has an effect
  -4 / -6                Use IPv4 / IPv6 only
      --connect-timeout SECS
                         Deadline per address when connecting (default 10)
  -q, --quiet            Suppress qsh's own messages
  -v, --verbose          Accepted for ssh compatibility (no extra output)
  -h, --help             Show this help
  -V, --version          Show the version

Examples:
  qsh server                              # interactive shell
  qsh server uptime                       # run a command
  rsync -e qsh -av ./data/ server:/backup # rsync transport
";

fn main() -> ExitCode {
    qsh::install_crypto_provider();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match dispatch(args) {
        // Statuses outside a byte cannot be represented; 255 is what ssh
        // reports for its own failures.
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(255)),
        Err(e) => {
            eprintln!("qsh: {e:#}");
            ExitCode::from(255)
        }
    }
}

fn dispatch(args: Vec<String>) -> Result<i32> {
    match args.first().map(String::as_str) {
        None => {
            eprint!("{USAGE}");
            Ok(255)
        }
        Some("-h" | "--help") => {
            print!("{USAGE}");
            Ok(0)
        }
        Some("-V" | "--version") => {
            println!("qsh {}", qsh::VERSION);
            Ok(0)
        }
        Some("keygen") => keygen(args.get(1..).unwrap_or_default()).map(|()| 0),
        Some("fingerprint") => fingerprint().map(|()| 0),
        Some("known-hosts") => known_hosts(args.get(1..).unwrap_or_default()).map(|()| 0),
        _ => connect(args),
    }
}

/// `qsh keygen`
fn keygen(args: &[String]) -> Result<()> {
    let mut days = 3650u32;
    let mut force = false;
    let mut dir: Option<PathBuf> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--force" | "-f" => force = true,
            "--days" => {
                days = it
                    .next()
                    .context("--days needs a value")?
                    .parse()
                    .context("--days must be a number")?;
            }
            "--identity" | "-i" | "--dir" => {
                dir = Some(PathBuf::from(it.next().context("--identity needs a path")?));
            }
            other => bail!("unknown option for keygen: {other}"),
        }
    }

    let paths = match dir {
        Some(d) => ClientPaths::new(d),
        None => ClientPaths::discover()?,
    };
    if paths.cert().exists() && !force {
        bail!(
            "{} already exists; pass --force to replace your identity",
            paths.cert().display()
        );
    }

    let name = format!(
        "{}@{}",
        std::env::var("USER").unwrap_or_else(|_| "user".into()),
        hostname()
    );
    let (cert_pem, key_pem) = crypto::generate_identity(&name, &["qsh-client".into()], days)?;
    crypto::write_private(&paths.key(), &key_pem)?;
    crypto::write_public(&paths.cert(), &cert_pem)?;

    let fp = Fingerprint::of_cert(&crypto::load_cert(&paths.cert())?)?;
    println!("Wrote {}", paths.key().display());
    println!("Wrote {}", paths.cert().display());
    println!("Fingerprint: {fp}");
    println!("Valid for {days} days.");
    println!();
    println!("Authorize this key on the server:");
    println!(
        "  scp {} server:/tmp/{}.crt",
        paths.cert().display(),
        whoami_tag()
    );
    println!(
        "  ssh server sudo qsh-server authorize /tmp/{}.crt --user <account>",
        whoami_tag()
    );
    Ok(())
}

/// `qsh fingerprint`
fn fingerprint() -> Result<()> {
    let paths = ClientPaths::discover()?;
    let cert = crypto::load_cert(&paths.cert())
        .with_context(|| format!("no identity in {} (run `qsh keygen`)", paths.dir.display()))?;
    println!("{}", Fingerprint::of_cert(&cert)?);
    Ok(())
}

/// `qsh known-hosts ...`
fn known_hosts(args: &[String]) -> Result<()> {
    let paths = ClientPaths::discover()?;
    let mut kh = KnownHosts::load(&paths.known_hosts())?;
    match args.first().map(String::as_str) {
        None | Some("list") => {
            if kh.entries().is_empty() {
                println!("no known hosts in {}", paths.known_hosts().display());
            }
            for (host, fp) in kh.entries() {
                println!("{host} {fp}");
            }
        }
        Some("add") => {
            let host = args
                .get(1)
                .context("usage: qsh known-hosts add <host:port> <sha256:...>")?;
            let fp = args
                .get(2)
                .context("usage: qsh known-hosts add <host:port> <sha256:...>")?;
            kh.set(host, Fingerprint::parse(fp)?)?;
            println!("pinned {host}");
        }
        Some("remove") => {
            let host = args
                .get(1)
                .context("usage: qsh known-hosts remove <host:port>")?;
            let n = kh.remove(host)?;
            println!(
                "removed {n} entr{} for {host}",
                if n == 1 { "y" } else { "ies" }
            );
        }
        Some(other) => bail!("unknown known-hosts command: {other}"),
    }
    Ok(())
}

/// Parsed command line for a connection.
#[derive(Debug)]
struct Cli {
    opts: Options,
}

/// `qsh [options] [user@]host [command...]`
fn connect(args: Vec<String>) -> Result<i32> {
    let cli = parse_connect(args)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")?;
    let result = runtime.block_on(qsh::client::run(cli.opts));
    // The stdin reader can be parked in a blocking read that nothing will
    // ever wake; dropping the runtime would wait for it forever.
    runtime.shutdown_background();
    result
}

/// The options as they accumulate while the command line is walked.
struct Parsed {
    port: u16,
    user: Option<String>,
    identity: Option<PathBuf>,
    pty: PtyPolicy,
    env: Vec<(String, String)>,
    policy: HostKeyPolicy,
    quiet: bool,
    family: AddressFamily,
    connect_timeout: u64,
}

impl Default for Parsed {
    fn default() -> Self {
        Self {
            port: DEFAULT_PORT,
            user: None,
            identity: None,
            pty: PtyPolicy::Auto,
            env: Vec::new(),
            policy: HostKeyPolicy::Ask,
            quiet: false,
            family: AddressFamily::Any,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT_SECS,
        }
    }
}

impl Parsed {
    fn into_options(self, host: String, command: Vec<String>) -> Options {
        Options {
            host,
            port: self.port,
            user: self.user,
            command: (!command.is_empty()).then_some(command),
            pty: self.pty,
            env: self.env,
            host_key_policy: self.policy,
            paths_dir: self.identity,
            quiet: self.quiet,
            family: self.family,
            connect_timeout_secs: self.connect_timeout,
        }
    }
}

fn parse_connect(args: Vec<String>) -> Result<Cli> {
    let mut p = Parsed::default();
    let mut host: Option<String> = None;
    let mut command: Vec<String> = Vec::new();

    let mut it = args.into_iter().peekable();
    // Options first; the first bare word is the host and ends option parsing.
    while let Some(arg) = it.next() {
        if host.is_some() {
            command.push(arg);
            continue;
        }
        // A value attached to a short flag, e.g. `-p2222`.
        let split = |arg: &str, flag: &str| -> Option<String> {
            arg.strip_prefix(flag)
                .filter(|rest| !rest.is_empty())
                .map(str::to_string)
        };
        match arg.as_str() {
            "--" => {
                host = it.next();
                if host.is_none() {
                    bail!("missing host after `--`");
                }
            }
            "-p" | "--port" => {
                p.port = it
                    .next()
                    .context("-p needs a port number")?
                    .parse()
                    .context("-p must be a port number")?;
            }
            a if split(a, "-p").is_some() => {
                p.port = split(a, "-p")
                    .unwrap_or_default()
                    .parse()
                    .context("-p must be a port number")?;
            }
            "-l" | "--login-name" => p.user = Some(it.next().context("-l needs a user name")?),
            a if split(a, "-l").is_some() => p.user = split(a, "-l"),
            "-i" | "--identity" => {
                p.identity = Some(PathBuf::from(it.next().context("-i needs a directory")?));
            }
            "-t" => p.pty = PtyPolicy::Force,
            "-T" => p.pty = PtyPolicy::Never,
            "-q" | "--quiet" => p.quiet = true,
            "-4" => p.family = AddressFamily::V4,
            "-6" => p.family = AddressFamily::V6,
            "--connect-timeout" => {
                p.connect_timeout = it
                    .next()
                    .context("--connect-timeout needs a number of seconds")?
                    .parse()
                    .context("--connect-timeout must be a number of seconds")?;
            }
            "-v" | "--verbose" | "-C" | "-n" | "-a" | "-x" => {}
            "-E" | "--setenv" => {
                let kv = it.next().context("-E needs KEY=VALUE")?;
                p.env.push(split_kv(&kv)?);
            }
            "--accept-new" => p.policy = HostKeyPolicy::AcceptNew,
            "--refuse-new" => p.policy = HostKeyPolicy::Refuse,
            "-o" | "--option" => {
                let opt = it.next().context("-o needs an option")?;
                apply_ssh_option(&opt, &mut p.policy);
            }
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            other if other.starts_with('-') && other.len() > 1 => {
                bail!("unknown option: {other}");
            }
            other => host = Some(other.to_string()),
        }
    }

    let Some(target) = host else {
        bail!("no host given\n\n{USAGE}");
    };
    let (target_user, host) = split_target(&target);
    if let Some(u) = target_user {
        p.user = Some(u);
    }
    if host.is_empty() {
        bail!("empty host name");
    }

    Ok(Cli {
        opts: p.into_options(host, command),
    })
}

/// Understand the handful of `-o` settings that map onto qsh behaviour.
fn apply_ssh_option(opt: &str, policy: &mut HostKeyPolicy) {
    let Some((key, value)) = opt.split_once('=') else {
        return;
    };
    if key.eq_ignore_ascii_case("StrictHostKeyChecking") {
        *policy = match value.to_ascii_lowercase().as_str() {
            "accept-new" | "no" | "off" => HostKeyPolicy::AcceptNew,
            "yes" | "on" => HostKeyPolicy::Refuse,
            _ => *policy,
        };
    }
}

fn split_kv(kv: &str) -> Result<(String, String)> {
    kv.split_once('=')
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .ok_or_else(|| anyhow::anyhow!("expected KEY=VALUE, got `{kv}`"))
}

/// Split `user@host`, leaving IPv6 literals such as `[::1]` intact.
fn split_target(target: &str) -> (Option<String>, String) {
    match target.rsplit_once('@') {
        Some((user, host)) if !user.is_empty() => (Some(user.to_string()), host.to_string()),
        _ => (None, target.to_string()),
    }
}

fn hostname() -> String {
    nix::unistd::gethostname()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "localhost".into())
}

fn whoami_tag() -> String {
    format!(
        "{}-{}",
        std::env::var("USER").unwrap_or_else(|_| "user".into()),
        hostname()
    )
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

    fn parse(args: &[&str]) -> Options {
        parse_connect(args.iter().map(|s| (*s).to_owned()).collect())
            .unwrap()
            .opts
    }

    #[test]
    fn plain_host_opens_a_shell() {
        let o = parse(&["server"]);
        assert_eq!(o.host, "server");
        assert_eq!(o.port, DEFAULT_PORT);
        assert!(o.command.is_none());
        assert!(o.user.is_none());
    }

    #[test]
    fn user_at_host_and_dash_l_both_work() {
        assert_eq!(parse(&["alice@server"]).user.as_deref(), Some("alice"));
        assert_eq!(
            parse(&["-l", "alice", "server"]).user.as_deref(),
            Some("alice")
        );
        assert_eq!(parse(&["-lalice", "server"]).user.as_deref(), Some("alice"));
    }

    #[test]
    fn options_after_the_host_belong_to_the_remote_command() {
        // Exactly how rsync invokes the transport.
        let o = parse(&[
            "-l",
            "alice",
            "server",
            "rsync",
            "--server",
            "-vlogDtpre.iLsfxCIvu",
            ".",
            "/backup/data/",
        ]);
        assert_eq!(o.host, "server");
        assert_eq!(o.user.as_deref(), Some("alice"));
        assert_eq!(
            o.command.unwrap(),
            vec![
                "rsync",
                "--server",
                "-vlogDtpre.iLsfxCIvu",
                ".",
                "/backup/data/"
            ]
        );
    }

    #[test]
    fn ports_parse_in_both_spellings() {
        assert_eq!(parse(&["-p", "9000", "h"]).port, 9000);
        assert_eq!(parse(&["-p9000", "h"]).port, 9000);
        assert_eq!(parse(&["--port", "9000", "h"]).port, 9000);
    }

    #[test]
    fn pty_flags_are_honoured() {
        assert_eq!(parse(&["-t", "h", "top"]).pty, PtyPolicy::Force);
        assert_eq!(parse(&["-T", "h"]).pty, PtyPolicy::Never);
        assert_eq!(parse(&["h"]).pty, PtyPolicy::Auto);
    }

    #[test]
    fn ssh_compatibility_options_are_tolerated() {
        let o = parse(&["-C", "-v", "-o", "Compression=yes", "h", "true"]);
        assert_eq!(o.host, "h");
        assert_eq!(o.command.unwrap(), vec!["true"]);
        assert_eq!(o.host_key_policy, HostKeyPolicy::Ask);
    }

    #[test]
    fn address_family_flags_are_honoured_not_ignored() {
        assert_eq!(parse(&["h"]).family, AddressFamily::Any);
        assert_eq!(parse(&["-4", "h"]).family, AddressFamily::V4);
        assert_eq!(parse(&["-6", "h"]).family, AddressFamily::V6);
    }

    #[test]
    fn connect_timeout_is_configurable() {
        assert_eq!(
            parse(&["h"]).connect_timeout_secs,
            DEFAULT_CONNECT_TIMEOUT_SECS
        );
        assert_eq!(
            parse(&["--connect-timeout", "3", "h"]).connect_timeout_secs,
            3
        );
    }

    #[test]
    fn strict_host_key_checking_maps_to_a_policy() {
        assert_eq!(
            parse(&["-o", "StrictHostKeyChecking=accept-new", "h"]).host_key_policy,
            HostKeyPolicy::AcceptNew
        );
        assert_eq!(
            parse(&["-o", "stricthostkeychecking=yes", "h"]).host_key_policy,
            HostKeyPolicy::Refuse
        );
    }

    #[test]
    fn double_dash_allows_hosts_that_look_like_options() {
        let o = parse(&["--", "-weird-host", "ls"]);
        assert_eq!(o.host, "-weird-host");
        assert_eq!(o.command.unwrap(), vec!["ls"]);
    }

    #[test]
    fn setenv_is_collected() {
        let o = parse(&["-E", "LC_ALL=C", "h"]);
        assert_eq!(o.env, vec![("LC_ALL".to_string(), "C".to_string())]);
    }

    #[test]
    fn unknown_options_before_the_host_are_errors() {
        let err = parse_connect(vec!["--nope".into(), "h".into()]).unwrap_err();
        assert!(err.to_string().contains("unknown option"), "{err}");
    }

    #[test]
    fn missing_host_is_an_error() {
        assert!(parse_connect(vec!["-t".into()]).is_err());
    }

    #[test]
    fn ipv6_literals_survive_target_splitting() {
        assert_eq!(split_target("[::1]"), (None, "[::1]".to_string()));
        assert_eq!(
            split_target("alice@[::1]"),
            (Some("alice".into()), "[::1]".to_string())
        );
    }
}
