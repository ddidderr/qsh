//! Spawning the remote process: privilege drop, environment, PTY setup.

use std::ffi::CString;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{bail, Context, Result};
use nix::sys::signal::{killpg, Signal};
use nix::unistd::{Gid, Pid, Uid, User};
use tokio::process::{ChildStderr, ChildStdin, ChildStdout, Command};

use crate::config::env_allowed;
use crate::proto::{PtySize, Request};
use crate::pty::{self, PtyMaster};

/// Default `PATH` for remote processes. Clients cannot override it.
const DEFAULT_PATH: &str = "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin";

/// How the remote process is wired up.
#[derive(Debug)]
pub enum ChildIo {
    /// Interactive session: one bidirectional terminal.
    Pty(PtyMaster),
    /// Non-interactive session: three untouched byte streams.
    Pipes {
        stdin: ChildStdin,
        stdout: ChildStdout,
        stderr: ChildStderr,
    },
}

/// A running remote process.
#[derive(Debug)]
pub struct Spawned {
    pub child: tokio::process::Child,
    pub io: ChildIo,
}

/// Deliver a signal to a remote process and, preferably, its whole job.
///
/// The child called `setsid`, so it leads its own process group and the
/// negative pid reaches every process in it — the same reach a terminal has
/// when you press Ctrl-C. If the group is gone, do not signal that numeric pid:
/// it may already belong to an unrelated process.
///
/// This is the only place in the crate that signals anything.
pub fn signal_process_group(pid: u32, sig: i32) {
    let (Ok(pid), Ok(sig)) = (i32::try_from(pid), Signal::try_from(sig)) else {
        return;
    };
    if pid <= 0 {
        return;
    }
    let pid = Pid::from_raw(pid);
    let _ = killpg(pid, sig);
}

/// Does the process group still have any member left?
///
/// Uses signal 0, which performs the permission and existence checks without
/// delivering anything.
#[must_use]
pub fn process_group_alive(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    pid > 0 && killpg(Pid::from_raw(pid), None).is_ok()
}

impl Spawned {
    /// Send a signal to the process group of the remote process.
    pub fn signal(&self, sig: i32) {
        if let Some(pid) = self.child.id() {
            signal_process_group(pid, sig);
        }
    }

    /// Resize the terminal, if this session has one.
    ///
    /// # Errors
    /// Fails if the `TIOCSWINSZ` ioctl on the PTY master is rejected.
    pub fn resize(&self, size: PtySize) -> Result<()> {
        if let ChildIo::Pty(master) = &self.io {
            master.set_size(size)?;
            self.signal(libc::SIGWINCH);
        }
        Ok(())
    }
}

fn home_of(user: &User) -> PathBuf {
    if user.dir.is_dir() {
        user.dir.clone()
    } else {
        PathBuf::from("/")
    }
}

fn shell_of(user: &User) -> PathBuf {
    if user.shell.as_os_str().is_empty() {
        PathBuf::from("/bin/sh")
    } else {
        user.shell.clone()
    }
}

/// Decide before forking whether the target needs fresh supplementary groups.
#[allow(unsafe_code, reason = "issetugid has no safe wrapper")]
fn needs_identity_switch(user: &User) -> Result<bool> {
    let running_as_root = Uid::effective().is_root();
    let must_switch = user.uid != Uid::current()
        || user.uid != Uid::effective()
        || user.gid != Gid::current()
        || user.gid != Gid::effective();
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd"
    ))]
    let must_switch = {
        let uids = nix::unistd::getresuid().context("reading server user IDs")?;
        let gids = nix::unistd::getresgid().context("reading server group IDs")?;
        must_switch || user.uid != uids.saved || user.gid != gids.saved
    };
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "netbsd"))]
    if !running_as_root && unsafe { libc::issetugid() } != 0 {
        bail!(
            "cannot run as `{}`: qsh-server has changed credentials",
            user.name
        );
    }
    if must_switch && !running_as_root {
        bail!(
            "cannot run as `{}`: qsh-server is not running as root",
            user.name
        );
    }
    Ok(must_switch)
}

/// The identity information that may require NSS lookups. Resolve this before
/// taking the server's short-lived authorization lock for the final check.
#[derive(Debug)]
pub(crate) struct PreparedIdentity {
    switch: bool,
    groups: Vec<libc::gid_t>,
}

/// Resolve the target's supplementary groups before spawning a child.
///
/// # Errors
/// Fails if the daemon cannot assume the target identity or group lookup fails.
pub(crate) fn prepare_identity(user: &User) -> Result<PreparedIdentity> {
    let switch = needs_identity_switch(user)?;
    let username = CString::new(user.name.as_str()).context("user name contains a NUL byte")?;
    let groups = if switch {
        nix::unistd::getgrouplist(&username, user.gid)
            .with_context(|| format!("looking up the groups of `{}`", user.name))?
            .into_iter()
            .map(Gid::as_raw)
            .collect()
    } else {
        Vec::new()
    };
    Ok(PreparedIdentity { switch, groups })
}

/// Start the process described by `req` as `user`.
///
/// When the server does not run as root, `user` must be the account the
/// server itself runs as; there is no way to change identity otherwise.
///
/// # Errors
/// Fails if the target user cannot be assumed, a PTY cannot be allocated, or
/// the program cannot be executed.
pub fn spawn(user: &User, req: &Request) -> Result<Spawned> {
    spawn_prepared(user, req, prepare_identity(user)?)
}

/// Spawn using identity data that was resolved before the final authorization
/// check. The caller must not use this for another account.
///
/// # Errors
/// Fails if a PTY cannot be allocated or the program cannot be executed.
#[allow(unsafe_code, reason = "pre_exec runs between fork and exec")]
pub(crate) fn spawn_prepared(
    user: &User,
    req: &Request,
    identity: PreparedIdentity,
) -> Result<Spawned> {
    let PreparedIdentity { switch, groups } = identity;

    let home = home_of(user);
    let shell = shell_of(user);

    let mut cmd =
        if let Some((program, args)) = req.command.as_deref().and_then(<[String]>::split_first) {
            let mut cmd = Command::new(program);
            cmd.args(args);
            cmd
        } else {
            // No command: an interactive login shell, exactly like `ssh host`.
            // The leading `-` in argv[0] is how a shell learns it is a login shell.
            let mut cmd = Command::new(&shell);
            let base = shell.file_name().and_then(|s| s.to_str()).unwrap_or("sh");
            cmd.as_std_mut().arg0(format!("-{base}"));
            cmd
        };

    cmd.env_clear()
        .env("PATH", DEFAULT_PATH)
        .env("HOME", &home)
        .env("USER", &user.name)
        .env("LOGNAME", &user.name)
        .env("SHELL", &shell)
        .current_dir(&home);

    if let Some(p) = &req.pty {
        cmd.env("TERM", sanitize_term(&p.term));
    }
    for (k, v) in &req.env {
        if env_allowed(k) && !v.contains('\0') && !k.contains('\0') {
            if k == "TERM" {
                cmd.env(k, sanitize_term(v));
            } else {
                cmd.env(k, v);
            }
        }
    }

    // All NSS/group lookups have already finished before the fork. In the
    // child the pre-exec hook only applies the resolved numeric identities.
    let uid = user.uid.as_raw();
    let gid = user.gid.as_raw();

    let master = if let Some(p) = &req.pty {
        let (master, slave) = pty::open(p.size)?;
        let slave_in = slave.try_clone().context("duplicating the PTY slave")?;
        let slave_out = slave.try_clone().context("duplicating the PTY slave")?;
        cmd.stdin(Stdio::from(slave_in))
            .stdout(Stdio::from(slave_out))
            .stderr(Stdio::from(slave));
        Some(master)
    } else {
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        None
    };
    let controlling_terminal = master.is_some();
    // SAFETY: only async-signal-safe libc calls between fork and exec.
    unsafe {
        cmd.as_std_mut().pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // stdin is the PTY slave; make it our controlling terminal.
            if controlling_terminal && libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            drop_privileges(switch, &groups, uid, gid)
        });
    }
    let mut child = {
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let _guard = pty::spawn_lock()?;
        cmd.spawn()
            .with_context(|| describe(req.command.as_ref(), &shell))?
    };
    let io = if let Some(master) = master {
        ChildIo::Pty(master)
    } else {
        let missing = || anyhow::anyhow!("a piped standard stream was not created");
        ChildIo::Pipes {
            stdin: child.stdin.take().ok_or_else(missing)?,
            stdout: child.stdout.take().ok_or_else(missing)?,
            stderr: child.stderr.take().ok_or_else(missing)?,
        }
    };
    Ok(Spawned { child, io })
}

fn describe(command: Option<&Vec<String>>, shell: &Path) -> String {
    match command.and_then(|argv| argv.first()) {
        Some(program) => format!("executing `{program}`"),
        None => format!("starting login shell `{}`", shell.display()),
    }
}

/// Runs between `fork` and `exec`; must stay async-signal-safe.
///
/// Every call here is a plain syscall. `groups` was resolved before the fork
/// precisely so that no NSS lookup happens on this side of it.
#[allow(
    unsafe_code,
    reason = "credential and group syscalls must run between fork and exec"
)]
fn drop_privileges(
    switch: bool,
    groups: &[libc::gid_t],
    uid: libc::uid_t,
    gid: libc::gid_t,
) -> std::io::Result<()> {
    // SAFETY: async-signal-safe syscalls only. `groups` is owned by the
    // closure, so the slice stays valid across the fork.
    unsafe {
        if switch && libc::setgroups(groups.len(), groups.as_ptr()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // Always normalize all three IDs, even when the visible real and
        // effective IDs already match. A saved ID can otherwise survive exec
        // and let the remote program regain a different identity.
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "openbsd"
        ))]
        {
            if libc::setresgid(gid, gid, gid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setresuid(uid, uid, uid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let (mut group_real, mut group_effective, mut group_saved) = (0, 0, 0);
            if libc::getresgid(
                &raw mut group_real,
                &raw mut group_effective,
                &raw mut group_saved,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            let (mut user_real, mut user_effective, mut user_saved) = (0, 0, 0);
            if libc::getresuid(
                &raw mut user_real,
                &raw mut user_effective,
                &raw mut user_saved,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if [group_real, group_effective, group_saved] != [gid; 3]
                || [user_real, user_effective, user_saved] != [uid; 3]
            {
                return Err(std::io::Error::other("failed to drop privileges"));
            }
        }
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "netbsd"))]
        {
            // Privileged calls reset saved IDs. NetBSD also does so for the
            // current real ID; on macOS, the issetugid check above rejects
            // unprivileged processes whose IDs changed since exec.
            if libc::setgid(gid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setuid(uid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "openbsd",
            target_os = "macos",
            target_os = "ios",
            target_os = "netbsd"
        )))]
        {
            return Err(std::io::Error::other(
                "cannot safely normalize saved user and group IDs on this platform",
            ));
        }
        // Refuse to exec if the identity change did not stick, and make sure
        // it cannot be undone.
        if libc::getuid() != uid
            || libc::geteuid() != uid
            || libc::getgid() != gid
            || libc::getegid() != gid
            || (uid != 0 && libc::setuid(0) == 0)
            || (uid != 0 && gid != 0 && libc::setgid(0) == 0)
        {
            return Err(std::io::Error::other("failed to drop privileges"));
        }
    }
    Ok(())
}

/// `TERM` ends up in the child's environment, so keep it boring.
fn sanitize_term(term: &str) -> String {
    let cleaned: String = term
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+'))
        .take(64)
        .collect();
    if cleaned.is_empty() {
        "dumb".to_owned()
    } else {
        cleaned
    }
}

/// Look up a local account by name.
///
/// # Errors
/// Fails if the lookup errors or no such account exists.
pub fn resolve_user(name: &str) -> Result<User> {
    User::from_name(name)
        .with_context(|| format!("looking up user `{name}`"))?
        .ok_or_else(|| anyhow::anyhow!("no such local user: `{name}`"))
}

/// The account the current process runs as.
///
/// # Errors
/// Fails if the current uid has no passwd entry.
pub fn current_user() -> Result<User> {
    User::from_uid(Uid::current())
        .context("looking up the current user")?
        .ok_or_else(|| anyhow::anyhow!("the current uid has no passwd entry"))
}

/// Terminal file descriptor of the child's PTY, if any (used by tests).
#[must_use]
pub fn pty_fd(io: &ChildIo) -> Option<i32> {
    match io {
        ChildIo::Pty(m) => Some(m.as_raw_fd()),
        ChildIo::Pipes { .. } => None,
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
    use crate::proto::{PtyRequest, PROTOCOL_VERSION};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn request(argv: &[&str], pty: bool) -> Request {
        Request {
            version: PROTOCOL_VERSION,
            user: None,
            command: Some(argv.iter().map(|s| (*s).to_owned()).collect()),
            pty: pty.then(|| PtyRequest {
                term: "xterm".into(),
                size: PtySize { cols: 80, rows: 24 },
            }),
            env: Vec::new(),
        }
    }

    #[test]
    fn term_is_sanitized() {
        assert_eq!(sanitize_term("xterm-256color"), "xterm-256color");
        assert_eq!(sanitize_term("x;rm -rf /"), "xrm-rf");
        assert_eq!(sanitize_term(""), "dumb");
        assert_eq!(sanitize_term(&"a".repeat(200)).len(), 64);
    }

    #[tokio::test]
    async fn exec_streams_stdout_and_stderr_separately() {
        let user = current_user().unwrap();
        let mut sp = spawn(
            &user,
            &request(&["sh", "-c", "printf out; printf err >&2; exit 7"], false),
        )
        .unwrap();

        let ChildIo::Pipes { stdout, stderr, .. } = &mut sp.io else {
            panic!("expected pipes");
        };
        let mut o = String::new();
        let mut e = String::new();
        stdout.read_to_string(&mut o).await.unwrap();
        stderr.read_to_string(&mut e).await.unwrap();
        assert_eq!(o, "out");
        assert_eq!(e, "err");
        assert_eq!(sp.child.wait().await.unwrap().code(), Some(7));
    }

    #[tokio::test]
    async fn exec_passes_binary_stdin_through_unchanged() {
        let user = current_user().unwrap();
        let Spawned { mut child, io } = spawn(&user, &request(&["cat"], false)).unwrap();
        let payload: Vec<u8> = (0u8..=255).collect();

        let ChildIo::Pipes {
            mut stdin,
            mut stdout,
            ..
        } = io
        else {
            panic!("expected pipes");
        };
        stdin.write_all(&payload).await.unwrap();
        // Only dropping the handle closes the pipe, which is what the server
        // does on StdinEof; `shutdown()` alone would leave `cat` waiting.
        drop(stdin);
        let mut got = Vec::new();
        stdout.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, payload);
        assert!(child.wait().await.unwrap().success());
    }

    #[tokio::test]
    async fn environment_is_scrubbed() {
        let user = current_user().unwrap();
        let mut req = request(&["sh", "-c", "echo \"$LD_PRELOAD/$TERM/$LC_ALL\""], false);
        req.env = vec![
            ("LD_PRELOAD".into(), "/evil.so".into()),
            ("LC_ALL".into(), "C".into()),
        ];
        req.pty = None;
        let mut sp = spawn(&user, &req).unwrap();
        let ChildIo::Pipes { stdout, .. } = &mut sp.io else {
            panic!("expected pipes");
        };
        let mut out = String::new();
        stdout.read_to_string(&mut out).await.unwrap();
        assert_eq!(out.trim(), "//C");
    }

    #[tokio::test]
    async fn explicit_term_is_sanitized_in_pty_and_pipe_sessions() {
        let user = current_user().unwrap();
        for pty in [false, true] {
            for (value, expected) in [
                ("evil term\n../x".to_owned(), "evilterm..x".to_owned()),
                ("☃\n/".to_owned(), "dumb".to_owned()),
                ("a".repeat(200), "a".repeat(64)),
                ("xterm-256color".to_owned(), "xterm-256color".to_owned()),
            ] {
                let mut req = request(&["printenv", "TERM"], pty);
                req.env = vec![
                    ("TERM".into(), "earlier".into()),
                    ("TERM".into(), value),
                    ("TERM".into(), "ignored\0value".into()),
                ];
                let mut sp = spawn(&user, &req).unwrap();
                let mut out = String::new();
                match &mut sp.io {
                    ChildIo::Pty(master) => master.read_to_string(&mut out).await.unwrap(),
                    ChildIo::Pipes { stdout, .. } => stdout.read_to_string(&mut out).await.unwrap(),
                };
                assert!(sp.child.wait().await.unwrap().success());
                assert_eq!(out.trim_end_matches(['\r', '\n']), expected);
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn another_session_does_not_inherit_open_pty_descriptors() {
        use std::os::fd::AsRawFd;

        let user = current_user().unwrap();
        let (master, slave) = pty::open(PtySize::default()).unwrap();
        let script = format!(
            "test ! -e /proc/self/fd/{} && test ! -e /proc/self/fd/{}",
            master.as_raw_fd(),
            slave.as_raw_fd()
        );
        for use_pty in [false, true] {
            let mut sp = spawn(&user, &request(&["sh", "-c", &script], use_pty)).unwrap();
            assert!(sp.child.wait().await.unwrap().success());
        }
    }

    #[tokio::test]
    async fn pty_session_gets_a_controlling_terminal() {
        let user = current_user().unwrap();
        let mut sp = spawn(&user, &request(&["sh", "-c", "tty; exit 0"], true)).unwrap();
        let ChildIo::Pty(master) = &mut sp.io else {
            panic!("expected a pty");
        };
        let mut buf = vec![0u8; 256];
        let n = master.read(&mut buf).await.unwrap();
        let out = String::from_utf8_lossy(&buf[..n]).to_string();
        assert!(
            out.contains("/dev/pts/") || out.contains("/dev/tty"),
            "{out}"
        );
        let _ = sp.child.wait().await;
    }

    #[tokio::test]
    async fn signals_reach_the_child() {
        let user = current_user().unwrap();
        let mut sp = spawn(&user, &request(&["sleep", "60"], false)).unwrap();
        sp.signal(libc::SIGTERM);
        let status = sp.child.wait().await.unwrap();
        assert!(status.code().is_none(), "expected death by signal");
    }

    #[test]
    fn switching_user_without_root_is_refused() {
        if Uid::effective().is_root() {
            return; // meaningless as root
        }
        let other = User::from_uid(Uid::from_raw(0)).unwrap().unwrap();
        let Err(err) = spawn(&other, &request(&["true"], false)) else {
            panic!("expected the spawn to be refused")
        };
        assert!(err.to_string().contains("not running as root"), "{err}");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[allow(
        unsafe_code,
        reason = "construct mixed credentials in a test subprocess"
    )]
    async fn mixed_credentials_cannot_reach_remote_exec() {
        use std::os::unix::process::CommandExt as _;

        const MARKER: &str = "QSH_TEST_MIXED_CREDENTIALS";
        let user = ["nobody", "daemon"].into_iter().find_map(|name| {
            User::from_name(name)
                .unwrap()
                .filter(|user| !user.uid.is_root() && user.gid.as_raw() != 0)
        });
        let Some(user) = user else {
            return;
        };

        if let Ok(case) = std::env::var(MARKER) {
            if case == "saved-root" {
                // Exec copies the effective ID into the saved slot, so create
                // this state after the isolated test subprocess has started.
                // SAFETY: only this subprocess changes credentials; both calls
                // use fixed numeric IDs and run before starting a remote child.
                unsafe {
                    assert_eq!(libc::setresgid(user.gid.as_raw(), user.gid.as_raw(), 0), 0);
                    assert_eq!(libc::setresuid(user.uid.as_raw(), user.uid.as_raw(), 0), 0);
                }
            }
            assert_eq!(Uid::current(), user.uid);
            assert_eq!(Gid::current(), user.gid);
            if case == "effective-root" {
                assert!(Uid::effective().is_root());
                let mut spawned =
                    spawn(&user, &request(&["cat", "/proc/self/status"], false)).unwrap();
                let ChildIo::Pipes { stdout, .. } = &mut spawned.io else {
                    panic!("expected pipes");
                };
                let mut status = String::new();
                stdout.read_to_string(&mut status).await.unwrap();
                assert!(spawned.child.wait().await.unwrap().success());
                for (field, id) in [("Uid:", user.uid.as_raw()), ("Gid:", user.gid.as_raw())] {
                    let line = status.lines().find(|line| line.starts_with(field)).unwrap();
                    let ids: Vec<_> = line.split_whitespace().skip(1).collect();
                    assert_eq!(ids, vec![id.to_string(); 4], "{line}");
                }
                let groups = status
                    .lines()
                    .find(|line| line.starts_with("Groups:"))
                    .unwrap();
                assert!(!groups.split_whitespace().skip(1).any(|id| id == "0"));
            } else {
                assert_eq!(case, "saved-root");
                assert_eq!(Uid::effective(), user.uid);
                let error = spawn(&user, &request(&["true"], false)).unwrap_err();
                assert!(error.to_string().contains("not running as root"), "{error}");
            }
            return;
        }
        if !Uid::effective().is_root() {
            return;
        }

        for case in ["effective-root", "saved-root"] {
            let uid = user.uid.as_raw();
            let gid = user.gid.as_raw();
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "child::tests::mixed_credentials_cannot_reach_remote_exec",
                ])
                .env(MARKER, case);
            if case == "effective-root" {
                // SAFETY: the subprocess changes only its own IDs before exec,
                // using async-signal-safe syscalls and no shared memory.
                unsafe {
                    command.pre_exec(move || {
                        if libc::setresgid(gid, 0, 0) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        if libc::setresuid(uid, 0, 0) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "{case}: stdout: {} stderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
