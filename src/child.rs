//! Spawning the remote process: privilege drop, environment, PTY setup.

use std::ffi::CString;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{bail, Context, Result};
use nix::unistd::{Gid, Uid, User};
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
/// when you press Ctrl-C. If the group is already gone, fall back to the
/// process itself.
///
/// This is the only place in the crate that signals anything.
#[allow(
    unsafe_code,
    reason = "kill(2) has no safe wrapper; pid comes from our own child"
)]
pub fn signal_process_group(pid: u32, sig: i32) {
    let Ok(pid) = i32::try_from(pid) else {
        return;
    };
    // SAFETY: `kill` only reads the two scalar arguments. A stale pid can at
    // worst return ESRCH, which we ignore.
    unsafe {
        if libc::kill(-pid, sig) < 0 {
            libc::kill(pid, sig);
        }
    }
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

/// Start the process described by `req` as `user`.
///
/// When the server does not run as root, `user` must be the account the
/// server itself runs as; there is no way to change identity otherwise.
///
/// # Errors
/// Fails if the target user cannot be assumed, a PTY cannot be allocated, or
/// the program cannot be executed.
#[allow(
    unsafe_code,
    reason = "pre_exec is inherently unsafe: its closure runs between fork and exec"
)]
pub fn spawn(user: &User, req: &Request) -> Result<Spawned> {
    let running_as_root = Uid::effective().is_root();
    let must_switch = user.uid != Uid::current() || user.gid != Gid::current();
    if must_switch && !running_as_root {
        bail!(
            "cannot run as `{}`: qsh-server is not running as root",
            user.name
        );
    }

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
            cmd.env(k, v);
        }
    }

    // Everything the pre-exec hook needs, prepared while allocation is still safe.
    let username = CString::new(user.name.as_str()).context("user name contains a NUL byte")?;
    let uid = user.uid.as_raw();
    let gid = user.gid.as_raw();
    let switch = must_switch;

    let (io, spawned) = if let Some(p) = &req.pty {
        {
            let (master, slave) = pty::open(p.size)?;
            let slave_in = slave.try_clone().context("duplicating the PTY slave")?;
            let slave_out = slave.try_clone().context("duplicating the PTY slave")?;
            cmd.stdin(Stdio::from(slave_in))
                .stdout(Stdio::from(slave_out))
                .stderr(Stdio::from(slave));

            // SAFETY: only async-signal-safe libc calls between fork and exec.
            unsafe {
                cmd.as_std_mut().pre_exec(move || {
                    if libc::setsid() < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    // stdin is the PTY slave; make it our controlling terminal.
                    if libc::ioctl(0, libc::TIOCSCTTY as libc::c_ulong, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    drop_privileges(switch, username.as_ptr(), uid, gid)
                });
            }
            let child = cmd
                .spawn()
                .with_context(|| describe(req.command.as_ref(), &shell))?;
            (ChildIo::Pty(master), child)
        }
    } else {
        {
            cmd.stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            // SAFETY: only async-signal-safe libc calls between fork and exec.
            unsafe {
                cmd.as_std_mut().pre_exec(move || {
                    if libc::setsid() < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    drop_privileges(switch, username.as_ptr(), uid, gid)
                });
            }
            let mut child = cmd
                .spawn()
                .with_context(|| describe(req.command.as_ref(), &shell))?;
            let missing = || anyhow::anyhow!("a piped standard stream was not created");
            let io = ChildIo::Pipes {
                stdin: child.stdin.take().ok_or_else(missing)?,
                stdout: child.stdout.take().ok_or_else(missing)?,
                stderr: child.stderr.take().ok_or_else(missing)?,
            };
            (io, child)
        }
    };

    Ok(Spawned { child: spawned, io })
}

fn describe(command: Option<&Vec<String>>, shell: &Path) -> String {
    match command.and_then(|argv| argv.first()) {
        Some(program) => format!("executing `{program}`"),
        None => format!("starting login shell `{}`", shell.display()),
    }
}

/// Runs between `fork` and `exec`; must stay async-signal-safe.
#[allow(
    unsafe_code,
    reason = "setuid/setgid/initgroups have no safe wrappers and must run here"
)]
fn drop_privileges(
    switch: bool,
    username: *const libc::c_char,
    uid: libc::uid_t,
    gid: libc::gid_t,
) -> std::io::Result<()> {
    if !switch {
        return Ok(());
    }
    // SAFETY: async-signal-safe libc calls; `username` outlives the closure.
    unsafe {
        if libc::initgroups(username, gid) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::setgid(gid) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::setuid(uid) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // Refuse to exec if the identity change did not stick, and make sure
        // it cannot be undone.
        if libc::getuid() != uid || libc::geteuid() != uid || libc::setuid(0) == 0 {
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
}
