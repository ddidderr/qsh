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
pub struct Spawned {
    pub child: tokio::process::Child,
    pub io: ChildIo,
}

impl Spawned {
    /// Send a signal to the process group of the remote process.
    pub fn signal(&self, sig: i32) -> Result<()> {
        let Some(pid) = self.child.id() else {
            return Ok(());
        };
        // The child called setsid(), so it leads its own process group; the
        // negative pid reaches the whole job, like a terminal would.
        // SAFETY: plain libc call with a validated pid.
        unsafe {
            if libc::kill(-(pid as i32), sig) < 0 && libc::kill(pid as i32, sig) < 0 {
                bail!("kill: {}", std::io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// Resize the terminal, if this session has one.
    pub fn resize(&self, size: PtySize) -> Result<()> {
        if let ChildIo::Pty(master) = &self.io {
            master.set_size(size)?;
            if let Some(pid) = self.child.id() {
                // SAFETY: plain libc call with a validated pid.
                unsafe {
                    libc::kill(-(pid as i32), libc::SIGWINCH);
                }
            }
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

    let mut cmd = match &req.command {
        Some(argv) if !argv.is_empty() => {
            let mut cmd = Command::new(&argv[0]);
            cmd.args(&argv[1..]);
            cmd
        }
        // No command: an interactive login shell, exactly like `ssh host`.
        _ => {
            let mut cmd = Command::new(&shell);
            let base = shell
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("sh")
                .to_string();
            cmd.as_std_mut().arg0(format!("-{base}"));
            cmd
        }
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

    let (io, spawned) = match &req.pty {
        Some(p) => {
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
                .with_context(|| describe(&req.command, &shell))?;
            (ChildIo::Pty(master), child)
        }
        None => {
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
                .with_context(|| describe(&req.command, &shell))?;
            let io = ChildIo::Pipes {
                stdin: child.stdin.take().expect("stdin was piped"),
                stdout: child.stdout.take().expect("stdout was piped"),
                stderr: child.stderr.take().expect("stderr was piped"),
            };
            (io, child)
        }
    };

    Ok(Spawned { child: spawned, io })
}

fn describe(command: &Option<Vec<String>>, shell: &Path) -> String {
    match command {
        Some(argv) if !argv.is_empty() => format!("executing `{}`", argv[0]),
        _ => format!("starting login shell `{}`", shell.display()),
    }
}

/// Runs between `fork` and `exec`; must stay async-signal-safe.
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
        "dumb".to_string()
    } else {
        cleaned
    }
}

/// Look up a local account by name.
pub fn resolve_user(name: &str) -> Result<User> {
    User::from_name(name)
        .with_context(|| format!("looking up user `{name}`"))?
        .ok_or_else(|| anyhow::anyhow!("no such local user: `{name}`"))
}

/// The account the current process runs as.
pub fn current_user() -> Result<User> {
    User::from_uid(Uid::current())
        .context("looking up the current user")?
        .ok_or_else(|| anyhow::anyhow!("the current uid has no passwd entry"))
}

/// Terminal file descriptor of the child's PTY, if any (used by tests).
pub fn pty_fd(io: &ChildIo) -> Option<i32> {
    match io {
        ChildIo::Pty(m) => Some(m.as_raw_fd()),
        ChildIo::Pipes { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{PtyRequest, PROTOCOL_VERSION};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn request(argv: &[&str], pty: bool) -> Request {
        Request {
            version: PROTOCOL_VERSION,
            user: None,
            command: Some(argv.iter().map(|s| s.to_string()).collect()),
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
        sp.signal(libc::SIGTERM).unwrap();
        let status = sp.child.wait().await.unwrap();
        assert!(status.code().is_none(), "expected death by signal");
    }

    #[test]
    fn switching_user_without_root_is_refused() {
        if Uid::effective().is_root() {
            return; // meaningless as root
        }
        let other = User::from_uid(Uid::from_raw(0)).unwrap().unwrap();
        let err = match spawn(&other, &request(&["true"], false)) {
            Ok(_) => panic!("expected the spawn to be refused"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("not running as root"), "{err}");
    }
}
