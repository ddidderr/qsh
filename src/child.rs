//! Spawning the remote process: privilege drop, environment, PTY setup.

use std::convert::Infallible;
use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{bail, Context, Result};
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::sys::signal::{killpg, Signal};
use nix::unistd::{Gid, Pid, Uid, User};
use tokio::process::{ChildStderr, ChildStdin, ChildStdout, Command};

use crate::cgroup::{self, SessionCgroup};
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
    /// Group for the session's terminal: `tty` where the system has one.
    terminal_group: Option<Gid>,
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
    // A failed lookup must not refuse sessions, most of which need no
    // terminal: like sshd, fall back to the user's own group.
    let terminal_group = if switch {
        nix::unistd::Group::from_name("tty")
            .ok()
            .flatten()
            .map(|group| group.gid)
    } else {
        None
    };
    Ok(PreparedIdentity {
        switch,
        groups,
        terminal_group,
    })
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
    spawn_prepared(user, req, prepare_identity(user)?, None)
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
    cgroup: Option<&SessionCgroup>,
) -> Result<Spawned> {
    let PreparedIdentity {
        switch,
        groups,
        terminal_group,
    } = identity;
    let cgroup_procs = cgroup.map(SessionCgroup::attach_fd).transpose()?;

    let home = home_of(user);
    let shell = shell_of(user);

    let (mut cmd, arg0) =
        if let Some((program, args)) = req.command.as_deref().and_then(<[String]>::split_first) {
            let mut cmd = Command::new(program);
            cmd.args(args);
            (cmd, OsString::from(program))
        } else {
            // No command: an interactive login shell, exactly like `ssh host`.
            // The leading `-` in argv[0] is how a shell learns it is a login shell.
            let base = shell.file_name().and_then(|s| s.to_str()).unwrap_or("sh");
            (Command::new(&shell), OsString::from(format!("-{base}")))
        };

    // The working directory is set in the pre-exec hook, after the inherited
    // descriptors are gone: like exec, chdir can block on a slow filesystem.
    cmd.env_clear()
        .env("PATH", DEFAULT_PATH)
        .env("HOME", &home)
        .env("USER", &user.name)
        .env("LOGNAME", &user.name)
        .env("SHELL", &shell);

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
        if switch {
            pty::assign(&slave, user.uid, user.gid, terminal_group)?;
        }
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

    // A forked child holds a copy of every descriptor the server had open at
    // the fork: other sessions' pipes and terminals, including the child ends
    // of spawns in flight on other threads. Close-on-exec only releases them
    // once exec succeeds, and the client decides how long exec takes: its
    // program can sit on a filesystem that never answers. A child stuck there
    // would keep those sessions from ever seeing EOF. So the hook closes
    // everything first, then execs by itself and reports a failure through
    // this pipe; std's own report channel is among what gets closed, and std
    // takes that as success, so the outcome is read from here instead.
    let (status_read, status_write) = exec_status_pipe()?;
    let exec = ChildExec {
        program: PreparedExec::new(cmd.as_std(), &arg0, &home)?,
        status: status_write.as_raw_fd(),
        cgroup_procs: cgroup_procs.as_ref().map(AsRawFd::as_raw_fd),
        controlling_terminal: master.is_some(),
        switch,
        groups,
        uid,
        gid,
    };
    // SAFETY: `run` only makes async-signal-safe libc calls, on memory
    // prepared before the fork.
    unsafe {
        cmd.as_std_mut().pre_exec(move || exec.run());
    }
    let mut child = {
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let _guard = pty::spawn_lock()?;
        cmd.spawn()
            .map_err(|error| spawn_error(error, req.command.as_ref(), &shell, &home))?
    };
    drop(status_write);
    if let Some(error) = read_exec_status(status_read)? {
        // The child has exited; tokio reaps it once `child` is dropped.
        return Err(spawn_error(error, req.command.as_ref(), &shell, &home));
    }
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

/// The pipe through which the pre-exec hook reports a failed exec. The write
/// end is close-on-exec, so a successful exec reads as end of file, and it is
/// kept above the standard descriptors that std's `dup2` overwrites.
fn exec_status_pipe() -> Result<(OwnedFd, OwnedFd)> {
    let (read, write) = nix::unistd::pipe2(OFlag::O_CLOEXEC).context("creating a pipe")?;
    let write = if write.as_raw_fd() > 2 {
        write
    } else {
        let raised = fcntl(&write, FcntlArg::F_DUPFD_CLOEXEC(3)).context("moving a pipe")?;
        // SAFETY: `fcntl` just returned this descriptor, and nothing else owns it.
        #[allow(unsafe_code, reason = "adopting a descriptor fcntl returned")]
        unsafe {
            OwnedFd::from_raw_fd(raised)
        }
    };
    Ok((read, write))
}

/// Wait until the child has exec'd, and return the error if it could not.
/// A child that is still trying holds nothing but its own session's
/// descriptors, so this may block as long as exec does.
fn read_exec_status(status: OwnedFd) -> Result<Option<std::io::Error>> {
    let mut report = Vec::with_capacity(4);
    File::from(status)
        .read_to_end(&mut report)
        .context("reading the exec status of the remote process")?;
    if report.is_empty() {
        return Ok(None);
    }
    let errno = <[u8; 4]>::try_from(report.as_slice())
        .map(i32::from_ne_bytes)
        .map_err(|_| anyhow::anyhow!("malformed exec status from the remote process"))?;
    Ok(Some(std::io::Error::from_raw_os_error(errno)))
}

/// Everything the child does between fork and exec, prepared before the fork.
struct ChildExec {
    program: PreparedExec,
    /// Write end of the exec status pipe.
    status: RawFd,
    cgroup_procs: Option<RawFd>,
    controlling_terminal: bool,
    switch: bool,
    groups: Vec<libc::gid_t>,
    uid: libc::uid_t,
    gid: libc::gid_t,
}

impl ChildExec {
    /// Runs in the forked child, and never returns: once std's report channel
    /// is closed, an error returned to std would abort the child.
    #[allow(unsafe_code, reason = "runs between fork and exec")]
    fn run(&self) -> ! {
        let Err(error) = self.try_run();
        let errno = error.raw_os_error().unwrap_or(libc::EINVAL).to_ne_bytes();
        // SAFETY: async-signal-safe calls on a stack buffer.
        unsafe {
            libc::write(self.status, errno.as_ptr().cast(), errno.len());
            libc::_exit(127)
        }
    }

    #[allow(unsafe_code, reason = "runs between fork and exec")]
    fn try_run(&self) -> std::io::Result<Infallible> {
        // First, before anything that can block.
        close_descriptors_except([self.status, self.cgroup_procs.unwrap_or(self.status)])?;
        clear_inheritable_capabilities()?;
        // SAFETY: async-signal-safe syscalls on prepared, NUL-terminated data.
        unsafe {
            if let Some(procs) = self.cgroup_procs {
                cgroup::join_pre_exec(procs)?;
                #[cfg(target_os = "linux")]
                {
                    // An opted-in account must not use a setuid binary or
                    // file capability to gain the right to migrate itself
                    // out of the root-owned session cgroup.
                    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
            }
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // stdin is the PTY slave; make it our controlling terminal.
            if self.controlling_terminal && libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::chdir(self.program.home.as_ptr()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        drop_privileges(self.switch, &self.groups, self.uid, self.gid)?;
        self.program.exec()
    }
}

/// Program, argument and environment arrays for `execvp`, built before the
/// fork because nothing may allocate after it.
struct PreparedExec {
    program: CString,
    argv: CStringArray,
    envp: CStringArray,
    home: CString,
}

impl PreparedExec {
    /// Take everything from `cmd`, which stays the one description of what
    /// runs; only `argv[0]`, which std does not expose, comes separately.
    fn new(cmd: &std::process::Command, name: &OsStr, home: &Path) -> Result<Self> {
        let c_string = |text: &OsStr| {
            CString::new(text.as_bytes()).context("argument or environment contains a NUL byte")
        };
        let argv = std::iter::once(name)
            .chain(cmd.get_args())
            .map(c_string)
            .collect::<Result<_>>()?;
        let envp = cmd
            .get_envs()
            .filter_map(|(key, value)| Some((key, value?)))
            .map(|(key, value)| {
                let mut entry = key.to_owned();
                entry.push("=");
                entry.push(value);
                c_string(&entry)
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            program: c_string(cmd.get_program())?,
            argv: CStringArray::new(argv),
            envp: CStringArray::new(envp),
            home: c_string(home.as_os_str())?,
        })
    }

    /// Exec, searching `PATH` in the new environment the way std does. Only
    /// returns on failure.
    #[allow(unsafe_code, reason = "exec runs between fork and exec")]
    fn exec(&self) -> std::io::Result<Infallible> {
        extern "C" {
            static mut environ: *const *const libc::c_char;
        }
        // SAFETY: this is the forked child, which has a single thread; the
        // arrays are NULL-terminated and live until exec.
        unsafe {
            environ = self.envp.as_ptr();
            libc::execvp(self.program.as_ptr(), self.argv.as_ptr());
        }
        Err(std::io::Error::last_os_error())
    }
}

/// A NULL-terminated array of pointers into strings it owns.
struct CStringArray {
    _strings: Vec<CString>,
    pointers: Vec<*const libc::c_char>,
}

// SAFETY: the pointers refer into `_strings`, whose heap buffers never move or
// change while the array exists; sharing it is sharing immutable bytes.
#[allow(unsafe_code, reason = "raw pointers into owned, immutable strings")]
unsafe impl Send for CStringArray {}
#[allow(unsafe_code, reason = "raw pointers into owned, immutable strings")]
unsafe impl Sync for CStringArray {}

impl CStringArray {
    fn new(strings: Vec<CString>) -> Self {
        let pointers = strings
            .iter()
            .map(|string| string.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        Self {
            _strings: strings,
            pointers,
        }
    }

    fn as_ptr(&self) -> *const *const libc::c_char {
        self.pointers.as_ptr()
    }
}

/// Close every descriptor from 3 up except those in `keep`. Runs between fork
/// and exec, so it only uses syscalls.
#[allow(unsafe_code, reason = "close_range runs between fork and exec")]
fn close_descriptors_except(mut keep: [RawFd; 2]) -> std::io::Result<()> {
    keep.sort_unstable();
    let mut first: RawFd = 3;
    for fd in keep {
        if fd > first {
            close_range(first, fd - 1)?;
        }
        first = first.max(fd.saturating_add(1));
    }
    close_range(first, RawFd::MAX)
}

#[allow(unsafe_code, reason = "close_range runs between fork and exec")]
fn close_range(first: RawFd, last: RawFd) -> std::io::Result<()> {
    // SAFETY: plain syscalls on descriptor numbers; nothing in the child
    // uses the closed descriptors afterwards.
    unsafe {
        #[cfg(target_os = "linux")]
        {
            if libc::syscall(libc::SYS_close_range, first, last, 0) == 0 {
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ENOSYS) {
                return Err(error);
            }
        }
        // Kernels before 5.9: close one at a time, up to the descriptor limit.
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let end = RawFd::try_from(limit.rlim_cur).unwrap_or(RawFd::MAX);
        for fd in first..end.min(last.saturating_add(1)) {
            libc::close(fd);
        }
    }
    Ok(())
}

/// Service-specific inheritable or ambient capabilities must not reach remote
/// commands. Preserve the current permitted/effective sets until the remaining
/// cgroup and identity syscalls finish; ordinary exec then applies its normal
/// setuid and file-permitted-capability rules.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[allow(
    unsafe_code,
    reason = "capget and capset are async-signal-safe pre-exec syscalls"
)]
fn clear_inheritable_capabilities() -> std::io::Result<()> {
    const VERSION_3: u32 = 0x2008_0522;

    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    let mut header = Header {
        version: VERSION_3,
        pid: 0,
    };
    let mut data = [Data {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: both syscalls receive fixed-size stack objects matching the Linux
    // capability v3 ABI, and pid 0 selects the calling thread.
    if unsafe { libc::syscall(libc::SYS_capget, &raw mut header, data.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    for word in &mut data {
        word.inheritable = 0;
    }
    if unsafe { libc::syscall(libc::SYS_capset, &raw const header, data.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "same pre-exec contract on every Unix platform"
)]
fn clear_inheritable_capabilities() -> std::io::Result<()> {
    Ok(())
}

/// exec found no file to run: the program itself, or the interpreter or loader
/// it names. A shell reports 127 for both.
#[derive(Debug)]
pub struct ProgramNotFound {
    /// The program exists, so what is missing is what it needs to run.
    exists: bool,
}

impl std::fmt::Display for ProgramNotFound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The wording bash uses for each case.
        f.write_str(if self.exists {
            "cannot execute: required file not found"
        } else {
            "command not found"
        })
    }
}

fn spawn_error(
    error: std::io::Error,
    command: Option<&Vec<String>>,
    shell: &Path,
    home: &Path,
) -> anyhow::Error {
    let not_found = error.kind() == std::io::ErrorKind::NotFound;
    let program = match command.and_then(|argv| argv.first()) {
        Some(program) => Path::new(program),
        None => shell,
    };
    let error = anyhow::Error::new(error).context(describe(command, shell));
    if not_found {
        error.context(ProgramNotFound {
            exists: program_exists(program, home),
        })
    } else {
        error
    }
}

/// Whether `program` exists where exec looks for it: relative to the session's
/// home when it names a path, otherwise in the fixed `PATH`.
fn program_exists(program: &Path, home: &Path) -> bool {
    if program.components().count() > 1 {
        home.join(program).exists()
    } else {
        DEFAULT_PATH
            .split(':')
            .any(|dir| Path::new(dir).join(program).exists())
    }
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
    async fn exec_finding_no_file_is_reported_as_not_found() {
        let user = current_user().unwrap();
        let Err(missing) = spawn(&user, &request(&["/nonexistent/qsh-program"], false)) else {
            panic!("spawning a missing program succeeded");
        };
        assert!(missing.is::<ProgramNotFound>(), "{missing:#}");
        assert!(format!("{missing:#}").contains("command not found"));
        // Found but not executable: a shell says 126, not 127.
        let Err(refused) = spawn(&user, &request(&["/etc/hostname"], false)) else {
            panic!("executing a data file succeeded");
        };
        assert!(!refused.is::<ProgramNotFound>(), "{refused:#}");
        // A script whose interpreter is missing: still 127, as from a shell,
        // but not described as a missing command.
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("orphan.sh");
        std::fs::write(&script, "#!/nonexistent/interpreter\n").unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let Err(orphan) = spawn(&user, &request(&[script.to_str().unwrap()], false)) else {
            panic!("a script without an interpreter ran");
        };
        assert!(orphan.is::<ProgramNotFound>(), "{orphan:#}");
        assert!(format!("{orphan:#}").contains("required file not found"));
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
        // Inspect the environment directly: some shells initialize TERM=dumb
        // themselves even when it was absent from their environment.
        let mut req = request(&["env"], false);
        req.env = vec![
            ("LD_PRELOAD".into(), "/evil.so".into()),
            ("LC_ALL".into(), "C".into()),
        ];
        let mut sp = spawn(&user, &req).unwrap();
        let ChildIo::Pipes { stdout, .. } = &mut sp.io else {
            panic!("expected pipes");
        };
        let mut out = String::new();
        stdout.read_to_string(&mut out).await.unwrap();
        assert!(sp.child.wait().await.unwrap().success());
        assert!(!out.lines().any(|line| line.starts_with("LD_PRELOAD=")));
        assert!(!out.lines().any(|line| line.starts_with("TERM=")));
        assert!(out.lines().any(|line| line == "LC_ALL=C"));
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
    async fn sessions_do_not_inherit_service_capabilities() {
        const MARKER: &str = "QSH_TEST_SERVICE_CAPABILITIES";
        if let Ok(case) = std::env::var(MARKER) {
            let status = std::fs::read_to_string("/proc/thread-self/status").unwrap();
            let capability = |field: &str| {
                let line = status.lines().find(|line| line.starts_with(field)).unwrap();
                u64::from_str_radix(line.split_whitespace().nth(1).unwrap(), 16).unwrap()
            };
            assert_eq!(capability("CapInh:"), 0x400);
            if case == "direct" {
                assert_eq!(capability("CapAmb:"), 0x400);
                let permitted = capability("CapPrm:");
                let effective = capability("CapEff:");
                clear_inheritable_capabilities().unwrap();
                let cleared = std::fs::read_to_string("/proc/thread-self/status").unwrap();
                for field in ["CapInh:", "CapAmb:"] {
                    let line = cleared
                        .lines()
                        .find(|line| line.starts_with(field))
                        .unwrap();
                    assert!(line.ends_with("0000000000000000"), "{line}");
                }
                assert!(cleared
                    .lines()
                    .any(|line| line == format!("CapPrm:\t{permitted:016x}")));
                assert!(cleared
                    .lines()
                    .any(|line| line == format!("CapEff:\t{effective:016x}")));
                return;
            }
            let user = if case == "child" {
                let user = current_user().unwrap();
                assert!(!user.uid.is_root());
                user
            } else {
                assert_eq!(case, "root-switch");
                assert!(Uid::effective().is_root());
                resolve_user("nobody").unwrap()
            };
            let mut spawned = spawn(&user, &request(&["cat", "/proc/self/status"], false)).unwrap();
            let ChildIo::Pipes { stdout, .. } = &mut spawned.io else {
                panic!("expected pipes");
            };
            let mut child_status = String::new();
            stdout.read_to_string(&mut child_status).await.unwrap();
            assert!(spawned.child.wait().await.unwrap().success());
            for field in ["CapInh:", "CapAmb:", "CapPrm:", "CapEff:"] {
                let line = child_status
                    .lines()
                    .find(|line| line.starts_with(field))
                    .unwrap();
                assert!(line.ends_with("0000000000000000"), "{line}");
            }
            // Ordinary sessions can still use normal setuid/file-capability
            // programs; this fix removes inherited service authority only.
            assert!(child_status.lines().any(|line| line == "NoNewPrivs:\t0"));
            return;
        }
        if !Uid::effective().is_root() {
            eprintln!("skipping service capability integration: requires root and setpriv");
            return;
        }
        let user = resolve_user("nobody").unwrap();
        let executable = std::env::current_exe().unwrap();
        let test = "child::tests::sessions_do_not_inherit_service_capabilities";
        for case in ["direct", "child"] {
            let output = std::process::Command::new("setpriv")
                .args([
                    "--reuid",
                    &user.uid.as_raw().to_string(),
                    "--regid",
                    &user.gid.as_raw().to_string(),
                    "--clear-groups",
                    "--inh-caps=+net_bind_service",
                    "--ambient-caps=+net_bind_service",
                ])
                .arg(&executable)
                .args(["--exact", test])
                .env(MARKER, case)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{case}: stdout: {} stderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let output = std::process::Command::new("setpriv")
            .arg("--inh-caps=+net_bind_service")
            .arg(&executable)
            .args(["--exact", test])
            .env(MARKER, "root-switch")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "root-switch: stdout: {} stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
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
