//! Optional Linux cgroup v2 containment for one remote session.
//!
//! A child joins its leaf *before* dropping credentials and executing. Moving
//! its PID from the parent after spawn would let a fast program fork outside
//! the leaf. Only root-owned daemon state and a non-root target are accepted:
//! a process with write access to the cgroup tree can migrate itself out.

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CString;
    use std::fs::{self, File, OpenOptions, Permissions};
    use std::io::{self, Write};
    use std::os::fd::RawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::{Component, Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use anyhow::{anyhow, bail, Context, Result};
    use nix::unistd::{Uid, User};

    static SESSION_NUMBER: AtomicU64 = AtomicU64::new(0);
    const CGROUP_MOUNT: &str = "/sys/fs/cgroup";
    const PRIVATE_ROOT: &str = "qsh-restricted";

    /// A leaf containing the direct process tree of one restricted session.
    #[derive(Debug)]
    pub struct SessionCgroup {
        path: PathBuf,
        procs: Option<File>,
        kill_fd: Option<File>,
        killed: bool,
        removed: bool,
    }

    impl SessionCgroup {
        /// Create a root-owned leaf and verify the kernel kill control exists.
        ///
        /// # Errors
        /// Fails before remote spawn if delegation, ownership, or cgroup v2
        /// support is absent. A restricted session never falls back to a
        /// process-group-only session.
        pub fn create(target: &User) -> Result<Self> {
            if !Uid::effective().is_root() {
                bail!("restricted sessions require qsh-server to run as root");
            }
            if target.uid.is_root() {
                bail!("restricted sessions cannot constrain a root login");
            }

            let service = current_service_cgroup()?;
            let root = service.join(PRIVATE_ROOT);
            match fs::create_dir(&root) {
                Ok(()) => fs::set_permissions(&root, Permissions::from_mode(0o700))
                    .with_context(|| format!("setting permissions on {}", root.display()))?,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(error).with_context(|| format!("creating {}", root.display()))
                }
            }
            require_private_root(&root)?;

            for _ in 0..32 {
                let number = SESSION_NUMBER.fetch_add(1, Ordering::Relaxed);
                let path = root.join(format!("session-{}-{number:016x}", std::process::id()));
                match fs::create_dir(&path) {
                    Ok(()) => return Self::open_new(path),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => {
                        return Err(error).with_context(|| format!("creating {}", path.display()));
                    }
                }
            }
            bail!("could not allocate a fresh session cgroup")
        }

        fn open_new(path: PathBuf) -> Result<Self> {
            let opened = (|| -> Result<(File, File)> {
                fs::set_permissions(&path, Permissions::from_mode(0o700))
                    .with_context(|| format!("setting permissions on {}", path.display()))?;
                require_cgroup2(&path)?;
                require_private_root(&path)?;
                let mut options = OpenOptions::new();
                options
                    .write(true)
                    .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
                let procs = options
                    .open(path.join("cgroup.procs"))
                    .with_context(|| format!("opening {}/cgroup.procs", path.display()))?;
                // cgroup.kill appeared in cgroup v2 in Linux 5.14. Check it
                // *before* starting a child so old kernels fail closed.
                let kill = options
                    .open(path.join("cgroup.kill"))
                    .with_context(|| format!("opening {}/cgroup.kill", path.display()))?;
                Ok((procs, kill))
            })();
            match opened {
                Ok((procs, kill_fd)) => Ok(Self {
                    path,
                    procs: Some(procs),
                    kill_fd: Some(kill_fd),
                    killed: false,
                    removed: false,
                }),
                Err(error) => {
                    let _ = fs::remove_dir(&path);
                    Err(error)
                }
            }
        }

        /// Duplicate the process-attachment control for the pre-exec hook.
        ///
        /// # Errors
        /// Fails if the descriptor cannot be duplicated.
        pub fn attach_fd(&self) -> Result<File> {
            self.procs
                .as_ref()
                .ok_or_else(|| anyhow!("session cgroup attachment is already closed"))?
                .try_clone()
                .with_context(|| format!("duplicating {}/cgroup.procs", self.path.display()))
        }

        /// Kill every process still in this leaf and its descendants.
        ///
        /// # Errors
        /// Fails if the kernel rejects the kill request. The caller must not
        /// present a successful session ending in that case.
        pub fn kill(&mut self) -> Result<()> {
            if self.killed {
                return Ok(());
            }
            let kill = self
                .kill_fd
                .as_mut()
                .ok_or_else(|| anyhow!("session cgroup kill control is already closed"))?;
            kill.write_all(b"1")
                .with_context(|| format!("killing session cgroup {}", self.path.display()))?;
            self.killed = true;
            Ok(())
        }

        /// Remove a killed leaf after its members have disappeared.
        ///
        /// # Errors
        /// Fails if the directory remains populated or cannot be removed.
        pub async fn remove_empty(&mut self) -> Result<()> {
            self.kill()?;
            self.procs.take();
            self.kill_fd.take();
            for attempt in 0..80 {
                match fs::remove_dir(&self.path) {
                    Ok(()) => {
                        self.removed = true;
                        return Ok(());
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        self.removed = true;
                        return Ok(());
                    }
                    Err(error)
                        if matches!(error.raw_os_error(), Some(libc::EBUSY | libc::ENOTEMPTY))
                            && attempt < 79 =>
                    {
                        tokio::time::sleep(Duration::from_millis(25)).await;
                    }
                    Err(error) => {
                        return Err(error)
                            .with_context(|| format!("removing {}", self.path.display()));
                    }
                }
            }
            Err(anyhow!(
                "session cgroup remained populated: {}",
                self.path.display()
            ))
        }
    }

    impl Drop for SessionCgroup {
        fn drop(&mut self) {
            if self.removed {
                return;
            }
            // This path also runs on task cancellation. There is no async
            // cleanup available here; a leftover empty leaf is harmless, but
            // killing its members is mandatory.
            if let Err(error) = self.kill() {
                eprintln!("qsh-server: {error:#}");
            }
            self.procs.take();
            self.kill_fd.take();
            let _ = fs::remove_dir(&self.path);
        }
    }

    fn current_service_cgroup() -> Result<PathBuf> {
        if !Path::new(CGROUP_MOUNT).join("cgroup.controllers").is_file() {
            bail!("restricted sessions require a mounted Linux cgroup v2 filesystem");
        }
        let membership = fs::read_to_string("/proc/self/cgroup")
            .context("reading the server's cgroup membership")?;
        let relative = parse_unified_membership(&membership)?;
        let mount = Path::new(CGROUP_MOUNT)
            .canonicalize()
            .context("resolving the cgroup v2 mount")?;
        require_cgroup2(&mount)?;
        let service = mount.join(relative);
        let canonical = service
            .canonicalize()
            .with_context(|| format!("resolving {}", service.display()))?;
        if !canonical.starts_with(&mount) {
            bail!("the server's cgroup is outside {CGROUP_MOUNT}");
        }
        require_cgroup2(&canonical)?;
        // A target must not be able to write *any* ancestor's cgroup.procs:
        // that would let it migrate out of its private leaf after exec.
        for ancestor in canonical.ancestors() {
            require_root_owned(ancestor)?;
            require_root_control(&ancestor.join("cgroup.procs"))?;
            require_root_control(&ancestor.join("cgroup.threads"))?;
            if ancestor == mount {
                break;
            }
        }
        Ok(canonical)
    }

    fn parse_unified_membership(membership: &str) -> Result<PathBuf> {
        let mut found = membership
            .lines()
            .filter_map(|line| line.strip_prefix("0::"));
        let path = found.next().ok_or_else(|| {
            anyhow!("restricted sessions require the unified cgroup v2 hierarchy")
        })?;
        if found.next().is_some() {
            bail!("ambiguous unified cgroup membership");
        }
        let path = Path::new(path);
        if !path.is_absolute() {
            bail!("the server's cgroup path is not absolute");
        }
        let mut relative = PathBuf::new();
        for component in path.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => relative.push(name),
                _ => bail!("invalid component in the server's cgroup path"),
            }
        }
        Ok(relative)
    }

    fn require_root_owned(path: &Path) -> Result<()> {
        let metadata = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            bail!(
                "{} must be a root-owned cgroup not writable by other users",
                path.display()
            );
        }
        Ok(())
    }

    fn require_private_root(path: &Path) -> Result<()> {
        require_root_owned(path)?;
        require_root_control(&path.join("cgroup.procs"))?;
        require_root_control(&path.join("cgroup.threads"))?;
        require_root_control(&path.join("cgroup.kill"))?;
        let mode = fs::metadata(path)?.mode();
        if mode & 0o077 != 0 {
            bail!("{} must be private to root (mode 0700)", path.display());
        }
        Ok(())
    }

    fn require_root_control(path: &Path) -> Result<()> {
        let metadata =
            fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
        // POSIX ACL write grants are limited by the group permission mask,
        // which is reflected in these mode bits. Reject even a group write
        // grant not presently held by the target: credentials may change.
        if !metadata.file_type().is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            bail!(
                "{} must be a root-owned cgroup control not writable by other users",
                path.display()
            );
        }
        Ok(())
    }

    #[allow(
        unsafe_code,
        reason = "statfs is needed to verify the kernel cgroup v2 filesystem"
    )]
    fn require_cgroup2(path: &Path) -> Result<()> {
        let raw = CString::new(path.as_os_str().as_bytes())
            .with_context(|| format!("invalid cgroup path {}", path.display()))?;
        let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: `raw` is a NUL-terminated path and statfs initializes the
        // output structure on success.
        if unsafe { libc::statfs(raw.as_ptr(), stat.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("statfs {}", path.display()));
        }
        // SAFETY: statfs returned success, so it initialized every field.
        let stat = unsafe { stat.assume_init() };
        // Linux's CGROUP2_SUPER_MAGIC. Checking a file name alone would also
        // accept an ordinary bind mount with fake cgroup controls.
        if stat.f_type != 0x6367_7270 {
            bail!("{} is not on a cgroup v2 filesystem", path.display());
        }
        Ok(())
    }

    /// Attach the forked child before it can execute or fork again. A write
    /// of PID 0 to cgroup.procs means the writing process itself.
    #[allow(unsafe_code, reason = "only the raw write syscall is safe after fork")]
    pub(crate) fn join_pre_exec(fd: RawFd) -> io::Result<()> {
        loop {
            // SAFETY: `b"0"` is static memory, fd is a pre-opened cgroup.procs
            // handle, and write(2) is async-signal-safe.
            let written = unsafe { libc::write(fd, b"0".as_ptr().cast(), 1) };
            if written == 1 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if written < 0 && error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(if written < 0 {
                error
            } else {
                io::Error::from_raw_os_error(libc::EIO)
            });
        }
    }

    #[cfg(test)]
    #[allow(clippy::unwrap_used, clippy::expect_used, reason = "test assertions")]
    mod tests {
        use super::*;

        #[test]
        fn parses_only_one_absolute_unified_membership() {
            assert_eq!(
                parse_unified_membership("0::/system.slice/qsh.service\n").unwrap(),
                PathBuf::from("system.slice/qsh.service")
            );
            assert!(parse_unified_membership("3:memory:/x\n").is_err());
            assert!(parse_unified_membership("0::relative\n").is_err());
            assert!(parse_unified_membership("0::/ok\n0::/bad\n").is_err());
            assert!(parse_unified_membership("0::/../escape\n").is_err());
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::SessionCgroup;

#[cfg(not(target_os = "linux"))]
mod unsupported {
    use std::fs::File;
    use std::io;
    use std::os::fd::RawFd;

    use anyhow::{bail, Result};
    use nix::unistd::User;

    /// Linux-only session cgroup support placeholder for other Unix hosts.
    #[derive(Debug)]
    pub struct SessionCgroup;

    impl SessionCgroup {
        /// # Errors
        /// Restricted sessions require Linux cgroup v2.
        pub fn create(_target: &User) -> Result<Self> {
            bail!("restricted sessions require Linux cgroup v2")
        }

        /// # Errors
        /// Restricted sessions require Linux cgroup v2.
        pub fn attach_fd(&self) -> Result<File> {
            bail!("restricted sessions require Linux cgroup v2")
        }

        /// # Errors
        /// Restricted sessions require Linux cgroup v2.
        pub fn kill(&mut self) -> Result<()> {
            bail!("restricted sessions require Linux cgroup v2")
        }

        /// # Errors
        /// Restricted sessions require Linux cgroup v2.
        pub async fn remove_empty(&mut self) -> Result<()> {
            bail!("restricted sessions require Linux cgroup v2")
        }
    }

    pub(crate) fn join_pre_exec(_fd: RawFd) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOTSUP))
    }
}

#[cfg(target_os = "linux")]
pub(crate) use linux::join_pre_exec;

#[cfg(not(target_os = "linux"))]
pub(crate) use unsupported::join_pre_exec;

#[cfg(not(target_os = "linux"))]
pub use unsupported::SessionCgroup;
