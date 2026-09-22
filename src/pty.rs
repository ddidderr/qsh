//! Pseudo-terminal support: an async wrapper around a PTY master fd, plus the
//! `ioctl`s for window size.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::{Context as _, Result};
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::proto::PtySize;

fn winsize(size: PtySize) -> libc::winsize {
    libc::winsize {
        ws_row: size.rows,
        ws_col: size.cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}

/// Apply a new window size to a terminal file descriptor.
#[allow(unsafe_code, reason = "TIOCSWINSZ is an ioctl with no safe wrapper")]
///
/// # Errors
/// Fails if the descriptor is not a terminal.
pub fn set_size(fd: RawFd, size: PtySize) -> io::Result<()> {
    let ws = winsize(size);
    // SAFETY: `fd` is a valid descriptor and `ws` is the struct TIOCSWINSZ expects.
    if unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Read the window size of a terminal file descriptor.
#[allow(unsafe_code, reason = "TIOCGWINSZ is an ioctl with no safe wrapper")]
///
/// # Errors
/// Fails if the descriptor is not a terminal.
pub fn get_size(fd: RawFd) -> io::Result<PtySize> {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is a valid descriptor and `ws` is the struct TIOCGWINSZ fills in.
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PtySize {
        cols: ws.ws_col,
        rows: ws.ws_row,
    })
}

/// The master side of a pseudo terminal, usable with tokio.
#[derive(Debug)]
pub struct PtyMaster {
    inner: AsyncFd<OwnedFd>,
}

/// Allocate a PTY pair. Returns `(master, slave)`.
///
/// # Errors
/// Fails if no PTY can be allocated or the master cannot be registered with
/// the async reactor.
pub fn open(size: PtySize) -> Result<(PtyMaster, OwnedFd)> {
    let (master, slave) = open_pair().context("allocating a pseudo terminal")?;
    set_size(master.as_raw_fd(), size).context("setting the PTY size")?;
    set_nonblocking(&master).context("making the PTY master non-blocking")?;
    Ok((
        PtyMaster {
            inner: AsyncFd::new(master).context("registering the PTY with the reactor")?,
        },
        slave,
    ))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn open_pair() -> Result<(OwnedFd, OwnedFd)> {
    // Set CLOEXEC at creation: setting it after openpty races other threads'
    // fork/exec and can give another user's session access to this terminal.
    let flags = OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_CLOEXEC;
    let master = nix::pty::posix_openpt(flags)?;
    nix::pty::grantpt(&master)?;
    nix::pty::unlockpt(&master)?;
    let slave_name = nix::pty::ptsname_r(&master)?;
    let slave = nix::fcntl::open(slave_name.as_str(), flags, nix::sys::stat::Mode::empty())?;
    Ok((master.into(), slave))
}

// Other Unix platforms lack nix's thread-safe ptsname_r. Serialize openpty's
// non-atomic descriptor setup against every remote-process spawn instead.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(crate) fn spawn_lock() -> io::Result<std::sync::MutexGuard<'static, ()>> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock()
        .map_err(|_| io::Error::other("PTY spawn lock poisoned"))
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn open_pair() -> Result<(OwnedFd, OwnedFd)> {
    use nix::fcntl::FdFlag;

    let _guard = spawn_lock()?;
    let pair = nix::pty::openpty(None, None)?;
    fcntl(&pair.master, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
    fcntl(&pair.slave, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
    Ok((pair.master, pair.slave))
}

fn set_nonblocking(fd: impl AsFd) -> io::Result<()> {
    let flags = OFlag::from_bits_truncate(fcntl(&fd, FcntlArg::F_GETFL)?);
    fcntl(&fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;
    Ok(())
}

impl PtyMaster {
    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.inner.get_ref().as_raw_fd()
    }

    /// Resize the terminal.
    ///
    /// # Errors
    /// Fails if the `TIOCSWINSZ` ioctl is rejected.
    pub fn set_size(&self, size: PtySize) -> io::Result<()> {
        set_size(self.as_raw_fd(), size)
    }
}

impl AsyncRead for PtyMaster {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            let mut guard = match this.inner.poll_read_ready(cx) {
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            let unfilled = buf.initialize_unfilled();
            let result = guard.try_io(|inner| {
                nix::unistd::read(inner.get_ref(), unfilled).map_err(io::Error::from)
            });
            match result {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                // Linux reports EIO on the master once the last slave closes.
                // For us that is simply end of output.
                Ok(Err(e)) if e.raw_os_error() == Some(libc::EIO) => {
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => (),
            }
        }
    }
}

impl AsyncWrite for PtyMaster {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            let mut guard = match this.inner.poll_write_ready(cx) {
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            let result = guard
                .try_io(|inner| nix::unistd::write(inner.get_ref(), buf).map_err(io::Error::from));
            match result {
                Ok(res) => return Poll::Ready(res),
                Err(_would_block) => (),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Restore previously saved terminal settings on `fd`.
///
/// Safe to call from a signal-driven path: it only issues one `tcsetattr`.
#[allow(
    unsafe_code,
    reason = "borrows a terminal fd the caller guarantees is still open"
)]
pub fn restore_termios(fd: RawFd, saved: &nix::sys::termios::Termios) {
    // SAFETY: the borrow lives only for this call.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let _ = nix::sys::termios::tcsetattr(borrowed, nix::sys::termios::SetArg::TCSANOW, saved);
}

/// Put a terminal into raw mode, restoring the previous settings on drop.
///
/// This is what keeps the remote side in charge of echo, line editing and
/// `Ctrl-C`: the local terminal must not interfere.
#[derive(Debug)]
pub struct RawMode {
    fd: RawFd,
    saved: nix::sys::termios::Termios,
    restored: bool,
}

impl RawMode {
    /// A copy of the settings to restore, for use outside the guard.
    ///
    /// A fatal signal terminates the process without unwinding, so `Drop`
    /// never runs and the user's terminal would be left raw. Handing the saved
    /// settings to a signal handler is the only way to put them back.
    #[must_use]
    pub fn saved(&self) -> nix::sys::termios::Termios {
        self.saved.clone()
    }

    /// Switch `fd` to raw mode.
    ///
    /// # Errors
    /// Fails if the descriptor is not a terminal or the settings are rejected.
    #[allow(
        unsafe_code,
        reason = "borrows the caller's terminal fd, which must outlive this guard"
    )]
    pub fn enable(fd: RawFd) -> Result<Self> {
        // SAFETY: the borrow lives only for this call; `fd` is an open terminal.
        let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
        let saved = nix::sys::termios::tcgetattr(borrowed).context("reading terminal settings")?;
        let mut raw = saved.clone();
        nix::sys::termios::cfmakeraw(&mut raw);
        nix::sys::termios::tcsetattr(borrowed, nix::sys::termios::SetArg::TCSANOW, &raw)
            .context("switching the terminal to raw mode")?;
        Ok(Self {
            fd,
            saved,
            restored: false,
        })
    }

    /// Restore the saved settings. Idempotent.
    #[allow(
        unsafe_code,
        reason = "borrows the same terminal fd the settings were captured from"
    )]
    pub fn restore(&mut self) {
        if self.restored {
            return;
        }
        self.restored = true;
        // SAFETY: same descriptor we captured the settings from.
        let borrowed = unsafe { BorrowedFd::borrow_raw(self.fd) };
        let _ =
            nix::sys::termios::tcsetattr(borrowed, nix::sys::termios::SetArg::TCSANOW, &self.saved);
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        self.restore();
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn pty_descriptors_and_slave_duplicates_are_cloexec() {
        use nix::fcntl::FdFlag;

        let (master, slave) = open(PtySize::default()).unwrap();
        let duplicate = slave.try_clone().unwrap();
        for fd in [master.inner.get_ref(), &slave, &duplicate] {
            let flags = FdFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFD).unwrap());
            assert!(flags.contains(FdFlag::FD_CLOEXEC));
        }
    }

    #[tokio::test]
    async fn pty_echoes_and_resizes() {
        let (mut master, slave) = open(PtySize { cols: 80, rows: 24 }).unwrap();
        assert_eq!(
            get_size(master.as_raw_fd()).unwrap(),
            PtySize { cols: 80, rows: 24 }
        );

        master
            .set_size(PtySize {
                cols: 132,
                rows: 43,
            })
            .unwrap();
        assert_eq!(
            get_size(master.as_raw_fd()).unwrap(),
            PtySize {
                cols: 132,
                rows: 43
            }
        );

        // The line discipline echoes what we write to the master.
        master.write_all(b"hi\n").await.unwrap();
        let mut buf = [0u8; 16];
        let n = master.read(&mut buf).await.unwrap();
        assert!(n > 0);
        drop(slave);
    }

    #[tokio::test]
    async fn closing_the_slave_reads_as_eof() {
        let (mut master, slave) = open(PtySize::default()).unwrap();
        drop(slave);
        let mut buf = [0u8; 16];
        // Either an immediate 0-length read or one after draining; both are EOF.
        let n = master.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }
}
