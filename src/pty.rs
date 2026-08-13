//! Pseudo-terminal support: an async wrapper around a PTY master fd, plus the
//! `ioctl`s for window size.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::{Context as _, Result};
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
#[allow(
    unsafe_code,
    reason = "reads the winsize struct through a raw pointer for openpty"
)]
pub fn open(size: PtySize) -> Result<(PtyMaster, OwnedFd)> {
    let ws = winsize(size);
    let pair = nix::pty::openpty(Some(&ws), None).context("allocating a pseudo terminal")?;
    set_nonblocking(pair.master.as_raw_fd()).context("making the PTY master non-blocking")?;
    Ok((
        PtyMaster {
            inner: AsyncFd::new(pair.master).context("registering the PTY with the reactor")?,
        },
        pair.slave,
    ))
}

#[allow(unsafe_code, reason = "fcntl has no safe wrapper for this flag dance")]
fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is valid for the duration of the calls.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
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
    #[allow(
        unsafe_code,
        reason = "read(2) on the PTY master fd; tokio has no safe wrapper for a raw fd"
    )]
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
                // SAFETY: writing into a slice we exclusively own.
                let n = unsafe {
                    libc::read(
                        inner.get_ref().as_raw_fd(),
                        unfilled.as_mut_ptr().cast(),
                        unfilled.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(usize::try_from(n).unwrap_or(0))
                }
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
    #[allow(
        unsafe_code,
        reason = "write(2) on the PTY master fd; tokio has no safe wrapper for a raw fd"
    )]
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
            let result = guard.try_io(|inner| {
                // SAFETY: reading from a slice we hold for the duration of the call.
                let n = unsafe {
                    libc::write(inner.get_ref().as_raw_fd(), buf.as_ptr().cast(), buf.len())
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(usize::try_from(n).unwrap_or(0))
                }
            });
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
