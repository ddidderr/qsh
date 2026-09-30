//! The qsh wire protocol.
//!
//! A session is a single QUIC bidirectional stream carrying a sequence of
//! frames. Every frame is `[kind: u8][len: u32be][payload: len bytes]`.
//!
//! Structured payloads are postcard-encoded; the three byte-stream payloads
//! (stdin/stdout/stderr) are raw and never transformed in any way — no
//! newline translation, no encoding conversion. That is what makes `rsync -e
//! qsh` work.

use std::{borrow::Cow, io};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

mod bounded;

/// ALPN protocol identifier negotiated during the QUIC/TLS handshake.
pub const ALPN: &[u8] = b"qsh/1";

/// Protocol version carried in [`Request`]. Bumped on incompatible changes.
pub const PROTOCOL_VERSION: u32 = 1;

/// Largest accepted frame payload. Data frames are chunked well below this.
pub const MAX_FRAME: usize = 1024 * 1024;

/// Request payload budget, including postcard's length prefixes.
pub const MAX_REQUEST: usize = 64 * 1024;

/// Enough for ordinary commands and multi-source rsync, with bounded metadata.
pub const MAX_ARGS: usize = 1024;

/// Environment entries accepted in a request.
pub const MAX_ENV: usize = 64;

/// Maximum bytes in an argument or environment value.
pub const MAX_VALUE_BYTES: usize = 16 * 1024;

/// Maximum bytes in a username, terminal type, or environment variable name.
pub const MAX_NAME_BYTES: usize = 256;

/// Chunk size used when forwarding byte streams.
pub const CHUNK: usize = 64 * 1024;

/// Application error code for a session stream torn down without an ending.
///
/// The server resets a stream with this code when it is giving up on a session
/// whose output it could not deliver — a peer that stopped reading, say. It is
/// deliberately distinguishable from a clean end of stream: a peer that sees it
/// knows it did not receive everything, which a graceful finish would not tell
/// it.
pub const RESET_ABANDONED: u32 = 2;

mod kind {
    pub(super) const REQUEST: u8 = 1;
    pub(super) const STDIN: u8 = 2;
    pub(super) const STDOUT: u8 = 3;
    pub(super) const STDERR: u8 = 4;
    pub(super) const STDIN_EOF: u8 = 5;
    pub(super) const RESIZE: u8 = 6;
    pub(super) const SIGNAL: u8 = 7;
    pub(super) const EXIT: u8 = 8;
    pub(super) const ERROR: u8 = 9;
    pub(super) const STARTED: u8 = 10;
}

/// Terminal geometry, in character cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtySize {
    pub cols: u16,
    pub rows: u16,
}

impl Default for PtySize {
    fn default() -> Self {
        Self { cols: 80, rows: 24 }
    }
}

/// Request for a pseudo terminal on the remote side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtyRequest {
    #[serde(deserialize_with = "bounded::name")]
    pub term: String,
    pub size: PtySize,
}

/// The first frame a client sends. `command == None` means "start my login
/// shell"; otherwise the argv is executed directly, never through `sh -c`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub version: u32,
    /// Account the client believes it is logging in as (`qsh -l alice host`).
    /// Purely a cross-check: the authoritative mapping lives on the server.
    #[serde(deserialize_with = "bounded::optional_name")]
    pub user: Option<String>,
    #[serde(deserialize_with = "bounded::command")]
    pub command: Option<Vec<String>>,
    pub pty: Option<PtyRequest>,
    #[serde(deserialize_with = "bounded::environment")]
    pub env: Vec<(String, String)>,
}

impl Request {
    /// Apply the same field limits to locally constructed outgoing requests.
    fn validate(&self) -> io::Result<()> {
        if let Some(user) = &self.user {
            check_size(user.len(), MAX_NAME_BYTES, "username")?;
        }
        if let Some(command) = &self.command {
            check_size(command.len(), MAX_ARGS, "argument count")?;
            for argument in command {
                check_size(argument.len(), MAX_VALUE_BYTES, "argument")?;
            }
        }
        if let Some(pty) = &self.pty {
            check_size(pty.term.len(), MAX_NAME_BYTES, "terminal type")?;
        }
        check_size(self.env.len(), MAX_ENV, "environment count")?;
        for (name, value) in &self.env {
            check_size(name.len(), MAX_NAME_BYTES, "environment name")?;
            check_size(value.len(), MAX_VALUE_BYTES, "environment value")?;
        }
        Ok(())
    }
}

/// How the remote process terminated.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ExitStatus {
    pub code: i32,
    pub signal: Option<i32>,
}

impl ExitStatus {
    /// The status a shell would report for this termination.
    #[must_use]
    pub fn wait_status(&self) -> i32 {
        match self.signal {
            Some(sig) => 128 + sig,
            None => self.code,
        }
    }
}

/// A protocol frame.
#[derive(Debug, Clone)]
pub enum Frame {
    Request(Request),
    /// Server acknowledges that the remote process was started.
    Started,
    Stdin(Vec<u8>),
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    StdinEof,
    Resize(PtySize),
    /// Signal name without the `SIG` prefix, e.g. `INT`, `TERM`, `HUP`.
    Signal(String),
    Exit(ExitStatus),
    /// Session could not be established or failed fatally; human-readable.
    Error(String),
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn check_size(length: usize, limit: usize, what: &str) -> io::Result<()> {
    if length > limit {
        return Err(invalid(format!("{what} of {length} exceeds limit {limit}")));
    }
    Ok(())
}

/// Control frames have much smaller budgets than byte streams. Check these
/// against the header before allocating or waiting for the advertised body.
fn payload_limit(kind: u8) -> io::Result<usize> {
    match kind {
        kind::REQUEST => Ok(MAX_REQUEST),
        kind::STDIN | kind::STDOUT | kind::STDERR => Ok(MAX_FRAME),
        kind::STARTED | kind::STDIN_EOF => Ok(0),
        kind::RESIZE => Ok(6), // Two postcard u16 varints, at most three bytes each.
        kind::EXIT => Ok(11),  // Two i32 varints and an Option discriminant.
        kind::SIGNAL => Ok(16),
        kind::ERROR => Ok(4096),
        other => Err(invalid(format!("unknown frame kind {other}"))),
    }
}

fn encode_control<T: Serialize>(value: &T, limit: usize) -> io::Result<Vec<u8>> {
    // A bounded output buffer also prevents oversized local requests from
    // causing an unbounded temporary allocation before write_frame rejects it.
    let mut buffer = vec![0; limit];
    let length = postcard::to_slice(value, &mut buffer)
        .map_err(|error| invalid(error.to_string()))?
        .len();
    buffer.truncate(length);
    Ok(buffer)
}

fn decode_control<T: serde::de::DeserializeOwned>(payload: &[u8]) -> io::Result<T> {
    let (value, trailing) =
        postcard::take_from_bytes(payload).map_err(|error| invalid(error.to_string()))?;
    if !trailing.is_empty() {
        return Err(invalid("trailing bytes after control payload"));
    }
    Ok(value)
}

impl Frame {
    fn kind(&self) -> u8 {
        match self {
            Frame::Request(_) => kind::REQUEST,
            Frame::Started => kind::STARTED,
            Frame::Stdin(_) => kind::STDIN,
            Frame::Stdout(_) => kind::STDOUT,
            Frame::Stderr(_) => kind::STDERR,
            Frame::StdinEof => kind::STDIN_EOF,
            Frame::Resize(_) => kind::RESIZE,
            Frame::Signal(_) => kind::SIGNAL,
            Frame::Exit(_) => kind::EXIT,
            Frame::Error(_) => kind::ERROR,
        }
    }

    fn payload(&self) -> io::Result<Cow<'_, [u8]>> {
        let limit = payload_limit(self.kind())?;
        let out = match self {
            Frame::Request(r) => {
                r.validate()?;
                Cow::Owned(encode_control(r, limit)?)
            }
            Frame::Resize(s) => Cow::Owned(encode_control(s, limit)?),
            Frame::Exit(s) => Cow::Owned(encode_control(s, limit)?),
            Frame::Signal(s) | Frame::Error(s) => Cow::Borrowed(s.as_bytes()),
            Frame::Stdin(b) | Frame::Stdout(b) | Frame::Stderr(b) => Cow::Borrowed(b.as_slice()),
            Frame::Started | Frame::StdinEof => Cow::Borrowed(&[][..]),
        };
        check_size(out.len(), limit, "frame payload")?;
        Ok(out)
    }

    fn decode(kind: u8, payload: Vec<u8>) -> io::Result<Frame> {
        check_size(payload.len(), payload_limit(kind)?, "frame payload")?;
        let de = |bytes: Vec<u8>| -> io::Result<String> {
            String::from_utf8(bytes).map_err(|_| invalid("payload is not valid UTF-8"))
        };
        Ok(match kind {
            kind::REQUEST => Frame::Request(decode_control(&payload)?),
            kind::STARTED => Frame::Started,
            kind::STDIN => Frame::Stdin(payload),
            kind::STDOUT => Frame::Stdout(payload),
            kind::STDERR => Frame::Stderr(payload),
            kind::STDIN_EOF => Frame::StdinEof,
            kind::RESIZE => Frame::Resize(decode_control(&payload)?),
            kind::SIGNAL => Frame::Signal(de(payload)?),
            kind::EXIT => Frame::Exit(decode_control(&payload)?),
            kind::ERROR => Frame::Error(de(payload)?),
            other => return Err(invalid(format!("unknown frame kind {other}"))),
        })
    }
}

/// Write a single frame.
///
/// # Errors
/// Fails if the frame cannot be encoded or the stream rejects the write.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &Frame) -> io::Result<()> {
    let payload = frame.payload()?;
    // `payload()` already rejects anything above MAX_FRAME, so this fits.
    let len = u32::try_from(payload.len()).map_err(|_| invalid("frame payload too large"))?;
    let mut header = [0u8; 5];
    header[0] = frame.kind();
    header[1..].copy_from_slice(&len.to_be_bytes());
    w.write_all(&header).await?;
    if !payload.is_empty() {
        w.write_all(&payload).await?;
    }
    w.flush().await
}

/// Read a single frame. Returns `Ok(None)` on a clean end of stream.
///
/// # Errors
/// Fails on a malformed header, an over-long or undecodable payload, or an
/// I/O error on the stream.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<Frame>> {
    let Some((kind, len)) = read_header(r).await? else {
        return Ok(None);
    };
    Frame::decode(kind, read_payload(r, len).await?).map(Some)
}

/// Read the first frame of a session, which must be a [`Request`].
///
/// A wrong kind or oversized request is rejected using only the header. This
/// prevents a peer from reserving a data-frame buffer before authorization.
/// Returns `Ok(None)` only when no bytes remain before a new frame.
///
/// # Errors
/// Fails on a non-Request frame, a malformed or oversized request, or an I/O
/// error. A partial header or payload is an error, not a clean end of stream.
pub async fn read_request<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<Request>> {
    let Some((kind, len)) = read_header(r).await? else {
        return Ok(None);
    };
    if kind != kind::REQUEST {
        return Err(invalid("first frame must be a Request"));
    }
    decode_control(&read_payload(r, len).await?).map(Some)
}

async fn read_header<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<(u8, usize)>> {
    let kind = match r.read_u8().await {
        Ok(kind) => kind,
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    };
    let len = r.read_u32().await? as usize;
    check_size(len, payload_limit(kind)?, "frame payload")?;
    Ok(Some((kind, len)))
}

async fn read_payload<R: AsyncRead + Unpin>(r: &mut R, len: usize) -> io::Result<Vec<u8>> {
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    Ok(payload)
}

/// Map a signal name (with or without `SIG` prefix) to its number.
#[must_use]
pub fn signal_number(name: &str) -> Option<i32> {
    let n = name
        .strip_prefix("SIG")
        .unwrap_or(name)
        .to_ascii_uppercase();
    Some(match n.as_str() {
        "HUP" => libc::SIGHUP,
        "INT" => libc::SIGINT,
        "QUIT" => libc::SIGQUIT,
        "ILL" => libc::SIGILL,
        "ABRT" => libc::SIGABRT,
        "KILL" => libc::SIGKILL,
        "ALRM" => libc::SIGALRM,
        "TERM" => libc::SIGTERM,
        "USR1" => libc::SIGUSR1,
        "USR2" => libc::SIGUSR2,
        "PIPE" => libc::SIGPIPE,
        "CONT" => libc::SIGCONT,
        "TSTP" => libc::SIGTSTP,
        "WINCH" => libc::SIGWINCH,
        _ => return None,
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    reason = "a failing assertion should panic loudly; that is the point of a test"
)]
mod tests;
