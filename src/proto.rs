//! The qsh wire protocol.
//!
//! A session is a single QUIC bidirectional stream carrying a sequence of
//! frames. Every frame is `[kind: u8][len: u32be][payload: len bytes]`.
//!
//! Structured payloads are postcard-encoded; the three byte-stream payloads
//! (stdin/stdout/stderr) are raw and never transformed in any way — no
//! newline translation, no encoding conversion. That is what makes `rsync -e
//! qsh` work.

use std::io;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// ALPN protocol identifier negotiated during the QUIC/TLS handshake.
pub const ALPN: &[u8] = b"qsh/1";

/// Protocol version carried in [`Request`]. Bumped on incompatible changes.
pub const PROTOCOL_VERSION: u32 = 1;

/// Largest accepted frame payload. Data frames are chunked well below this.
pub const MAX_FRAME: usize = 1024 * 1024;

/// Chunk size used when forwarding byte streams.
pub const CHUNK: usize = 64 * 1024;

mod kind {
    pub const REQUEST: u8 = 1;
    pub const STDIN: u8 = 2;
    pub const STDOUT: u8 = 3;
    pub const STDERR: u8 = 4;
    pub const STDIN_EOF: u8 = 5;
    pub const RESIZE: u8 = 6;
    pub const SIGNAL: u8 = 7;
    pub const EXIT: u8 = 8;
    pub const ERROR: u8 = 9;
    pub const STARTED: u8 = 10;
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
    pub user: Option<String>,
    pub command: Option<Vec<String>>,
    pub pty: Option<PtyRequest>,
    pub env: Vec<(String, String)>,
}

/// How the remote process terminated.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ExitStatus {
    pub code: i32,
    pub signal: Option<i32>,
}

impl ExitStatus {
    /// The status a shell would report for this termination.
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

    fn payload(&self) -> io::Result<Vec<u8>> {
        let out = match self {
            Frame::Request(r) => postcard::to_stdvec(r).map_err(|e| invalid(e.to_string()))?,
            Frame::Resize(s) => postcard::to_stdvec(s).map_err(|e| invalid(e.to_string()))?,
            Frame::Exit(s) => postcard::to_stdvec(s).map_err(|e| invalid(e.to_string()))?,
            Frame::Signal(s) => s.as_bytes().to_vec(),
            Frame::Error(s) => s.as_bytes().to_vec(),
            Frame::Stdin(b) | Frame::Stdout(b) | Frame::Stderr(b) => b.clone(),
            Frame::Started | Frame::StdinEof => Vec::new(),
        };
        if out.len() > MAX_FRAME {
            return Err(invalid("frame payload too large"));
        }
        Ok(out)
    }

    fn decode(kind: u8, payload: Vec<u8>) -> io::Result<Frame> {
        let de = |b: &[u8]| -> io::Result<String> {
            String::from_utf8(b.to_vec()).map_err(|_| invalid("payload is not valid UTF-8"))
        };
        Ok(match kind {
            kind::REQUEST => {
                Frame::Request(postcard::from_bytes(&payload).map_err(|e| invalid(e.to_string()))?)
            }
            kind::STARTED => Frame::Started,
            kind::STDIN => Frame::Stdin(payload),
            kind::STDOUT => Frame::Stdout(payload),
            kind::STDERR => Frame::Stderr(payload),
            kind::STDIN_EOF => Frame::StdinEof,
            kind::RESIZE => {
                Frame::Resize(postcard::from_bytes(&payload).map_err(|e| invalid(e.to_string()))?)
            }
            kind::SIGNAL => Frame::Signal(de(&payload)?),
            kind::EXIT => {
                Frame::Exit(postcard::from_bytes(&payload).map_err(|e| invalid(e.to_string()))?)
            }
            kind::ERROR => Frame::Error(de(&payload)?),
            other => return Err(invalid(format!("unknown frame kind {other}"))),
        })
    }
}

/// Write a single frame.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &Frame) -> io::Result<()> {
    let payload = frame.payload()?;
    let mut header = [0u8; 5];
    header[0] = frame.kind();
    header[1..].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    w.write_all(&header).await?;
    if !payload.is_empty() {
        w.write_all(&payload).await?;
    }
    w.flush().await
}

/// Read a single frame. Returns `Ok(None)` on a clean end of stream.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<Frame>> {
    let mut header = [0u8; 5];
    match r.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if len > MAX_FRAME {
        return Err(invalid(format!("frame of {len} bytes exceeds limit")));
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        r.read_exact(&mut payload).await?;
    }
    Frame::decode(header[0], payload).map(Some)
}

/// Map a signal name (with or without `SIG` prefix) to its number.
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
mod tests {
    use super::*;

    async fn roundtrip(frame: Frame) -> Frame {
        let mut buf = Vec::new();
        write_frame(&mut buf, &frame).await.unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        read_frame(&mut cursor).await.unwrap().unwrap()
    }

    #[tokio::test]
    async fn binary_data_survives_untouched() {
        // Everything a naive line-oriented transport would mangle.
        let payload: Vec<u8> = (0u8..=255).chain([b'\r', b'\n', 0]).collect();
        match roundtrip(Frame::Stdout(payload.clone())).await {
            Frame::Stdout(got) => assert_eq!(got, payload),
            other => panic!("wrong frame: {other:?}"),
        }
    }

    #[tokio::test]
    async fn request_roundtrips() {
        let req = Request {
            version: PROTOCOL_VERSION,
            user: Some("alice".into()),
            command: Some(vec![
                "rsync".into(),
                "--server".into(),
                "-vlogDtpre.iLsfxC".into(),
            ]),
            pty: None,
            env: vec![("LANG".into(), "C.UTF-8".into())],
        };
        match roundtrip(Frame::Request(req)).await {
            Frame::Request(got) => {
                assert_eq!(got.user.as_deref(), Some("alice"));
                assert_eq!(got.command.unwrap()[2], "-vlogDtpre.iLsfxC");
                assert!(got.pty.is_none());
            }
            other => panic!("wrong frame: {other:?}"),
        }
    }

    #[tokio::test]
    async fn exit_status_roundtrips() {
        match roundtrip(Frame::Exit(ExitStatus {
            code: 0,
            signal: Some(libc::SIGINT),
        }))
        .await
        {
            Frame::Exit(s) => assert_eq!(s.wait_status(), 130),
            other => panic!("wrong frame: {other:?}"),
        }
    }

    #[tokio::test]
    async fn clean_eof_is_none() {
        let mut empty = std::io::Cursor::new(Vec::new());
        assert!(read_frame(&mut empty).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected() {
        let mut buf = Vec::new();
        buf.push(kind::STDOUT);
        buf.extend_from_slice(&(MAX_FRAME as u32 + 1).to_be_bytes());
        let mut cursor = std::io::Cursor::new(buf);
        assert!(read_frame(&mut cursor).await.is_err());
    }

    #[test]
    fn signal_names_parse_with_and_without_prefix() {
        assert_eq!(signal_number("INT"), Some(libc::SIGINT));
        assert_eq!(signal_number("SIGTERM"), Some(libc::SIGTERM));
        assert_eq!(signal_number("nope"), None);
    }
}
