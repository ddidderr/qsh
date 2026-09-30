//! Server log lines go through a bounded queue to a dedicated writer thread,
//! so a blocked stderr pipe never blocks a Tokio worker; lines that do not fit
//! are counted and reported as suppressed. Delivery is best effort: a failed
//! write is not retried.
//!
//! Three entry points, by who controls the volume:
//!
//! * [`Diagnostics::emit`] — peer-triggered detail (session errors, refused
//!   streams). A global per-second budget stops a peer from flooding the log.
//! * [`Diagnostics::record`] — audit and security-relevant server events
//!   (logins, withdrawn authorizations, failed cgroup kills). They do not draw
//!   on that budget, so failing sessions cannot silence them, but they share
//!   the queue and are dropped (and counted) if it is full.
//! * [`Diagnostics::emit_administrative`] — authorization-reload state, which
//!   is reported once per change, so the newest few are held in a backlog
//!   while stderr is blocked.

use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

/// Burst headroom well above the peer budget, so a healthy writer should only
/// fall this far behind when the sink blocks or logins arrive in a large burst.
/// At most about 512 KiB of queued text.
const QUEUE_CAPACITY: usize = 256;
const ADMIN_CAPACITY: usize = 32;
const MESSAGES_PER_SECOND: usize = 16;
const MAX_MESSAGE_CHARS: usize = 512;

#[derive(Debug)]
enum Event {
    Line(String),
    Administrative,
}

#[derive(Clone, Debug)]
pub(crate) struct Diagnostics {
    sender: mpsc::SyncSender<Event>,
    administrative: Arc<Mutex<VecDeque<String>>>,
    limit: Arc<Mutex<RateLimit>>,
    suppressed: Arc<AtomicU64>,
}

impl Diagnostics {
    pub(super) fn stderr() -> io::Result<Self> {
        Self::with_writer(io::stderr())
    }

    pub(crate) fn with_writer(mut writer: impl Write + Send + 'static) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<Event>(QUEUE_CAPACITY);
        let administrative = Arc::new(Mutex::new(VecDeque::new()));
        let pending = Arc::clone(&administrative);
        std::thread::Builder::new()
            .name("qsh-diagnostics".into())
            .spawn(move || loop {
                let administrative = { crate::sync::mutex(&pending).pop_front() };
                if let Some(message) = administrative {
                    let _ = writeln!(writer, "{message}");
                    continue;
                }
                match receiver.recv() {
                    Ok(Event::Line(message)) => {
                        let _ = writeln!(writer, "{message}");
                    }
                    Ok(Event::Administrative) => {}
                    Err(_) => break,
                }
            })?;
        Ok(Self {
            sender,
            administrative,
            limit: Arc::new(Mutex::new(RateLimit {
                start: Instant::now(),
                remaining: MESSAGES_PER_SECOND,
            })),
            suppressed: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Build messages only after admission. Neither a full queue nor a slow
    /// writer can make an authenticated peer block the runtime on logging.
    pub(crate) fn emit(&self, message: impl FnOnce() -> String) {
        if !crate::sync::mutex(&self.limit).allow(Instant::now()) {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let message = message();
        let message = bounded(&message, MAX_MESSAGE_CHARS);
        if self.sender.try_send(Event::Line(message)).is_err() {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Log an audit or security-relevant server event without the peer
    /// budget. It still never blocks: if the writer is backed up, the line is
    /// counted as suppressed like any other.
    pub(crate) fn record(&self, message: impl FnOnce() -> String) {
        let message = bounded(&message(), MAX_MESSAGE_CHARS);
        if self.sender.try_send(Event::Line(message)).is_err() {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Retain operational state independently of the lossy peer queue. If
    /// stderr is blocked, preserve the newest bounded set and write it before
    /// peer diagnostics once the sink recovers.
    pub(super) fn emit_administrative(&self, message: &str) {
        let message = bounded(message, MAX_MESSAGE_CHARS);
        let mut pending = crate::sync::mutex(&self.administrative);
        if pending.iter().any(|old| old == &message) {
            return;
        }
        if pending.len() == ADMIN_CAPACITY {
            pending.pop_front();
        }
        pending.push_back(message);
        drop(pending);
        let _ = self.sender.try_send(Event::Administrative);
    }

    /// Called once per reload interval, including after malicious traffic
    /// stops. Preserve the total if stderr is still blocked and the queue full.
    pub(super) fn report_suppressed(&self) {
        let count = self.suppressed.swap(0, Ordering::Relaxed);
        if count > 0
            && self
                .sender
                .try_send(Event::Line(format!(
                    "qsh-server: suppressed {count} diagnostic message(s)"
                )))
                .is_err()
        {
            self.suppressed.fetch_add(count, Ordering::Relaxed);
        }
    }
}

fn bounded(message: &str, max_chars: usize) -> String {
    message
        .chars()
        .take(max_chars)
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect()
}

#[derive(Debug)]
struct RateLimit {
    start: Instant,
    remaining: usize,
}

impl RateLimit {
    fn allow(&mut self, now: Instant) -> bool {
        if now.duration_since(self.start) >= Duration::from_secs(1) {
            self.start = now;
            self.remaining = MESSAGES_PER_SECOND;
        }
        if self.remaining == 0 {
            return false;
        }
        self.remaining -= 1;
        true
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]
mod tests {
    use super::*;

    #[test]
    fn log_flood_is_bounded_and_the_allowance_recovers() {
        let now = Instant::now();
        let mut limit = RateLimit {
            start: now,
            remaining: MESSAGES_PER_SECOND,
        };
        for _ in 0..MESSAGES_PER_SECOND {
            assert!(limit.allow(now));
        }
        for _ in 0..10_000 {
            assert!(!limit.allow(now));
        }
        assert!(limit.allow(now + Duration::from_secs(1)));
    }

    #[test]
    fn malformed_stream_messages_are_counted_without_formatting_or_waiting() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let diagnostics = Diagnostics {
            sender,
            administrative: Arc::new(Mutex::new(VecDeque::new())),
            limit: Arc::new(Mutex::new(RateLimit {
                start: Instant::now(),
                remaining: MESSAGES_PER_SECOND,
            })),
            suppressed: Arc::new(AtomicU64::new(0)),
        };
        diagnostics.emit(|| "qsh-server: expected a request frame first".into());
        for _ in 1..MESSAGES_PER_SECOND {
            diagnostics.emit(|| "qsh-server: expected a request frame first".into());
        }
        diagnostics.emit(|| unreachable!("exhausted allowance must skip formatting"));
        assert_eq!(diagnostics.suppressed.load(Ordering::Relaxed), 16);
        diagnostics.report_suppressed();
        assert_eq!(diagnostics.suppressed.load(Ordering::Relaxed), 16);
        let Event::Line(message) = receiver.recv().unwrap() else {
            panic!("expected peer diagnostic");
        };
        assert!(message.contains("request frame"));
        diagnostics.report_suppressed();
        let Event::Line(message) = receiver.recv().unwrap() else {
            panic!("expected suppression diagnostic");
        };
        assert!(message.contains("suppressed 16"));
        assert_eq!(diagnostics.suppressed.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn messages_are_bounded_single_lines() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let diagnostics = Diagnostics {
            sender,
            administrative: Arc::new(Mutex::new(VecDeque::new())),
            limit: Arc::new(Mutex::new(RateLimit {
                start: Instant::now(),
                remaining: MESSAGES_PER_SECOND,
            })),
            suppressed: Arc::new(AtomicU64::new(0)),
        };
        diagnostics.emit(|| "\n\x1btest".repeat(1024));
        let Event::Line(message) = receiver.recv().unwrap() else {
            panic!("expected peer diagnostic");
        };
        assert_eq!(message.chars().count(), MAX_MESSAGE_CHARS);
        assert!(!message.chars().any(char::is_control));
    }

    #[test]
    fn recorded_events_bypass_an_exhausted_peer_budget() {
        let (sender, receiver) = mpsc::sync_channel(2);
        let diagnostics = Diagnostics {
            sender,
            administrative: Arc::new(Mutex::new(VecDeque::new())),
            limit: Arc::new(Mutex::new(RateLimit {
                start: Instant::now(),
                remaining: 0,
            })),
            suppressed: Arc::new(AtomicU64::new(0)),
        };
        diagnostics.emit(|| unreachable!("the peer budget is exhausted"));
        diagnostics.record(|| "qsh-server: peer authenticated as `alice`".into());
        assert_eq!(diagnostics.suppressed.load(Ordering::Relaxed), 1);
        let Event::Line(message) = receiver.recv().unwrap() else {
            panic!("expected the recorded event");
        };
        assert!(message.contains("authenticated as"));

        // A full queue still never blocks the caller; the loss is counted.
        diagnostics.record(|| "first".into());
        diagnostics.record(|| "second".into());
        diagnostics.record(|| "does not fit".into());
        assert_eq!(diagnostics.suppressed.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn blocked_writer_does_not_block_diagnostic_producers() {
        struct BlockedWriter {
            started: Option<mpsc::Sender<()>>,
            release: mpsc::Receiver<()>,
            stopped: mpsc::Sender<()>,
            output: Arc<Mutex<Vec<u8>>>,
        }

        impl Write for BlockedWriter {
            fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
                if let Some(started) = self.started.take() {
                    started.send(()).unwrap();
                    self.release.recv_timeout(Duration::from_secs(5)).unwrap();
                }
                crate::sync::mutex(&self.output).extend_from_slice(buffer);
                Ok(buffer.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        impl Drop for BlockedWriter {
            fn drop(&mut self) {
                let _ = self.stopped.send(());
            }
        }

        let (started, running) = mpsc::channel();
        let (finish, release) = mpsc::channel();
        let (stopped, finished) = mpsc::channel();
        let output = Arc::new(Mutex::new(Vec::new()));
        let diagnostics = Diagnostics::with_writer(BlockedWriter {
            started: Some(started),
            release,
            stopped,
            output: Arc::clone(&output),
        })
        .unwrap();
        diagnostics.emit_administrative("first authorization reload failure");
        running.recv_timeout(Duration::from_secs(5)).unwrap();

        // The writer must not hold the administrative queue lock while the
        // underlying sink is blocked.
        let producer = diagnostics.clone();
        let (emitted, done) = mpsc::channel();
        std::thread::spawn(move || {
            producer.emit_administrative("second authorization reload failure");
            emitted.send(()).unwrap();
        });
        done.recv_timeout(Duration::from_secs(1)).unwrap();

        // The sink stays parked until after every producer call returns.
        for _ in 0..10_000 {
            diagnostics.emit(|| "another malformed session".into());
        }
        assert!(diagnostics.suppressed.load(Ordering::Relaxed) > 0);
        finish.send(()).unwrap();
        drop(diagnostics);
        finished.recv_timeout(Duration::from_secs(5)).unwrap();
        let written = String::from_utf8(crate::sync::mutex(&output).clone()).unwrap();
        assert!(
            written.contains("first authorization reload failure"),
            "{written}"
        );
        assert!(
            written.contains("second authorization reload failure"),
            "{written}"
        );
    }
}
