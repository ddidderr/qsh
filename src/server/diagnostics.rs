//! Peer-triggered diagnostics have a global rate and memory budget. A dedicated
//! writer keeps a blocked stderr pipe from blocking a Tokio worker.

use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

const QUEUE_CAPACITY: usize = 32;
const ADMIN_CAPACITY: usize = 32;
const MESSAGES_PER_SECOND: usize = 16;
const MAX_MESSAGE_CHARS: usize = 512;
const ADMIN_RETRY_INTERVAL: Duration = Duration::from_secs(1);

type AdministrativeQueue = Arc<Mutex<VecDeque<Arc<str>>>>;
type RetainedSlot = Arc<Mutex<Option<Arc<str>>>>;

#[derive(Debug)]
enum Event {
    Peer(String),
    Retained,
}

#[derive(Clone, Debug)]
pub(crate) struct Diagnostics {
    sender: mpsc::SyncSender<Event>,
    administrative: AdministrativeQueue,
    restricted_cleanup: RetainedSlot,
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
        let restricted_cleanup = Arc::new(Mutex::new(None));
        let restricted = Arc::clone(&restricted_cleanup);
        let suppressed = Arc::new(AtomicU64::new(0));
        let writer_suppressed = Arc::clone(&suppressed);
        std::thread::Builder::new()
            .name("qsh-diagnostics".into())
            .spawn(move || {
                writer_loop(
                    &mut writer,
                    &receiver,
                    &pending,
                    &restricted,
                    &writer_suppressed,
                );
            })?;
        Ok(Self {
            sender,
            administrative,
            restricted_cleanup,
            limit: Arc::new(Mutex::new(RateLimit {
                start: Instant::now(),
                remaining: MESSAGES_PER_SECOND,
            })),
            suppressed,
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
        if self.sender.try_send(Event::Peer(message)).is_err() {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Retain operational state independently of the lossy peer queue. If
    /// stderr is blocked, preserve the newest bounded set and write it before
    /// peer diagnostics once the sink recovers.
    pub(super) fn emit_administrative(&self, message: &str) {
        let message: Arc<str> = bounded(message, MAX_MESSAGE_CHARS).into();
        let mut pending = crate::sync::mutex(&self.administrative);
        if pending.iter().any(|old| old.as_ref() == message.as_ref()) {
            return;
        }
        if pending.len() == ADMIN_CAPACITY {
            pending.pop_front();
        }
        pending.push_back(message);
        drop(pending);
        let _ = self.sender.try_send(Event::Retained);
    }

    /// Retain the latest failed mandatory cgroup kill independently of both
    /// authorization state and peer-triggered log pressure.
    pub(crate) fn emit_restricted_kill_failure(&self, message: &str) {
        let message: Arc<str> = bounded(message, MAX_MESSAGE_CHARS).into();
        *crate::sync::mutex(&self.restricted_cleanup) = Some(message);
        let _ = self.sender.try_send(Event::Retained);
    }

    /// Called once per reload interval, including after malicious traffic
    /// stops. Preserve the total if stderr is still blocked and the queue full.
    pub(super) fn report_suppressed(&self) {
        let count = self.suppressed.swap(0, Ordering::Relaxed);
        if count > 0
            && self
                .sender
                .try_send(Event::Peer(format!(
                    "qsh-server: suppressed {count} diagnostic message(s)"
                )))
                .is_err()
        {
            self.suppressed.fetch_add(count, Ordering::Relaxed);
        }
    }
}

enum WriterWait {
    Event(Event),
    Retry,
    Disconnected,
}

enum RetainedSource {
    Administrative,
    RestrictedCleanup,
}

struct RetainedWrite {
    source: RetainedSource,
    message: Arc<str>,
    line: Vec<u8>,
    written: usize,
}

impl RetainedWrite {
    fn new(source: RetainedSource, message: Arc<str>) -> Self {
        let mut line = Vec::with_capacity(message.len() + 1);
        line.extend_from_slice(message.as_bytes());
        line.push(b'\n');
        Self {
            source,
            message,
            line,
            written: 0,
        }
    }

    fn write_to(&mut self, writer: &mut impl Write) -> io::Result<()> {
        while self.written < self.line.len() {
            let remaining = self
                .line
                .get(self.written..)
                .ok_or_else(|| io::Error::other("invalid retained diagnostic offset"))?;
            match writer.write(remaining) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
                Ok(count) => {
                    let Some(written) = self
                        .written
                        .checked_add(count)
                        .filter(|written| *written <= self.line.len())
                    else {
                        return Err(io::Error::other(
                            "diagnostic writer reported an invalid byte count",
                        ));
                    };
                    self.written = written;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

fn writer_loop(
    writer: &mut impl Write,
    receiver: &mpsc::Receiver<Event>,
    administrative: &AdministrativeQueue,
    restricted_cleanup: &RetainedSlot,
    suppressed: &AtomicU64,
) {
    let mut retry_at = None;
    let mut retained_write: Option<RetainedWrite> = None;
    let mut deferred_peers = VecDeque::new();
    loop {
        let now = Instant::now();
        if retry_at.is_none_or(|deadline| now >= deadline) {
            // An unstarted cgroup alert may yield to newer authorization state.
            // Once any bytes were written, finish that line before switching.
            if retained_write.as_ref().is_some_and(|pending| {
                matches!(pending.source, RetainedSource::RestrictedCleanup)
                    && pending.written == 0
                    && !crate::sync::mutex(administrative).is_empty()
            }) {
                retained_write = None;
            }
            if retained_write.is_none() {
                retained_write = next_retained(administrative, restricted_cleanup);
            }
            if let Some(pending) = retained_write.as_mut() {
                if pending.write_to(writer).is_ok() {
                    acknowledge(administrative, restricted_cleanup, pending);
                    retained_write = None;
                    retry_at = None;
                    continue;
                }
                retry_at = Some(Instant::now() + ADMIN_RETRY_INTERVAL);
            } else {
                retry_at = None;
            }
        }

        if retry_at.is_none() {
            if let Some(message) = deferred_peers.pop_front() {
                let _ = writeln!(writer, "{message}");
                continue;
            }
        }

        match wait_for_event(receiver, retry_at) {
            WriterWait::Event(Event::Peer(message)) => {
                if deferred_peers.len() == QUEUE_CAPACITY {
                    suppressed.fetch_add(1, Ordering::Relaxed);
                } else {
                    deferred_peers.push_back(message);
                }
            }
            WriterWait::Event(Event::Retained) | WriterWait::Retry => {}
            WriterWait::Disconnected => break,
        }
    }
}

fn next_retained(
    administrative: &AdministrativeQueue,
    restricted_cleanup: &RetainedSlot,
) -> Option<RetainedWrite> {
    if let Some(message) = crate::sync::mutex(administrative).front().cloned() {
        return Some(RetainedWrite::new(RetainedSource::Administrative, message));
    }
    crate::sync::mutex(restricted_cleanup)
        .clone()
        .map(|message| RetainedWrite::new(RetainedSource::RestrictedCleanup, message))
}

fn acknowledge(
    administrative: &AdministrativeQueue,
    restricted_cleanup: &RetainedSlot,
    written: &RetainedWrite,
) {
    match written.source {
        RetainedSource::Administrative => {
            let mut pending = crate::sync::mutex(administrative);
            if pending
                .front()
                .is_some_and(|current| Arc::ptr_eq(current, &written.message))
            {
                pending.pop_front();
            }
        }
        RetainedSource::RestrictedCleanup => {
            let mut pending = crate::sync::mutex(restricted_cleanup);
            if pending
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &written.message))
            {
                pending.take();
            }
        }
    }
}

fn wait_for_event(receiver: &mpsc::Receiver<Event>, retry_at: Option<Instant>) -> WriterWait {
    let Some(deadline) = retry_at else {
        return receiver
            .recv()
            .map_or(WriterWait::Disconnected, WriterWait::Event);
    };
    match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(event) => WriterWait::Event(event),
        Err(mpsc::RecvTimeoutError::Timeout) => WriterWait::Retry,
        Err(mpsc::RecvTimeoutError::Disconnected) => WriterWait::Disconnected,
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
            restricted_cleanup: Arc::new(Mutex::new(None)),
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
        let Event::Peer(message) = receiver.recv().unwrap() else {
            panic!("expected peer diagnostic");
        };
        assert!(message.contains("request frame"));
        diagnostics.report_suppressed();
        let Event::Peer(message) = receiver.recv().unwrap() else {
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
            restricted_cleanup: Arc::new(Mutex::new(None)),
            limit: Arc::new(Mutex::new(RateLimit {
                start: Instant::now(),
                remaining: MESSAGES_PER_SECOND,
            })),
            suppressed: Arc::new(AtomicU64::new(0)),
        };
        diagnostics.emit(|| "\n\x1btest".repeat(1024));
        let Event::Peer(message) = receiver.recv().unwrap() else {
            panic!("expected peer diagnostic");
        };
        assert_eq!(message.chars().count(), MAX_MESSAGE_CHARS);
        assert!(!message.chars().any(char::is_control));
    }

    #[test]
    fn restricted_cleanup_lane_coalesces_without_evicting_administration() {
        let (sender, _receiver) = mpsc::sync_channel(QUEUE_CAPACITY);
        let diagnostics = Diagnostics {
            sender,
            administrative: Arc::new(Mutex::new(VecDeque::new())),
            restricted_cleanup: Arc::new(Mutex::new(None)),
            limit: Arc::new(Mutex::new(RateLimit {
                start: Instant::now(),
                remaining: MESSAGES_PER_SECOND,
            })),
            suppressed: Arc::new(AtomicU64::new(0)),
        };
        for index in 0..ADMIN_CAPACITY {
            diagnostics.emit_administrative(&format!("authorization failure {index}"));
        }
        diagnostics.emit_restricted_kill_failure("old cgroup failure");
        diagnostics.emit_restricted_kill_failure("latest cgroup failure");

        assert_eq!(
            crate::sync::mutex(&diagnostics.administrative).len(),
            ADMIN_CAPACITY
        );
        assert_eq!(
            crate::sync::mutex(&diagnostics.restricted_cleanup).as_deref(),
            Some("latest cgroup failure")
        );
    }

    #[test]
    fn authorization_state_preempts_an_unstarted_cgroup_retry() {
        struct FailFirstWriter {
            failed: bool,
            attempts: mpsc::Sender<()>,
            stopped: mpsc::Sender<()>,
            output: Arc<Mutex<Vec<u8>>>,
        }

        impl Write for FailFirstWriter {
            fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
                self.attempts.send(()).unwrap();
                if !self.failed {
                    self.failed = true;
                    return Err(io::Error::other("transient diagnostic failure"));
                }
                crate::sync::mutex(&self.output).extend_from_slice(buffer);
                Ok(buffer.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        impl Drop for FailFirstWriter {
            fn drop(&mut self) {
                let _ = self.stopped.send(());
            }
        }

        let (attempted, attempts) = mpsc::channel();
        let (stopped, finished) = mpsc::channel();
        let output = Arc::new(Mutex::new(Vec::new()));
        let diagnostics = Diagnostics::with_writer(FailFirstWriter {
            failed: false,
            attempts: attempted,
            stopped,
            output: Arc::clone(&output),
        })
        .unwrap();
        diagnostics.emit_restricted_kill_failure("cgroup kill failed");
        attempts.recv_timeout(Duration::from_secs(5)).unwrap();
        diagnostics.emit_administrative("authorization reload failed");
        attempts.recv_timeout(Duration::from_secs(5)).unwrap();
        attempts.recv_timeout(Duration::from_secs(5)).unwrap();
        drop(diagnostics);
        finished.recv_timeout(Duration::from_secs(5)).unwrap();
        let written = String::from_utf8(crate::sync::mutex(&output).clone()).unwrap();
        assert_eq!(written, "authorization reload failed\ncgroup kill failed\n");
    }

    #[test]
    fn failed_administrative_write_is_retried_without_another_message() {
        struct FailOnceWriter {
            failed: bool,
            attempts: mpsc::Sender<()>,
            stopped: mpsc::Sender<()>,
            output: Arc<Mutex<Vec<u8>>>,
        }

        impl Write for FailOnceWriter {
            fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
                self.attempts.send(()).unwrap();
                if !self.failed {
                    self.failed = true;
                    return Err(io::Error::other("transient diagnostic failure"));
                }
                crate::sync::mutex(&self.output).extend_from_slice(buffer);
                Ok(buffer.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        impl Drop for FailOnceWriter {
            fn drop(&mut self) {
                let _ = self.stopped.send(());
            }
        }

        let (attempted, attempts) = mpsc::channel();
        let (stopped, finished) = mpsc::channel();
        let output = Arc::new(Mutex::new(Vec::new()));
        let diagnostics = Diagnostics::with_writer(FailOnceWriter {
            failed: false,
            attempts: attempted,
            stopped,
            output: Arc::clone(&output),
        })
        .unwrap();
        diagnostics.emit_administrative("authorization reload failed");
        attempts.recv_timeout(Duration::from_secs(5)).unwrap();
        // Re-emitting the same state while it is backing off must not create a
        // second retained entry or reset the absolute retry deadline.
        diagnostics.emit_administrative("authorization reload failed");
        diagnostics.emit(|| "peer session failed".into());
        assert_eq!(crate::sync::mutex(&diagnostics.administrative).len(), 1);
        attempts.recv_timeout(Duration::from_secs(5)).unwrap();
        attempts.recv_timeout(Duration::from_secs(5)).unwrap();
        drop(diagnostics);
        finished.recv_timeout(Duration::from_secs(5)).unwrap();
        let written = String::from_utf8(crate::sync::mutex(&output).clone()).unwrap();
        assert_eq!(
            written,
            "authorization reload failed\npeer session failed\n"
        );
    }

    #[test]
    fn retained_write_resumes_after_a_partial_line() {
        struct PartialWriter {
            call: usize,
            attempts: mpsc::Sender<()>,
            stopped: mpsc::Sender<()>,
            output: Arc<Mutex<Vec<u8>>>,
        }

        impl Write for PartialWriter {
            fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
                self.attempts.send(()).unwrap();
                self.call += 1;
                if self.call == 1 {
                    let count = buffer.len().saturating_sub(1);
                    crate::sync::mutex(&self.output).extend_from_slice(
                        buffer
                            .get(..count)
                            .ok_or_else(|| io::Error::other("invalid test write"))?,
                    );
                    return Ok(count);
                }
                if self.call == 2 {
                    return Err(io::Error::other("newline write failed"));
                }
                crate::sync::mutex(&self.output).extend_from_slice(buffer);
                Ok(buffer.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        impl Drop for PartialWriter {
            fn drop(&mut self) {
                let _ = self.stopped.send(());
            }
        }

        let (attempted, attempts) = mpsc::channel();
        let (stopped, finished) = mpsc::channel();
        let output = Arc::new(Mutex::new(Vec::new()));
        let diagnostics = Diagnostics::with_writer(PartialWriter {
            call: 0,
            attempts: attempted,
            stopped,
            output: Arc::clone(&output),
        })
        .unwrap();
        diagnostics.emit_administrative("authorization reload failed");
        for _ in 0..3 {
            attempts.recv_timeout(Duration::from_secs(5)).unwrap();
        }
        drop(diagnostics);
        finished.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(
            crate::sync::mutex(&output).as_slice(),
            b"authorization reload failed\n"
        );
    }

    #[test]
    fn permanent_write_failure_backs_off_and_stops_on_disconnect() {
        struct FailedWriter {
            attempts: mpsc::Sender<()>,
            stopped: mpsc::Sender<()>,
        }

        impl Write for FailedWriter {
            fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
                self.attempts.send(()).unwrap();
                Err(io::Error::other("permanent diagnostic failure"))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        impl Drop for FailedWriter {
            fn drop(&mut self) {
                let _ = self.stopped.send(());
            }
        }

        let (attempted, attempts) = mpsc::channel();
        let (stopped, finished) = mpsc::channel();
        let diagnostics = Diagnostics::with_writer(FailedWriter {
            attempts: attempted,
            stopped,
        })
        .unwrap();
        diagnostics.emit_administrative("authorization reload failed");
        attempts.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(attempts.recv_timeout(ADMIN_RETRY_INTERVAL / 2).is_err());
        drop(diagnostics);
        finished.recv_timeout(Duration::from_secs(1)).unwrap();
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
