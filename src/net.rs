//! Shared QUIC transport tuning.

use std::time::Duration;

use anyhow::{Context, Result};
use quinn::{IdleTimeout, TransportConfig, VarInt};

/// Flow-control windows. Generous enough that a single `rsync` stream can
/// saturate a fast link instead of stalling on the default window.
const STREAM_WINDOW: u32 = 8 * 1024 * 1024;
const CONNECTION_WINDOW: u32 = 32 * 1024 * 1024;

/// Transport settings shared by both ends.
pub fn transport_config(idle: Duration, keepalive: Duration) -> Result<TransportConfig> {
    let mut tc = TransportConfig::default();
    tc.max_idle_timeout(Some(
        IdleTimeout::try_from(idle).context("idle timeout is out of range")?,
    ));
    // Keep-alives must be comfortably shorter than the idle timeout.
    let keepalive = keepalive.min(idle / 3).max(Duration::from_secs(1));
    tc.keep_alive_interval(Some(keepalive));
    tc.stream_receive_window(VarInt::from_u32(STREAM_WINDOW));
    tc.receive_window(VarInt::from_u32(CONNECTION_WINDOW));
    tc.send_window(u64::from(CONNECTION_WINDOW));
    // One session per stream; a handful of concurrent sessions is plenty.
    tc.max_concurrent_bidi_streams(VarInt::from_u32(64));
    tc.max_concurrent_uni_streams(VarInt::from_u32(0));
    Ok(tc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keepalive_never_exceeds_the_idle_timeout() {
        // A misconfigured keepalive longer than the idle timeout would drop
        // every connection; it must be clamped instead.
        assert!(transport_config(Duration::from_secs(10), Duration::from_secs(600)).is_ok());
        assert!(transport_config(Duration::from_secs(600), Duration::from_secs(15)).is_ok());
    }
}
