//! qsh — a small SSH replacement built on QUIC.
//!
//! The crate is deliberately narrow. It provides exactly what is needed to
//! log in to a machine, run a command on it, and transport `rsync`:
//!
//! * [`proto`] — the wire format,
//! * [`crypto`] — identities, fingerprints, certificate verification,
//! * [`config`] — on-disk layout, `known_hosts`, the authorisation store,
//! * [`pty`] and [`child`] — running the remote process,
//! * [`server`] and [`client`] — the two ends.

pub mod child;
pub mod client;
pub mod config;
pub mod crypto;
pub mod net;
pub mod proto;
pub mod pty;
pub mod server;

/// Lock helpers that treat poisoning as recoverable.
///
/// The crate denies `panic`, so a poisoned lock could only come from a panic
/// inside a dependency. The protected data would still be intact, and refusing
/// every subsequent session over it is the worse failure.
pub(crate) mod sync {
    use std::sync::{Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

    pub(crate) fn read<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
        lock.read().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn write<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
        lock.write().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn mutex<T>(lock: &Mutex<T>) -> MutexGuard<'_, T> {
        lock.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Version reported by `qsh --version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Install the cryptographic provider both binaries rely on.
///
/// Called once at start-up; rustls refuses to build configurations without it.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
