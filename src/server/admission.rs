//! Session admission counts work until its final owner finishes, including
//! blocking account preparation after its async waiter has been cancelled.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::crypto::Fingerprint;

const MAX_SESSIONS: usize = 128;
const MAX_SESSIONS_PER_KEY: usize = 32;

pub(super) struct SessionBudget {
    available: Arc<Semaphore>,
    per_key: Mutex<HashMap<Fingerprint, usize>>,
}

impl SessionBudget {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            available: Arc::new(Semaphore::new(MAX_SESSIONS)),
            per_key: Mutex::new(HashMap::new()),
        })
    }

    /// Never queue an unaffordable session: a waiting task would itself be an
    /// unaccounted resource, and a client can open unlimited sequential streams.
    pub(super) fn try_acquire(self: &Arc<Self>, key: Fingerprint) -> Option<SessionLease> {
        let permit = Arc::clone(&self.available).try_acquire_owned().ok()?;
        let mut per_key = crate::sync::mutex(&self.per_key);
        let count = per_key.entry(key).or_default();
        if *count == MAX_SESSIONS_PER_KEY {
            return None;
        }
        *count += 1;
        Some(SessionLease(Arc::new(SessionSlot {
            budget: Arc::clone(self),
            key,
            _permit: permit,
        })))
    }
}

/// Clones share one slot. In particular, a running `spawn_blocking` closure
/// retains its clone even when cancellation drops the async session owner.
#[derive(Clone)]
pub(super) struct SessionLease(Arc<SessionSlot>);

impl SessionLease {
    pub(super) fn retain(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

struct SessionSlot {
    budget: Arc<SessionBudget>,
    key: Fingerprint,
    _permit: OwnedSemaphorePermit,
}

impl Drop for SessionSlot {
    fn drop(&mut self) {
        let mut per_key = crate::sync::mutex(&self.budget.per_key);
        if let Some(count) = per_key.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                per_key.remove(&self.key);
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "test assertions")]
mod tests {
    use super::*;
    use std::time::Duration;

    fn key() -> Fingerprint {
        let (pem, _) = crate::crypto::generate_identity("test", &["test".into()], 30).unwrap();
        Fingerprint::of_cert(&crate::crypto::cert_from_pem(&pem).unwrap()).unwrap()
    }

    #[test]
    fn session_limits_leave_room_for_other_keys_and_release_entries() {
        let budget = SessionBudget::new();
        let first = key();
        let second = key();
        let held = (0..MAX_SESSIONS_PER_KEY)
            .map(|_| budget.try_acquire(first).unwrap())
            .collect::<Vec<_>>();
        assert!(budget.try_acquire(first).is_none());
        assert!(budget.try_acquire(second).is_some());
        drop(held);
        assert!(crate::sync::mutex(&budget.per_key).is_empty());
        assert_eq!(budget.available.available_permits(), MAX_SESSIONS);
    }

    #[test]
    fn global_limit_covers_all_keys() {
        let budget = SessionBudget::new();
        let mut held = Vec::new();
        for _ in 0..4 {
            let key = key();
            for _ in 0..MAX_SESSIONS_PER_KEY {
                held.push(budget.try_acquire(key).unwrap());
            }
        }
        assert_eq!(held.len(), MAX_SESSIONS);
        assert!(budget.try_acquire(key()).is_none());
        held.pop();
        assert!(budget.try_acquire(key()).is_some());
    }

    #[tokio::test]
    async fn cancelling_preparation_waiter_does_not_release_blocking_work() {
        let budget = SessionBudget::new();
        let key = key();
        let lease = budget.try_acquire(key).unwrap();
        let other = (1..MAX_SESSIONS_PER_KEY)
            .map(|_| budget.try_acquire(key).unwrap())
            .collect::<Vec<_>>();
        let (started, running) = tokio::sync::oneshot::channel();
        let (finish, release) = std::sync::mpsc::channel();
        let waiter = tokio::spawn(async move {
            let blocking_lease = lease.retain();
            let task = tokio::task::spawn_blocking(move || {
                let _lease = blocking_lease;
                started.send(()).unwrap();
                release.recv_timeout(Duration::from_secs(5)).unwrap();
            });
            let _ = task.await;
            drop(lease);
        });
        running.await.unwrap();
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert!(budget.try_acquire(key).is_none());
        finish.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while budget.try_acquire(key).is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        drop(other);
    }
}
