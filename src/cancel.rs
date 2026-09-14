use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Notify;

#[derive(Default)]
struct CancelInner {
    cancelled: AtomicBool,
    notify: Notify,
}

#[derive(Clone, Default)]
pub struct CancelToken {
    inner: Arc<CancelInner>,
}

impl CancelToken {
    pub fn cancel(&self) {
        if !self.inner.cancelled.swap(true, Ordering::SeqCst) {
            self.inner.notify.notify_waiters();
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::SeqCst)
    }

    pub async fn cancelled(&self) {
        let mut waiter_enabled = || {};
        self.cancelled_after_waiter_enabled(&mut waiter_enabled)
            .await;
    }

    async fn cancelled_after_waiter_enabled(&self, waiter_enabled: &mut (dyn FnMut() + Send)) {
        loop {
            if self.is_cancelled() {
                return;
            }
            let mut notified = pin!(self.inner.notify.notified());
            notified.as_mut().enable();
            waiter_enabled();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::CancelToken;
    use std::time::Duration;

    #[test]
    fn default_token_is_not_cancelled() {
        assert!(!CancelToken::default().is_cancelled());
    }

    #[test]
    fn cancel_flips_the_flag() {
        let token = CancelToken::default();
        token.cancel();
        assert!(token.is_cancelled());
    }

    #[test]
    fn cancel_is_visible_through_clones() {
        let token = CancelToken::default();
        let clone = token.clone();
        assert!(!clone.is_cancelled());
        token.cancel();
        assert!(clone.is_cancelled());
    }

    #[test]
    fn cancel_is_idempotent() {
        let token = CancelToken::default();
        token.cancel();
        token.cancel();
        assert!(token.is_cancelled());
    }

    #[tokio::test]
    async fn cancelled_resolves_immediately_when_already_cancelled() {
        let token = CancelToken::default();
        token.cancel();
        tokio::time::timeout(Duration::from_millis(50), token.cancelled())
            .await
            .expect("already cancelled token must resolve without waiting");
    }

    #[tokio::test]
    async fn cancelled_resolves_after_cancel() {
        let token = CancelToken::default();
        let waiter = token.clone();
        let handle = tokio::spawn(async move { waiter.cancelled().await });
        tokio::task::yield_now().await;
        token.cancel();
        tokio::time::timeout(Duration::from_millis(500), handle)
            .await
            .expect("cancelled() must wake on cancel")
            .expect("waiter task must not panic");
    }

    #[tokio::test]
    async fn cancelled_wakes_every_waiter() {
        let token = CancelToken::default();
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let waiter = token.clone();
                tokio::spawn(async move { waiter.cancelled().await })
            })
            .collect();
        tokio::task::yield_now().await;
        token.cancel();
        for handle in handles {
            tokio::time::timeout(Duration::from_millis(500), handle)
                .await
                .expect("every waiter must wake on cancel")
                .expect("waiter task must not panic");
        }
    }

    #[tokio::test]
    async fn cancelled_does_not_resolve_before_cancel() {
        let token = CancelToken::default();
        let result = tokio::time::timeout(Duration::from_millis(30), token.cancelled()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn cancel_racing_a_fresh_waiter_is_not_missed() {
        for _ in 0..64 {
            let token = CancelToken::default();
            let waiter = token.clone();
            let handle = tokio::spawn(async move { waiter.cancelled().await });
            token.cancel();
            tokio::time::timeout(Duration::from_millis(500), handle)
                .await
                .expect("cancel must not be lost when it races registration")
                .expect("waiter task must not panic");
        }
    }

    #[tokio::test]
    async fn cancellation_after_waiter_registration_is_observed_without_notification_loss() {
        let token = CancelToken::default();
        let cancelling_token = token.clone();

        let mut cancel_after_registration = || cancelling_token.cancel();
        token
            .cancelled_after_waiter_enabled(&mut cancel_after_registration)
            .await;

        assert!(token.is_cancelled());
    }
}
