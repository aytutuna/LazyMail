use std::future::Future;
use std::sync::Arc;

use tokio::sync::watch;

use crate::error::{Error, Result};

/// Ends everything an account is doing: `run` and every `watch` take a clone. Unlike a bare
/// `Notify`, a stop given while a task is busy is not lost and reaches all of them.
#[derive(Clone, Debug)]
pub struct Stop(Arc<watch::Sender<bool>>);

impl Default for Stop {
    fn default() -> Stop {
        Stop(Arc::new(watch::channel(false).0))
    }
}

impl Stop {
    pub fn new() -> Stop {
        Stop::default()
    }

    pub fn stop(&self) {
        self.0.send_replace(true);
    }

    pub(crate) async fn stopped(&self) {
        let mut rx = self.0.subscribe();
        let _ = rx.wait_for(|s| *s).await;
    }

    /// Runs `work` unless the stop comes first, which drops it between two of its awaits.
    /// Store writes are whole transactions, so a dropped sync leaves nothing half done.
    pub(crate) async fn guard<T>(&self, work: impl Future<Output = Result<T>>) -> Result<T> {
        tokio::select! {
            r = work => r,
            _ = self.stopped() => Err(Error::Stopped),
        }
    }
}
