use sha2::{Digest, Sha256};

use crate::crypto::hex;
use crate::replica::Meta;
use crate::wire::{Kind, Lease};
use crate::{DeviceId, Folder, Replica, Result};

/// How long a lease lasts, and so how long the main computer has to be silent
/// before another device takes over.
pub const LEASE_MS: u64 = 10 * 60 * 1000;

/// The settings key that names the main computer, by device id.
pub const MAIN_DEVICE: &str = "main_device";

/// The Message-ID every device gives a scheduled email, so whoever sends it
/// can look for it in Sent first.
pub fn scheduled_message_id(item_id: &str, domain: &str) -> String {
    let d = Sha256::new()
        .chain_update(b"lazymail scheduled v1")
        .chain_update(item_id.as_bytes())
        .finalize();
    format!("<{}@{domain}>", hex(&d[..16]))
}

impl<F: Folder> Replica<F> {
    /// The device that may do scheduled work now, as far as this device has read.
    pub fn lease_holder(&self) -> Option<DeviceId> {
        self.holder_at((self.clock)())
    }

    fn main_device(&self) -> Option<DeviceId> {
        DeviceId::parse(self.get(MAIN_DEVICE)?)
    }

    fn holder_at(&self, now: u64) -> Option<DeviceId> {
        let live = || self.leases.values().filter(|l| l.expires > now);
        if let Some(main) = self
            .main_device()
            .filter(|m| live().any(|l| l.holder == *m))
        {
            return Some(main);
        }
        live().min_by_key(|l| (l.since, l.holder)).map(|l| l.holder)
    }

    /// Claims or renews the lease; true when this device may run scheduled
    /// work. Call it every few minutes and again before each job. The main
    /// computer always wins; another device gets the lease only when no live
    /// one exists, which is 10 minutes after the last holder went quiet.
    pub async fn hold_lease(&mut self) -> Result<bool> {
        self.pull().await?;
        let me = self.me.id();
        let now = (self.clock)();
        let current = self.holder_at(now);
        if current.is_some_and(|h| h != me) && self.main_device() != Some(me) {
            return Ok(false);
        }
        let since = match self.leases.get(&me) {
            Some(l) if l.expires > now => l.since,
            _ => now,
        };
        let lease = Lease {
            holder: me,
            since,
            expires: now + LEASE_MS,
        };
        let old = self.lease_messages(me);
        self.put(Kind::Lease, &lease, Meta::Lease(me)).await?;
        self.leases.insert(me, lease);
        self.delete_all(&old).await?;
        // Another device may have written at the same moment.
        self.pull().await?;
        if self.holder_at((self.clock)()) == Some(me) {
            return Ok(true);
        }
        self.drop_lease().await?;
        Ok(false)
    }

    /// Gives the lease up, for a device that is closing.
    pub async fn drop_lease(&mut self) -> Result<()> {
        let ids = self.lease_messages(self.me.id());
        self.leases.remove(&self.me.id());
        self.delete_all(&ids).await
    }

    fn lease_messages(&self, who: DeviceId) -> Vec<String> {
        self.seen
            .iter()
            .filter(|(_, m)| matches!(m, Meta::Lease(d) if *d == who))
            .map(|(id, _)| id.clone())
            .collect()
    }
}
