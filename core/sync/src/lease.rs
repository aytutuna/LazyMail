use sha2::{Digest, Sha256};

use crate::crypto::hex;
use crate::replica::Meta;
use crate::wire::{Kind, Lease};
use crate::{DeviceId, Folder, Replica, Result};

/// How long a lease lasts.
pub const LEASE_MS: u64 = 10 * 60 * 1000;

/// Another device waits this much longer than the expiry before it takes a
/// lease over, so a clock that runs a little fast does not cut a holder off.
pub const LEASE_DRIFT_MS: u64 = 2 * 60 * 1000;

/// A lease that has been over this long is never kept alive by this device's
/// own sighting of it, so an old message put back into the folder is ignored.
const MAX_SKEW_MS: u64 = 30 * 60 * 1000;

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
        self.ranked((self.clock)()).first().map(|(d, _)| *d)
    }

    fn main_device(&self) -> Option<DeviceId> {
        DeviceId::parse(self.get(MAIN_DEVICE)?)
    }

    /// Devices with a live lease, the one whose lease was added to the folder
    /// first at the front. The folder's own order is the only order every
    /// device agrees on; each device's clock is only used to tell when a
    /// lease has run out.
    fn ranked(&self, now: u64) -> Vec<(DeviceId, usize)> {
        let mut first: std::collections::HashMap<DeviceId, usize> = Default::default();
        for (id, l) in &self.leases {
            // A lease only ends once this device's clock says so and it has
            // also gone a full lease without seeing the message change, so a
            // clock that is far off cannot cut a holder short.
            let seen = self.lease_seen.get(id).copied().unwrap_or(now);
            let wall_live = l.expires.saturating_add(LEASE_DRIFT_MS) > now;
            let seen_live = seen.saturating_add(LEASE_MS + LEASE_DRIFT_MS) > now
                && l.expires.saturating_add(MAX_SKEW_MS) > now;
            if !wall_live && !seen_live {
                continue;
            }
            let pos = self.order.get(id).copied().unwrap_or(usize::MAX);
            let e = first.entry(l.holder).or_insert(pos);
            *e = (*e).min(pos);
        }
        let mut all: Vec<_> = first.into_iter().collect();
        all.sort_by_key(|(d, pos)| (*pos, *d));
        all
    }

    /// Claims or renews the lease; true when this device may run scheduled
    /// work. Call it every few minutes and again before each job. Whoever's
    /// lease reached the folder first holds it. The main computer does not
    /// push another device off: it writes its own lease, the holder sees it
    /// on its next call and steps aside, and the main computer holds from its
    /// next call. Another device otherwise waits until the lease has run out
    /// or been dropped, which is 10 minutes after the last holder went quiet.
    pub async fn hold_lease(&mut self) -> Result<bool> {
        self.pull().await?;
        if !self.lease_may_try().await? {
            return Ok(false);
        }
        self.lease_write().await?;
        self.pull().await?;
        self.lease_settle().await
    }

    pub(crate) async fn lease_may_try(&mut self) -> Result<bool> {
        let me = self.me.id();
        let ranked = self.ranked((self.clock)());
        let main = self.main_device();
        if main != Some(me) {
            if main.is_some_and(|m| ranked.iter().any(|(d, _)| *d == m)) {
                self.drop_lease().await?;
                return Ok(false);
            }
            if ranked.first().is_some_and(|(d, _)| *d != me) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(crate) async fn lease_write(&mut self) -> Result<()> {
        let me = self.me.id();
        // Each lease has to outlast the last one so a copy of the last one
        // is told apart from it.
        let last = self.lease_high.get(&me).copied().unwrap_or(0);
        let lease = Lease {
            holder: me,
            expires: ((self.clock)() + LEASE_MS).max(last + 1),
        };
        let id = self.put(Kind::Lease, &lease, Meta::Lease(me)).await?;
        let high = self.lease_high.entry(me).or_insert(0);
        *high = (*high).max(lease.expires);
        self.lease_seen.insert(id.clone(), (self.clock)());
        self.leases.insert(id, lease);
        Ok(())
    }

    /// After a write and a pull: keeps the newest lease and returns true when
    /// this device is first in the folder, otherwise gives up (the main
    /// computer keeps one waiting).
    pub(crate) async fn lease_settle(&mut self) -> Result<bool> {
        let me = self.me.id();
        let ranked = self.ranked((self.clock)());
        let won = ranked.first().is_some_and(|(d, _)| *d == me);
        let mine = self.lease_messages(me);
        let newest = mine
            .iter()
            .max_by_key(|id| (self.leases.get(*id).map(|l| l.expires), self.order.get(*id)))
            .cloned();
        if won || self.main_device() == Some(me) {
            let old: Vec<String> = mine
                .into_iter()
                .filter(|id| Some(id) != newest.as_ref())
                .collect();
            self.delete_all(&old).await?;
        } else {
            self.drop_lease().await?;
        }
        Ok(won)
    }

    /// Gives the lease up, for a device that is closing.
    pub async fn drop_lease(&mut self) -> Result<()> {
        let ids = self.lease_messages(self.me.id());
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
