use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::crypto::{open, seal, unwrap_key, wrap_key, wraps_digest, RecoveryCode, SettingsKey};
use crate::join::JoinState;
use crate::wire::{Change, DeviceRecord, Entry, Hlc, Kind, Lease, Rotation, Snapshot, Wire, Wrap};
use crate::{DeviceId, Error, Folder, Identity, Result};

/// Changes in the folder after which a device writes a snapshot.
pub const COMPACT_AT: usize = 200;

/// Changes stamped further ahead than this are ignored.
const MAX_AHEAD_MS: u64 = 24 * 60 * 60 * 1000;

/// Epochs above this are taken as made up when picking the next one.
const MAX_EPOCH: u32 = 1 << 20;

/// Milliseconds since the Unix epoch.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

pub fn system_clock() -> Clock {
    Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    })
}

/// What a device knows about a message it has read, kept so it can delete the
/// messages it replaces.
pub(crate) enum Meta {
    Change,
    Snapshot,
    Device(DeviceId),
    Lease(DeviceId),
    /// Sealed under a key this device does not hold.
    Foreign {
        what: Kind,
        epoch: u32,
        from: DeviceId,
    },
    Join,
    Offer {
        nonce: [u8; 16],
    },
    Reveal {
        nonce: [u8; 16],
    },
    Approval,
    Rotation {
        /// A member's rotation that leaves this device out.
        excludes: bool,
    },
    Recovery,
    Junk,
}

#[derive(Debug, Default)]
pub struct Pulled {
    /// Settings entries that changed.
    pub changed: usize,
    /// A member rotated the key without this device: it has to join again.
    pub needs_rejoin: bool,
    /// The folder holds messages under a newer key that no rotation of this
    /// device's key explains. Either a key was started from scratch, which
    /// the person can confirm on the other devices, or someone with the
    /// mailbox wrote a made-up number. Writing goes on under the current key.
    pub key_replaced: bool,
    /// A second rotation to the epoch this device holds was written by a
    /// member of the old key. Writing stops until the person has checked the
    /// devices and recovered or started again.
    pub conflict: bool,
}

/// Shown before a device starts a new key because it has neither another
/// device nor the recovery code.
#[derive(Debug)]
pub struct NewKeyWarning {
    /// Devices that wrote to the folder; they stop syncing until they join again.
    pub devices: Vec<DeviceId>,
    /// Setting changes in the folder that are discarded.
    pub changes: usize,
    epoch: u32,
}

/// One device's view of one "Alazy" folder.
pub struct Replica<F> {
    pub(crate) folder: F,
    pub(crate) me: Identity,
    pub(crate) clock: Clock,
    last: Hlc,
    pub(crate) key: Option<SettingsKey>,
    pub(crate) rejoin: bool,
    /// The key before the last rotation, kept in memory to recognise a rival.
    prev: Option<SettingsKey>,
    /// Signature of the rotation this device followed or made.
    adopted: Option<[u8; 64]>,
    /// Where this device's own rotation is in the folder, to put it back.
    own_rotation: Option<(String, Rotation)>,
    conflict: bool,
    pub(crate) seen: HashMap<String, Meta>,
    entries: BTreeMap<String, Entry>,
    pub(crate) devices: HashMap<DeviceId, DeviceRecord>,
    /// Devices whose messages opened under the current key, record or not.
    senders: HashSet<DeviceId>,
    /// Lease messages by message id.
    pub(crate) leases: HashMap<String, Lease>,
    /// Where each message stands in the folder, oldest first.
    pub(crate) order: HashMap<String, usize>,
    /// When this device first read each lease message, on its own clock.
    pub(crate) lease_seen: HashMap<String, u64>,
    next_pos: usize,
    pub(crate) join: JoinState,
    reach: (Option<String>, Option<String>),
}

impl<F: Folder> Replica<F> {
    /// A device with no key yet: join, recover or create.
    pub fn new(folder: F, me: Identity, clock: Clock) -> Self {
        let last = Hlc {
            wall: 0,
            counter: 0,
            device: me.id(),
        };
        Replica {
            folder,
            me,
            clock,
            last,
            key: None,
            rejoin: false,
            prev: None,
            adopted: None,
            own_rotation: None,
            conflict: false,
            seen: HashMap::new(),
            entries: BTreeMap::new(),
            devices: HashMap::new(),
            senders: HashSet::new(),
            leases: HashMap::new(),
            order: HashMap::new(),
            lease_seen: HashMap::new(),
            next_pos: 0,
            join: JoinState::default(),
            reach: (None, None),
        }
    }

    /// A device that kept the key from an earlier run.
    pub fn with_key(folder: F, me: Identity, clock: Clock, key: SettingsKey) -> Self {
        let mut r = Self::new(folder, me, clock);
        r.key = Some(key);
        r
    }

    /// Starts the first key in an empty folder. The code is shown once to be printed.
    pub async fn create(folder: F, me: Identity, clock: Clock) -> Result<(Self, RecoveryCode)> {
        if !folder.list().await?.is_empty() {
            return Err(Error::FolderInUse);
        }
        let mut r = Self::new(folder, me, clock);
        let code = r.start(1).await?;
        Ok((r, code))
    }

    pub fn id(&self) -> DeviceId {
        self.me.id()
    }

    pub fn key(&self) -> Option<&SettingsKey> {
        self.key.as_ref()
    }

    /// Adopts a key learned elsewhere, for the folder of an account other than
    /// the sync account when the sync account's key has changed.
    pub fn set_key(&mut self, key: SettingsKey) {
        self.key = Some(key);
        self.rejoin = false;
        self.clear_rotation();
        self.seen.clear();
    }

    fn clear_rotation(&mut self) {
        self.prev = None;
        self.adopted = None;
        self.own_rotation = None;
        self.conflict = false;
    }

    /// Drops a key that turned out not to be the person's, and what was read with it.
    pub(crate) fn forget_key(&mut self) {
        self.key = None;
        self.rejoin = false;
        self.clear_rotation();
        self.seen.clear();
        self.entries.clear();
        self.devices.clear();
        self.senders.clear();
        self.leases.clear();
    }

    /// Like `set_key`, and moves what the folder holds under the new key. Done
    /// by the device that rotated the key.
    pub async fn rekey(&mut self, key: SettingsKey) -> Result<()> {
        self.pull().await?;
        let old = self.key.clone();
        let stale: Vec<String> = self.seen.keys().cloned().collect();
        self.set_key(key);
        self.put_snapshot().await?;
        if let Some(old) = old {
            self.absorb_late(&old, &stale).await?;
        }
        self.delete_all(&stale).await
    }

    /// Messages another device added under the old key after this device
    /// last read the folder. Their settings are folded into a new snapshot
    /// instead of being deleted unread.
    async fn absorb_late(&mut self, old: &SettingsKey, read: &[String]) -> Result<()> {
        let mut late = Vec::new();
        let mut merged = false;
        for id in self.folder.list().await? {
            if read.contains(&id) || self.seen.contains_key(&id) {
                continue;
            }
            let Some(body) = self.folder.fetch(&id).await? else {
                continue;
            };
            let Ok(Wire::Sealed {
                what,
                epoch,
                from,
                data,
            }) = serde_json::from_slice(&body)
            else {
                continue;
            };
            if epoch != old.epoch {
                continue;
            }
            let Ok(plain) = open(
                &old.bytes,
                &what.aad(epoch, from, self.folder.scope()),
                &data,
            ) else {
                continue;
            };
            if matches!(what, Kind::Change | Kind::Snapshot) {
                merged |= self.apply(&id, what, from, &plain).is_some();
            }
            late.push(id);
        }
        if merged {
            let prev: Vec<String> = self
                .seen
                .iter()
                .filter(|(_, m)| matches!(m, Meta::Snapshot))
                .map(|(id, _)| id.clone())
                .collect();
            self.put_snapshot().await?;
            self.delete_all(&prev).await?;
        }
        self.delete_all(&late).await
    }

    pub(crate) fn writable(&self) -> Result<SettingsKey> {
        if self.conflict {
            return Err(Error::KeyConflict);
        }
        if self.rejoin {
            return Err(Error::NeedsRejoin);
        }
        self.key.clone().ok_or(Error::NoKey)
    }

    fn tick(&mut self) -> Hlc {
        let now = (self.clock)();
        if now > self.last.wall {
            self.last.wall = now;
            self.last.counter = 0;
        } else if let Some(c) = self.last.counter.checked_add(1) {
            self.last.counter = c;
        } else {
            self.last.wall += 1;
            self.last.counter = 0;
        }
        self.last
    }

    fn observe(&mut self, h: &Hlc) {
        if (h.wall, h.counter) > (self.last.wall, self.last.counter) {
            self.last.wall = h.wall;
            self.last.counter = h.counter;
        }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key)?.value.as_deref()
    }

    /// Every key that has a value.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries
            .iter()
            .filter_map(|(k, e)| Some((k.as_str(), e.value.as_deref()?)))
    }

    pub async fn set(&mut self, key: &str, value: &str) -> Result<()> {
        self.write(key, Some(value.to_string())).await
    }

    pub async fn remove(&mut self, key: &str) -> Result<()> {
        self.write(key, None).await
    }

    async fn write(&mut self, key: &str, value: Option<String>) -> Result<()> {
        self.writable()?;
        let entry = Entry {
            hlc: self.tick(),
            value,
        };
        let change = Change {
            key: key.to_string(),
            entry: entry.clone(),
        };
        self.put(Kind::Change, &change, Meta::Change).await?;
        self.merge(key.to_string(), entry);
        let changes = self
            .seen
            .values()
            .filter(|m| matches!(m, Meta::Change))
            .count();
        if changes >= COMPACT_AT {
            self.compact().await?;
        }
        Ok(())
    }

    fn merge(&mut self, key: String, entry: Entry) -> bool {
        // A stamp far ahead of this clock would beat every later edit of the key.
        if entry.hlc.wall > (self.clock)().saturating_add(MAX_AHEAD_MS) {
            return false;
        }
        self.observe(&entry.hlc);
        match self.entries.get(&key) {
            Some(cur) if cur.hlc >= entry.hlc => false,
            _ => {
                self.entries.insert(key, entry);
                true
            }
        }
    }

    pub(crate) async fn put(
        &mut self,
        what: Kind,
        plain: &impl Serialize,
        meta: Meta,
    ) -> Result<String> {
        let key = self.writable()?;
        let from = self.me.id();
        let data = seal(
            &key.bytes,
            &what.aad(key.epoch, from, self.folder.scope()),
            &serde_json::to_vec(plain)?,
        );
        let wire = Wire::Sealed {
            what,
            epoch: key.epoch,
            from,
            data,
        };
        let id = self.folder.append(serde_json::to_vec(&wire)?).await?;
        self.note_written(&id, meta);
        Ok(id)
    }

    pub(crate) async fn append(&mut self, wire: &Wire, meta: Meta) -> Result<String> {
        let id = self.folder.append(serde_json::to_vec(wire)?).await?;
        self.note_written(&id, meta);
        Ok(id)
    }

    fn note_written(&mut self, id: &str, meta: Meta) {
        self.seen.insert(id.to_string(), meta);
        self.order.insert(id.to_string(), self.next_pos);
        self.next_pos += 1;
    }

    async fn put_snapshot(&mut self) -> Result<()> {
        let snapshot = Snapshot {
            entries: self.entries.clone(),
        };
        self.put(Kind::Snapshot, &snapshot, Meta::Snapshot).await?;
        Ok(())
    }

    /// Replaces the changes and snapshots this device has read with one snapshot.
    /// Messages another device added since are not touched.
    async fn compact(&mut self) -> Result<()> {
        let old: Vec<String> = self
            .seen
            .iter()
            .filter(|(_, m)| matches!(m, Meta::Change | Meta::Snapshot))
            .map(|(id, _)| id.clone())
            .collect();
        self.put_snapshot().await?;
        self.delete_all(&old).await
    }

    pub(crate) async fn delete_all(&mut self, ids: &[String]) -> Result<()> {
        for id in ids {
            self.folder.delete(id).await?;
            self.seen.remove(id);
            self.leases.remove(id);
            self.lease_seen.remove(id);
            self.order.remove(id);
        }
        Ok(())
    }

    /// Reads what the other devices wrote. Call it before showing or acting on settings.
    pub async fn pull(&mut self) -> Result<Pulled> {
        let mut changed = 0;
        let mut rotated = false;
        loop {
            let ids = self.folder.list().await?;
            let live: HashSet<&str> = ids.iter().map(String::as_str).collect();
            self.seen.retain(|id, _| live.contains(id.as_str()));
            self.join
                .requests
                .retain(|_, s| live.contains(s.id.as_str()));
            self.join
                .reveals
                .retain(|(_, id)| live.contains(id.as_str()));
            self.join
                .approvals
                .retain(|(_, id)| live.contains(id.as_str()));
            self.leases.retain(|id, _| live.contains(id.as_str()));
            self.lease_seen.retain(|id, _| live.contains(id.as_str()));
            self.order = ids.iter().cloned().zip(0..).collect();
            self.next_pos = ids.len();
            let mut rotations = Vec::new();
            for id in &ids {
                if self.seen.contains_key(id) {
                    continue;
                }
                let Some(body) = self.folder.fetch(id).await? else {
                    continue;
                };
                match serde_json::from_slice(&body) {
                    Ok(Wire::Rotation(r)) => rotations.push((id.clone(), r)),
                    Ok(wire) => changed += self.ingest(id.clone(), wire),
                    Err(_) => {
                        self.seen.insert(id.clone(), Meta::Junk);
                    }
                }
            }
            let mut switched = false;
            for (id, r) in rotations {
                if self.rival(&r) {
                    self.conflict = true;
                }
                let accepted = self.accept_rotation(&r);
                let excludes = accepted.is_none() && self.rotation_ok(&r);
                self.seen.insert(id, Meta::Rotation { excludes });
                if let Some(key) = accepted {
                    rotated = true;
                    self.prev = self.key.replace(key);
                    self.adopted = Some(r.sig);
                    self.own_rotation = None;
                    self.conflict = false;
                    self.seen.clear();
                    self.devices.clear();
                    self.senders.clear();
                    self.leases.clear();
                    self.lease_seen.clear();
                    switched = true;
                    break;
                }
            }
            if !switched {
                break;
            }
        }
        if rotated {
            self.republish_own().await?;
        }
        let listed: HashSet<DeviceId> = self
            .seen
            .values()
            .filter_map(|m| match m {
                Meta::Device(d) => Some(*d),
                _ => None,
            })
            .collect();
        self.devices.retain(|d, _| listed.contains(d));
        self.restore_own_rotation().await?;
        let mut key_replaced = false;
        if let Some(k) = &self.key {
            self.rejoin = self
                .seen
                .values()
                .any(|m| matches!(m, Meta::Rotation { excludes: true }));
            key_replaced = self
                .seen
                .values()
                .any(|m| matches!(m, Meta::Foreign { epoch, .. } if *epoch > k.epoch));
        }
        self.reveal_to_offers().await?;
        Ok(Pulled {
            changed,
            needs_rejoin: self.rejoin,
            key_replaced,
            conflict: self.conflict,
        })
    }

    fn ingest(&mut self, id: String, wire: Wire) -> usize {
        match wire {
            Wire::Sealed {
                what,
                epoch,
                from,
                data,
            } => self.ingest_sealed(id, what, epoch, from, &data),
            Wire::Join(_) | Wire::Offer(_) | Wire::Approval(_) | Wire::Reveal(_) => {
                self.ingest_join(id, wire);
                0
            }
            Wire::Recovery { .. } => {
                self.seen.insert(id, Meta::Recovery);
                0
            }
            Wire::Rotation(_) => unreachable!("rotations are handled by pull"),
        }
    }

    fn ingest_sealed(
        &mut self,
        id: String,
        what: Kind,
        epoch: u32,
        from: DeviceId,
        data: &[u8],
    ) -> usize {
        let foreign = Meta::Foreign { what, epoch, from };
        let Some(key) = self.key.as_ref().filter(|k| k.epoch == epoch) else {
            self.seen.insert(id, foreign);
            return 0;
        };
        let Ok(plain) = open(
            &key.bytes,
            &what.aad(epoch, from, self.folder.scope()),
            data,
        ) else {
            self.seen.insert(id, foreign);
            return 0;
        };
        self.senders.insert(from);
        match self.apply(&id, what, from, &plain) {
            Some((meta, changed)) => {
                self.seen.insert(id, meta);
                changed
            }
            None => {
                self.seen.insert(id, Meta::Junk);
                0
            }
        }
    }

    fn apply(
        &mut self,
        id: &str,
        what: Kind,
        from: DeviceId,
        plain: &[u8],
    ) -> Option<(Meta, usize)> {
        match what {
            Kind::Change => {
                let c: Change = serde_json::from_slice(plain).ok()?;
                let changed = self.merge(c.key, c.entry) as usize;
                Some((Meta::Change, changed))
            }
            Kind::Snapshot => {
                let s: Snapshot = serde_json::from_slice(plain).ok()?;
                let changed = s
                    .entries
                    .into_iter()
                    .filter(|(k, e)| self.merge(k.clone(), e.clone()))
                    .count();
                Some((Meta::Snapshot, changed))
            }
            Kind::Device => {
                let d: DeviceRecord = serde_json::from_slice(plain).ok()?;
                if !d.valid() {
                    return None;
                }
                let id = d.id;
                if self
                    .devices
                    .get(&id)
                    .is_none_or(|cur| cur.updated <= d.updated)
                {
                    self.devices.insert(id, d);
                }
                Some((Meta::Device(id), 0))
            }
            Kind::Lease => {
                let l: Lease = serde_json::from_slice(plain).ok()?;
                if l.holder != from {
                    return None;
                }
                let now = (self.clock)();
                self.lease_seen.entry(id.to_string()).or_insert(now);
                self.leases.insert(id.to_string(), l);
                Some((Meta::Lease(from), 0))
            }
        }
    }

    /// The new key from a rotation this device may follow: made by a current
    /// member and wrapped for this device.
    fn accept_rotation(&self, r: &Rotation) -> Option<SettingsKey> {
        if !self.rotation_ok(r) {
            return None;
        }
        let wrap = r.wraps.iter().find(|w| w.to == self.me.id())?;
        unwrap_key(&self.me, wrap)
            .ok()
            .filter(|k| k.epoch == r.epoch)
    }

    /// The rotation is for the next epoch and its proof opens under the
    /// current key, so a member made it.
    fn rotation_ok(&self, r: &Rotation) -> bool {
        let Some(key) = self.key.as_ref() else {
            return false;
        };
        key.epoch.checked_add(1) == Some(r.epoch) && self.proof_opens(key, r)
    }

    fn proof_opens(&self, key: &SettingsKey, r: &Rotation) -> bool {
        r.valid()
            && open(
                &key.bytes,
                &Rotation::aad(r.epoch, r.from, self.folder.scope()),
                &r.proof,
            )
            .is_ok_and(|p| p == wraps_digest(&r.wraps))
    }

    /// A different rotation to the epoch this device holds, made by a member
    /// of the key before it. Copies of the one this device followed are not.
    fn rival(&self, r: &Rotation) -> bool {
        let (Some(key), Some(prev)) = (&self.key, &self.prev) else {
            return false;
        };
        r.epoch == key.epoch && self.adopted != Some(r.sig) && self.proof_opens(prev, r)
    }

    /// After following a rotation: this device's own settings, in case it
    /// wrote one under the old key after the rotating device had read the
    /// folder, which nobody reads any more.
    async fn republish_own(&mut self) -> Result<()> {
        let me = self.me.id();
        let entries: BTreeMap<String, Entry> = self
            .entries
            .iter()
            .filter(|(_, e)| e.hlc.device == me)
            .map(|(k, e)| (k.clone(), e.clone()))
            .collect();
        if entries.is_empty() || self.writable().is_err() {
            return Ok(());
        }
        self.put(Kind::Snapshot, &Snapshot { entries }, Meta::Snapshot)
            .await?;
        Ok(())
    }

    /// The device that rotated the key puts its rotation back if someone
    /// deleted it before the others read it.
    async fn restore_own_rotation(&mut self) -> Result<()> {
        let Some((id, r)) = &self.own_rotation else {
            return Ok(());
        };
        if self.seen.contains_key(id) {
            return Ok(());
        }
        let wire = Wire::Rotation(r.clone());
        let r = r.clone();
        let id = self
            .append(&wire, Meta::Rotation { excludes: false })
            .await?;
        self.own_rotation = Some((id, r));
        Ok(())
    }

    /// Every device known in the folder, this one included once it has joined.
    pub fn devices(&self) -> Vec<DeviceRecord> {
        let mut all: Vec<_> = self.devices.values().cloned().collect();
        all.sort_by(|a, b| (&a.name, a.id).cmp(&(&b.name, b.id)));
        all
    }

    /// Devices that wrote to the folder under the current key but have no
    /// record in it, for instance because one was deleted. They can be
    /// removed like any other.
    pub fn unlisted_devices(&self) -> Vec<DeviceId> {
        let mut all: Vec<_> = self
            .senders
            .iter()
            .copied()
            .filter(|d| *d != self.me.id() && !self.devices.contains_key(d))
            .collect();
        all.sort();
        all
    }

    /// Updates how other devices reach this one.
    pub async fn set_reach(
        &mut self,
        address: Option<String>,
        relay_group: Option<String>,
    ) -> Result<()> {
        self.reach = (address, relay_group);
        self.publish_device().await
    }

    pub(crate) async fn publish_device(&mut self) -> Result<()> {
        let me = self.me.id();
        let mut record = DeviceRecord {
            id: me,
            name: self.me.name().to_string(),
            x_pub: self.me.x_pub(),
            ed_pub: self.me.ed_pub(),
            address: self.reach.0.clone(),
            relay_group: self.reach.1.clone(),
            updated: (self.clock)(),
            sig: [0; 64],
        };
        record.sig = self.me.sign(&record.sig_bytes());
        let old: Vec<String> = self
            .seen
            .iter()
            .filter(|(_, m)| matches!(m, Meta::Device(d) if *d == me))
            .map(|(id, _)| id.clone())
            .collect();
        self.put(Kind::Device, &record, Meta::Device(me)).await?;
        self.devices.insert(me, record);
        self.delete_all(&old).await
    }

    async fn start(&mut self, epoch: u32) -> Result<RecoveryCode> {
        self.key = Some(SettingsKey::random(epoch));
        self.rejoin = false;
        self.publish_device().await?;
        self.write_recovery().await
    }

    async fn write_recovery(&mut self) -> Result<RecoveryCode> {
        let key = self.writable()?;
        let code = RecoveryCode::random();
        let old: Vec<String> = self
            .seen
            .iter()
            .filter(|(_, m)| matches!(m, Meta::Recovery))
            .map(|(id, _)| id.clone())
            .collect();
        let wire = Wire::Recovery {
            data: code.seal_key(&key),
        };
        self.append(&wire, Meta::Recovery).await?;
        self.delete_all(&old).await?;
        Ok(code)
    }

    /// Replaces the recovery code, for when the printed one is lost.
    pub async fn reissue_recovery(&mut self) -> Result<RecoveryCode> {
        self.writable()?;
        self.pull().await?;
        self.write_recovery().await
    }

    /// Gets the key from the printed code. Needs no other device.
    pub async fn recover(&mut self, code: &str) -> Result<()> {
        let code = RecoveryCode::parse(code).ok_or(Error::BadRecoveryCode)?;
        self.pull().await?;
        let ids: Vec<String> = self
            .seen
            .iter()
            .filter(|(_, m)| matches!(m, Meta::Recovery))
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            let Some(body) = self.folder.fetch(&id).await? else {
                continue;
            };
            if let Ok(Wire::Recovery { data }) = serde_json::from_slice(&body) {
                if let Ok(key) = code.open_key(&data) {
                    self.set_key(key);
                    self.pull().await?;
                    return self.publish_device().await;
                }
            }
        }
        Err(Error::BadRecoveryCode)
    }

    /// What starting a new key would cost the other devices.
    pub async fn lost_key_warning(&mut self) -> Result<NewKeyWarning> {
        self.pull().await?;
        let mut devices = BTreeSet::new();
        let mut changes = 0;
        let mut epoch = self.key.as_ref().map_or(0, |k| k.epoch);
        for m in self.seen.values() {
            if let Meta::Foreign {
                what,
                epoch: e,
                from,
            } = m
            {
                devices.insert(*from);
                if *e <= MAX_EPOCH {
                    epoch = epoch.max(*e);
                }
                if *what == Kind::Change {
                    changes += 1;
                }
            }
        }
        devices.remove(&self.me.id());
        Ok(NewKeyWarning {
            devices: devices.into_iter().collect(),
            changes,
            epoch,
        })
    }

    /// Starts a new key with nothing from the folder: every message in it is
    /// removed, and this device's own settings become the new state.
    pub async fn replace_key(&mut self, warning: NewKeyWarning) -> Result<RecoveryCode> {
        for id in self.folder.list().await? {
            self.folder.delete(&id).await?;
        }
        self.seen.clear();
        self.devices.clear();
        self.senders.clear();
        self.leases.clear();
        self.join = JoinState::default();
        self.clear_rotation();
        let epoch = warning.epoch.checked_add(1).ok_or(Error::Corrupt)?;
        let code = self.start(epoch).await?;
        if !self.entries.is_empty() {
            self.put_snapshot().await?;
        }
        Ok(code)
    }

    /// Ends a device: the settings key changes for the ones that stay, and
    /// everything the old key protected is deleted. The returned recovery code
    /// replaces the old one. Call `rekey` on the replicas of the other accounts.
    ///
    /// `keep` is the list of devices the person saw and agreed should keep
    /// access. If the folder now holds a different set, nothing is changed:
    /// the new key is wrapped for every device in it, so a device someone
    /// added in the meantime must not slip in unseen.
    pub async fn remove_device(&mut self, id: DeviceId, keep: &[DeviceId]) -> Result<RecoveryCode> {
        self.writable()?;
        if id == self.me.id() {
            return Err(Error::RemoveSelf);
        }
        self.pull().await?;
        let old = self.writable()?;
        if !self.devices.contains_key(&id) && !self.senders.contains(&id) {
            return Err(Error::UnknownDevice);
        }
        self.own_record().await?;
        let stays: BTreeSet<DeviceId> = self.devices.keys().copied().filter(|d| *d != id).collect();
        if stays != keep.iter().copied().collect() {
            return Err(Error::DevicesChanged);
        }
        let keep: Vec<DeviceRecord> = self
            .devices
            .values()
            .filter(|d| d.id != id)
            .cloned()
            .collect();
        self.rotate(old, keep).await
    }

    /// Starts a new key for exactly these devices, each of which needs a
    /// record in the folder, this one included. It works when the device to be
    /// ended has no record of its own to pick, as when someone deleted it.
    pub async fn keep_only(&mut self, keep: &[DeviceId]) -> Result<RecoveryCode> {
        self.writable()?;
        self.pull().await?;
        let old = self.writable()?;
        self.own_record().await?;
        if !keep.contains(&self.me.id()) {
            return Err(Error::RemoveSelf);
        }
        let mut records = Vec::new();
        for id in keep.iter().collect::<BTreeSet<_>>() {
            records.push(self.devices.get(id).ok_or(Error::UnknownDevice)?.clone());
        }
        self.rotate(old, records).await
    }

    /// A rotation wraps the key for the records in the folder, so this
    /// device's own has to be there.
    async fn own_record(&mut self) -> Result<()> {
        if self.devices.contains_key(&self.me.id()) {
            return Ok(());
        }
        self.publish_device().await
    }

    async fn rotate(&mut self, old: SettingsKey, keep: Vec<DeviceRecord>) -> Result<RecoveryCode> {
        let new = SettingsKey::random(old.epoch.checked_add(1).ok_or(Error::Corrupt)?);
        let wraps: Vec<Wrap> = keep
            .iter()
            .map(|d| wrap_key(d.id, &d.x_pub, &new))
            .collect();
        let me = self.me.id();
        let mut rotation = Rotation {
            epoch: new.epoch,
            from: me,
            x_pub: self.me.x_pub(),
            ed_pub: self.me.ed_pub(),
            proof: seal(
                &old.bytes,
                &Rotation::aad(new.epoch, me, self.folder.scope()),
                &wraps_digest(&wraps),
            ),
            wraps,
            sig: [0; 64],
        };
        rotation.sig = self.me.sign(&rotation.sig_bytes());
        let stale: Vec<String> = self.seen.keys().cloned().collect();
        let rotation_id = self
            .folder
            .append(serde_json::to_vec(&Wire::Rotation(rotation.clone()))?)
            .await?;
        self.clear_rotation();
        self.prev = Some(old.clone());
        self.adopted = Some(rotation.sig);
        self.own_rotation = Some((rotation_id.clone(), rotation));
        self.key = Some(new);
        self.seen.clear();
        self.devices.clear();
        self.senders.clear();
        self.leases.clear();
        self.seen
            .insert(rotation_id, Meta::Rotation { excludes: false });
        for record in keep {
            let id = record.id;
            self.put(Kind::Device, &record, Meta::Device(id)).await?;
            self.devices.insert(id, record);
        }
        self.put_snapshot().await?;
        let code = self.write_recovery().await?;
        self.absorb_late(&old, &stale).await?;
        for id in stale {
            self.folder.delete(&id).await?;
        }
        Ok(code)
    }
}
