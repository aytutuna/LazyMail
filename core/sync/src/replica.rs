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
    Approval,
    Rotation,
    Recovery,
    Junk,
}

#[derive(Debug, Default)]
pub struct Pulled {
    /// Settings entries that changed.
    pub changed: usize,
    /// The key was replaced without this device: it has to join again.
    pub needs_rejoin: bool,
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
    pub(crate) seen: HashMap<String, Meta>,
    entries: BTreeMap<String, Entry>,
    pub(crate) devices: HashMap<DeviceId, DeviceRecord>,
    pub(crate) leases: HashMap<DeviceId, Lease>,
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
            seen: HashMap::new(),
            entries: BTreeMap::new(),
            devices: HashMap::new(),
            leases: HashMap::new(),
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
        self.seen.clear();
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
            let Ok(plain) = open(&old.bytes, &what.aad(epoch, from), &data) else {
                continue;
            };
            if matches!(what, Kind::Change | Kind::Snapshot) {
                merged |= self.apply(what, &plain).is_some();
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
        } else {
            self.last.counter += 1;
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
            &what.aad(key.epoch, from),
            &serde_json::to_vec(plain)?,
        );
        let wire = Wire::Sealed {
            what,
            epoch: key.epoch,
            from,
            data,
        };
        let id = self.folder.append(serde_json::to_vec(&wire)?).await?;
        self.seen.insert(id.clone(), meta);
        Ok(id)
    }

    pub(crate) async fn append(&mut self, wire: &Wire, meta: Meta) -> Result<String> {
        let id = self.folder.append(serde_json::to_vec(wire)?).await?;
        self.seen.insert(id.clone(), meta);
        Ok(id)
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
        }
        Ok(())
    }

    /// Reads what the other devices wrote. Call it before showing or acting on settings.
    pub async fn pull(&mut self) -> Result<Pulled> {
        let mut changed = 0;
        loop {
            let ids = self.folder.list().await?;
            let live: HashSet<&str> = ids.iter().map(String::as_str).collect();
            self.seen.retain(|id, _| live.contains(id.as_str()));
            self.join
                .requests
                .retain(|_, (_, id)| live.contains(id.as_str()));
            self.drop_dead_leases();
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
                self.seen.insert(id, Meta::Rotation);
                if let Some(key) = self.accept_rotation(&r) {
                    self.key = Some(key);
                    self.seen.clear();
                    self.devices.clear();
                    self.leases.clear();
                    switched = true;
                    break;
                }
            }
            if !switched {
                break;
            }
        }
        if let Some(k) = &self.key {
            self.rejoin = self
                .seen
                .values()
                .any(|m| matches!(m, Meta::Foreign { epoch, .. } if *epoch > k.epoch));
        }
        Ok(Pulled {
            changed,
            needs_rejoin: self.rejoin,
        })
    }

    /// Forgets leases whose message another device has removed.
    fn drop_dead_leases(&mut self) {
        let held: HashSet<DeviceId> = self
            .seen
            .values()
            .filter_map(|m| match m {
                Meta::Lease(d) => Some(*d),
                _ => None,
            })
            .collect();
        self.leases.retain(|d, _| held.contains(d));
    }

    fn ingest(&mut self, id: String, wire: Wire) -> usize {
        match wire {
            Wire::Sealed {
                what,
                epoch,
                from,
                data,
            } => self.ingest_sealed(id, what, epoch, from, &data),
            Wire::Join(r) => {
                if r.valid() {
                    self.join.requests.insert(r.nonce, (r, id.clone()));
                }
                self.seen.insert(id, Meta::Join);
                0
            }
            Wire::Offer(o) => {
                if self.join.pending == Some(o.nonce)
                    && o.valid()
                    && !self.join.offers.iter().any(|x| x.from == o.from)
                {
                    self.join.offers.push(o.clone());
                }
                self.seen.insert(id, Meta::Offer { nonce: o.nonce });
                0
            }
            Wire::Approval(a) => {
                if self.join.pending == Some(a.nonce) && a.to == self.me.id() {
                    self.join.approval = Some((a, id.clone()));
                }
                self.seen.insert(id, Meta::Approval);
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
        let Ok(plain) = open(&key.bytes, &what.aad(epoch, from), data) else {
            self.seen.insert(id, foreign);
            return 0;
        };
        match self.apply(what, &plain) {
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

    fn apply(&mut self, what: Kind, plain: &[u8]) -> Option<(Meta, usize)> {
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
                let holder = l.holder;
                if self
                    .leases
                    .get(&holder)
                    .is_none_or(|cur| cur.expires <= l.expires)
                {
                    self.leases.insert(holder, l);
                }
                Some((Meta::Lease(holder), 0))
            }
        }
    }

    /// The new key from a rotation this device may follow: made by a current
    /// member and wrapped for this device.
    fn accept_rotation(&self, r: &Rotation) -> Option<SettingsKey> {
        let key = self.key.as_ref()?;
        if r.epoch != key.epoch + 1 {
            return None;
        }
        let proof = open(&key.bytes, &Rotation::aad(r.epoch, r.from), &r.proof).ok()?;
        if proof != wraps_digest(&r.wraps) {
            return None;
        }
        let wrap = r.wraps.iter().find(|w| w.to == self.me.id())?;
        unwrap_key(&self.me, wrap)
            .ok()
            .filter(|k| k.epoch == r.epoch)
    }

    /// Every device known in the folder, this one included once it has joined.
    pub fn devices(&self) -> Vec<DeviceRecord> {
        let mut all: Vec<_> = self.devices.values().cloned().collect();
        all.sort_by(|a, b| (&a.name, a.id).cmp(&(&b.name, b.id)));
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
        let record = DeviceRecord {
            id: me,
            name: self.me.name().to_string(),
            x_pub: self.me.x_pub(),
            ed_pub: self.me.ed_pub(),
            address: self.reach.0.clone(),
            relay_group: self.reach.1.clone(),
            updated: (self.clock)(),
        };
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
                epoch = epoch.max(*e);
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
        self.leases.clear();
        self.join = JoinState::default();
        let code = self.start(warning.epoch + 1).await?;
        if !self.entries.is_empty() {
            self.put_snapshot().await?;
        }
        Ok(code)
    }

    /// Ends a device: the settings key changes for the ones that stay, and
    /// everything the old key protected is deleted. The returned recovery code
    /// replaces the old one. Call `rekey` on the replicas of the other accounts.
    pub async fn remove_device(&mut self, id: DeviceId) -> Result<RecoveryCode> {
        self.writable()?;
        if id == self.me.id() {
            return Err(Error::RemoveSelf);
        }
        self.pull().await?;
        let old = self.writable()?;
        if !self.devices.contains_key(&id) {
            return Err(Error::UnknownDevice);
        }
        let keep: Vec<DeviceRecord> = self
            .devices
            .values()
            .filter(|d| d.id != id)
            .cloned()
            .collect();
        let new = SettingsKey::random(old.epoch + 1);
        let wraps: Vec<Wrap> = keep
            .iter()
            .map(|d| wrap_key(d.id, &d.x_pub, &new))
            .collect();
        let me = self.me.id();
        let rotation = Rotation {
            epoch: new.epoch,
            from: me,
            proof: seal(
                &old.bytes,
                &Rotation::aad(new.epoch, me),
                &wraps_digest(&wraps),
            ),
            wraps,
        };
        let stale: Vec<String> = self.seen.keys().cloned().collect();
        let rotation_id = self
            .folder
            .append(serde_json::to_vec(&Wire::Rotation(rotation))?)
            .await?;
        self.key = Some(new);
        self.seen.clear();
        self.devices.clear();
        self.leases.clear();
        self.seen.insert(rotation_id, Meta::Rotation);
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
