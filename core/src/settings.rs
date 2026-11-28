use std::sync::atomic::Ordering;

use lazymail_accounts::MailAccess;
use lazymail_sync::{DeviceId, Replica, MAIN_DEVICE};
use tokio::sync::MutexGuard;

use crate::error::{invalid, CoreError, Result};
use crate::mailfolder::AccountFolder;
use crate::shared::{hex, unhex, AccountRt, Shared};
use crate::types::{
    CoreEvent, DeviceInfo, JoinOffer, JoinRequest, PullResult, SettingEntry, SettingsSetup,
    SettingsState,
};

type Slot<'a> = MutexGuard<'a, Option<(MailAccess, Replica<AccountFolder>)>>;

fn sync_error(detail: &str) -> CoreError {
    CoreError::Sync {
        detail: detail.into(),
    }
}

fn device_id(s: &str) -> Result<DeviceId> {
    DeviceId::parse(s).ok_or_else(|| invalid("that is not a device id"))
}

impl Shared {
    fn folder_for(&self, acc: &AccountRt) -> Result<AccountFolder> {
        let address = acc.account.lock().unwrap().address.clone();
        match acc.mode() {
            MailAccess::Imap => {
                let imap = acc
                    .imap()
                    .ok_or_else(|| sync_error("the account has no mail server"))?;
                Ok(AccountFolder::imap(imap, &address))
            }
            MailAccess::Graph => Ok(AccountFolder::graph(acc.graph.clone(), &address)),
            MailAccess::None => Err(sync_error("the sync account needs a mailbox")),
        }
    }

    /// The replica of the sync account's folder, made when first needed and again when the
    /// account starts reading its mail another way.
    async fn slot(&self) -> Result<Slot<'_>> {
        let id = self
            .sync_account_id()
            .ok_or_else(|| sync_error("there is no sync account"))?;
        let acc = self.account(&id)?;
        let mode = acc.mode();
        let mut slot = self.replica.lock().await;
        if slot.as_ref().is_none_or(|(m, _)| *m != mode) {
            let folder = self.folder_for(&acc)?;
            let (identity, key) = {
                let d = self.device.lock().unwrap();
                (d.identity(), d.key())
            };
            let replica = match key {
                Some(k) => Replica::with_key(folder, identity, self.clock.clone(), k),
                None => Replica::new(folder, identity, self.clock.clone()),
            };
            *slot = Some((mode, replica));
        }
        Ok(slot)
    }

    async fn with_replica<T>(
        &self,
        op: impl AsyncFnOnce(&mut Replica<AccountFolder>) -> lazymail_sync::Result<T>,
    ) -> Result<T> {
        let mut slot = self.slot().await?;
        let (_, replica) = slot.as_mut().expect("made above");
        let out = op(replica).await;
        self.keep_key(replica)?;
        if replica.key().is_some() && out.is_ok() {
            self.needs_rejoin.store(false, Ordering::Relaxed);
        }
        Ok(out?)
    }

    /// Starts the settings sync on the sync account: the first device makes the key, any other
    /// has to be let in.
    pub(crate) async fn setup_settings(&self) -> SettingsSetup {
        let started = async {
            if self.device.lock().unwrap().key().is_some() {
                return Err(sync_error("settings sync is already set up on this device"));
            }
            let id = self
                .sync_account_id()
                .ok_or_else(|| sync_error("there is no sync account"))?;
            let acc = self.account(&id)?;
            let folder = self.folder_for(&acc)?;
            let identity = self.device.lock().unwrap().identity();
            let mut slot = self.replica.lock().await;
            match Replica::create(folder, identity, self.clock.clone()).await {
                Ok((replica, code)) => {
                    self.keep_key(&replica)?;
                    *slot = Some((acc.mode(), replica));
                    Ok(SettingsSetup::Created {
                        recovery_code: code.to_string(),
                    })
                }
                Err(lazymail_sync::Error::FolderInUse) => {
                    *slot = None;
                    Ok(SettingsSetup::MustJoin)
                }
                Err(e) => Err(e.into()),
            }
        };
        started
            .await
            .unwrap_or_else(|e: CoreError| SettingsSetup::Failed {
                detail: e.to_string(),
            })
    }

    pub(crate) fn settings_state(&self) -> SettingsState {
        let d = self.device.lock().unwrap();
        if d.sync_account.is_none() {
            SettingsState::NoSyncAccount
        } else if d.settings_key.is_none() {
            SettingsState::NoKey
        } else if self.needs_rejoin.load(Ordering::Relaxed) {
            SettingsState::NeedsRejoin
        } else {
            SettingsState::Ready
        }
    }

    pub(crate) async fn pull_settings(&self) -> Result<PullResult> {
        let p = self.with_replica(async |r| r.pull().await).await?;
        if p.needs_rejoin {
            self.needs_rejoin.store(true, Ordering::Relaxed);
        }
        Ok(PullResult {
            changed: p.changed as u32,
            needs_rejoin: p.needs_rejoin,
            key_replaced: p.key_replaced,
            conflict: p.conflict,
        })
    }

    pub(crate) async fn settings(&self) -> Result<Vec<SettingEntry>> {
        self.with_replica(async |r| {
            read(r).await?;
            Ok(r.entries()
                .map(|(k, v)| SettingEntry {
                    key: k.to_string(),
                    value: v.to_string(),
                })
                .collect())
        })
        .await
    }

    pub(crate) async fn setting(&self, key: &str) -> Result<Option<String>> {
        self.with_replica(async |r| {
            read(r).await?;
            Ok(r.get(key).map(str::to_string))
        })
        .await
    }

    pub(crate) async fn set_setting(&self, key: &str, value: Option<&str>) -> Result<()> {
        self.with_replica(async |r| match value {
            Some(v) => r.set(key, v).await,
            None => r.remove(key).await,
        })
        .await
    }

    pub(crate) async fn request_join(&self) -> Result<()> {
        self.with_replica(async |r| r.request_join().await).await
    }

    pub(crate) async fn join_offers(&self) -> Result<Vec<JoinOffer>> {
        self.with_replica(async |r| {
            r.pull().await?;
            Ok(r.join_offers()
                .into_iter()
                .map(|o| JoinOffer {
                    device_id: o.device.to_string(),
                    name: o.name,
                    code: o.code,
                })
                .collect())
        })
        .await
    }

    pub(crate) async fn finish_join(&self, device: &str, shown: &str) -> Result<()> {
        let device = device_id(device)?;
        self.with_replica(async |r| {
            r.pull().await?;
            r.finish_join(device, shown).await
        })
        .await
    }

    pub(crate) async fn join_requests(&self) -> Result<Vec<JoinRequest>> {
        self.with_replica(async |r| {
            r.pull().await?;
            Ok(r.join_requests()
                .into_iter()
                .map(|q| JoinRequest {
                    nonce: hex(&q.nonce),
                    device_id: q.device.to_string(),
                    name: q.name,
                    look_alike: q.look_alike,
                })
                .collect())
        })
        .await
    }

    pub(crate) async fn offer_join(&self, nonce: &str) -> Result<()> {
        let nonce = unhex::<16>(nonce).ok_or_else(|| invalid("that is not a request"))?;
        self.with_replica(async |r| r.offer_join(nonce).await).await
    }

    /// The code this device shows for a request, once the new device has answered its offer.
    pub(crate) async fn join_code(&self, nonce: &str) -> Result<String> {
        let nonce = unhex::<16>(nonce).ok_or_else(|| invalid("that is not a request"))?;
        self.with_replica(async |r| {
            r.pull().await?;
            r.join_code(nonce)
        })
        .await
    }

    pub(crate) async fn approve_join(&self, nonce: &str, typed: &str) -> Result<()> {
        let nonce = unhex::<16>(nonce).ok_or_else(|| invalid("that is not a request"))?;
        self.with_replica(async |r| r.approve_join(nonce, typed).await)
            .await
    }

    pub(crate) async fn deny_join(&self, nonce: &str) -> Result<()> {
        let nonce = unhex::<16>(nonce).ok_or_else(|| invalid("that is not a request"))?;
        self.with_replica(async |r| r.deny_join(nonce).await).await
    }

    pub(crate) async fn recover(&self, code: &str) -> Result<()> {
        self.with_replica(async |r| r.recover(code).await).await
    }

    pub(crate) async fn reissue_recovery(&self) -> Result<String> {
        self.with_replica(async |r| Ok(r.reissue_recovery().await?.to_string()))
            .await
    }

    pub(crate) async fn devices(&self) -> Result<Vec<DeviceInfo>> {
        self.with_replica(async |r| {
            read(r).await?;
            let me = r.id();
            let main = r.get(MAIN_DEVICE).and_then(DeviceId::parse);
            Ok(r.devices()
                .into_iter()
                .map(|d| DeviceInfo {
                    id: d.id.to_string(),
                    name: d.name,
                    is_this_device: d.id == me,
                    is_main_computer: main == Some(d.id),
                    address: d.address,
                    relay_group: d.relay_group,
                    updated: d.updated,
                })
                .collect())
        })
        .await
    }

    /// Ends a device. `keep` is the list of device ids the person saw and agreed should stay.
    pub(crate) async fn remove_device(&self, id: &str, keep: &[String]) -> Result<String> {
        let id = device_id(id)?;
        let keep = keep
            .iter()
            .map(|k| device_id(k))
            .collect::<Result<Vec<_>>>()?;
        self.with_replica(async |r| Ok(r.remove_device(id, &keep).await?.to_string()))
            .await
    }

    /// Starts a new key for exactly these devices.
    pub(crate) async fn keep_only(&self, keep: &[String]) -> Result<String> {
        let keep = keep
            .iter()
            .map(|k| device_id(k))
            .collect::<Result<Vec<_>>>()?;
        self.with_replica(async |r| Ok(r.keep_only(&keep).await?.to_string()))
            .await
    }

    pub(crate) async fn set_main_computer(&self, device: Option<&str>) -> Result<()> {
        let device = device.map(device_id).transpose()?;
        self.with_replica(async |r| match device {
            Some(d) => r.set(MAIN_DEVICE, &d.to_string()).await,
            None => r.remove(MAIN_DEVICE).await,
        })
        .await
    }

    pub(crate) async fn main_computer(&self) -> Result<Option<String>> {
        self.with_replica(async |r| {
            read(r).await?;
            Ok(r.get(MAIN_DEVICE).map(str::to_string))
        })
        .await
    }

    /// Claims or renews the lease for scheduled work; true when this device may do it now.
    pub(crate) async fn hold_lease(&self) -> Result<bool> {
        let held = self.with_replica(async |r| r.hold_lease().await).await?;
        if self.lease_held.swap(held, Ordering::Relaxed) != held {
            self.events.emit(CoreEvent::LeaseChanged { held });
        }
        Ok(held)
    }

    pub(crate) async fn drop_lease(&self) -> Result<()> {
        self.with_replica(async |r| r.drop_lease().await).await?;
        if self.lease_held.swap(false, Ordering::Relaxed) {
            self.events.emit(CoreEvent::LeaseChanged { held: false });
        }
        Ok(())
    }

    pub(crate) async fn lease_holder(&self) -> Result<Option<String>> {
        self.with_replica(async |r| {
            read(r).await?;
            Ok(r.lease_holder().map(|d| d.to_string()))
        })
        .await
    }
}

/// Reads what the other devices wrote. A device without the key has nothing to read.
async fn read(r: &mut Replica<AccountFolder>) -> lazymail_sync::Result<()> {
    if r.key().is_none() {
        return Err(lazymail_sync::Error::NoKey);
    }
    r.pull().await.map(drop)
}
