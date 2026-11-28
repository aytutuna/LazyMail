use std::future::Future;
use std::pin::pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use lazymail_sync::{
    scheduled_message_id, Clock, Error, Folder, Identity, MemoryFolder, Replica, SettingsKey,
    COMPACT_AT, LEASE_DRIFT_MS, LEASE_MS, MAIN_DEVICE,
};

type R = Replica<MemoryFolder>;

#[derive(Clone)]
struct Time(Arc<AtomicU64>);

impl Time {
    fn new() -> Self {
        Time(Arc::new(AtomicU64::new(1_800_000_000_000)))
    }

    fn advance(&self, ms: u64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }

    /// A device clock that runs `skew` milliseconds off the shared time.
    fn clock(&self, skew: i64) -> Clock {
        let t = self.0.clone();
        Arc::new(move || (t.load(Ordering::SeqCst) as i64 + skew) as u64)
    }
}

async fn first(folder: &MemoryFolder, time: &Time, name: &str) -> R {
    Replica::create(folder.clone(), Identity::generate(name), time.clock(0))
        .await
        .unwrap()
        .0
}

/// Walks the join through both screens, the way a person would.
async fn join(host: &mut R, folder: &MemoryFolder, time: &Time, name: &str, skew: i64) -> R {
    let mut new = Replica::new(folder.clone(), Identity::generate(name), time.clock(skew));
    new.request_join().await.unwrap();
    host.pull().await.unwrap();
    let req = host
        .join_requests()
        .into_iter()
        .find(|r| r.name == name)
        .unwrap();
    host.offer_join(req.nonce).await.unwrap();
    new.pull().await.unwrap();
    let offer = new.join_offers().pop().unwrap();
    host.pull().await.unwrap();
    let shown = host.join_code(req.nonce).unwrap();
    assert_eq!(offer.code, shown);
    host.approve_join(req.nonce, &offer.code).await.unwrap();
    new.pull().await.unwrap();
    new.finish_join(offer.device, &shown).await.unwrap();
    host.pull().await.unwrap();
    new
}

#[tokio::test]
async fn changes_reach_other_devices() {
    let time = Time::new();
    let folder = MemoryFolder::new();
    let mut a = first(&folder, &time, "laptop").await;
    let mut b = join(&mut a, &folder, &time, "phone", 0).await;
    a.set("theme", "dark").await.unwrap();
    a.set("font", "serif").await.unwrap();
    assert_eq!(b.pull().await.unwrap().changed, 2);
    assert_eq!(b.get("theme"), Some("dark"));
    b.remove("font").await.unwrap();
    a.pull().await.unwrap();
    assert_eq!(a.get("font"), None);
    assert_eq!(a.entries().collect::<Vec<_>>(), vec![("theme", "dark")]);
}

#[tokio::test]
async fn the_key_survives_a_restart_through_the_secrets_table() {
    let time = Time::new();
    let folder = MemoryFolder::new();
    let mut a = first(&folder, &time, "laptop").await;
    a.set("theme", "dark").await.unwrap();
    let stored = a.key().unwrap().to_secret();

    let key = lazymail_sync::SettingsKey::from_secret(&stored).unwrap();
    assert_eq!(key.epoch(), 1);
    let mut b = Replica::with_key(
        folder.clone(),
        Identity::generate("again"),
        time.clock(0),
        key,
    );
    b.pull().await.unwrap();
    assert_eq!(b.get("theme"), Some("dark"));
    assert!(lazymail_sync::SettingsKey::from_secret(&stored[..10]).is_err());
}

#[tokio::test]
async fn nothing_readable_is_stored() {
    let time = Time::new();
    let folder = MemoryFolder::new();
    let mut a = first(&folder, &time, "laptop").await;
    a.set("signature", "needle-in-a-haystack").await.unwrap();
    for body in folder.bodies() {
        let text = String::from_utf8_lossy(&body);
        assert!(!text.contains("needle"));
        assert!(!text.contains("signature"));
    }
}

#[tokio::test]
async fn concurrent_writes_settle_the_same_everywhere() {
    let time = Time::new();
    let folder = MemoryFolder::new();
    let mut a = first(&folder, &time, "laptop").await;
    let mut b = join(&mut a, &folder, &time, "phone", 0).await;
    let mut c = join(&mut a, &folder, &time, "tablet", 0).await;
    a.pull().await.unwrap();
    b.pull().await.unwrap();
    for (r, v) in [(&mut a, "a"), (&mut b, "b"), (&mut c, "c")] {
        r.set("k", v).await.unwrap();
    }
    // Pull in a different order on each device.
    a.pull().await.unwrap();
    c.pull().await.unwrap();
    b.pull().await.unwrap();
    assert_eq!(a.get("k"), b.get("k"));
    assert_eq!(b.get("k"), c.get("k"));
    assert!(a.get("k").is_some());
}

#[tokio::test]
async fn a_slow_clock_does_not_lose_a_later_edit() {
    let time = Time::new();
    let folder = MemoryFolder::new();
    let mut a = first(&folder, &time, "laptop").await;
    let mut b = join(&mut a, &folder, &time, "phone", -3_600_000).await;
    a.set("k", "from a").await.unwrap();
    b.pull().await.unwrap();
    time.advance(5);
    b.set("k", "from b").await.unwrap();
    a.pull().await.unwrap();
    assert_eq!(a.get("k"), Some("from b"));

    // A fast clock does not stop a slower device from editing afterwards.
    let mut c = join(&mut a, &folder, &time, "tablet", 7_200_000).await;
    c.set("k", "from c").await.unwrap();
    a.pull().await.unwrap();
    a.set("k", "from a again").await.unwrap();
    c.pull().await.unwrap();
    assert_eq!(c.get("k"), Some("from a again"));
}

#[tokio::test]
async fn old_changes_are_folded_into_a_snapshot() {
    let time = Time::new();
    let folder = MemoryFolder::new();
    let mut a = first(&folder, &time, "laptop").await;
    let mut b = join(&mut a, &folder, &time, "phone", 0).await;
    for i in 0..COMPACT_AT + 5 {
        a.set(&format!("key{}", i % 7), &i.to_string())
            .await
            .unwrap();
    }
    let left = folder.list().await.unwrap().len();
    assert!(left < 20, "{left} messages left");
    assert!(b.pull().await.unwrap().changed >= 7);
    assert_eq!(b.get("key0"), a.get("key0"));
    assert_eq!(b.entries().count(), 7);
    // A device that missed nothing still merges what the other wrote meanwhile.
    b.set("late", "x").await.unwrap();
    a.pull().await.unwrap();
    assert_eq!(a.get("late"), Some("x"));
}

#[tokio::test]
async fn three_devices_join_through_each_other() {
    let time = Time::new();
    let folder = MemoryFolder::new();
    let mut a = first(&folder, &time, "laptop").await;
    a.set("theme", "dark").await.unwrap();
    let mut b = join(&mut a, &folder, &time, "phone", 0).await;
    let mut c = join(&mut b, &folder, &time, "tablet", 0).await;
    assert_eq!(c.get("theme"), Some("dark"));
    c.set("lang", "tr").await.unwrap();
    a.pull().await.unwrap();
    b.pull().await.unwrap();
    assert_eq!(a.get("lang"), Some("tr"));
    for r in [&a, &b, &c] {
        let names: Vec<_> = r.devices().into_iter().map(|d| d.name).collect();
        assert_eq!(names, ["laptop", "phone", "tablet"]);
    }
}

#[tokio::test]
async fn reach_is_shared_between_devices() {
    let time = Time::new();
    let folder = MemoryFolder::new();
    let mut a = first(&folder, &time, "laptop").await;
    let mut b = join(&mut a, &folder, &time, "phone", 0).await;
    b.set_reach(Some("192.168.1.20:52735".into()), Some("group-1".into()))
        .await
        .unwrap();
    a.pull().await.unwrap();
    let rec = a.devices().into_iter().find(|d| d.name == "phone").unwrap();
    assert_eq!(rec.address.as_deref(), Some("192.168.1.20:52735"));
    assert_eq!(rec.relay_group.as_deref(), Some("group-1"));
}

#[tokio::test]
async fn a_wrong_code_is_refused_and_three_void_the_request() {
    let time = Time::new();
    let folder = MemoryFolder::new();
    let mut a = first(&folder, &time, "laptop").await;
    let mut new = Replica::new(folder.clone(), Identity::generate("phone"), time.clock(0));
    new.request_join().await.unwrap();
    a.pull().await.unwrap();
    let nonce = a.join_requests()[0].nonce;
    assert!(matches!(
        a.approve_join(nonce, "0000").await,
        Err(Error::NoOffer)
    ));
    a.offer_join(nonce).await.unwrap();
    // The new device has not published its secret yet, so there is no code.
    assert!(matches!(
        a.approve_join(nonce, "0000").await,
        Err(Error::NotRevealed)
    ));
    new.pull().await.unwrap();
    a.pull().await.unwrap();
    let code = new.join_offers()[0].code.clone();
    let wrong = if code == "0000" { "0001" } else { "0000" };
    assert!(matches!(
        a.approve_join(nonce, wrong).await,
        Err(Error::WrongCode)
    ));
    assert!(matches!(
        a.approve_join(nonce, wrong).await,
        Err(Error::WrongCode)
    ));
    assert!(matches!(
        a.approve_join(nonce, wrong).await,
        Err(Error::TooManyAttempts)
    ));
    // Even the right code is too late now.
    assert!(matches!(
        a.approve_join(nonce, &code).await,
        Err(Error::UnknownRequest)
    ));
    new.pull().await.unwrap();
    let who = new.join_offers()[0].device;
    assert!(matches!(
        new.finish_join(who, &code).await,
        Err(Error::NoApproval)
    ));
    assert!(new.key().is_none());
}

#[tokio::test]
async fn the_new_device_needs_the_code_of_the_device_it_trusts() {
    let time = Time::new();
    let folder = MemoryFolder::new();
    let mut a = first(&folder, &time, "laptop").await;
    let mut new = Replica::new(folder.clone(), Identity::generate("phone"), time.clock(0));
    new.request_join().await.unwrap();
    a.pull().await.unwrap();
    let nonce = a.join_requests()[0].nonce;
    a.offer_join(nonce).await.unwrap();
    new.pull().await.unwrap();
    a.pull().await.unwrap();
    let shown = a.join_code(nonce).unwrap();
    a.approve_join(nonce, &shown).await.unwrap();
    new.pull().await.unwrap();
    let who = new.join_offers()[0].device;
    let wrong = if shown == "0000" { "0001" } else { "0000" };
    assert!(matches!(
        new.finish_join(who, wrong).await,
        Err(Error::WrongCode)
    ));
    assert!(new.key().is_none());
    new.finish_join(who, &shown).await.unwrap();
    assert!(new.key().is_some());
}

#[tokio::test]
async fn a_rogue_key_at_an_unused_epoch_is_not_taken() {
    let time = Time::new();
    let folder = MemoryFolder::new();
    let mut a = first(&folder, &time, "laptop").await;
    a.set("theme", "dark").await.unwrap();
    let mut new = Replica::new(folder.clone(), Identity::generate("phone"), time.clock(0));
    new.request_join().await.unwrap();

    // Someone with the mailbox password but not the key plays approver, with a
    // key of their own at an epoch the folder does not use.
    let mut rogue = Replica::new(folder.clone(), Identity::generate("laptop"), time.clock(0));
    let mut raw = {
        let other = MemoryFolder::new();
        first(&other, &time, "x")
            .await
            .key()
            .unwrap()
            .to_secret()
            .to_vec()
    };
    raw[0] = 7;
    rogue.set_key(SettingsKey::from_secret(&raw).unwrap());
    a.pull().await.unwrap();
    rogue.pull().await.unwrap();
    let nonce = a.join_requests()[0].nonce;
    a.offer_join(nonce).await.unwrap();
    rogue.offer_join(nonce).await.unwrap();
    new.pull().await.unwrap();
    a.pull().await.unwrap();
    rogue.pull().await.unwrap();
    let offers = new.join_offers();
    assert_eq!(offers.len(), 2);
    let real = offers.iter().find(|o| o.device == a.id()).unwrap().clone();
    let fake = offers
        .iter()
        .find(|o| o.device == rogue.id())
        .unwrap()
        .clone();

    // The real approval comes first, the rogue's after it.
    a.approve_join(nonce, &real.code).await.unwrap();
    rogue.approve_join(nonce, &fake.code).await.unwrap();
    new.pull().await.unwrap();

    // The person typed what the real laptop shows, so naming the rogue fails.
    let res = new.finish_join(rogue.id(), &real.code).await;
    assert!(matches!(res, Err(Error::WrongCode)), "{res:?}");
    // Even a person who confirmed the rogue's code gets no key: nothing in the
    // folder was ever sealed under it by the rogue's device.
    let res = new.finish_join(rogue.id(), &fake.code).await;
    assert!(matches!(res, Err(Error::UntrustedKey)), "{res:?}");
    assert!(new.key().is_none());
    assert_eq!(new.entries().count(), 0);
    assert!(new.devices().is_empty());

    // The real approval was not displaced by the later one.
    new.finish_join(a.id(), &real.code).await.unwrap();
    assert_eq!(new.key().unwrap().epoch(), 1);
    assert_eq!(new.get("theme"), Some("dark"));
}

#[tokio::test]
async fn joining_does_not_expose_secrets() {
    let time = Time::new();
    let folder = MemoryFolder::new();
    let mut a = first(&folder, &time, "laptop").await;
    let b = join(&mut a, &folder, &time, "phone", 0).await;
    assert_eq!(b.key().unwrap().epoch(), a.key().unwrap().epoch());
    assert_eq!(b.entries().count(), 0);
}

#[tokio::test]
async fn the_printed_code_recovers_without_another_device() {
    let time = Time::new();
    let folder = MemoryFolder::new();
    let (mut a, code) =
        Replica::create(folder.clone(), Identity::generate("laptop"), time.clock(0))
            .await
            .unwrap();
    a.set("theme", "dark").await.unwrap();

    let mut b = Replica::new(
        folder.clone(),
        Identity::generate("new laptop"),
        time.clock(0),
    );
    assert!(matches!(
        b.recover("0000-0000-0000-0000-0000-0000-0000-0000").await,
        Err(Error::BadRecoveryCode)
    ));
    assert!(matches!(
        b.recover("nonsense").await,
        Err(Error::BadRecoveryCode)
    ));
    b.recover(&code.to_string().to_lowercase()).await.unwrap();
    assert_eq!(b.get("theme"), Some("dark"));
    a.pull().await.unwrap();
    assert_eq!(a.devices().len(), 2);

    let fresh = a.reissue_recovery().await.unwrap();
    let mut c = Replica::new(folder.clone(), Identity::generate("third"), time.clock(0));
    assert!(c.recover(&code.to_string()).await.is_err());
    c.recover(&fresh.to_string()).await.unwrap();
}

#[tokio::test]
async fn a_new_key_names_what_the_others_lose() {
    let time = Time::new();
    let folder = MemoryFolder::new();
    let mut a = first(&folder, &time, "laptop").await;
    let mut b = join(&mut a, &folder, &time, "phone", 0).await;
    a.set("theme", "dark").await.unwrap();
    b.set("lang", "tr").await.unwrap();

    let mut lost = Replica::new(folder.clone(), Identity::generate("fresh"), time.clock(0));
    let warning = lost.lost_key_warning().await.unwrap();
    assert_eq!(warning.devices.len(), 2);
    assert!(warning.devices.contains(&a.id()) && warning.devices.contains(&b.id()));
    assert_eq!(warning.changes, 2);
    lost.replace_key(warning).await.unwrap();
    assert_eq!(lost.entries().count(), 0);

    assert!(a.pull().await.unwrap().needs_rejoin);
    assert!(matches!(a.set("x", "y").await, Err(Error::NeedsRejoin)));
    // The old devices come back by joining the new one.
    let mut a2 = Replica::new(folder.clone(), Identity::generate("laptop"), time.clock(0));
    a2.request_join().await.unwrap();
    lost.pull().await.unwrap();
    let nonce = lost.join_requests()[0].nonce;
    lost.offer_join(nonce).await.unwrap();
    a2.pull().await.unwrap();
    let offer = a2.join_offers().pop().unwrap();
    lost.pull().await.unwrap();
    let shown = lost.join_code(nonce).unwrap();
    lost.approve_join(nonce, &offer.code).await.unwrap();
    a2.pull().await.unwrap();
    a2.finish_join(offer.device, &shown).await.unwrap();
    assert_eq!(a2.key().unwrap().epoch(), 2);
}

#[tokio::test]
async fn removing_a_device_rotates_the_key() {
    let time = Time::new();
    let folder = MemoryFolder::new();
    let mut a = first(&folder, &time, "laptop").await;
    let mut b = join(&mut a, &folder, &time, "phone", 0).await;
    let mut c = join(&mut a, &folder, &time, "tablet", 0).await;
    a.pull().await.unwrap();
    a.set("theme", "dark").await.unwrap();

    assert!(matches!(
        a.remove_device(a.id(), &[]).await,
        Err(Error::RemoveSelf)
    ));
    let before = folder.bodies();
    let new_code = remove(&mut a, c.id()).await;
    assert_eq!(a.key().unwrap().epoch(), 2);
    // Nothing the old key protected is left in the folder.
    for old in before {
        assert!(!folder.bodies().contains(&old));
    }

    b.pull().await.unwrap();
    assert_eq!(b.key().unwrap().epoch(), 2);
    assert_eq!(b.get("theme"), Some("dark"));
    b.set("lang", "tr").await.unwrap();
    a.pull().await.unwrap();
    assert_eq!(a.get("lang"), Some("tr"));
    assert_eq!(a.devices().len(), 2);

    assert!(c.pull().await.unwrap().needs_rejoin);
    assert!(matches!(c.set("x", "y").await, Err(Error::NeedsRejoin)));
    assert_eq!(c.get("lang"), None);

    let mut d = Replica::new(folder.clone(), Identity::generate("d"), time.clock(0));
    d.recover(&new_code.to_string()).await.unwrap();
    assert_eq!(d.get("lang"), Some("tr"));
}

#[tokio::test]
async fn other_accounts_follow_a_new_key() {
    let time = Time::new();
    let sync_folder = MemoryFolder::new();
    let acct_folder = MemoryFolder::new();
    let mut a = first(&sync_folder, &time, "laptop").await;
    let mut b = join(&mut a, &sync_folder, &time, "phone", 0).await;
    let mut c = join(&mut a, &sync_folder, &time, "tablet", 0).await;

    let mut acct_a = Replica::new(
        acct_folder.clone(),
        Identity::generate("laptop"),
        time.clock(0),
    );
    acct_a.set_key(a.key().unwrap().clone());
    let mut acct_b = Replica::new(
        acct_folder.clone(),
        Identity::generate("phone"),
        time.clock(0),
    );
    acct_b.set_key(b.key().unwrap().clone());
    acct_a.set("signature", "Best, A").await.unwrap();
    acct_b.pull().await.unwrap();
    assert_eq!(acct_b.get("signature"), Some("Best, A"));

    a.pull().await.unwrap();
    remove(&mut a, c.id()).await;
    acct_a.rekey(a.key().unwrap().clone()).await.unwrap();
    assert!(acct_b.pull().await.unwrap().needs_rejoin);
    b.pull().await.unwrap();
    acct_b.set_key(b.key().unwrap().clone());
    acct_b.pull().await.unwrap();
    assert_eq!(acct_b.get("signature"), Some("Best, A"));
    acct_b.set("rule", "x").await.unwrap();
    acct_a.pull().await.unwrap();
    assert_eq!(acct_a.get("rule"), Some("x"));
    c.pull().await.unwrap();
}

/// Asks every device for the lease and checks that at most one says yes.
async fn lease_round(devices: &mut [&mut R]) -> Vec<bool> {
    let mut answers = Vec::new();
    for d in devices.iter_mut() {
        answers.push(d.hold_lease().await.unwrap());
    }
    answers
}

#[tokio::test]
async fn the_main_computer_keeps_the_lease() {
    let time = Time::new();
    let folder = MemoryFolder::new();
    let mut a = first(&folder, &time, "laptop").await;
    let mut b = join(&mut a, &folder, &time, "phone", 0).await;
    a.set(MAIN_DEVICE, &a.id().to_string()).await.unwrap();
    b.pull().await.unwrap();

    assert!(a.hold_lease().await.unwrap());
    assert!(!b.hold_lease().await.unwrap());
    assert_eq!(b.lease_holder(), Some(a.id()));
    time.advance(LEASE_MS / 2);
    assert!(a.hold_lease().await.unwrap());
    time.advance(LEASE_MS / 2 + 1);
    // a renewed five minutes ago, so it still holds.
    assert!(!b.hold_lease().await.unwrap());
}

#[tokio::test]
async fn another_device_takes_over_after_the_main_computer_has_been_quiet() {
    let time = Time::new();
    let folder = MemoryFolder::new();
    let mut a = first(&folder, &time, "laptop").await;
    let mut b = join(&mut a, &folder, &time, "phone", 0).await;
    a.set(MAIN_DEVICE, &a.id().to_string()).await.unwrap();
    b.pull().await.unwrap();

    assert_eq!(lease_round(&mut [&mut a, &mut b]).await, [true, false]);
    // The main computer goes quiet; the phone keeps looking.
    for _ in 0..3 {
        time.advance(LEASE_MS / 3);
        b.pull().await.unwrap();
    }
    time.advance(1);
    // Past the expiry but inside the margin for clocks that differ.
    assert!(!b.hold_lease().await.unwrap());
    time.advance(LEASE_DRIFT_MS);
    assert!(b.hold_lease().await.unwrap());
    assert!(b.hold_lease().await.unwrap());

    // The main computer returns. It waits, the phone steps aside, then it holds.
    assert!(!a.hold_lease().await.unwrap());
    assert!(!b.hold_lease().await.unwrap());
    assert!(a.hold_lease().await.unwrap());
    assert!(!b.hold_lease().await.unwrap());
    assert_eq!(b.lease_holder(), Some(a.id()));
}

#[tokio::test]
async fn without_a_main_computer_the_first_lease_in_the_folder_wins() {
    let time = Time::new();
    let folder = MemoryFolder::new();
    let mut x = first(&folder, &time, "x").await;
    let mut y = join(&mut x, &folder, &time, "y", 0).await;
    assert!(y.hold_lease().await.unwrap());
    assert!(!x.hold_lease().await.unwrap());
    y.drop_lease().await.unwrap();
    assert!(x.hold_lease().await.unwrap());
}

#[tokio::test]
async fn a_device_with_a_fast_clock_does_not_take_a_live_lease() {
    let time = Time::new();
    let folder = MemoryFolder::new();
    let mut a = first(&folder, &time, "laptop").await;
    let mut b = join(&mut a, &folder, &time, "phone", 10 * 60 * 1000).await;
    assert!(a.hold_lease().await.unwrap());
    b.pull().await.unwrap();
    assert!(!b.hold_lease().await.unwrap());
    time.advance(LEASE_MS / 2);
    assert!(a.hold_lease().await.unwrap());
    assert!(!b.hold_lease().await.unwrap());
}

#[test]
fn scheduled_message_ids_are_fixed() {
    let id = scheduled_message_id("item-1", "alazy.app");
    assert_eq!(id, scheduled_message_id("item-1", "alazy.app"));
    assert_ne!(id, scheduled_message_id("item-2", "alazy.app"));
    assert!(id.starts_with('<') && id.ends_with("@alazy.app>"));
}

/// Runs a folder call to the end; the memory folder never waits.
fn block_on<T>(f: impl Future<Output = T>) -> T {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    match f.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("memory folder did not finish"),
    }
}

type Hook = Box<dyn FnOnce() + Send>;

/// A folder that lets another device write right after the first message
/// containing `marker` is appended, the way a real mailbox is shared.
#[derive(Clone)]
struct Spy {
    inner: MemoryFolder,
    marker: &'static str,
    hook: Arc<Mutex<Option<Hook>>>,
}

impl Spy {
    fn new(inner: &MemoryFolder, marker: &'static str, hook: Hook) -> Self {
        Spy {
            inner: inner.clone(),
            marker,
            hook: Arc::new(Mutex::new(Some(hook))),
        }
    }
}

impl Folder for Spy {
    fn scope(&self) -> &str {
        self.inner.scope()
    }

    async fn list(&self) -> Result<Vec<String>, Error> {
        self.inner.list().await
    }

    async fn fetch(&self, id: &str) -> Result<Option<Vec<u8>>, Error> {
        self.inner.fetch(id).await
    }

    async fn append(&self, body: Vec<u8>) -> Result<String, Error> {
        let hit = String::from_utf8_lossy(&body).contains(self.marker);
        let id = self.inner.append(body).await?;
        if hit {
            if let Some(hook) = self.hook.lock().unwrap().take() {
                hook();
            }
        }
        Ok(id)
    }

    async fn delete(&self, id: &str) -> Result<(), Error> {
        self.inner.delete(id).await
    }
}

#[tokio::test]
async fn a_lost_recovery_code_stops_working_after_a_restart() {
    let time = Time::new();
    let folder = MemoryFolder::new();
    let ida = Identity::generate("laptop");
    let (a, lost) = Replica::create(folder.clone(), ida.clone(), time.clock(0))
        .await
        .unwrap();
    // A fresh run of the app has read nothing yet.
    let key = a.key().unwrap().clone();
    let mut again = Replica::with_key(folder.clone(), ida, time.clock(0), key);
    let fresh = again.reissue_recovery().await.unwrap();
    let mut c = Replica::new(folder.clone(), Identity::generate("c"), time.clock(0));
    assert!(c.recover(&lost.to_string()).await.is_err());
    c.recover(&fresh.to_string()).await.unwrap();
}

#[tokio::test]
async fn a_change_written_while_the_key_rotates_is_not_lost() {
    let time = Time::new();
    let folder = MemoryFolder::new();
    let ida = Identity::generate("laptop");
    let (mut a0, _) = Replica::create(folder.clone(), ida.clone(), time.clock(0))
        .await
        .unwrap();
    let mut b = join(&mut a0, &folder, &time, "phone", 0).await;
    let mut c = join(&mut a0, &folder, &time, "tablet", 0).await;
    let a_key = a0.key().unwrap().clone();

    // The phone writes just after the laptop has read the folder and begun to rotate.
    let spy = Spy::new(
        &folder,
        "\"t\":\"rotation\"",
        Box::new(move || block_on(b.set("late", "from the phone")).unwrap()),
    );
    let mut a = Replica::with_key(spy, ida, time.clock(0), a_key);
    a.pull().await.unwrap();
    remove(&mut a, c.id()).await;
    assert_eq!(a.get("late"), Some("from the phone"));
    let key = a.key().unwrap().clone();
    let mut a2 = Replica::with_key(folder.clone(), Identity::generate("x"), time.clock(0), key);
    a2.pull().await.unwrap();
    assert_eq!(a2.get("late"), Some("from the phone"));
    assert!(c.pull().await.unwrap().needs_rejoin);
}

#[tokio::test]
async fn rekeying_another_account_keeps_a_change_made_meanwhile() {
    let time = Time::new();
    let sync_folder = MemoryFolder::new();
    let acct = MemoryFolder::new();
    let a = first(&sync_folder, &time, "laptop").await;
    let key = a.key().unwrap().clone();
    let mut other = Replica::with_key(
        acct.clone(),
        Identity::generate("phone"),
        time.clock(0),
        key.clone(),
    );
    let spy = Spy::new(
        &acct,
        "\"what\":\"snapshot\"",
        Box::new(move || block_on(other.set("late", "x")).unwrap()),
    );
    let mut mine = Replica::with_key(spy, Identity::generate("laptop"), time.clock(0), key);
    mine.set("early", "y").await.unwrap();
    let mut raw = a.key().unwrap().to_secret().to_vec();
    raw[0] = 2;
    let new_key = SettingsKey::from_secret(&raw).unwrap();
    mine.rekey(new_key.clone()).await.unwrap();
    assert_eq!(mine.get("late"), Some("x"));
    let mut check = Replica::with_key(
        acct.clone(),
        Identity::generate("z"),
        time.clock(0),
        new_key,
    );
    check.pull().await.unwrap();
    assert_eq!(check.get("late"), Some("x"));
    assert_eq!(check.get("early"), Some("y"));
}

/// Removes a device after the person has looked at the list of those that stay.
async fn remove<F: Folder>(
    a: &mut Replica<F>,
    who: lazymail_sync::DeviceId,
) -> lazymail_sync::RecoveryCode {
    a.pull().await.unwrap();
    let keep: Vec<_> = a
        .devices()
        .iter()
        .map(|d| d.id)
        .filter(|d| *d != who)
        .collect();
    a.remove_device(who, &keep).await.unwrap()
}

#[tokio::test]
async fn removing_refuses_a_list_that_is_out_of_date() {
    let time = Time::new();
    let folder = MemoryFolder::new();
    let mut a = first(&folder, &time, "laptop").await;
    let b = join(&mut a, &folder, &time, "phone", 0).await;
    let shown = vec![a.id()];
    let _late = join(&mut a, &folder, &time, "tablet", 0).await;
    let res = a.remove_device(b.id(), &shown).await;
    assert!(matches!(res, Err(Error::DevicesChanged)), "{res:?}");
    assert_eq!(a.key().unwrap().epoch(), 1);
}
