//! Attacks that need to write messages a well-behaved device never would.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::replica::Meta;
use crate::wire::{DeviceRecord, JoinRequest, JoinReveal, Kind, Wire};
use crate::{Clock, Folder, Identity, MemoryFolder, Replica};

type R = Replica<MemoryFolder>;

pub(crate) fn clock() -> Clock {
    Arc::new(|| 1_800_000_000_000)
}

/// Walks a join the way a person would and returns the new device.
pub(crate) async fn join(host: &mut R, folder: &MemoryFolder, name: &str) -> R {
    let mut new = Replica::new(folder.clone(), Identity::generate(name), clock());
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
    host.approve_join(req.nonce, &offer.code).await.unwrap();
    new.pull().await.unwrap();
    new.finish_join(offer.device, &shown).await.unwrap();
    host.pull().await.unwrap();
    new
}

fn signed(me: &Identity, mut r: DeviceRecord) -> DeviceRecord {
    r.sig = me.sign(&r.sig_bytes());
    r
}

#[tokio::test]
async fn a_stolen_device_cannot_write_a_record_for_another_device() {
    let folder = MemoryFolder::new();
    let (mut laptop, _) = R::create(folder.clone(), Identity::generate("laptop"), clock())
        .await
        .unwrap();
    let mut phone = join(&mut laptop, &folder, "phone").await;
    let real = laptop.devices.get(&laptop.id()).unwrap().clone();

    // The phone's own keys under the laptop's id, from the far future.
    let own = signed(
        &phone.me,
        DeviceRecord {
            id: laptop.id(),
            name: "laptop".into(),
            x_pub: phone.me.x_pub(),
            ed_pub: phone.me.ed_pub(),
            address: None,
            relay_group: None,
            updated: u64::MAX,
            sig: [0; 64],
        },
    );
    phone
        .put(Kind::Device, &own, Meta::Device(laptop.id()))
        .await
        .unwrap();
    // The laptop's keys, signed by the phone.
    let mut sig_by_phone = DeviceRecord {
        updated: u64::MAX,
        address: Some("evil".into()),
        ..real.clone()
    };
    sig_by_phone.sig = phone.me.sign(&sig_by_phone.sig_bytes());
    phone
        .put(Kind::Device, &sig_by_phone, Meta::Device(laptop.id()))
        .await
        .unwrap();
    // A replay of the laptop's own record with the bytes changed.
    let mut flipped = real.clone();
    flipped.address = Some("evil".into());
    phone
        .put(Kind::Device, &flipped, Meta::Device(laptop.id()))
        .await
        .unwrap();

    laptop.pull().await.unwrap();
    assert_eq!(laptop.devices.get(&laptop.id()).unwrap(), &real);

    // Removing the phone wraps the next key to the laptop's real key only.
    let keep = [laptop.id()];
    laptop.remove_device(phone.id(), &keep).await.unwrap();
    assert!(phone.pull().await.unwrap().needs_rejoin);
}

/// Takes the first message of a kind out of the folder and returns it.
async fn take<T>(folder: &MemoryFolder, pick: impl Fn(Wire) -> Option<T>) -> T {
    for id in folder.list().await.unwrap() {
        let body = folder.fetch(&id).await.unwrap().unwrap();
        if let Some(v) = serde_json::from_slice(&body).ok().and_then(&pick) {
            folder.delete(&id).await.unwrap();
            return v;
        }
    }
    panic!("no such message");
}

async fn put_wire(folder: &MemoryFolder, wire: &Wire) {
    folder
        .append(serde_json::to_vec(wire).unwrap())
        .await
        .unwrap();
}

#[tokio::test]
async fn a_changed_approval_is_not_taken() {
    let folder = MemoryFolder::new();
    let (mut host, _) = R::create(folder.clone(), Identity::generate("laptop"), clock())
        .await
        .unwrap();
    let mut new = Replica::new(folder.clone(), Identity::generate("phone"), clock());
    new.request_join().await.unwrap();
    host.pull().await.unwrap();
    let nonce = host.join_requests()[0].nonce;
    host.offer_join(nonce).await.unwrap();
    new.pull().await.unwrap();
    let offer = new.join_offers().pop().unwrap();
    host.pull().await.unwrap();
    host.approve_join(nonce, &offer.code).await.unwrap();

    let real = take(&folder, |w| match w {
        Wire::Approval(a) => Some(a),
        _ => None,
    })
    .await;
    let mut bad = Vec::new();
    let mut flipped = real.clone();
    flipped.sig[0] ^= 1;
    bad.push(flipped);
    let mut other_offer = real.clone();
    other_offer.anonce[0] ^= 1;
    bad.push(other_offer);
    let mut other_request = real.clone();
    other_request.nonce[0] ^= 1;
    bad.push(other_request);
    let mut other_key = real.clone();
    other_key.wrap.data[30] ^= 1;
    bad.push(other_key);
    for a in bad {
        put_wire(&folder, &Wire::Approval(a)).await;
    }
    new.pull().await.unwrap();
    let res = new.finish_join(offer.device, &offer.code).await;
    assert!(matches!(res, Err(crate::Error::NoApproval)), "{res:?}");
    assert!(new.key().is_none());

    put_wire(&folder, &Wire::Approval(real)).await;
    new.pull().await.unwrap();
    new.finish_join(offer.device, &offer.code).await.unwrap();
}

#[tokio::test]
async fn a_secret_that_does_not_match_the_commitment_gives_no_code() {
    let folder = MemoryFolder::new();
    let (mut host, _) = R::create(folder.clone(), Identity::generate("laptop"), clock())
        .await
        .unwrap();
    let mut new = Replica::new(folder.clone(), Identity::generate("phone"), clock());
    new.request_join().await.unwrap();
    host.pull().await.unwrap();
    let nonce = host.join_requests()[0].nonce;
    host.offer_join(nonce).await.unwrap();
    new.pull().await.unwrap();

    // An attacker swaps the revealed secret for one of their choosing.
    take(&folder, |w| matches!(w, Wire::Reveal(_)).then_some(())).await;
    put_wire(
        &folder,
        &Wire::Reveal(JoinReveal {
            nonce,
            secret: [9; 16],
        }),
    )
    .await;
    host.pull().await.unwrap();
    assert!(matches!(
        host.join_code(nonce),
        Err(crate::Error::NotRevealed)
    ));
}

#[tokio::test]
async fn a_request_cannot_be_replaced_by_one_with_the_same_nonce() {
    let folder = MemoryFolder::new();
    let (mut host, _) = R::create(folder.clone(), Identity::generate("laptop"), clock())
        .await
        .unwrap();
    let mut new = Replica::new(folder.clone(), Identity::generate("phone"), clock());
    new.request_join().await.unwrap();
    let real: JoinRequest = take(&folder, |w| match w {
        Wire::Join(r) => Some(r),
        _ => None,
    })
    .await;
    put_wire(&folder, &Wire::Join(real.clone())).await;

    let evil = Identity::generate("phone");
    let mut copy = JoinRequest {
        id: evil.id(),
        x_pub: evil.x_pub(),
        ed_pub: evil.ed_pub(),
        ..real.clone()
    };
    copy.sig = evil.sign(&copy.sig_bytes());
    assert!(copy.valid());
    put_wire(&folder, &Wire::Join(copy)).await;

    host.pull().await.unwrap();
    let list = host.join_requests();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].device, new.id());
}

#[tokio::test]
async fn requests_with_the_same_name_are_flagged() {
    let folder = MemoryFolder::new();
    let (mut host, _) = R::create(folder.clone(), Identity::generate("laptop"), clock())
        .await
        .unwrap();
    for name in ["phone", "Phone", "tablet"] {
        let mut n = Replica::new(folder.clone(), Identity::generate(name), clock());
        n.request_join().await.unwrap();
    }
    host.pull().await.unwrap();
    for r in host.join_requests() {
        assert_eq!(
            r.look_alike,
            r.name.eq_ignore_ascii_case("phone"),
            "{}",
            r.name
        );
    }
}

#[tokio::test]
async fn a_request_ages_by_the_approvers_clock_not_the_senders() {
    let now = Arc::new(AtomicU64::new(1_800_000_000_000));
    let at = |skew: i64| -> Clock {
        let n = now.clone();
        Arc::new(move || (n.load(Ordering::SeqCst) as i64 + skew) as u64)
    };
    let folder = MemoryFolder::new();
    let (mut host, _) = R::create(folder.clone(), Identity::generate("laptop"), at(0))
        .await
        .unwrap();
    let mut slow = Replica::new(
        folder.clone(),
        Identity::generate("phone"),
        at(-2 * 3_600_000),
    );
    slow.request_join().await.unwrap();
    host.pull().await.unwrap();
    assert_eq!(host.join_requests().len(), 1);
    now.fetch_add(61 * 60 * 1000, Ordering::SeqCst);
    assert!(host.join_requests().is_empty());
}

#[tokio::test]
async fn copied_changed_or_replayed_messages_do_nothing() {
    let folder = MemoryFolder::new();
    let (mut a, _) = R::create(folder.clone(), Identity::generate("laptop"), clock())
        .await
        .unwrap();
    let mut b = join(&mut a, &folder, "phone").await;
    a.set("k", "1").await.unwrap();
    let list = folder.list().await.unwrap();
    let first_change = folder.fetch(list.last().unwrap()).await.unwrap().unwrap();
    a.set("k", "2").await.unwrap();
    b.pull().await.unwrap();
    assert_eq!(b.get("k"), Some("2"));

    // The old change put back after the newer one.
    folder.append(first_change.clone()).await.unwrap();
    // The same message with its kind, its sender or its data changed.
    let text = String::from_utf8(first_change).unwrap();
    let other = Identity::generate("x").id().to_string();
    let from = text.split("\"from\":\"").nth(1).unwrap()[..32].to_string();
    for forged in [
        text.replace("\"what\":\"change\"", "\"what\":\"snapshot\""),
        text.replace(&from, &other),
        text.replace("\"data\":\"", "\"data\":\"AAAA"),
    ] {
        assert_ne!(forged, text);
        folder.append(forged.into_bytes()).await.unwrap();
    }
    let pulled = b.pull().await.unwrap();
    assert_eq!(pulled.changed, 0);
    assert!(!pulled.needs_rejoin);
    assert_eq!(b.get("k"), Some("2"));
}
