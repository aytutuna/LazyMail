//! Attacks that need to write messages a well-behaved device never would.

use std::sync::Arc;

use crate::replica::Meta;
use crate::wire::{DeviceRecord, Kind};
use crate::{Clock, Identity, MemoryFolder, Replica};

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
    host.approve_join(req.nonce, &offer.code).await.unwrap();
    new.pull().await.unwrap();
    new.finish_join(offer.device).await.unwrap();
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
