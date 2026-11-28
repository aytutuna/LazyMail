use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::identity::{verify, DeviceId};

pub(crate) mod b64 {
    use super::*;

    pub fn serialize<S: Serializer, T: AsRef<[u8]>>(v: &T, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, T: TryFrom<Vec<u8>>>(
        d: D,
    ) -> Result<T, D::Error> {
        let s = String::deserialize(d)?;
        let v = STANDARD.decode(s).map_err(de::Error::custom)?;
        T::try_from(v).map_err(|_| de::Error::custom("wrong length"))
    }
}

/// What every message in the folder looks like on the wire.
#[derive(Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub(crate) enum Wire {
    Sealed {
        what: Kind,
        epoch: u32,
        from: DeviceId,
        #[serde(with = "b64")]
        data: Vec<u8>,
    },
    Join(JoinRequest),
    Offer(JoinOffer),
    Approval(Approval),
    Rotation(Rotation),
    Recovery {
        #[serde(with = "b64")]
        data: Vec<u8>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Kind {
    Change,
    Snapshot,
    Device,
    Lease,
}

impl Kind {
    pub(crate) fn aad(self, epoch: u32, from: DeviceId) -> Vec<u8> {
        format!("lazymail:{self:?}:{epoch}:{from}").into_bytes()
    }
}

/// Hybrid logical clock stamp. The order is wall time, counter, device.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub struct Hlc {
    pub wall: u64,
    pub counter: u32,
    pub device: DeviceId,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub hlc: Hlc,
    /// `None` is a removed key.
    pub value: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Change {
    pub key: String,
    #[serde(flatten)]
    pub entry: Entry,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Snapshot {
    pub entries: BTreeMap<String, Entry>,
}

/// A device's public keys and how to reach it.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub id: DeviceId,
    pub name: String,
    #[serde(with = "b64")]
    pub x_pub: [u8; 32],
    #[serde(with = "b64")]
    pub ed_pub: [u8; 32],
    pub address: Option<String>,
    pub relay_group: Option<String>,
    pub updated: u64,
    /// By the device's own key, so only that device can write its record.
    #[serde(with = "b64")]
    pub sig: [u8; 64],
}

fn field(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(bytes);
}

fn opt_field(buf: &mut Vec<u8>, s: &Option<String>) {
    match s {
        Some(s) => {
            buf.push(1);
            field(buf, s.as_bytes());
        }
        None => buf.push(0),
    }
}

impl DeviceRecord {
    pub(crate) fn sig_bytes(&self) -> Vec<u8> {
        let mut b = b"lazymail device record v1".to_vec();
        b.extend_from_slice(&self.id.0);
        b.extend_from_slice(&self.x_pub);
        b.extend_from_slice(&self.ed_pub);
        field(&mut b, self.name.as_bytes());
        opt_field(&mut b, &self.address);
        opt_field(&mut b, &self.relay_group);
        b.extend_from_slice(&self.updated.to_le_bytes());
        b
    }

    /// The id belongs to the keys and the keys signed the record.
    pub(crate) fn valid(&self) -> bool {
        self.id == DeviceId::from_keys(&self.x_pub, &self.ed_pub)
            && verify(&self.ed_pub, &self.sig_bytes(), &self.sig)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub(crate) struct Lease {
    pub holder: DeviceId,
    pub since: u64,
    pub expires: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Wrap {
    pub to: DeviceId,
    #[serde(with = "b64")]
    pub eph: [u8; 32],
    #[serde(with = "b64")]
    pub data: Vec<u8>,
}

impl Wrap {
    pub(crate) fn sig_bytes(&self) -> Vec<u8> {
        [self.to.0.as_slice(), &self.eph, &self.data].concat()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct JoinRequest {
    pub id: DeviceId,
    pub name: String,
    #[serde(with = "b64")]
    pub x_pub: [u8; 32],
    #[serde(with = "b64")]
    pub ed_pub: [u8; 32],
    #[serde(with = "b64")]
    pub nonce: [u8; 16],
    pub at: u64,
    #[serde(with = "b64")]
    pub sig: [u8; 64],
}

impl JoinRequest {
    pub(crate) fn sig_bytes(&self) -> Vec<u8> {
        [
            b"lazymail join v1".as_slice(),
            &self.id.0,
            &self.x_pub,
            &self.ed_pub,
            &self.nonce,
            &self.at.to_le_bytes(),
            self.name.as_bytes(),
        ]
        .concat()
    }

    pub(crate) fn valid(&self) -> bool {
        self.id == DeviceId::from_keys(&self.x_pub, &self.ed_pub)
            && verify(&self.ed_pub, &self.sig_bytes(), &self.sig)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct JoinOffer {
    #[serde(with = "b64")]
    pub nonce: [u8; 16],
    pub from: DeviceId,
    pub name: String,
    #[serde(with = "b64")]
    pub x_pub: [u8; 32],
    #[serde(with = "b64")]
    pub ed_pub: [u8; 32],
    #[serde(with = "b64")]
    pub sig: [u8; 64],
}

impl JoinOffer {
    pub(crate) fn sig_bytes(&self) -> Vec<u8> {
        [
            b"lazymail offer v1".as_slice(),
            &self.nonce,
            &self.from.0,
            &self.x_pub,
            &self.ed_pub,
            self.name.as_bytes(),
        ]
        .concat()
    }

    pub(crate) fn valid(&self) -> bool {
        self.from == DeviceId::from_keys(&self.x_pub, &self.ed_pub)
            && verify(&self.ed_pub, &self.sig_bytes(), &self.sig)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Approval {
    #[serde(with = "b64")]
    pub nonce: [u8; 16],
    pub to: DeviceId,
    pub from: DeviceId,
    pub wrap: Wrap,
    #[serde(with = "b64")]
    pub sig: [u8; 64],
}

impl Approval {
    pub(crate) fn sig_bytes(&self) -> Vec<u8> {
        [
            b"lazymail approval v1".as_slice(),
            &self.nonce,
            &self.to.0,
            &self.from.0,
            &self.wrap.sig_bytes(),
        ]
        .concat()
    }
}

/// The key for the next epoch, wrapped once per device that stays. `proof`
/// is sealed under the old key, so only a current member could have made it.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Rotation {
    pub epoch: u32,
    pub from: DeviceId,
    pub wraps: Vec<Wrap>,
    #[serde(with = "b64")]
    pub proof: Vec<u8>,
}

impl Rotation {
    pub(crate) fn aad(epoch: u32, from: DeviceId) -> Vec<u8> {
        format!("lazymail:rotation:{epoch}:{from}").into_bytes()
    }
}
