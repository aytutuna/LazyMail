use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::{hex, random, unhex};

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceId(pub(crate) [u8; 16]);

impl DeviceId {
    pub(crate) fn from_keys(x_pub: &[u8; 32], ed_pub: &[u8; 32]) -> Self {
        let digest = Sha256::new()
            .chain_update(b"lazymail device v1")
            .chain_update(x_pub)
            .chain_update(ed_pub)
            .finalize();
        DeviceId(digest[..16].try_into().unwrap())
    }

    pub fn parse(s: &str) -> Option<Self> {
        unhex(s)?.try_into().ok().map(DeviceId)
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex(&self.0))
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId({self})")
    }
}

impl Serialize for DeviceId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for DeviceId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        DeviceId::parse(&s).ok_or_else(|| de::Error::custom("bad device id"))
    }
}

/// This device's key pairs. Keep the seeds in the device's secret store and
/// rebuild with [`Identity::from_seeds`].
#[derive(Clone)]
pub struct Identity {
    id: DeviceId,
    name: String,
    x: StaticSecret,
    ed: SigningKey,
}

impl Identity {
    pub fn generate(name: &str) -> Self {
        Self::from_seeds(name, random(), random())
    }

    pub fn from_seeds(name: &str, x: [u8; 32], ed: [u8; 32]) -> Self {
        let x = StaticSecret::from(x);
        let ed = SigningKey::from_bytes(&ed);
        let id = DeviceId::from_keys(
            PublicKey::from(&x).as_bytes(),
            ed.verifying_key().as_bytes(),
        );
        Identity {
            id,
            name: name.to_string(),
            x,
            ed,
        }
    }

    /// The x25519 and ed25519 seeds, in that order.
    pub fn seeds(&self) -> ([u8; 32], [u8; 32]) {
        (self.x.to_bytes(), self.ed.to_bytes())
    }

    pub fn id(&self) -> DeviceId {
        self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn x_pub(&self) -> [u8; 32] {
        *PublicKey::from(&self.x).as_bytes()
    }

    pub(crate) fn ed_pub(&self) -> [u8; 32] {
        *self.ed.verifying_key().as_bytes()
    }

    pub(crate) fn x_secret(&self) -> &StaticSecret {
        &self.x
    }

    pub(crate) fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.ed.sign(msg).to_bytes()
    }
}

pub(crate) fn verify(ed_pub: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(ed_pub)
        .map(|k| k.verify_strict(msg, &Signature::from_bytes(sig)).is_ok())
        .unwrap_or(false)
}
