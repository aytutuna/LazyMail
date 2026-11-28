use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::identity::DeviceId;
use crate::wire::Wrap;
use crate::{Error, Identity, Result};

const NONCE: usize = 24;

pub(crate) fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("system random source");
    b
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub(crate) fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// The nonce followed by the ciphertext.
pub(crate) fn seal(key: &[u8; 32], aad: &[u8], plain: &[u8]) -> Vec<u8> {
    let nonce = random::<NONCE>();
    let ct = XChaCha20Poly1305::new(&Key::from(*key))
        .encrypt(&XNonce::from(nonce), Payload { msg: plain, aad })
        .expect("encryption does not fail");
    [nonce.as_slice(), &ct].concat()
}

pub(crate) fn open(key: &[u8; 32], aad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < NONCE {
        return Err(Error::Corrupt);
    }
    let (nonce, ct) = data.split_at(NONCE);
    XChaCha20Poly1305::new(&Key::from(*key))
        .decrypt(
            &XNonce::try_from(nonce).map_err(|_| Error::Corrupt)?,
            Payload { msg: ct, aad },
        )
        .map_err(|_| Error::Corrupt)
}

fn derive(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(None, ikm)
        .expand(info, &mut out)
        .expect("32 bytes is a valid length");
    out
}

/// The key every sealed message of one epoch uses.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SettingsKey {
    pub(crate) epoch: u32,
    pub(crate) bytes: [u8; 32],
}

impl SettingsKey {
    pub(crate) fn random(epoch: u32) -> Self {
        SettingsKey {
            epoch,
            bytes: random(),
        }
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// The epoch and key bytes, for the device's secrets table. Anyone who
    /// reads it can read the person's synced settings.
    pub fn to_secret(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.to_plain())
    }

    /// The inverse of [`SettingsKey::to_secret`].
    pub fn from_secret(p: &[u8]) -> Result<Self> {
        Self::from_plain(p)
    }

    fn to_plain(&self) -> Vec<u8> {
        [self.epoch.to_le_bytes().as_slice(), &self.bytes].concat()
    }

    fn from_plain(p: &[u8]) -> Result<Self> {
        if p.len() != 36 {
            return Err(Error::Corrupt);
        }
        Ok(SettingsKey {
            epoch: u32::from_le_bytes(p[..4].try_into().unwrap()),
            bytes: p[4..].try_into().unwrap(),
        })
    }
}

impl fmt::Debug for SettingsKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SettingsKey(epoch {})", self.epoch)
    }
}

fn wrap_info(eph: &[u8; 32], to_x: &[u8; 32]) -> Vec<u8> {
    [b"lazymail wrap v1".as_slice(), eph, to_x].concat()
}

fn wrap_aad(to: DeviceId, eph: &[u8; 32]) -> Vec<u8> {
    [to.0.as_slice(), eph].concat()
}

/// Seals the key to a device's x25519 key with a throwaway sender key.
pub(crate) fn wrap_key(to: DeviceId, to_x: &[u8; 32], key: &SettingsKey) -> Wrap {
    let eph = StaticSecret::from(random::<32>());
    let eph_pub = *PublicKey::from(&eph).as_bytes();
    let shared = eph.diffie_hellman(&PublicKey::from(*to_x));
    let k = derive(shared.as_bytes(), &wrap_info(&eph_pub, to_x));
    let mut plain = key.to_plain();
    let data = seal(&k, &wrap_aad(to, &eph_pub), &plain);
    plain.zeroize();
    Wrap {
        to,
        eph: eph_pub,
        data,
    }
}

pub(crate) fn unwrap_key(me: &Identity, w: &Wrap) -> Result<SettingsKey> {
    let shared = me.x_secret().diffie_hellman(&PublicKey::from(w.eph));
    if !shared.was_contributory() {
        return Err(Error::Corrupt);
    }
    let k = derive(shared.as_bytes(), &wrap_info(&w.eph, &me.x_pub()));
    let mut plain = open(&k, &wrap_aad(w.to, &w.eph), &w.data)?;
    let key = SettingsKey::from_plain(&plain);
    plain.zeroize();
    key
}

pub(crate) fn wraps_digest(wraps: &[Wrap]) -> Vec<u8> {
    let mut h = Sha256::new();
    for w in wraps {
        h.update(w.sig_bytes());
    }
    h.finalize().to_vec()
}

/// 128 random bits, written as eight groups of four hex digits to be printed.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryCode([u8; 16]);

impl RecoveryCode {
    pub(crate) fn random() -> Self {
        RecoveryCode(random())
    }

    pub fn parse(s: &str) -> Option<Self> {
        let digits: String = s
            .chars()
            .filter(|c| *c != '-' && !c.is_whitespace())
            .collect::<String>()
            .to_ascii_lowercase();
        unhex(&digits)?.try_into().ok().map(RecoveryCode)
    }

    fn key(&self) -> [u8; 32] {
        derive(&self.0, b"lazymail recovery v1")
    }

    pub(crate) fn seal_key(&self, key: &SettingsKey) -> Vec<u8> {
        let mut plain = key.to_plain();
        let data = seal(&self.key(), b"lazymail recovery", &plain);
        plain.zeroize();
        data
    }

    pub(crate) fn open_key(&self, data: &[u8]) -> Result<SettingsKey> {
        let mut plain =
            open(&self.key(), b"lazymail recovery", data).map_err(|_| Error::BadRecoveryCode)?;
        let key = SettingsKey::from_plain(&plain);
        plain.zeroize();
        key
    }
}

impl fmt::Display for RecoveryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let h = hex(&self.0).to_ascii_uppercase();
        let groups: Vec<&str> = (0..8).map(|i| &h[i * 4..i * 4 + 4]).collect();
        f.write_str(&groups.join("-"))
    }
}

impl fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryCode(..)")
    }
}

impl Drop for RecoveryCode {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Four digits both screens show. They match only if both devices saw the
/// same two key pairs and the same request.
pub(crate) fn join_code(
    nonce: &[u8; 16],
    new: (&[u8; 32], &[u8; 32]),
    approver: (&[u8; 32], &[u8; 32]),
) -> String {
    let d = Sha256::new()
        .chain_update(b"lazymail join code v1")
        .chain_update(nonce)
        .chain_update(new.0)
        .chain_update(new.1)
        .chain_update(approver.0)
        .chain_update(approver.1)
        .finalize();
    let n = u32::from_le_bytes(d[..4].try_into().unwrap()) % 10_000;
    format!("{n:04}")
}
