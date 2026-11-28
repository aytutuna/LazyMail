use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::{Error, Result};

const NONCE: usize = 24;

pub fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("system random source");
    b
}

pub fn derive(key: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(None, key)
        .expand(info, &mut out)
        .expect("32 bytes is a valid length");
    out
}

/// Returns the nonce followed by the ciphertext.
pub fn seal(key: &[u8; 32], aad: &[u8], plain: &[u8]) -> Vec<u8> {
    let nonce = random::<NONCE>();
    let ct = XChaCha20Poly1305::new(&Key::from(*key))
        .encrypt(&XNonce::from(nonce), Payload { msg: plain, aad })
        .expect("encryption does not fail");
    [nonce.as_slice(), &ct].concat()
}

pub fn open(key: &[u8; 32], aad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
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
