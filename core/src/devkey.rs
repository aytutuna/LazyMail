use std::path::PathBuf;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

use crate::callbacks::{KeyError, WrappingKey};

const NONCE: usize = 24;

/// A wrapping key kept in a plain file, for the command line tool and tests on Linux. Anyone who
/// can read the file can read everything the core keeps, which is the opposite of what the
/// platform keys are for. It is not built unless the `dev-key` feature asks for it.
pub struct DevKey {
    key: [u8; 32],
}

impl DevKey {
    /// Reads the key from `path`, or makes the file.
    pub fn open(path: PathBuf) -> std::io::Result<DevKey> {
        match std::fs::read(&path) {
            Ok(b) => {
                let key = b.try_into().map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "wrong key file size")
                })?;
                Ok(DevKey { key })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut key = [0u8; 32];
                getrandom::fill(&mut key).map_err(std::io::Error::other)?;
                std::fs::write(&path, key)?;
                Ok(DevKey { key })
            }
            Err(e) => Err(e),
        }
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(&Key::from(self.key))
    }
}

fn unavailable(detail: &str) -> KeyError {
    KeyError::Unavailable {
        detail: detail.into(),
    }
}

impl WrappingKey for DevKey {
    fn wrap(&self, aad: Vec<u8>, plain: Vec<u8>) -> Result<Vec<u8>, KeyError> {
        let mut nonce = [0u8; NONCE];
        getrandom::fill(&mut nonce).map_err(|e| unavailable(&e.to_string()))?;
        let sealed = self
            .cipher()
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &plain,
                    aad: &aad,
                },
            )
            .map_err(|_| unavailable("cannot seal"))?;
        Ok([nonce.as_slice(), &sealed].concat())
    }

    fn unwrap(&self, aad: Vec<u8>, wrapped: Vec<u8>) -> Result<Vec<u8>, KeyError> {
        let bad = || unavailable("the wrapped data does not open");
        let (nonce, sealed) = wrapped.split_at_checked(NONCE).ok_or_else(bad)?;
        self.cipher()
            .decrypt(
                &XNonce::try_from(nonce).map_err(|_| bad())?,
                Payload {
                    msg: sealed,
                    aad: &aad,
                },
            )
            .map_err(|_| bad())
    }
}
