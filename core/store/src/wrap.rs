use std::path::Path;

use crate::{crypto, Error, Result};

/// Raw 256-bit key of one account's database.
pub struct StoreKey([u8; 32]);

impl StoreKey {
    pub fn generate() -> StoreKey {
        StoreKey(crypto::random())
    }

    pub fn from_bytes(bytes: [u8; 32]) -> StoreKey {
        StoreKey(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// The device wrapping key, kept by the platform: DPAPI, Keychain, Android
/// Keystore or the Secret Service. The key may never leave the platform, so
/// the trait encrypts instead of handing the key out.
pub trait Wrapper: Send + Sync {
    fn wrap(&self, plain: &[u8]) -> Result<Vec<u8>>;
    fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>>;
}

/// In-memory wrapper for tests and the command line tool.
pub struct TestWrapper([u8; 32]);

impl TestWrapper {
    pub fn new() -> TestWrapper {
        TestWrapper(crypto::random())
    }
}

impl Default for TestWrapper {
    fn default() -> Self {
        Self::new()
    }
}

impl Wrapper for TestWrapper {
    fn wrap(&self, plain: &[u8]) -> Result<Vec<u8>> {
        Ok(crypto::seal(&self.0, b"", plain))
    }

    fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>> {
        crypto::open(&self.0, b"", wrapped)
    }
}

/// Reads the account's store key from `path`, wrapped by the device key, or
/// makes and saves a new one.
pub fn load_or_create_key(path: &Path, wrapper: &dyn Wrapper) -> Result<StoreKey> {
    match std::fs::read(path) {
        Ok(wrapped) => {
            let plain = wrapper.unwrap(&wrapped)?;
            let bytes: [u8; 32] = plain.try_into().map_err(|_| Error::Corrupt)?;
            Ok(StoreKey(bytes))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = StoreKey::generate();
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, wrapper.wrap(key.as_bytes())?)?;
            std::fs::rename(&tmp, path)?;
            Ok(key)
        }
        Err(e) => Err(e.into()),
    }
}
