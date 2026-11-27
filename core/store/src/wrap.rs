use std::io::Write;
use std::path::Path;

use zeroize::{Zeroize, Zeroizing};

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

    pub(crate) fn hex(&self) -> Zeroizing<String> {
        Zeroizing::new(self.0.iter().map(|b| format!("{b:02x}")).collect())
    }
}

impl Drop for StoreKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The device wrapping key, kept by the platform: DPAPI, Keychain, Android
/// Keystore or the Secret Service. The key may never leave the platform, so
/// the trait encrypts instead of handing the key out. `aad` is authenticated with the data
/// (AES-GCM associated data, DPAPI entropy, Keychain context), so a blob only unwraps under the
/// name it was wrapped for.
pub trait Wrapper: Send + Sync {
    fn wrap(&self, aad: &[u8], plain: &[u8]) -> Result<Vec<u8>>;
    fn unwrap(&self, aad: &[u8], wrapped: &[u8]) -> Result<Vec<u8>>;
}

/// In-memory wrapper for tests. Its key lives only as long as the process, so nothing it
/// wrapped can be read by a later run.
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
    fn wrap(&self, aad: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
        Ok(crypto::seal(&self.0, aad, plain))
    }

    fn unwrap(&self, aad: &[u8], wrapped: &[u8]) -> Result<Vec<u8>> {
        crypto::open(&self.0, aad, wrapped)
    }
}

/// Reads the account's store key from `path`, wrapped by the device key, or
/// makes and saves a new one. The key sits in its own file and not in the secrets table, since
/// the table is inside the database the key opens.
pub fn load_or_create_key(path: &Path, wrapper: &dyn Wrapper) -> Result<StoreKey> {
    match std::fs::read(path) {
        Ok(wrapped) => {
            let plain = wrapper.unwrap(KEY_AAD, &wrapped)?;
            let bytes: [u8; 32] = plain.try_into().map_err(|_| Error::Corrupt)?;
            Ok(StoreKey(bytes))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = StoreKey::generate();
            write_durably(path, &wrapper.wrap(KEY_AAD, key.as_bytes())?)?;
            Ok(key)
        }
        Err(e) => Err(e.into()),
    }
}

const KEY_AAD: &[u8] = b"store key";

/// Writes through a temporary file that reaches the disk before the rename, so a power loss
/// leaves the old file or the whole new one.
pub(crate) fn write_durably(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}
