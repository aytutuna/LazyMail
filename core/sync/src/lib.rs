//! Settings sync, device join and leases through the person's own mailbox.
//!
//! Every change is its own small message in a folder called "Alazy". The
//! [`Folder`] trait is all the code needs from it; only an in-memory folder
//! exists so far, and the IMAP and Graph folders are still to be written.
//!
//! One random settings key per person, versioned by an epoch, seals every
//! change, snapshot, device record and lease (XChaCha20-Poly1305, with kind,
//! epoch, sender and folder as associated data). Merging is per key, last
//! writer wins on a hybrid clock; stamps more than a day ahead are ignored.
//!
//! A device is an x25519 key and an ed25519 key, and its id is a hash of both.
//! Device records are signed by their own device and checked against their
//! id, so nobody can write another device's record.
//!
//! Joining: the new device commits to a secret in its request. A device that
//! offers adds a random value of its own, and the new device then publishes
//! the secret and takes no further offers; a later one needs a new request.
//! Both show a 4-digit code made from the secret, the random value, the
//! request and all four public keys. The approver types the new device's
//! code, and the new device takes a key only from the approver whose code the
//! person typed. The code is the only thing that vouches for the key, since
//! anyone with the mailbox can write anything else into the folder.
//!
//! Removing a device wraps a new key for the devices the person was shown and
//! deletes everything the old key protected. The rotation is signed by the
//! device that made it. A device that rotated puts its rotation back if it
//! vanishes, and a device that followed one stops syncing, with
//! [`Error::KeyConflict`], when a different rotation to the same epoch turns
//! up that the old key also opens. A printed recovery code unwraps
//! the key without another device.
//!
//! Leases keep scheduled work on one device: the lease first in the folder
//! holds, and the main computer asks the holder to step aside instead of
//! taking over. Clocks only decide when a lease has run out, with a margin.
//!
//! What a person with only the mailbox password can still do is delete
//! messages and write ones nobody opens; they cannot read or change settings,
//! join a device or move a lease.

mod crypto;
mod folder;
mod identity;
mod join;
mod lease;
mod replica;
#[cfg(test)]
mod tests;
mod wire;

pub use crypto::{RecoveryCode, SettingsKey};
pub use folder::{Folder, MemoryFolder};
pub use identity::{DeviceId, Identity};
pub use join::{JoinOffered, JoinRequestInfo};
pub use lease::{scheduled_message_id, LEASE_DRIFT_MS, LEASE_MS, MAIN_DEVICE};
pub use replica::{system_clock, Clock, NewKeyWarning, Pulled, Replica, COMPACT_AT};
pub use wire::{DeviceRecord, Entry, Hlc};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("folder: {0}")]
    Folder(String),
    #[error("this device has no settings key yet")]
    NoKey,
    #[error("the folder already holds synced settings")]
    FolderInUse,
    #[error("the code does not match")]
    WrongCode,
    #[error("too many wrong codes, the new device has to start again")]
    TooManyAttempts,
    #[error("wrong recovery code")]
    BadRecoveryCode,
    #[error("no such device")]
    UnknownDevice,
    #[error("no such join request")]
    UnknownRequest,
    #[error("this device has to offer before it can approve")]
    NoOffer,
    #[error("a device cannot remove itself")]
    RemoveSelf,
    #[error("the settings key was replaced without this device; join again")]
    NeedsRejoin,
    #[error("this device already has the settings key")]
    AlreadyJoined,
    #[error("that device has not approved yet")]
    NoApproval,
    #[error("the devices in the folder are not the ones that were shown")]
    DevicesChanged,
    #[error("the new device has not answered this device's offer yet")]
    NotRevealed,
    #[error("two devices show the same code; start again")]
    AmbiguousCode,
    #[error("that key did not come from this person's devices")]
    UntrustedKey,
    #[error("two different new keys were started; stop and check the devices")]
    KeyConflict,
    #[error("a message could not be read")]
    Corrupt,
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Error::Corrupt
    }
}
