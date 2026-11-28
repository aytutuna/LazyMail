//! Settings sync, device join and leases through the person's own mailbox.
//!
//! Every change is its own small message in a folder called "Alazy" (a
//! label in Gmail), so the mail provider is the only server involved. The
//! [`Folder`] trait is all the code needs from it; the IMAP and Graph
//! implementations set the subject "Alazy settings, do not delete".
//!
//! Key design:
//! - One random 256-bit settings key per person, versioned by an epoch. Changes,
//!   snapshots, device records and leases are sealed with it (XChaCha20-Poly1305,
//!   header fields bound as associated data). Plain messages are only the ones a
//!   device without the key must be able to read: join requests, offers and
//!   approvals, which are signed, and the recovery blob.
//! - Merge is per key, last writer wins on a hybrid logical clock that breaks
//!   ties by device id. Merging is commutative, so pull order does not matter.
//!   A snapshot is the merged state; after 200 changes a device writes one and
//!   removes the messages it covers.
//! - A device is an x25519 key (receives the settings key) and an ed25519 key
//!   (signs join messages); its id is a hash of both public keys.
//! - Joining: the new device posts a request, an existing device posts an
//!   offer, and both compute a 4-digit code from the two devices' keys and the
//!   request nonce. The approver types what the new screen shows; three wrong
//!   tries void the request. Approval wraps the settings key to the new
//!   device's x25519 key. Tokens and passwords are never part of this.
//! - Recovery: a printed 128-bit code unwraps the settings key stored in the
//!   folder. A new code is issued whenever the key rotates.
//! - Removing a device rotates the key: the new key is wrapped for each device
//!   that stays, authenticated by a proof sealed under the old key, and every
//!   older message is deleted. A device that finds only a newer epoch it cannot
//!   open must join again.
//! - Leases keep scheduled work on one device. A lease is valid until its
//!   expiry; the main device's lease beats any other, otherwise the earliest
//!   one wins.
//!
//! One [`Replica`] per folder. The sync account's folder carries devices, joins
//! and leases as well as settings; the folder of every other account only
//! carries that account's settings, sealed with the same key.

mod crypto;
mod folder;
mod identity;
mod join;
mod lease;
mod replica;
mod wire;

pub use crypto::{RecoveryCode, SettingsKey};
pub use folder::{Folder, MemoryFolder};
pub use identity::{DeviceId, Identity};
pub use join::{JoinOffered, JoinRequestInfo};
pub use lease::{scheduled_message_id, LEASE_MS, MAIN_DEVICE};
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
    #[error("a message could not be read")]
    Corrupt,
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Error::Corrupt
    }
}
