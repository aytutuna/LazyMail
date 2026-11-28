//! IMAP sync into the encrypted store.

mod actions;
mod blobs;
mod conn;
mod error;
mod folders;
mod parse;
mod run;
mod stop;
mod stream;
mod sync;
pub mod utf7;

#[cfg(test)]
mod tests;

pub use actions::{MoveUndo, Placed};
pub use blobs::BlobRef;
pub use conn::{Capabilities, Connection, Credential, RemoteFolder, Server, Transport};
pub use error::{Error, Result};
pub use folders::{role_of, SETTINGS_FOLDER};
pub use run::{Imap, Update};
pub use stop::Stop;
pub use sync::{Phase, Policy, Progress, Summary};
