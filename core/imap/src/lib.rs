//! IMAP sync into the encrypted store.

mod conn;
mod error;
mod parse;
mod stream;
pub mod utf7;

pub use conn::{Capabilities, Connection, Credential, RemoteFolder, Server, Transport};
pub use error::{Error, Result};
