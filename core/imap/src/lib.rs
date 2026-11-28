//! IMAP sync into the encrypted store.

mod actions;
mod conn;
mod error;
mod folders;
mod parse;
mod stream;
mod sync;
pub mod utf7;

pub use actions::{Appended, MoveUndo, Moved};
pub use conn::{Capabilities, Connection, Credential, RemoteFolder, Server, Transport};
pub use error::{Error, Result};
pub use folders::role_of;
pub use sync::{Phase, Policy, Progress, Summary};
