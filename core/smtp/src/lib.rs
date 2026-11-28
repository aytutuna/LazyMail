mod message;

pub use message::{build, Address, Attachment, Built, Draft, InlineImage};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cannot build the message: {0}")]
    Draft(&'static str),
}
