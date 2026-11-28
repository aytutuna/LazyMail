mod message;
mod outbox;
mod transport;

pub use message::{build, Address, Attachment, Built, Draft, InlineImage};
pub use outbox::{Outbox, Report, SentBox};
pub use transport::{Auth, SendError, Smtp};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cannot build the message: {0}")]
    Draft(&'static str),
    #[error(transparent)]
    Store(#[from] lazymail_store::Error),
}

type Result<T> = std::result::Result<T, Error>;
