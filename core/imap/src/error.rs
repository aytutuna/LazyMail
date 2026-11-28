use std::io;

use lazymail_accounts::AuthFailure;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The server refused the sign-in. Feed it to `SignIn::report_failure`.
    #[error("{}", .0.message())]
    Auth(AuthFailure),
    /// A login refusal that says nothing about the credentials (busy server, connection limit).
    #[error("server is busy: {0}")]
    Busy(String),
    /// Gmail's daily download limit; the download resumes the next day.
    #[error("the daily download limit was reached")]
    DownloadLimit,
    #[error("server said no: {0}")]
    Refused(String),
    /// The account needs a new sign-in and its next hourly retry is not due.
    #[error("waiting for a new sign-in")]
    Paused,
    #[error("connection closed")]
    Closed,
    #[error("stopped")]
    Stopped,
    #[error("unexpected server reply: {0}")]
    Protocol(String),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Store(#[from] lazymail_store::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<async_imap::error::Error> for Error {
    fn from(e: async_imap::error::Error) -> Error {
        use async_imap::error::Error as E;
        match e {
            E::Io(e) => Error::Io(e),
            E::No(t) | E::Bad(t) => Error::Refused(t),
            E::ConnectionLost => Error::Closed,
            other => Error::Protocol(other.to_string()),
        }
    }
}

impl Error {
    /// True for failures worth another try after a pause: the connection dropped or timed out.
    pub fn is_transient(&self) -> bool {
        matches!(self, Error::Closed | Error::Io(_) | Error::Busy(_))
    }
}
