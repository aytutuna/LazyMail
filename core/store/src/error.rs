#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("wrong store key")]
    WrongKey,
    #[error("store was written by a newer version (schema {0})")]
    TooNew(u32),
    #[error("stored data failed authentication")]
    Corrupt,
    #[error("wrapping key unavailable: {0}")]
    Wrapper(String),
    #[error("not found")]
    NotFound,
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
