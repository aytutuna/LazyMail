/// What the apps see when a call fails. The detail is a sentence for a log or a message box.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CoreError {
    #[error("not found: {detail}")]
    NotFound { detail: String },
    /// The caller's input is wrong: a password of the wrong shape, a code that does not match.
    #[error("{detail}")]
    Invalid { detail: String },
    /// The account has to be signed in again.
    #[error("sign-in needed: {detail}")]
    SignIn { detail: String },
    #[error("network: {detail}")]
    Network { detail: String },
    #[error("storage: {detail}")]
    Storage { detail: String },
    /// Settings sync and device joining.
    #[error("{detail}")]
    Sync { detail: String },
    #[error("{detail}")]
    Unsupported { detail: String },
}

impl From<lazymail_store::Error> for CoreError {
    fn from(e: lazymail_store::Error) -> Self {
        match e {
            lazymail_store::Error::NotFound => CoreError::NotFound {
                detail: "no such row".into(),
            },
            e => CoreError::Storage {
                detail: e.to_string(),
            },
        }
    }
}

impl From<lazymail_imap::Error> for CoreError {
    fn from(e: lazymail_imap::Error) -> Self {
        use lazymail_imap::Error as E;
        match e {
            E::Auth(f) => CoreError::SignIn {
                detail: f.message().to_string(),
            },
            E::Paused => CoreError::SignIn {
                detail: "waiting for a new sign-in".into(),
            },
            E::Store(e) => e.into(),
            e => CoreError::Network {
                detail: e.to_string(),
            },
        }
    }
}

impl From<lazymail_graph::Error> for CoreError {
    fn from(e: lazymail_graph::Error) -> Self {
        use lazymail_graph::Error as E;
        match e {
            E::NeedsSignIn => CoreError::SignIn {
                detail: "sign in again".into(),
            },
            E::NotFound => CoreError::NotFound {
                detail: "not found on the server".into(),
            },
            E::Store(e) => e.into(),
            e => CoreError::Network {
                detail: e.to_string(),
            },
        }
    }
}

impl From<lazymail_smtp::Error> for CoreError {
    fn from(e: lazymail_smtp::Error) -> Self {
        match e {
            lazymail_smtp::Error::Draft(d) => CoreError::Invalid { detail: d.into() },
            lazymail_smtp::Error::Store(e) => e.into(),
        }
    }
}

impl From<lazymail_sync::Error> for CoreError {
    fn from(e: lazymail_sync::Error) -> Self {
        CoreError::Sync {
            detail: e.to_string(),
        }
    }
}

impl From<std::io::Error> for CoreError {
    fn from(e: std::io::Error) -> Self {
        CoreError::Storage {
            detail: e.to_string(),
        }
    }
}
