use crate::types::CoreEvent;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum KeyError {
    #[error("wrapping key unavailable: {detail}")]
    Unavailable { detail: String },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for KeyError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        KeyError::Unavailable { detail: e.reason }
    }
}

/// The device's wrapping key, kept by the platform (DPAPI, Keychain, Android Keystore, Secret
/// Service). It never leaves the platform, so the core hands data over to be wrapped. `aad` is
/// authenticated with the data, so a blob only unwraps under the name it was wrapped for.
#[uniffi::export(callback_interface)]
pub trait WrappingKey: Send + Sync {
    fn wrap(&self, aad: Vec<u8>, plain: Vec<u8>) -> Result<Vec<u8>, KeyError>;
    fn unwrap(&self, aad: Vec<u8>, wrapped: Vec<u8>) -> Result<Vec<u8>, KeyError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum TokenResource {
    /// IMAP and SMTP on outlook.office.com.
    Mail,
    Graph,
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum TokenFailure {
    /// The refresh token is gone or the person has to sign in again.
    #[error("sign-in needed")]
    InteractionRequired,
    #[error("token request failed: {detail}")]
    Failed { detail: String },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for TokenFailure {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        TokenFailure::Failed { detail: e.reason }
    }
}

/// Microsoft access tokens, from MSAL in the native layer, which also does the refreshing. The
/// core calls it on its own threads and waits for the answer.
#[uniffi::export(callback_interface)]
pub trait TokenProvider: Send + Sync {
    fn access_token(
        &self,
        account_id: String,
        resource: TokenResource,
    ) -> Result<String, TokenFailure>;
}

/// Receives what the core wants the app to show or act on. Called from a thread of the core's
/// own, one event at a time, so the handler may call back into the core.
#[uniffi::export(callback_interface)]
pub trait EventListener: Send + Sync {
    fn on_event(&self, event: CoreEvent);
}
