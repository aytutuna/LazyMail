use std::sync::Arc;

use lazymail_accounts::{Resource, TokenError, TokenSource};

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

pub(crate) struct Wrap(pub Box<dyn WrappingKey>);

impl lazymail_store::Wrapper for Wrap {
    fn wrap(&self, aad: &[u8], plain: &[u8]) -> lazymail_store::Result<Vec<u8>> {
        self.0
            .wrap(aad.to_vec(), plain.to_vec())
            .map_err(|e| lazymail_store::Error::Wrapper(e.to_string()))
    }

    fn unwrap(&self, aad: &[u8], wrapped: &[u8]) -> lazymail_store::Result<Vec<u8>> {
        self.0
            .unwrap(aad.to_vec(), wrapped.to_vec())
            .map_err(|e| lazymail_store::Error::Wrapper(e.to_string()))
    }
}

#[derive(Clone)]
pub(crate) struct Tokens(pub Arc<dyn TokenProvider>);

impl TokenSource for Tokens {
    async fn access_token(
        &self,
        account_id: &str,
        resource: Resource,
    ) -> Result<String, TokenError> {
        let provider = self.0.clone();
        let id = account_id.to_string();
        let resource = match resource {
            Resource::Mail => TokenResource::Mail,
            Resource::Graph => TokenResource::Graph,
        };
        tokio::task::spawn_blocking(move || provider.access_token(id, resource))
            .await
            .map_err(|e| TokenError::Failed(e.to_string()))?
            .map_err(|e| match e {
                TokenFailure::InteractionRequired => TokenError::InteractionRequired,
                TokenFailure::Failed { detail } => TokenError::Failed(detail),
            })
    }
}
