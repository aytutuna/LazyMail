use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;

use base64::{engine::general_purpose::STANDARD, Engine};
use thiserror::Error;

/// The API an access token is for; Microsoft issues one per resource from one refresh token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Resource {
    /// IMAP and SMTP on outlook.office.com.
    Mail,
    Graph,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum TokenError {
    /// The refresh token is gone or the person has to sign in again.
    #[error("sign-in needed")]
    InteractionRequired,
    #[error("token request failed: {0}")]
    Failed(String),
}

/// Implemented by the native layer over MSAL, which also does the refreshing.
pub trait TokenSource: Send + Sync {
    fn access_token(
        &self,
        account_id: &str,
        resource: Resource,
    ) -> impl Future<Output = Result<String, TokenError>> + Send;
}

/// Fixed tokens for tests; anything not set needs a sign-in.
#[derive(Default)]
pub struct StaticTokens {
    tokens: Mutex<HashMap<(String, Resource), Result<String, TokenError>>>,
}

impl StaticTokens {
    pub fn set(&self, account_id: &str, resource: Resource, token: Result<String, TokenError>) {
        self.tokens
            .lock()
            .unwrap()
            .insert((account_id.to_string(), resource), token);
    }
}

impl TokenSource for StaticTokens {
    async fn access_token(
        &self,
        account_id: &str,
        resource: Resource,
    ) -> Result<String, TokenError> {
        self.tokens
            .lock()
            .unwrap()
            .get(&(account_id.to_string(), resource))
            .cloned()
            .unwrap_or(Err(TokenError::InteractionRequired))
    }
}

/// The XOAUTH2 initial response before base64.
pub fn xoauth2(user: &str, access_token: &str) -> String {
    format!("user={user}\x01auth=Bearer {access_token}\x01\x01")
}

pub fn xoauth2_base64(user: &str, access_token: &str) -> String {
    STANDARD.encode(xoauth2(user, access_token))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xoauth2_matches_the_documented_example() {
        // Example from Google's XOAUTH2 protocol page.
        let s = xoauth2_base64(
            "someuser@example.com",
            "ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg",
        );
        assert_eq!(
            s,
            "dXNlcj1zb21ldXNlckBleGFtcGxlLmNvbQFhdXRoPUJlYXJlciB5YTI5LnZGOWRmdDRxbVRjMk52YjNSbGNrQmhkSFJoZG1semRHRXVZMjl0Q2cBAQ=="
        );
    }

    #[tokio::test]
    async fn static_tokens_return_set_values_and_default_to_sign_in() {
        let t = StaticTokens::default();
        t.set("a", Resource::Mail, Ok("tok".into()));
        assert_eq!(t.access_token("a", Resource::Mail).await.unwrap(), "tok");
        assert_eq!(
            t.access_token("a", Resource::Graph).await,
            Err(TokenError::InteractionRequired)
        );
    }
}
