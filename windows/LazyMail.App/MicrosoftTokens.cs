using uniffi.lazymail_core;

namespace LazyMail;

// Microsoft access tokens for the core, from MSAL with the WAM broker.
// TODO: needs the client id of the Entra app, which is not registered yet. Until then an
// account that signs in with Microsoft is asked to sign in again.
sealed class MicrosoftTokens : TokenProvider
{
    public string AccessToken(string accountId, TokenResource resource) =>
        throw new TokenFailure.InteractionRequired();
}
