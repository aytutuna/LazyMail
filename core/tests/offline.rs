mod common;

use common::{open, Time};
use lazymail_core::{
    AccountSetup, AccountStatus, CoreError, MailAccessKind, ProviderKind, SettingsState,
};
use tempfile::TempDir;

fn local(address: &str) -> AccountSetup {
    AccountSetup {
        address: address.into(),
        name: "Test".into(),
        provider: Some(ProviderKind::Local),
        password: None,
        server: None,
        pinned_certificate: None,
        use_graph: false,
    }
}

#[test]
fn a_local_account_survives_a_restart_and_goes_away_on_removal() {
    let dir = TempDir::new().unwrap();
    let time = Time::now();
    let id = {
        let core = open(dir.path(), "laptop", &time);
        let added = core.add_account(local("me@local.test")).unwrap();
        assert_eq!(added.account.mail, MailAccessKind::Local);
        assert_eq!(added.account.status, AccountStatus::SignedIn);
        // A local account has no mailbox to carry the settings.
        assert_eq!(added.settings, None);
        assert_eq!(core.settings_state(), SettingsState::NoSyncAccount);
        added.account.id
    };

    let core = open(dir.path(), "laptop", &time);
    let accounts = core.accounts();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].id, id);
    assert_eq!(accounts[0].address, "me@local.test");
    assert!(core.folders(id.clone()).unwrap().is_empty());

    let err = core.add_account(local("ME@local.test")).unwrap_err();
    assert!(matches!(err, CoreError::Invalid { .. }), "{err:?}");

    core.remove_account(id.clone()).unwrap();
    assert!(core.accounts().is_empty());
    assert!(!dir.path().join("data/accounts").join(&id).exists());
    assert!(matches!(
        core.folders(id).unwrap_err(),
        CoreError::NotFound { .. }
    ));
}

#[test]
fn the_wrong_key_does_not_open_the_data() {
    let dir = TempDir::new().unwrap();
    let time = Time::now();
    open(dir.path(), "laptop", &time)
        .add_account(local("me@local.test"))
        .unwrap();
    std::fs::remove_file(dir.path().join("dev.key")).unwrap();
    let key = lazymail_core::DevKey::open(dir.path().join("dev.key")).unwrap();
    let opened = lazymail_core::Core::with_clock(
        &dir.path().join("data"),
        "laptop",
        Box::new(key),
        Box::new(NoTokens),
        time.clock(),
    );
    assert!(opened.is_err());
}

struct NoTokens;

impl lazymail_core::TokenProvider for NoTokens {
    fn access_token(
        &self,
        _: String,
        _: lazymail_core::TokenResource,
    ) -> Result<String, lazymail_core::TokenFailure> {
        Err(lazymail_core::TokenFailure::InteractionRequired)
    }
}

#[test]
fn app_passwords_are_checked_before_they_are_used() {
    let dir = TempDir::new().unwrap();
    let core = open(dir.path(), "laptop", &Time::now());
    assert_eq!(
        core.check_app_password(ProviderKind::Gmail, "abcd efgh ijkl mnop".into())
            .unwrap(),
        "abcdefghijklmnop"
    );
    for bad in ["", "nope"] {
        let err = core
            .check_app_password(ProviderKind::Gmail, bad.into())
            .unwrap_err();
        assert!(matches!(err, CoreError::Invalid { .. }), "{err:?}");
    }
    assert!(core.app_password_help(ProviderKind::Gmail).is_some());
}

#[test]
fn an_account_needs_a_real_address_and_server_settings() {
    let dir = TempDir::new().unwrap();
    let core = open(dir.path(), "laptop", &Time::now());
    let mut setup = local("not-an-address");
    assert!(core.add_account(setup.clone()).is_err());
    setup.address = "me@example.org".into();
    setup.provider = Some(ProviderKind::Other);
    let err = core.add_account(setup).unwrap_err();
    assert!(matches!(err, CoreError::Invalid { .. }), "{err:?}");
    assert!(core.accounts().is_empty());
}
