use std::sync::Arc;

use lazymail_accounts::{
    check_app_password, discover, Account, Endpoint, Login, MailAccess, PasswordProblem, Provider,
    ServerSettings, SignIn, SystemNetwork,
};
use lazymail_store::Store;

use crate::error::{invalid, CoreError, Result};
use crate::shared::{hex, AccountRt, Shared};
use crate::types::{
    AccountInfo, AccountSetup, AddedAccount, AppPasswordHelp, Discovered, ProviderKind,
    ServerConfig,
};

pub(crate) async fn discover_settings(address: &str) -> Option<Discovered> {
    let found = discover(&SystemNetwork::new(), address).await?;
    Some(Discovered {
        provider: Provider::detect(address).into(),
        server: (&found.settings).into(),
        needs_confirmation: found.needs_confirmation,
    })
}

pub(crate) fn password_help(provider: ProviderKind) -> Option<AppPasswordHelp> {
    let g = lazymail_accounts::app_password_guide(provider.into())?;
    Some(AppPasswordHelp {
        url: g.url.to_string(),
        steps: g.steps.iter().map(|s| s.to_string()).collect(),
    })
}

pub(crate) fn check_password(provider: ProviderKind, input: &str) -> Result<String> {
    check_app_password(provider.into(), input).map_err(|p| match p {
        PasswordProblem::Empty => invalid("the password is empty"),
        PasswordProblem::WrongShape => invalid("this is not the shape of an app password"),
    })
}

fn server_settings(c: &ServerConfig, provider: Provider) -> ServerSettings {
    let login = if c.login_is_local_part {
        Login::LocalPart
    } else {
        Login::Address
    };
    let mut s = provider.settings().unwrap_or(ServerSettings {
        imap: Endpoint {
            host: String::new(),
            port: 0,
            security: lazymail_accounts::Security::Tls,
            login,
        },
        smtp: Endpoint {
            host: String::new(),
            port: 0,
            security: lazymail_accounts::Security::StartTls,
            login,
        },
        files_sent: false,
        gmail: false,
        max_connections: 4,
    });
    s.imap = Endpoint {
        host: c.imap_host.clone(),
        port: c.imap_port,
        security: c.imap_security.into(),
        login,
    };
    s.smtp = Endpoint {
        host: c.smtp_host.clone(),
        port: c.smtp_port,
        security: c.smtp_security.into(),
        login,
    };
    s
}

fn new_id() -> String {
    let mut b = [0u8; 6];
    getrandom::fill(&mut b).expect("system random source");
    format!("a{}", hex(&b))
}

impl Shared {
    pub(crate) fn account_infos(&self) -> Vec<AccountInfo> {
        let sync = self.sync_account_id();
        self.accounts
            .lock()
            .unwrap()
            .iter()
            .map(|a| a.info(sync.as_deref()))
            .collect()
    }

    pub(crate) async fn add_account(self: &Arc<Self>, setup: AccountSetup) -> Result<AddedAccount> {
        let address = setup.address.trim().to_string();
        if address
            .split_once('@')
            .is_none_or(|(l, d)| l.is_empty() || d.is_empty())
        {
            return Err(invalid("that is not an email address"));
        }
        let taken = self.accounts.lock().unwrap().iter().any(|a| {
            a.account
                .lock()
                .unwrap()
                .address
                .eq_ignore_ascii_case(&address)
        });
        if taken {
            return Err(invalid("this account is already added"));
        }
        let provider = setup
            .provider
            .map_or_else(|| Provider::detect(&address), Into::into);
        let password = match &setup.password {
            Some(p) => Some(check_password(provider.into(), p)?),
            None => None,
        };
        let mut account = Account::new(&new_id(), provider, &address, &setup.name);
        if let Some(c) = &setup.server {
            account.settings = Some(server_settings(c, provider));
        }
        if setup.use_graph {
            account.mail = MailAccess::Graph;
        }
        if account.mail == MailAccess::Imap && account.settings.is_none() {
            return Err(invalid("this provider needs server settings"));
        }

        let dir = self.dir.join("accounts").join(&account.id);
        std::fs::create_dir_all(&dir)?;
        let acc = match self.make_account(&dir, account, password, setup.pinned_certificate) {
            Ok(a) => a,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&dir);
                return Err(e);
            }
        };
        if let Err(e) = self.check_sign_in(&acc).await {
            let _ = self.finish_remove(acc);
            return Err(e);
        }
        acc.save()?;
        let mail = acc.mode();
        self.accounts.lock().unwrap().push(acc.clone());

        let first_with_mail = mail != MailAccess::None && self.sync_account_id().is_none();
        let settings = if first_with_mail {
            self.set_sync_account(Some(acc.id.clone()))?;
            Some(self.setup_settings().await)
        } else {
            None
        };
        let info = acc.info(self.sync_account_id().as_deref());
        Ok(AddedAccount {
            account: info,
            settings,
        })
    }

    fn make_account(
        self: &Arc<Self>,
        dir: &std::path::Path,
        account: Account,
        password: Option<String>,
        pinned: Option<Vec<u8>>,
    ) -> Result<Arc<AccountRt>> {
        let key =
            lazymail_store::load_or_create_key(&dir.join("store.key"), self.wrapper.as_ref())?;
        let wrapper: Arc<dyn lazymail_store::Wrapper> = self.wrapper.clone();
        let store = Store::open(dir, &key, wrapper)?;
        if let Some(p) = password {
            store.set_secret("password", p.as_bytes())?;
        }
        if let Some(der) = &pinned {
            store.set_secret("pin", der)?;
        }
        Ok(self.assemble(dir, account, SignIn::default(), store, pinned, false))
    }

    /// Signs in once, so a wrong password is told before anything is saved.
    async fn check_sign_in(&self, acc: &AccountRt) -> Result<()> {
        match acc.mode() {
            MailAccess::Imap => {
                let imap = acc
                    .imap()
                    .ok_or_else(|| invalid("this account has no mail server"))?;
                imap.connect().await?.logout().await;
            }
            MailAccess::Graph => {
                let store = self.open_store(acc)?;
                acc.graph.sync_folders(&store).await?;
            }
            MailAccess::None => {}
        }
        Ok(())
    }

    /// Changes the app password and signs in with it; the account is signed in again if it works.
    pub(crate) async fn set_password(self: &Arc<Self>, id: &str, password: &str) -> Result<()> {
        let acc = self.account(id)?;
        let provider = acc.account.lock().unwrap().provider;
        let password = check_password(provider.into(), password)?;
        acc.store
            .lock()
            .unwrap()
            .set_secret("password", password.as_bytes())?;
        self.build_imap(&acc, false);
        acc.signin.lock().unwrap().report_success(id);
        let imap = acc
            .imap()
            .ok_or_else(|| invalid("this account has no mail server"))?;
        let outcome = imap.connect().await;
        match outcome {
            Ok(c) => {
                c.logout().await;
                acc.save()?;
                Ok(())
            }
            Err(e) => {
                let _ = acc.save();
                Err(e.into())
            }
        }
    }

    pub(crate) async fn remove_account(&self, id: &str) -> Result<()> {
        let acc = self.account(id)?;
        self.accounts.lock().unwrap().retain(|a| a.id != id);
        if self.sync_account_id().as_deref() == Some(id) {
            self.set_sync_account(None)?;
            *self.replica.lock().await = None;
        }
        self.finish_remove(acc)
    }

    /// Ends the account's background work and deletes its store, files and secrets here.
    fn finish_remove(&self, acc: Arc<AccountRt>) -> Result<()> {
        acc.stop.lock().unwrap().stop();
        let thread = acc.thread.lock().unwrap().take();
        if let Some(t) = thread {
            let _ = t.join();
        }
        let dir = acc.dir.clone();
        drop(acc);
        std::fs::remove_dir_all(&dir).map_err(|e| CoreError::Storage {
            detail: e.to_string(),
        })
    }
}
