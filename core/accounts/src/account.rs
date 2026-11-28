use serde::{Deserialize, Serialize};

use crate::provider::{Provider, ServerSettings};

/// How mail is read and sent for an account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MailAccess {
    Imap,
    /// Microsoft 365 tenants that turned IMAP or SMTP AUTH off.
    Graph,
    /// Local accounts have no mail server.
    None,
}

/// An address the person can send from: the account's own, an alias or a send-as address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub address: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub provider: Provider,
    pub address: String,
    pub settings: Option<ServerSettings>,
    pub mail: MailAccess,
    /// The first entry is the account's own address.
    pub identities: Vec<Identity>,
}

impl Account {
    pub fn new(id: &str, provider: Provider, address: &str, name: &str) -> Account {
        Account {
            id: id.to_string(),
            provider,
            address: address.to_string(),
            settings: provider.settings(),
            mail: if provider == Provider::Local {
                MailAccess::None
            } else {
                MailAccess::Imap
            },
            identities: vec![Identity {
                address: address.to_string(),
                name: name.to_string(),
            }],
        }
    }

    /// Adds an alias or send-as address; an address already listed is left alone.
    pub fn add_identity(&mut self, address: &str, name: &str) -> bool {
        if self.identity(address).is_some() {
            return false;
        }
        self.identities.push(Identity {
            address: address.to_string(),
            name: name.to_string(),
        });
        true
    }

    /// The account's own address cannot be removed.
    pub fn remove_identity(&mut self, address: &str) -> bool {
        if address.eq_ignore_ascii_case(&self.address) {
            return false;
        }
        let before = self.identities.len();
        self.identities
            .retain(|i| !i.address.eq_ignore_ascii_case(address));
        self.identities.len() != before
    }

    pub fn identity(&self, address: &str) -> Option<&Identity> {
        self.identities
            .iter()
            .find(|i| i.address.eq_ignore_ascii_case(address))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_keep_the_own_address() {
        let mut a = Account::new("a", Provider::Fastmail, "ann@fastmail.com", "Ann");
        assert!(a.add_identity("sales@example.org", "Ann Sales"));
        assert!(!a.add_identity("SALES@example.org", "Again"));
        assert_eq!(a.identity("Sales@Example.org").unwrap().name, "Ann Sales");
        assert!(!a.remove_identity("ann@fastmail.com"));
        assert!(a.remove_identity("sales@example.org"));
        assert_eq!(a.identities.len(), 1);
    }

    #[test]
    fn local_accounts_have_no_server() {
        let a = Account::new("l", Provider::Local, "me@local", "Me");
        assert_eq!(a.mail, MailAccess::None);
        assert!(a.settings.is_none());
    }
}
