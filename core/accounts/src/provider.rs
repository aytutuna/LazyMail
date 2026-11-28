use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Provider {
    Outlook,
    Microsoft365,
    Gmail,
    ICloud,
    Yahoo,
    Aol,
    Fastmail,
    ProtonBridge,
    Other,
    Local,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Security {
    Tls,
    StartTls,
}

/// How the login name is made from the email address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Login {
    Address,
    LocalPart,
}

impl Login {
    pub fn resolve(self, address: &str) -> String {
        match self {
            Login::Address => address.to_string(),
            Login::LocalPart => address.split('@').next().unwrap_or(address).to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub security: Security,
    pub login: Login,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerSettings {
    pub imap: Endpoint,
    pub smtp: Endpoint,
    /// The server files a copy of sent mail itself, so the app must not append one.
    pub files_sent: bool,
    /// Gmail's IMAP rules: only All Mail, Spam and Trash, X-GM-MSGID and X-GM-LABELS.
    pub gmail: bool,
    pub max_connections: u8,
}

impl Provider {
    /// Named providers by address domain. Microsoft 365 and Workspace cannot be told
    /// apart from a domain name, so the person picks those.
    pub fn detect(address: &str) -> Provider {
        let domain = domain_of(address);
        let is = |names: &[&str]| names.contains(&domain.as_str());
        let (stem, rest) = domain.split_once('.').unwrap_or((&domain, ""));
        if is(&["msn.com"])
            || ["hotmail", "live", "outlook"].contains(&stem) && is_country_ending(rest)
        {
            Provider::Outlook
        } else if is(&["gmail.com", "googlemail.com"]) {
            Provider::Gmail
        } else if is(&["icloud.com", "me.com", "mac.com"]) {
            Provider::ICloud
        } else if is(YAHOO) {
            Provider::Yahoo
        } else if is(&["aol.com"]) {
            Provider::Aol
        } else if is(&["fastmail.com", "fastmail.fm"]) {
            Provider::Fastmail
        } else if is(&["proton.me", "protonmail.com", "pm.me"]) {
            Provider::ProtonBridge
        } else {
            Provider::Other
        }
    }

    /// Built-in settings; `None` for Other and Local, which come from discovery or the person.
    pub fn settings(self) -> Option<ServerSettings> {
        use Security::{StartTls, Tls};
        let (imap, smtp, files_sent, max_connections) = match self {
            Provider::Outlook => (
                ("outlook.office365.com", 993, Tls),
                ("smtp-mail.outlook.com", 587, StartTls),
                true,
                4,
            ),
            Provider::Microsoft365 => (
                ("outlook.office365.com", 993, Tls),
                ("smtp.office365.com", 587, StartTls),
                true,
                4,
            ),
            Provider::Gmail => (
                ("imap.gmail.com", 993, Tls),
                ("smtp.gmail.com", 465, Tls),
                true,
                3,
            ),
            Provider::ICloud => (
                ("imap.mail.me.com", 993, Tls),
                ("smtp.mail.me.com", 587, StartTls),
                false,
                5,
            ),
            Provider::Yahoo => (
                ("imap.mail.yahoo.com", 993, Tls),
                ("smtp.mail.yahoo.com", 465, Tls),
                false,
                5,
            ),
            Provider::Aol => (
                ("imap.aol.com", 993, Tls),
                ("smtp.aol.com", 465, Tls),
                false,
                5,
            ),
            Provider::Fastmail => (
                ("imap.fastmail.com", 993, Tls),
                ("smtp.fastmail.com", 465, Tls),
                false,
                10,
            ),
            Provider::ProtonBridge => (
                ("127.0.0.1", 1143, StartTls),
                ("127.0.0.1", 1025, StartTls),
                true,
                3,
            ),
            Provider::Other | Provider::Local => return None,
        };
        let endpoint = |(host, port, security): (&str, u16, Security)| Endpoint {
            host: host.to_string(),
            port,
            security,
            login: Login::Address,
        };
        Some(ServerSettings {
            imap: endpoint(imap),
            smtp: endpoint(smtp),
            files_sent,
            gmail: self == Provider::Gmail,
            max_connections,
        })
    }

    pub fn uses_microsoft_sign_in(self) -> bool {
        matches!(self, Provider::Outlook | Provider::Microsoft365)
    }
}

// Yahoo Japan is a different company with its own servers, so it is not here.
const YAHOO: &[&str] = &[
    "yahoo.com",
    "yahoo.co.uk",
    "yahoo.ca",
    "yahoo.com.au",
    "yahoo.co.nz",
    "yahoo.co.in",
    "yahoo.in",
    "yahoo.co.id",
    "yahoo.com.sg",
    "yahoo.com.ph",
    "yahoo.com.hk",
    "yahoo.com.tw",
    "yahoo.com.vn",
    "yahoo.com.my",
    "yahoo.co.za",
    "yahoo.com.br",
    "yahoo.com.mx",
    "yahoo.com.ar",
    "yahoo.de",
    "yahoo.fr",
    "yahoo.es",
    "yahoo.it",
    "yahoo.ie",
    "yahoo.nl",
    "yahoo.se",
    "yahoo.no",
    "yahoo.dk",
    "yahoo.pl",
    "yahoo.gr",
    "yahoo.com.tr",
    "ymail.com",
    "rocketmail.com",
];

pub(crate) fn domain_of(address: &str) -> String {
    address
        .rsplit_once('@')
        .map_or(address, |(_, d)| d)
        .trim()
        .to_ascii_lowercase()
}

// com, a two-letter country code, or co/com before one (hotmail.fr, live.co.uk).
fn is_country_ending(rest: &str) -> bool {
    let is_cc = |s: &str| s.len() == 2 && s.bytes().all(|b| b.is_ascii_lowercase());
    match rest.split_once('.') {
        None => rest == "com" || is_cc(rest),
        Some((a, b)) => matches!(a, "co" | "com") && is_cc(b),
    }
}
