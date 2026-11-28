use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_imap::imap_proto::{
    MailboxDatum, NameAttribute, RequestId, Response, ResponseCode, Status, UidSetMember,
};
use async_imap::{Authenticator, Client, Session};
use lazymail_accounts::{classify_login_error, xoauth2, Account, MailAccess, Provider, Security};
use rustls::ClientConfig;
use tokio::io::AsyncWriteExt;

use crate::error::{Error, Result};
use crate::parse::{self, Fetched};
use crate::stream::{self, Stream};
use crate::utf7;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tls,
    StartTls,
    /// No encryption, for the test servers on this machine.
    Plain,
}

impl From<Security> for Transport {
    fn from(s: Security) -> Transport {
        match s {
            Security::Tls => Transport::Tls,
            Security::StartTls => Transport::StartTls,
        }
    }
}

/// Where and as whom to connect.
#[derive(Debug, Clone)]
pub struct Server {
    pub host: String,
    pub port: u16,
    pub transport: Transport,
    pub user: String,
    pub provider: Provider,
    pub gmail: bool,
}

impl Server {
    /// None for an account without a mail server (Local) or one that reads mail through Graph.
    pub fn of(account: &Account) -> Option<Server> {
        if account.mail != MailAccess::Imap {
            return None;
        }
        let s = account.settings.as_ref()?;
        Some(Server {
            host: s.imap.host.clone(),
            port: s.imap.port,
            transport: s.imap.security.into(),
            user: s.imap.login.resolve(&account.address),
            provider: account.provider,
            gmail: s.gmail,
        })
    }
}

pub enum Credential {
    Password(String),
    /// An access token for XOAUTH2.
    OAuth(String),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Capabilities {
    pub idle: bool,
    pub condstore: bool,
    pub qresync: bool,
    pub move_: bool,
    pub uidplus: bool,
    pub gmail: bool,
}

/// What a SELECT told us about the folder.
#[derive(Debug, Clone)]
pub(crate) struct Selected {
    pub validity: u32,
    pub uidnext: Option<u32>,
    pub modseq: Option<i64>,
    pub exists: u32,
}

/// What a command's replies held, picked out as they arrived.
#[derive(Default)]
pub(crate) struct Reply {
    pub fetched: Vec<Fetched>,
    pub search: Vec<u32>,
    /// UIDs the server says are gone (QRESYNC's VANISHED).
    pub vanished: Vec<u32>,
    pub copy_uid: Option<UidMap>,
    pub append_uid: Option<(u32, u32)>,
    pub folders: Vec<RemoteFolder>,
    pub exists: Option<u32>,
    pub validity: Option<u32>,
    pub uidnext: Option<u32>,
    pub modseq: Option<i64>,
}

pub(crate) struct UidMap {
    pub validity: u32,
    pub to: Vec<u32>,
}

fn expand(set: &[UidSetMember]) -> Vec<u32> {
    set.iter()
        .flat_map(|m| match m {
            UidSetMember::Uid(u) => *u..=*u,
            UidSetMember::UidRange(r) => r.clone(),
        })
        .collect()
}

impl Reply {
    /// The FETCH data of the messages that were asked for, merged per UID. Responses for other
    /// messages (another client's flag change announced mid-command) are left out.
    pub(crate) fn fetched_for(self, uids: &[u32]) -> HashMap<u32, Fetched> {
        let mut out: HashMap<u32, Fetched> = HashMap::new();
        for f in self.fetched {
            if !uids.contains(&f.uid) {
                continue;
            }
            match out.get_mut(&f.uid) {
                Some(have) => have.merge(f),
                None => {
                    out.insert(f.uid, f);
                }
            }
        }
        out
    }

    fn absorb(&mut self, r: &Response<'_>) {
        match r {
            Response::Fetch(_, attrs) => self.fetched.extend(parse::fetched(attrs)),
            Response::Vanished { uids, .. } => {
                self.vanished.extend(uids.iter().flat_map(|u| u.clone()))
            }
            Response::MailboxData(MailboxDatum::Search(v)) => self.search.extend(v),
            Response::MailboxData(MailboxDatum::Exists(n)) => self.exists = Some(*n),
            Response::MailboxData(MailboxDatum::List {
                name_attributes,
                delimiter,
                name,
            }) => self.folders.push(RemoteFolder {
                name: utf7::decode(&parse::unescape(name)),
                delimiter: delimiter.as_ref().map(|d| d.to_string()),
                attributes: name_attributes.iter().map(attribute).collect(),
            }),
            Response::Data {
                code: Some(code), ..
            }
            | Response::Done {
                code: Some(code), ..
            } => match code {
                ResponseCode::UidValidity(v) => self.validity = Some(*v),
                ResponseCode::UidNext(n) => self.uidnext = Some(*n),
                ResponseCode::HighestModSeq(m) => self.modseq = Some(*m as i64),
                ResponseCode::CopyUid(validity, _, to) => {
                    self.copy_uid = Some(UidMap {
                        validity: *validity,
                        to: expand(to),
                    })
                }
                ResponseCode::AppendUid(validity, uids) => {
                    self.append_uid = expand(uids).first().map(|u| (*validity, *u))
                }
                _ => {}
            },
            _ => {}
        }
    }
}

/// A folder as LIST gave it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteFolder {
    /// The readable name; the server's own form is `utf7::encode(name)`.
    pub name: String,
    pub delimiter: Option<String>,
    /// Lowercase attribute names such as "\\sent" or "\\noselect".
    pub attributes: Vec<String>,
}

impl RemoteFolder {
    pub fn has(&self, attribute: &str) -> bool {
        self.attributes.iter().any(|a| a == attribute)
    }
}

pub struct Connection {
    session: Session<Stream>,
    pub(crate) server: Server,
    pub(crate) caps: Capabilities,
    pub(crate) qresync_on: bool,
    current: Option<String>,
    /// Held while the connection lives, when the account limits its connections.
    pub(crate) permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

struct XOAuth2 {
    first: Option<String>,
}

impl Authenticator for XOAuth2 {
    type Response = String;

    fn process(&mut self, _challenge: &[u8]) -> String {
        // After the first answer the server only sends a JSON error; an empty line ends it.
        self.first.take().unwrap_or_default()
    }
}

impl Connection {
    /// Connects, secures the channel and signs in. `worked_before` says whether this account
    /// has signed in successfully already, which changes how a refusal is read.
    pub async fn open(
        server: &Server,
        credential: &Credential,
        tls: &Arc<ClientConfig>,
        worked_before: bool,
    ) -> Result<Connection> {
        let tcp = stream::tcp(&server.host, server.port).await?;
        let mut client = match server.transport {
            Transport::Plain => Client::new(Stream::Plain(tcp)),
            Transport::Tls => Client::new(stream::upgrade(tcp, &server.host, tls).await?),
            Transport::StartTls => {
                let mut plain = Client::new(Stream::Plain(tcp));
                greeting(&mut plain).await?;
                plain.run_command_and_check_ok("STARTTLS", None).await?;
                let Stream::Plain(tcp) = plain.into_inner() else {
                    unreachable!("the client was made over a plain stream")
                };
                Client::new(stream::upgrade(tcp, &server.host, tls).await?)
            }
        };
        if server.transport != Transport::StartTls {
            greeting(&mut client).await?;
        }
        let login = match credential {
            Credential::Password(p) => client.login(&server.user, p).await,
            Credential::OAuth(token) => {
                let auth = XOAuth2 {
                    first: Some(xoauth2(&server.user, token)),
                };
                client.authenticate("XOAUTH2", auth).await
            }
        };
        let mut session = login.map_err(|(e, _)| login_error(e, server, worked_before))?;
        let caps = session.capabilities().await?;
        let caps = Capabilities {
            idle: caps.has_str("IDLE"),
            condstore: caps.has_str("CONDSTORE") || caps.has_str("QRESYNC"),
            qresync: caps.has_str("QRESYNC"),
            move_: caps.has_str("MOVE"),
            uidplus: caps.has_str("UIDPLUS"),
            gmail: caps.has_str("X-GM-EXT-1"),
        };
        let mut conn = Connection {
            session,
            server: server.clone(),
            caps,
            qresync_on: false,
            current: None,
            permit: None,
        };
        if conn.caps.qresync {
            conn.exec("ENABLE QRESYNC").await?;
            conn.qresync_on = true;
        }
        Ok(conn)
    }

    pub fn capabilities(&self) -> Capabilities {
        self.caps
    }

    pub fn is_gmail(&self) -> bool {
        self.server.gmail
    }

    /// Runs a command and gathers its replies up to the tagged one.
    pub(crate) async fn exec(&mut self, command: &str) -> Result<Reply> {
        let tag = self.session.run_command(command).await?;
        self.collect(&tag).await
    }

    async fn collect(&mut self, tag: &RequestId) -> Result<Reply> {
        let mut reply = Reply::default();
        loop {
            let next = tokio::time::timeout(COMMAND_TIMEOUT, self.session.read_response())
                .await
                .map_err(|_| Error::Io(std::io::ErrorKind::TimedOut.into()))??;
            let Some(r) = next else {
                return Err(Error::Closed);
            };
            match r.parsed() {
                Response::Done {
                    tag: t,
                    status,
                    information,
                    ..
                } if t == tag => {
                    if *status != Status::Ok {
                        return Err(refusal(information.as_deref().unwrap_or("")));
                    }
                    reply.absorb(r.parsed());
                    return Ok(reply);
                }
                Response::Data {
                    status: Status::Bye,
                    information,
                    ..
                } => return Err(bye(information.as_deref().unwrap_or(""))),
                other => reply.absorb(other),
            }
        }
    }

    pub async fn list_folders(&mut self) -> Result<Vec<RemoteFolder>> {
        Ok(self.exec("LIST \"\" \"*\"").await?.folders)
    }

    /// Selects the folder unless it is the one already open.
    pub(crate) async fn ensure(&mut self, name: &str) -> Result<()> {
        if self.current.as_deref() != Some(name) {
            self.select(name).await?;
        }
        Ok(())
    }

    pub(crate) async fn select(&mut self, name: &str) -> Result<Selected> {
        self.current = None;
        let with = if self.caps.condstore && !self.qresync_on {
            " (CONDSTORE)"
        } else {
            ""
        };
        let reply = self
            .exec(&format!("SELECT {}{with}", quote(&utf7::encode(name))?))
            .await?;
        let Some(validity) = reply.validity else {
            return Err(Error::Protocol("SELECT gave no UIDVALIDITY".into()));
        };
        self.current = Some(name.to_string());
        Ok(Selected {
            validity,
            uidnext: reply.uidnext,
            modseq: reply.modseq,
            exists: reply.exists.unwrap_or(0),
        })
    }

    /// APPEND with the message as a literal; the server's APPENDUID comes back in the reply.
    pub(crate) async fn append(
        &mut self,
        folder: &str,
        flags: &str,
        message: &[u8],
    ) -> Result<Reply> {
        let tag = self
            .session
            .run_command(&format!(
                "APPEND {} ({flags}) {{{}}}",
                quote(&utf7::encode(folder))?,
                message.len()
            ))
            .await?;
        loop {
            let next = tokio::time::timeout(COMMAND_TIMEOUT, self.session.read_response())
                .await
                .map_err(|_| Error::Io(std::io::ErrorKind::TimedOut.into()))??;
            match next.as_ref().map(|r| r.parsed()) {
                None => return Err(Error::Closed),
                Some(Response::Continue { .. }) => break,
                Some(Response::Done {
                    tag: t,
                    information,
                    ..
                }) if *t == tag => return Err(refusal(information.as_deref().unwrap_or(""))),
                Some(_) => {}
            }
        }
        let out: &mut Stream = self.session.as_mut();
        out.write_all(message).await?;
        out.write_all(b"\r\n").await?;
        out.flush().await?;
        self.collect(&tag).await
    }

    pub(crate) async fn uid_search(&mut self, query: &str) -> Result<Vec<u32>> {
        let mut uids = self.exec(&format!("UID SEARCH {query}")).await?.search;
        uids.sort_unstable();
        Ok(uids)
    }

    pub async fn noop(&mut self) -> Result<()> {
        self.exec("NOOP").await.map(drop)
    }

    pub async fn logout(mut self) {
        let _ = self.exec("LOGOUT").await;
    }

    /// IDLEs on the selected folder until something changes, `max` passes or `stop` fires.
    pub(crate) async fn idle(
        &mut self,
        max: Duration,
        stop: &tokio::sync::Notify,
    ) -> Result<IdleEnd> {
        let tag = self.session.run_command("IDLE").await?;
        loop {
            let next = tokio::time::timeout(COMMAND_TIMEOUT, self.session.read_response())
                .await
                .map_err(|_| Error::Io(std::io::ErrorKind::TimedOut.into()))??;
            match next.as_ref().map(|r| r.parsed()) {
                None => return Err(Error::Closed),
                Some(Response::Continue { .. }) => break,
                Some(Response::Done {
                    tag: t,
                    information,
                    ..
                }) if *t == tag => return Err(refusal(information.as_deref().unwrap_or(""))),
                Some(_) => {}
            }
        }
        let end = tokio::select! {
            r = self.wait_for_change() => r?,
            _ = tokio::time::sleep(max) => IdleEnd::Timeout,
            _ = stop.notified() => IdleEnd::Stopped,
        };
        self.session.run_command_untagged("DONE").await?;
        self.collect(&tag).await?;
        Ok(end)
    }

    async fn wait_for_change(&mut self) -> Result<IdleEnd> {
        loop {
            let Some(r) = self.session.read_response().await? else {
                return Err(Error::Closed);
            };
            match r.parsed() {
                Response::MailboxData(MailboxDatum::Exists(_))
                | Response::Expunge(_)
                | Response::Fetch(..)
                | Response::Vanished { .. } => return Ok(IdleEnd::Changed),
                Response::Data {
                    status: Status::Bye,
                    information,
                    ..
                } => return Err(bye(information.as_deref().unwrap_or(""))),
                _ => {}
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdleEnd {
    Changed,
    Timeout,
    Stopped,
}

async fn greeting(client: &mut Client<Stream>) -> Result<()> {
    let first = tokio::time::timeout(COMMAND_TIMEOUT, client.read_response())
        .await
        .map_err(|_| Error::Io(std::io::ErrorKind::TimedOut.into()))??;
    match first.as_ref().map(|r| r.parsed()) {
        Some(Response::Data {
            status: Status::Ok | Status::PreAuth,
            ..
        }) => Ok(()),
        Some(Response::Data {
            status: Status::Bye,
            information,
            ..
        }) => Err(bye(information.as_deref().unwrap_or(""))),
        Some(_) => Err(Error::Protocol("no greeting".into())),
        None => Err(Error::Closed),
    }
}

fn login_error(e: async_imap::error::Error, server: &Server, worked_before: bool) -> Error {
    use async_imap::error::Error as E;
    match e {
        E::No(text) | E::Bad(text) => {
            match classify_login_error(server.provider, &text, worked_before) {
                Some(failure) => Error::Auth(failure),
                None => Error::Busy(text),
            }
        }
        other => other.into(),
    }
}

/// Gmail ends a session with this once the day's download allowance is used up.
pub(crate) fn is_download_limit(text: &str) -> bool {
    text.to_ascii_lowercase()
        .contains("exceeded command or bandwidth limits")
}

fn refusal(text: &str) -> Error {
    if is_download_limit(text) {
        Error::DownloadLimit
    } else {
        Error::Refused(text.to_string())
    }
}

fn bye(text: &str) -> Error {
    if is_download_limit(text) {
        Error::DownloadLimit
    } else {
        Error::Closed
    }
}

fn attribute(a: &NameAttribute<'_>) -> String {
    match a {
        NameAttribute::NoInferiors => "\\noinferiors".into(),
        NameAttribute::NoSelect => "\\noselect".into(),
        NameAttribute::Marked => "\\marked".into(),
        NameAttribute::Unmarked => "\\unmarked".into(),
        NameAttribute::All => "\\all".into(),
        NameAttribute::Archive => "\\archive".into(),
        NameAttribute::Drafts => "\\drafts".into(),
        NameAttribute::Flagged => "\\flagged".into(),
        NameAttribute::Junk => "\\junk".into(),
        NameAttribute::Sent => "\\sent".into(),
        NameAttribute::Trash => "\\trash".into(),
        NameAttribute::Extension(e) => e.to_ascii_lowercase(),
        _ => String::new(),
    }
}

/// A string argument in quotes. Line breaks cannot be written inside quotes.
pub(crate) fn quote(s: &str) -> Result<String> {
    if s.contains(['\r', '\n', '\0']) {
        return Err(Error::Protocol("a name contains a line break".into()));
    }
    Ok(format!(
        "\"{}\"",
        s.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

/// UIDs as a compact set such as "1:5,9,12:13".
pub(crate) fn uid_set(uids: &[u32]) -> String {
    let mut sorted = uids.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut out = String::new();
    let mut i = 0;
    while i < sorted.len() {
        let mut j = i;
        while j + 1 < sorted.len() && sorted[j + 1] == sorted[j] + 1 {
            j += 1;
        }
        if !out.is_empty() {
            out.push(',');
        }
        if j > i {
            out.push_str(&format!("{}:{}", sorted[i], sorted[j]));
        } else {
            out.push_str(&sorted[i].to_string());
        }
        i = j + 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uid_sets_are_compact() {
        assert_eq!(uid_set(&[9, 1, 2, 3, 4, 5, 12, 13, 5]), "1:5,9,12:13");
        assert_eq!(uid_set(&[7]), "7");
        assert_eq!(uid_set(&[]), "");
    }

    #[test]
    fn names_are_quoted() {
        assert_eq!(quote("a \"b\" \\c").unwrap(), "\"a \\\"b\\\" \\\\c\"");
        assert!(quote("a\r\nb").is_err());
    }
}
