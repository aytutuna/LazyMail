use lazymail_accounts as acct;
use lazymail_store as store;

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ProviderKind {
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

impl From<acct::Provider> for ProviderKind {
    fn from(p: acct::Provider) -> Self {
        match p {
            acct::Provider::Outlook => ProviderKind::Outlook,
            acct::Provider::Microsoft365 => ProviderKind::Microsoft365,
            acct::Provider::Gmail => ProviderKind::Gmail,
            acct::Provider::ICloud => ProviderKind::ICloud,
            acct::Provider::Yahoo => ProviderKind::Yahoo,
            acct::Provider::Aol => ProviderKind::Aol,
            acct::Provider::Fastmail => ProviderKind::Fastmail,
            acct::Provider::ProtonBridge => ProviderKind::ProtonBridge,
            acct::Provider::Other => ProviderKind::Other,
            acct::Provider::Local => ProviderKind::Local,
        }
    }
}

impl From<ProviderKind> for acct::Provider {
    fn from(p: ProviderKind) -> Self {
        match p {
            ProviderKind::Outlook => acct::Provider::Outlook,
            ProviderKind::Microsoft365 => acct::Provider::Microsoft365,
            ProviderKind::Gmail => acct::Provider::Gmail,
            ProviderKind::ICloud => acct::Provider::ICloud,
            ProviderKind::Yahoo => acct::Provider::Yahoo,
            ProviderKind::Aol => acct::Provider::Aol,
            ProviderKind::Fastmail => acct::Provider::Fastmail,
            ProviderKind::ProtonBridge => acct::Provider::ProtonBridge,
            ProviderKind::Other => acct::Provider::Other,
            ProviderKind::Local => acct::Provider::Local,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ConnectionSecurity {
    Tls,
    StartTls,
}

impl From<acct::Security> for ConnectionSecurity {
    fn from(s: acct::Security) -> Self {
        match s {
            acct::Security::Tls => ConnectionSecurity::Tls,
            acct::Security::StartTls => ConnectionSecurity::StartTls,
        }
    }
}

impl From<ConnectionSecurity> for acct::Security {
    fn from(s: ConnectionSecurity) -> Self {
        match s {
            ConnectionSecurity::Tls => acct::Security::Tls,
            ConnectionSecurity::StartTls => acct::Security::StartTls,
        }
    }
}

/// Server settings, found by autoconfig or typed by the person.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ServerConfig {
    pub imap_host: String,
    pub imap_port: u16,
    pub imap_security: ConnectionSecurity,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_security: ConnectionSecurity,
    /// The login is the part of the address before the @, not the whole address.
    pub login_is_local_part: bool,
}

impl From<&acct::ServerSettings> for ServerConfig {
    fn from(s: &acct::ServerSettings) -> Self {
        ServerConfig {
            imap_host: s.imap.host.clone(),
            imap_port: s.imap.port,
            imap_security: s.imap.security.into(),
            smtp_host: s.smtp.host.clone(),
            smtp_port: s.smtp.port,
            smtp_security: s.smtp.security.into(),
            login_is_local_part: s.imap.login == acct::Login::LocalPart,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Discovered {
    pub provider: ProviderKind,
    pub server: ServerConfig,
    /// The settings came from DNS, which is not verified: show them before the password goes there.
    pub needs_confirmation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AppPasswordHelp {
    pub url: String,
    pub steps: Vec<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct AccountSetup {
    pub address: String,
    /// The name mail from this account is sent under.
    pub name: String,
    /// Left out, the provider is picked from the address.
    pub provider: Option<ProviderKind>,
    /// An app password. Microsoft accounts sign in through the token callback instead.
    pub password: Option<String>,
    /// Left out, the provider's built-in settings are used.
    pub server: Option<ServerConfig>,
    /// The server's certificate (DER), when it is not one the system trusts and the person has
    /// confirmed it, as with Proton Mail Bridge.
    pub pinned_certificate: Option<Vec<u8>>,
    /// Read and send mail through Microsoft Graph instead of IMAP and SMTP.
    pub use_graph: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MailAccessKind {
    Imap,
    Graph,
    /// A local account: no mail server.
    Local,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum AccountStatus {
    SignedIn,
    /// Shown red, with the reason as text; mail and the Outbox of this account wait.
    NeedsSignIn {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AccountInfo {
    pub id: String,
    pub address: String,
    pub name: String,
    pub provider: ProviderKind,
    pub mail: MailAccessKind,
    pub status: AccountStatus,
    /// The account whose mailbox carries the synced settings.
    pub is_sync_account: bool,
}

/// What setting up settings sync on the sync account came to.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum SettingsSetup {
    /// First device: the recovery code is shown once, to be printed.
    Created {
        recovery_code: String,
    },
    /// Another device already uses the mailbox; ask it to allow this one.
    MustJoin,
    Failed {
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AddedAccount {
    pub account: AccountInfo,
    /// Set when this was the first account and so the sync account.
    pub settings: Option<SettingsSetup>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FolderInfo {
    pub id: i64,
    pub name: String,
    /// "inbox", "sent", "drafts", "trash", "junk", "archive" or "all".
    pub role: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, uniffi::Record)]
pub struct FlagSet {
    pub seen: bool,
    pub flagged: bool,
    pub answered: bool,
    pub draft: bool,
    pub deleted: bool,
}

impl From<store::Flags> for FlagSet {
    fn from(f: store::Flags) -> Self {
        FlagSet {
            seen: f.seen,
            flagged: f.flagged,
            answered: f.answered,
            draft: f.draft,
            deleted: f.deleted,
        }
    }
}

impl From<FlagSet> for store::Flags {
    fn from(f: FlagSet) -> Self {
        store::Flags {
            seen: f.seen,
            flagged: f.flagged,
            answered: f.answered,
            draft: f.draft,
            deleted: f.deleted,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MessageSummary {
    pub id: i64,
    pub folder_id: i64,
    pub thread_id: i64,
    pub subject: String,
    pub from_name: String,
    pub from_addr: String,
    /// Seconds since the epoch.
    pub date: i64,
    pub flags: FlagSet,
    pub has_attachments: bool,
    /// The start of the text, or in a search the matching part with the store's mark characters
    /// around each hit.
    pub snippet: String,
}

impl From<store::SearchHit> for MessageSummary {
    fn from(h: store::SearchHit) -> Self {
        MessageSummary {
            id: h.message_id,
            folder_id: h.folder_id,
            thread_id: h.thread_id,
            subject: h.subject,
            from_name: h.from_name,
            from_addr: h.from_addr,
            date: h.date,
            flags: h.flags.into(),
            has_attachments: h.has_attachments,
            snippet: h.snippet,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AttachmentInfo {
    pub id: i64,
    pub filename: String,
    pub mime: String,
    pub size: u32,
    pub content_id: Option<String>,
    /// The file is on this device already.
    pub stored: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MessageDetail {
    pub summary: MessageSummary,
    pub to: String,
    pub cc: String,
    pub message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    pub labels: Vec<String>,
    pub body_text: Option<String>,
    pub body_html: Option<String>,
    pub attachments: Vec<AttachmentInfo>,
}

#[derive(Debug, Clone, Default, uniffi::Record)]
pub struct SearchRequest {
    pub text: String,
    pub from: Option<String>,
    pub to: Option<String>,
    pub subject: Option<String>,
    pub folder_id: Option<i64>,
    pub label: Option<String>,
    pub after: Option<i64>,
    pub before: Option<i64>,
    pub has_attachment: bool,
    pub unread: bool,
    pub flagged: bool,
    /// 0 means 50.
    pub limit: u32,
    pub offset: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MailAddress {
    pub name: Option<String>,
    pub email: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OutgoingFile {
    pub filename: String,
    pub content_type: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct OutgoingMessage {
    /// Left out, the account's own address is used.
    pub from: Option<MailAddress>,
    pub to: Vec<MailAddress>,
    pub cc: Vec<MailAddress>,
    pub bcc: Vec<MailAddress>,
    pub subject: String,
    pub text: Option<String>,
    pub html: Option<String>,
    pub attachments: Vec<OutgoingFile>,
    /// Message-ID without angle brackets, of the mail being answered.
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum OutboxStatus {
    Queued,
    Sending,
    /// Gave up, or may already have been sent; waits for the person to retry or remove it.
    Failed,
    /// Taken by the server; its copy is not in Sent yet.
    Sent,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OutboxEntry {
    pub id: i64,
    pub message_id: String,
    pub status: OutboxStatus,
    pub attempts: u32,
    pub last_error: Option<String>,
    pub created: i64,
    /// When the next attempt is due.
    pub next_try: i64,
}

impl From<store::OutboxItem> for OutboxEntry {
    fn from(i: store::OutboxItem) -> Self {
        OutboxEntry {
            id: i.id,
            message_id: i.message_id,
            status: match i.state {
                store::OutboxState::Queued => OutboxStatus::Queued,
                store::OutboxState::Sending => OutboxStatus::Sending,
                store::OutboxState::Failed => OutboxStatus::Failed,
                store::OutboxState::Sent => OutboxStatus::Sent,
            },
            attempts: i.attempts,
            last_error: i.last_error,
            created: i.created,
            next_try: i.next_try,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, uniffi::Record)]
pub struct OutboxReport {
    pub sent: u32,
    pub retry: u32,
    pub failed: u32,
    pub copies_pending: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, uniffi::Record)]
pub struct SyncSummary {
    pub added: u32,
    pub removed: u32,
    pub changed: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SyncPhase {
    Headers,
    Bodies,
}

/// Something the app should show or act on, sent as it happens.
#[derive(Debug, Clone, PartialEq, uniffi::Enum)]
pub enum CoreEvent {
    Progress {
        account_id: String,
        folder: String,
        phase: SyncPhase,
        done: u32,
        total: u32,
        per_second: f64,
        remaining_seconds: Option<u64>,
    },
    FolderSynced {
        account_id: String,
        folder: String,
        summary: SyncSummary,
    },
    NeedsSignIn {
        account_id: String,
        reason: String,
    },
    /// The tenant turned IMAP or SMTP off, so mail is now read through Graph.
    UsesGraph {
        account_id: String,
    },
    /// Gmail's daily download limit was reached; syncing waits until `resume_at`.
    DownloadLimit {
        account_id: String,
        resume_at: i64,
    },
    FolderFailed {
        account_id: String,
        folder: String,
        reason: String,
    },
    OutboxRan {
        account_id: String,
        report: OutboxReport,
    },
    /// Settings written by another device arrived.
    SettingsChanged {
        entries: u32,
    },
    /// Another device asks to join: show "Allow this device?" and its code.
    JoinRequested {
        device_id: String,
        name: String,
    },
    /// This device holds, or no longer holds, the lease for scheduled work.
    LeaseChanged {
        held: bool,
    },
    /// The settings key was replaced without this device: join again.
    NeedsRejoin,
    /// A background task failed; the next try is made later.
    TaskFailed {
        account_id: Option<String>,
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SettingEntry {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum SettingsState {
    /// No account is the sync account yet.
    NoSyncAccount,
    /// This device has no settings key: join, recover, or ask the setup again.
    NoKey,
    Ready,
    /// A device that stays rotated the key without this one.
    NeedsRejoin,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,
    pub is_this_device: bool,
    pub is_main_computer: bool,
    /// How other devices reach it: a local network address and a relay group.
    pub address: Option<String>,
    pub relay_group: Option<String>,
    pub updated: u64,
}

/// A device asking to join, as shown on a device that already has the key.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct JoinRequest {
    /// Names the request in the other calls.
    pub nonce: String,
    pub device_id: String,
    pub name: String,
    /// Another request with the same name is open: ask which one is the person's.
    pub look_alike: bool,
}

/// A device that answered this device's request to join, with the code this device shows for it.
/// The person types that code on the answering device, and the code that device shows here.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct JoinOffer {
    pub device_id: String,
    pub name: String,
    pub code: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, uniffi::Record)]
pub struct PullResult {
    pub changed: u32,
    pub needs_rejoin: bool,
    pub key_replaced: bool,
    pub conflict: bool,
}
