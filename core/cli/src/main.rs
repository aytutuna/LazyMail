use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use lazymail_core::{
    AccountSetup, AccountStatus, ConnectionSecurity, Core, CoreEvent, DevKey, EventListener,
    FlagSet, MailAddress, MessageSummary, OutgoingMessage, ProviderKind, SearchRequest,
    ServerConfig, SettingsSetup, TokenFailure, TokenProvider, TokenResource,
};

#[derive(Parser)]
#[command(name = "lazymail", about = "Command line for the Lazy Mail core")]
struct Cli {
    /// Print the core version
    #[arg(long, short = 'V')]
    version: bool,
    /// Where the accounts and their mail are kept (default: ~/.local/share/lazymail-cli)
    #[arg(long, env = "LAZYMAIL_DIR")]
    dir: Option<PathBuf>,
    /// The name this device goes by in the device list
    #[arg(long, default_value = "lazymail-cli")]
    device: String,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Add, list and remove accounts
    #[command(subcommand)]
    Account(AccountCmd),
    /// Download new mail and send what waits in the Outbox
    Sync {
        /// Account ids; every account when none are given
        accounts: Vec<String>,
    },
    /// List the folders of an account, or the messages of one folder
    Ls {
        account: String,
        /// Folder name or id
        folder: Option<String>,
        #[arg(long, default_value_t = 30)]
        limit: u32,
        #[arg(long, default_value_t = 0)]
        offset: u32,
    },
    /// Show one message
    Show { account: String, message: i64 },
    /// Search an account for words
    Search {
        account: String,
        words: Vec<String>,
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        folder: Option<String>,
        #[arg(long)]
        unread: bool,
        #[arg(long, default_value_t = 30)]
        limit: u32,
    },
    /// Mark a message read or unread, starred or not, or move or delete it
    Mark {
        account: String,
        message: i64,
        #[arg(long)]
        read: Option<bool>,
        #[arg(long)]
        star: Option<bool>,
        /// Folder name or id to move the message to
        #[arg(long, name = "FOLDER")]
        to: Option<String>,
        #[arg(long)]
        delete: bool,
    },
    /// Queue a message and send it
    Send {
        account: String,
        #[arg(long, required = true)]
        to: Vec<String>,
        #[arg(long)]
        cc: Vec<String>,
        #[arg(long)]
        bcc: Vec<String>,
        #[arg(long, default_value = "")]
        subject: String,
        /// The text; read from standard input when left out
        #[arg(long)]
        text: Option<String>,
        /// Queue it without sending
        #[arg(long)]
        queue_only: bool,
    },
    /// The Outbox
    Outbox {
        account: String,
        #[command(subcommand)]
        action: Option<OutboxCmd>,
    },
    /// This device's view of the others, and the main computer lease
    #[command(subcommand)]
    Devices(DevicesCmd),
    /// Settings synced between devices
    #[command(subcommand)]
    Settings(SettingsCmd),
}

#[derive(Subcommand)]
enum AccountCmd {
    Add(AddArgs),
    List,
    Remove {
        id: String,
    },
    /// Replace the app password of an account that needs a new sign-in
    Password {
        id: String,
        #[arg(long)]
        password_stdin: bool,
        #[arg(long)]
        password: Option<String>,
    },
}

#[derive(Args)]
struct AddArgs {
    address: String,
    #[arg(long)]
    name: Option<String>,
    #[arg(long, value_enum)]
    provider: Option<Provider>,
    /// An app password
    #[arg(long, conflicts_with = "password_stdin")]
    password: Option<String>,
    /// Read the app password from the first line of standard input
    #[arg(long)]
    password_stdin: bool,
    /// IMAP server as host:port; found automatically when left out
    #[arg(long)]
    imap: Option<String>,
    #[arg(long, value_enum, default_value = "tls")]
    imap_security: Security,
    /// SMTP server as host:port
    #[arg(long)]
    smtp: Option<String>,
    #[arg(long, value_enum, default_value = "starttls")]
    smtp_security: Security,
    /// The login is the part of the address before the @
    #[arg(long)]
    local_part_login: bool,
    /// The server's certificate (a PEM file) that the person has confirmed
    #[arg(long)]
    pin_certificate: Option<PathBuf>,
    /// Read and send through Microsoft Graph
    #[arg(long)]
    graph: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum Security {
    Tls,
    Starttls,
}

#[derive(Clone, Copy, ValueEnum)]
enum Provider {
    Outlook,
    Microsoft365,
    Gmail,
    Icloud,
    Yahoo,
    Aol,
    Fastmail,
    ProtonBridge,
    Other,
    Local,
}

#[derive(Subcommand)]
enum OutboxCmd {
    /// Send what is due
    Run,
    Retry {
        id: i64,
    },
    Remove {
        id: i64,
    },
}

#[derive(Subcommand)]
enum DevicesCmd {
    List,
    /// On a new device: ask the other devices to let this one in
    Join,
    /// On a new device: the devices that answered, with the code each expects
    Offers,
    /// On a new device: take the key from the device that shows this code
    Finish {
        device: String,
        code: String,
    },
    /// On a device with the key: who is asking to join
    Requests,
    /// On a device with the key: answer a request
    Offer {
        request: String,
    },
    /// On a device with the key: the code to type on the new device
    Code {
        request: String,
    },
    /// On a device with the key: type the code the new device shows
    Approve {
        request: String,
        code: String,
    },
    Deny {
        request: String,
    },
    /// Get the key from the printed recovery code
    Recover {
        code: String,
    },
    /// Make a new recovery code
    NewRecoveryCode,
    /// End a device; the others keep working with a new key
    Remove {
        device: String,
    },
    /// Start a new key for exactly these devices
    KeepOnly {
        devices: Vec<String>,
    },
    /// Choose the computer that does scheduled work
    Main {
        device: Option<String>,
    },
    /// The lease for scheduled work
    Lease {
        #[arg(value_enum, default_value = "holder")]
        action: LeaseAction,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum LeaseAction {
    Hold,
    Drop,
    Holder,
}

#[derive(Subcommand)]
enum SettingsCmd {
    List,
    Get {
        key: String,
    },
    Set {
        key: String,
        value: String,
    },
    Remove {
        key: String,
    },
    /// Where settings sync stands on this device
    State,
    /// Start the sync on the sync account again
    Setup,
}

/// Microsoft sign-in lives in the apps, so this tool has no tokens to give.
struct NoTokens;

impl TokenProvider for NoTokens {
    fn access_token(&self, _: String, _: TokenResource) -> Result<String, TokenFailure> {
        Err(TokenFailure::InteractionRequired)
    }
}

struct Printer;

impl EventListener for Printer {
    fn on_event(&self, event: CoreEvent) {
        match event {
            CoreEvent::Progress {
                folder,
                done,
                total,
                per_second,
                ..
            } => eprintln!("  {folder}: {done}/{total} ({per_second:.0}/s)"),
            CoreEvent::NeedsSignIn { account_id, reason } => {
                eprintln!("  {account_id} needs a sign-in: {reason}")
            }
            CoreEvent::FolderFailed { folder, reason, .. } => {
                eprintln!("  {folder} failed: {reason}")
            }
            CoreEvent::UsesGraph { account_id } => {
                eprintln!("  {account_id} now reads its mail through Graph")
            }
            _ => {}
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if cli.version {
        println!("{}", lazymail_core::core_version());
        return ExitCode::SUCCESS;
    }
    let Some(command) = cli.command else {
        eprintln!("no command given; try --help");
        return ExitCode::from(2);
    };
    match run(cli.dir, &cli.device, command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

type Failure = Box<dyn std::error::Error>;

fn run(dir: Option<PathBuf>, device: &str, command: Command) -> Result<(), Failure> {
    let dir = match dir {
        Some(d) => d,
        None => PathBuf::from(std::env::var("HOME")?).join(".local/share/lazymail-cli"),
    };
    std::fs::create_dir_all(&dir)?;
    let key_file = dir.join("dev-wrapping.key");
    if !key_file.exists() {
        eprintln!(
            "making {}: a plain file that wraps the secrets, for Linux development only",
            key_file.display()
        );
    }
    let core = Core::new(
        dir.join("data").to_string_lossy().into_owned(),
        device.to_string(),
        Box::new(DevKey::open(key_file)?),
        Box::new(NoTokens),
    )?;
    core.set_listener(Some(Box::new(Printer)));
    match command {
        Command::Account(c) => account(&core, c),
        Command::Sync { accounts } => sync(&core, accounts),
        Command::Ls {
            account,
            folder,
            limit,
            offset,
        } => ls(&core, &account, folder, limit, offset),
        Command::Show { account, message } => show(&core, &account, message),
        Command::Search {
            account,
            words,
            from,
            folder,
            unread,
            limit,
        } => {
            let folder_id = folder
                .map(|f| find_folder(&core, &account, &f))
                .transpose()?;
            let hits = core.search(
                account,
                SearchRequest {
                    text: words.join(" "),
                    from,
                    folder_id,
                    unread,
                    limit,
                    ..SearchRequest::default()
                },
            )?;
            hits.iter().for_each(print_message);
            Ok(())
        }
        Command::Mark {
            account,
            message,
            read,
            star,
            to,
            delete,
        } => mark(&core, account, message, read, star, to, delete),
        Command::Send {
            account,
            to,
            cc,
            bcc,
            subject,
            text,
            queue_only,
        } => send(&core, account, to, cc, bcc, subject, text, queue_only),
        Command::Outbox { account, action } => outbox(&core, account, action),
        Command::Devices(c) => devices(&core, c),
        Command::Settings(c) => settings(&core, c),
    }
}

fn account(core: &Core, cmd: AccountCmd) -> Result<(), Failure> {
    match cmd {
        AccountCmd::Add(a) => {
            let password = if a.password_stdin {
                Some(read_line()?)
            } else {
                a.password
            };
            let server = match &a.imap {
                Some(imap) => {
                    let smtp = a.smtp.as_deref().ok_or("--smtp is needed with --imap")?;
                    let (imap_host, imap_port) = host_port(imap)?;
                    let (smtp_host, smtp_port) = host_port(smtp)?;
                    Some(ServerConfig {
                        imap_host,
                        imap_port,
                        imap_security: a.imap_security.into(),
                        smtp_host,
                        smtp_port,
                        smtp_security: a.smtp_security.into(),
                        login_is_local_part: a.local_part_login,
                    })
                }
                None => None,
            };
            let pinned_certificate = a.pin_certificate.map(|p| pem_to_der(&p)).transpose()?;
            let added = core.add_account(AccountSetup {
                name: a.name.unwrap_or_else(|| a.address.clone()),
                address: a.address,
                provider: a.provider.map(Into::into),
                password,
                server,
                pinned_certificate,
                use_graph: a.graph,
            })?;
            println!("{}", added.account.id);
            match added.settings {
                Some(SettingsSetup::Created { recovery_code }) => {
                    println!("recovery code (print it, it is shown once): {recovery_code}")
                }
                Some(SettingsSetup::MustJoin) => {
                    println!("another device uses this mailbox for settings: run `devices join`")
                }
                Some(SettingsSetup::Failed { detail }) => {
                    println!("settings sync did not start: {detail}")
                }
                None => {}
            }
        }
        AccountCmd::List => {
            for a in core.accounts() {
                let status = match a.status {
                    AccountStatus::SignedIn => "ok".to_string(),
                    AccountStatus::NeedsSignIn { reason } => format!("needs sign-in: {reason}"),
                };
                let sync = if a.is_sync_account {
                    " (sync account)"
                } else {
                    ""
                };
                println!("{}  {}  {:?}  {status}{sync}", a.id, a.address, a.mail);
            }
        }
        AccountCmd::Remove { id } => core.remove_account(id)?,
        AccountCmd::Password {
            id,
            password_stdin,
            password,
        } => {
            let p = if password_stdin {
                read_line()?
            } else {
                password.ok_or("give --password or --password-stdin")?
            };
            core.set_app_password(id, p)?;
        }
    }
    Ok(())
}

fn sync(core: &Core, accounts: Vec<String>) -> Result<(), Failure> {
    let ids = if accounts.is_empty() {
        core.accounts().into_iter().map(|a| a.id).collect()
    } else {
        accounts
    };
    for id in ids {
        match core.sync_now(id.clone()) {
            Ok(s) => println!(
                "{id}: {} added, {} changed, {} removed",
                s.added, s.changed, s.removed
            ),
            Err(e) => eprintln!("{id}: {e}"),
        }
    }
    Ok(())
}

fn find_folder(core: &Core, account: &str, name: &str) -> Result<i64, Failure> {
    let folders = core.folders(account.to_string())?;
    folders
        .iter()
        .find(|f| f.name.eq_ignore_ascii_case(name) || f.id.to_string() == name)
        .map(|f| f.id)
        .ok_or_else(|| format!("no folder {name}").into())
}

fn ls(
    core: &Core,
    account: &str,
    folder: Option<String>,
    limit: u32,
    offset: u32,
) -> Result<(), Failure> {
    match folder {
        None => {
            for f in core.folders(account.to_string())? {
                println!("{:>4}  {}  {}", f.id, f.name, f.role.unwrap_or_default());
            }
        }
        Some(name) => {
            let id = find_folder(core, account, &name)?;
            core.messages(account.to_string(), id, offset, limit)?
                .iter()
                .for_each(print_message);
        }
    }
    Ok(())
}

fn print_message(m: &MessageSummary) {
    let flags = format!(
        "{}{}",
        if m.flags.seen { ' ' } else { '*' },
        if m.flags.flagged { '!' } else { ' ' }
    );
    let from = if m.from_name.is_empty() {
        &m.from_addr
    } else {
        &m.from_name
    };
    println!(
        "{:>6} {flags} {}  {from}: {}",
        m.id,
        date(m.date),
        m.subject
    );
}

fn show(core: &Core, account: &str, message: i64) -> Result<(), Failure> {
    let m = core.message(account.to_string(), message)?;
    let s = &m.summary;
    println!("From: {} <{}>", s.from_name, s.from_addr);
    println!("To: {}", m.to);
    if !m.cc.is_empty() {
        println!("Cc: {}", m.cc);
    }
    println!("Date: {}", date(s.date));
    println!("Subject: {}", s.subject);
    for a in &m.attachments {
        println!(
            "Attachment {}: {} ({}, {} bytes)",
            a.id, a.filename, a.mime, a.size
        );
    }
    println!();
    match (&m.body_text, &m.body_html) {
        (Some(t), _) => println!("{t}"),
        (None, Some(h)) => println!("{h}"),
        (None, None) => println!("(the body has not been downloaded)"),
    }
    Ok(())
}

fn mark(
    core: &Core,
    account: String,
    message: i64,
    read: Option<bool>,
    star: Option<bool>,
    to: Option<String>,
    delete: bool,
) -> Result<(), Failure> {
    if read.is_some() || star.is_some() {
        let mut flags: FlagSet = core.message(account.clone(), message)?.summary.flags;
        flags.seen = read.unwrap_or(flags.seen);
        flags.flagged = star.unwrap_or(flags.flagged);
        core.set_flags(account.clone(), message, flags)?;
    }
    if let Some(folder) = to {
        let id = find_folder(core, &account, &folder)?;
        core.move_message(account.clone(), message, id)?;
    }
    if delete {
        core.delete_message(account, message)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn send(
    core: &Core,
    account: String,
    to: Vec<String>,
    cc: Vec<String>,
    bcc: Vec<String>,
    subject: String,
    text: Option<String>,
    queue_only: bool,
) -> Result<(), Failure> {
    let text = match text {
        Some(t) => t,
        None => {
            let mut t = String::new();
            std::io::stdin().read_to_string(&mut t)?;
            t
        }
    };
    let addresses = |v: Vec<String>| {
        v.into_iter()
            .map(|email| MailAddress { name: None, email })
            .collect()
    };
    let queued = core.send(
        account.clone(),
        OutgoingMessage {
            from: None,
            to: addresses(to),
            cc: addresses(cc),
            bcc: addresses(bcc),
            subject,
            text: Some(text),
            html: None,
            attachments: Vec::new(),
            in_reply_to: None,
            references: Vec::new(),
        },
    )?;
    println!("queued {} as {}", queued.id, queued.message_id);
    if !queue_only {
        let r = core.run_outbox(account)?;
        println!("{} sent, {} to retry, {} failed", r.sent, r.retry, r.failed);
    }
    Ok(())
}

fn outbox(core: &Core, account: String, action: Option<OutboxCmd>) -> Result<(), Failure> {
    match action {
        None => {
            for i in core.outbox(account)? {
                println!(
                    "{:>4}  {:?}  tries {}  {}  {}",
                    i.id,
                    i.status,
                    i.attempts,
                    i.message_id,
                    i.last_error.unwrap_or_default()
                );
            }
        }
        Some(OutboxCmd::Run) => {
            let r = core.run_outbox(account)?;
            println!(
                "{} sent, {} to retry, {} failed, {} copies waiting for Sent",
                r.sent, r.retry, r.failed, r.copies_pending
            );
        }
        Some(OutboxCmd::Retry { id }) => core.retry_outbox_item(account, id)?,
        Some(OutboxCmd::Remove { id }) => core.remove_outbox_item(account, id)?,
    }
    Ok(())
}

fn devices(core: &Core, cmd: DevicesCmd) -> Result<(), Failure> {
    match cmd {
        DevicesCmd::List => {
            for d in core.devices()? {
                let marks = format!(
                    "{}{}",
                    if d.is_this_device {
                        " (this device)"
                    } else {
                        ""
                    },
                    if d.is_main_computer {
                        " (main computer)"
                    } else {
                        ""
                    }
                );
                println!("{}  {}{marks}", d.id, d.name);
            }
        }
        DevicesCmd::Join => {
            core.request_join()?;
            println!("asked; run `devices offers` once another device has answered");
        }
        DevicesCmd::Offers => {
            for o in core.join_offers()? {
                println!(
                    "{}  {}  type this code on it: {}",
                    o.device_id, o.name, o.code
                );
            }
        }
        DevicesCmd::Finish { device, code } => core.finish_join(device, code)?,
        DevicesCmd::Requests => {
            for r in core.join_requests()? {
                let alike = if r.look_alike {
                    "  (another request has the same name)"
                } else {
                    ""
                };
                println!("{}  {}  {}{alike}", r.nonce, r.name, r.device_id);
            }
        }
        DevicesCmd::Offer { request } => core.offer_join(request)?,
        DevicesCmd::Code { request } => println!("{}", core.join_code(request)?),
        DevicesCmd::Approve { request, code } => core.approve_join(request, code)?,
        DevicesCmd::Deny { request } => core.deny_join(request)?,
        DevicesCmd::Recover { code } => core.recover(code)?,
        DevicesCmd::NewRecoveryCode => println!("{}", core.reissue_recovery()?),
        DevicesCmd::Remove { device } => {
            let keep = core
                .devices()?
                .into_iter()
                .filter(|d| d.id != device)
                .map(|d| d.id)
                .collect();
            println!("new recovery code: {}", core.remove_device(device, keep)?);
        }
        DevicesCmd::KeepOnly { devices } => {
            println!("new recovery code: {}", core.keep_only(devices)?)
        }
        DevicesCmd::Main { device } => {
            let device = device.filter(|d| d != "none");
            core.set_main_computer(device)?;
        }
        DevicesCmd::Lease { action } => match action {
            LeaseAction::Hold => println!(
                "{}",
                if core.hold_lease()? {
                    "held"
                } else {
                    "not held"
                }
            ),
            LeaseAction::Drop => core.drop_lease()?,
            LeaseAction::Holder => println!(
                "{}",
                core.lease_holder()?.unwrap_or_else(|| "nobody".into())
            ),
        },
    }
    Ok(())
}

fn settings(core: &Core, cmd: SettingsCmd) -> Result<(), Failure> {
    match cmd {
        SettingsCmd::List => {
            for e in core.settings()? {
                println!("{} = {}", e.key, e.value);
            }
        }
        SettingsCmd::Get { key } => match core.setting(key)? {
            Some(v) => println!("{v}"),
            None => return Err("not set".into()),
        },
        SettingsCmd::Set { key, value } => core.set_setting(key, value)?,
        SettingsCmd::Remove { key } => core.remove_setting(key)?,
        SettingsCmd::State => println!("{:?}", core.settings_state()),
        SettingsCmd::Setup => match core.setup_settings() {
            SettingsSetup::Created { recovery_code } => {
                println!("recovery code (print it, it is shown once): {recovery_code}")
            }
            SettingsSetup::MustJoin => {
                println!("another device already uses this mailbox: `devices join`")
            }
            SettingsSetup::Failed { detail } => return Err(detail.into()),
        },
    }
    Ok(())
}

fn read_line() -> Result<String, Failure> {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

fn host_port(s: &str) -> Result<(String, u16), Failure> {
    let (host, port) = s.rsplit_once(':').ok_or("expected host:port")?;
    Ok((host.to_string(), port.parse()?))
}

fn pem_to_der(path: &std::path::Path) -> Result<Vec<u8>, Failure> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let pem = std::fs::read_to_string(path)?;
    let body: String = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    Ok(STANDARD.decode(body)?)
}

/// Seconds since the epoch as "2026-11-28 14:05" in UTC.
fn date(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rest = secs.rem_euclid(86_400);
    // Civil date from a day count (Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year}-{month:02}-{day:02} {:02}:{:02}",
        rest / 3600,
        rest % 3600 / 60
    )
}

impl From<Security> for ConnectionSecurity {
    fn from(s: Security) -> Self {
        match s {
            Security::Tls => ConnectionSecurity::Tls,
            Security::Starttls => ConnectionSecurity::StartTls,
        }
    }
}

impl From<Provider> for ProviderKind {
    fn from(p: Provider) -> Self {
        match p {
            Provider::Outlook => ProviderKind::Outlook,
            Provider::Microsoft365 => ProviderKind::Microsoft365,
            Provider::Gmail => ProviderKind::Gmail,
            Provider::Icloud => ProviderKind::ICloud,
            Provider::Yahoo => ProviderKind::Yahoo,
            Provider::Aol => ProviderKind::Aol,
            Provider::Fastmail => ProviderKind::Fastmail,
            Provider::ProtonBridge => ProviderKind::ProtonBridge,
            Provider::Other => ProviderKind::Other,
            Provider::Local => ProviderKind::Local,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lazymail_core::CoreError;

    #[test]
    fn dates_read_as_utc() {
        assert_eq!(date(0), "1970-01-01 00:00");
        assert_eq!(date(1_672_740_000), "2023-01-03 10:00");
        assert_eq!(date(1_709_251_199), "2024-02-29 23:59");
    }

    #[test]
    fn a_server_is_host_and_port() {
        assert_eq!(
            host_port("mail.example.org:993").unwrap(),
            ("mail.example.org".into(), 993)
        );
        assert!(host_port("mail.example.org").is_err());
    }

    #[test]
    fn errors_from_the_core_read_as_sentences() {
        let e: Failure = CoreError::Invalid {
            detail: "bad".into(),
        }
        .into();
        assert_eq!(e.to_string(), "bad");
    }
}
