use std::time::Duration;

use lazymail_accounts::{
    classify_login_error, Account, AuthFailure, MailAccess, Provider, Resource, Security,
    TokenSource,
};
use lettre::address::Envelope;
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::transport::smtp::client::{AsyncSmtpConnection, TlsParameters};
use lettre::transport::smtp::extension::ClientId;
use lettre::transport::smtp::Error as SmtpError;
use mail_parser::MessageParser;
use tokio::time::timeout;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
const SEND_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SendError {
    /// The server refused the sign-in; the account needs attention, the mail is fine.
    Auth(AuthFailure),
    /// The server answered with a 4xx reply, so it did not take the mail: try again later.
    Temporary(String),
    /// The server or the message itself will never work, for example a refused recipient.
    Permanent(String),
    /// No usable connection: the server could not be reached, the encryption failed or the
    /// certificate is not the confirmed one. Nothing was sent, and the rest of the queue
    /// would fail the same way.
    Offline(String),
    /// The connection broke after the server may have taken the mail. It may have been sent.
    Unsure(String),
}

pub enum Auth {
    Password(String),
    /// XOAUTH2 with a token the account's `TokenSource` hands out.
    OAuth,
}

pub struct Smtp {
    host: String,
    port: u16,
    security: Security,
    credentials: Credentials,
    mechanisms: Vec<Mechanism>,
    pin: Option<Vec<u8>>,
    provider: Provider,
    conn: Option<AsyncSmtpConnection>,
}

impl Smtp {
    /// With `pinned_cert` (DER) the server's certificate must be exactly that one and the usual
    /// chain and name checks are skipped, for Proton Bridge's own certificate. Credentials are
    /// only sent once it matched. The connection is made by the first `send` and kept for the
    /// next ones.
    pub async fn new<T: TokenSource>(
        account: &Account,
        auth: &Auth,
        tokens: &T,
        pinned_cert: Option<&[u8]>,
    ) -> Result<Smtp, SendError> {
        let settings = match (&account.settings, account.mail) {
            (Some(s), MailAccess::Imap) => s,
            _ => {
                return Err(SendError::Permanent(
                    "the account has no SMTP server".into(),
                ))
            }
        };
        let ep = &settings.smtp;
        let user = ep.login.resolve(&account.address);

        let (secret, mechanisms) = match auth {
            Auth::Password(p) => (p.clone(), vec![Mechanism::Plain, Mechanism::Login]),
            Auth::OAuth => {
                let token = tokens
                    .access_token(&account.id, Resource::Mail)
                    .await
                    .map_err(|e| match AuthFailure::from_token_error(&e) {
                        Some(f) => SendError::Auth(f),
                        None => SendError::Temporary(e.to_string()),
                    })?;
                (token, vec![Mechanism::Xoauth2])
            }
        };
        Ok(Smtp {
            host: ep.host.clone(),
            port: ep.port,
            security: ep.security,
            credentials: Credentials::new(user, secret),
            mechanisms,
            pin: pinned_cert.map(<[u8]>::to_vec),
            provider: account.provider,
            conn: None,
        })
    }

    /// Sends a stored message. Recipients come from To, Cc and Bcc; the Bcc header does not
    /// go out.
    pub async fn send(&mut self, raw: &[u8]) -> Result<(), SendError> {
        let envelope = envelope(raw)?;
        let body = strip_bcc(raw);
        let mut kept = self.conn.take();
        // A connection the server dropped while idle would fail the send after the message
        // was written, which looks like an unsure outcome, so it is tried first.
        if let Some(c) = kept.as_mut() {
            if c.has_broken() || !c.test_connected().await {
                kept = None;
            }
        }
        let mut conn = match kept {
            Some(c) => c,
            None => timeout(CONNECT_TIMEOUT, self.connect())
                .await
                .unwrap_or_else(|_| Err(SendError::Offline("timed out connecting".into())))?,
        };
        let sent = match timeout(SEND_TIMEOUT, conn.send(&envelope, &body)).await {
            Ok(r) => r.map_err(|e| self.send_error(&e)),
            Err(_) => Err(SendError::Unsure("timed out waiting for the server".into())),
        };
        match sent {
            Ok(_) => {
                self.conn = Some(conn);
                Ok(())
            }
            Err(e) => {
                conn.abort().await;
                Err(e)
            }
        }
    }

    pub async fn close(&mut self) {
        if let Some(mut c) = self.conn.take() {
            let _ = c.quit().await;
        }
    }

    async fn connect(&self) -> Result<AsyncSmtpConnection, SendError> {
        let mut tls = TlsParameters::builder(self.host.clone());
        if self.pin.is_some() {
            tls = tls
                .dangerous_accept_invalid_certs(true)
                .dangerous_accept_invalid_hostnames(true);
        }
        let tls = tls.build().map_err(|e| SendError::Offline(e.to_string()))?;
        let hello = ClientId::default();
        let addr = (self.host.as_str(), self.port);
        let offline = |e: SmtpError| SendError::Offline(detail(&e));

        let mut conn = match self.security {
            Security::Tls => AsyncSmtpConnection::connect_tokio1(
                addr,
                Some(CONNECT_TIMEOUT),
                &hello,
                Some(tls),
                None,
            )
            .await
            .map_err(offline)?,
            Security::StartTls => {
                let mut c = AsyncSmtpConnection::connect_tokio1(
                    addr,
                    Some(CONNECT_TIMEOUT),
                    &hello,
                    None,
                    None,
                )
                .await
                .map_err(offline)?;
                if !c.can_starttls() {
                    c.abort().await;
                    return Err(SendError::Offline(
                        "the server does not offer STARTTLS".into(),
                    ));
                }
                c.starttls(tls, &hello).await.map_err(offline)?;
                c
            }
        };

        if let Some(pin) = &self.pin {
            if conn.peer_certificate().ok().as_ref() != Some(pin) {
                conn.abort().await;
                return Err(SendError::Offline(
                    "the server's certificate is not the one you confirmed".into(),
                ));
            }
        }
        if let Err(e) = conn.auth(&self.mechanisms, &self.credentials).await {
            conn.abort().await;
            return Err(match self.reply_error(&e) {
                SendError::Temporary(t) | SendError::Permanent(t) => SendError::Offline(t),
                other => other,
            });
        }
        Ok(conn)
    }

    /// An error from the conversation itself. A reply means the server did not take the mail;
    /// anything else (a broken connection, a garbled or missing answer) comes after the
    /// message was handed over, so it may have been taken.
    fn send_error(&self, e: &SmtpError) -> SendError {
        if e.is_transient() || e.is_permanent() {
            self.reply_error(e)
        } else if e.is_client() {
            SendError::Permanent(detail(e))
        } else {
            SendError::Unsure(detail(e))
        }
    }

    fn reply_error(&self, e: &SmtpError) -> SendError {
        let code = e.status().map(|c| c.to_string());
        let detail = detail(e);
        let text = match &code {
            Some(c) => format!("{c} {detail}"),
            None => detail,
        };
        let auth_reply = matches!(code.as_deref(), Some("530" | "534" | "535" | "538"))
            || ["5.7.30", "5.7.139"].iter().any(|s| text.contains(s));
        if auth_reply {
            return match classify_login_error(self.provider, &text, true) {
                Some(f) => SendError::Auth(f),
                None => SendError::Temporary(text),
            };
        }
        if e.is_permanent() {
            SendError::Permanent(text)
        } else {
            SendError::Temporary(text)
        }
    }
}

fn detail(e: &SmtpError) -> String {
    std::error::Error::source(e).map_or_else(|| e.to_string(), |s| s.to_string())
}

fn envelope(raw: &[u8]) -> Result<Envelope, SendError> {
    let bad = |what: &str| SendError::Permanent(format!("bad message: {what}"));
    let msg = MessageParser::default()
        .parse(raw)
        .ok_or_else(|| bad("unreadable"))?;
    let from = msg
        .sender()
        .or_else(|| msg.from())
        .and_then(|a| a.first())
        .and_then(|a| a.address())
        .ok_or_else(|| bad("no sender"))?;
    let mut to = Vec::new();
    for list in [msg.to(), msg.cc(), msg.bcc()].into_iter().flatten() {
        for mb in list.mailboxes() {
            let addr = mb
                .address()
                .ok_or_else(|| bad("recipient without address"))?;
            to.push(addr.parse().map_err(|_| bad("recipient address"))?);
        }
    }
    Envelope::new(Some(from.parse().map_err(|_| bad("sender address"))?), to)
        .map_err(|e| bad(&e.to_string()))
}

/// Drops the Bcc header, folded lines included, from the header block.
fn strip_bcc(raw: &[u8]) -> Vec<u8> {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(raw.len(), |p| p + 2);
    let mut out = Vec::with_capacity(raw.len());
    let mut skipping = false;
    for line in raw[..end].split_inclusive(|&b| b == b'\n') {
        let folded = line.first().is_some_and(|b| *b == b' ' || *b == b'\t');
        if !folded {
            skipping = line.len() >= 4 && line[..4].eq_ignore_ascii_case(b"bcc:");
        }
        if !skipping {
            out.extend_from_slice(line);
        }
    }
    out.extend_from_slice(&raw[end..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_bcc_removes_folded_header_only_from_the_headers() {
        let raw =
            b"From: a@x.test\r\nBcc: b@x.test,\r\n c@x.test\r\nSubject: s\r\n\r\nBcc: not a header\r\n";
        assert_eq!(
            strip_bcc(raw),
            b"From: a@x.test\r\nSubject: s\r\n\r\nBcc: not a header\r\n"
        );
    }

    #[test]
    fn envelope_has_every_recipient_and_the_sender() {
        let raw = b"From: Ann <ann@x.test>\r\nTo: Bob <bob@x.test>, carl@x.test\r\nCc: d@x.test\r\nBcc: e@x.test\r\nSubject: s\r\n\r\nhi\r\n";
        let e = envelope(raw).unwrap();
        assert_eq!(e.from().unwrap().to_string(), "ann@x.test");
        let to: Vec<String> = e.to().iter().map(|a| a.to_string()).collect();
        assert_eq!(to, ["bob@x.test", "carl@x.test", "d@x.test", "e@x.test"]);
    }

    #[test]
    fn a_message_without_recipients_is_permanent() {
        let e = envelope(b"From: a@x.test\r\nSubject: s\r\n\r\nhi\r\n").unwrap_err();
        assert!(matches!(e, SendError::Permanent(_)));
    }
}
