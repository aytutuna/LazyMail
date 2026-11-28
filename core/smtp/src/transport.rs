use std::time::Duration;

use lazymail_accounts::{
    classify_login_error, Account, AuthFailure, MailAccess, Provider, Resource, Security,
    TokenSource,
};
use lettre::address::Envelope;
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::transport::smtp::client::{Certificate, Tls, TlsParameters};
use lettre::transport::smtp::Error as SmtpError;
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use mail_parser::MessageParser;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SendError {
    /// The server refused the sign-in; the account needs attention, the mail is fine.
    Auth(AuthFailure),
    /// Network trouble, a busy server or a 4xx reply: try again later.
    Temporary(String),
    /// The server or the message itself will never work, for example a refused recipient.
    Permanent(String),
}

pub enum Auth {
    Password(String),
    /// XOAUTH2 with a token the account's `TokenSource` hands out.
    OAuth,
}

pub struct Smtp {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    provider: Provider,
}

impl Smtp {
    /// `pinned_cert` (DER) is trusted in addition to the system roots, for Proton Bridge.
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

        let mut tls = TlsParameters::builder(ep.host.clone());
        if let Some(der) = pinned_cert {
            let cert = Certificate::from_der(der.to_vec())
                .map_err(|e| SendError::Permanent(e.to_string()))?;
            tls = tls.add_root_certificate(cert);
        }
        let tls = tls
            .build()
            .map_err(|e| SendError::Permanent(e.to_string()))?;
        let tls = match ep.security {
            Security::Tls => Tls::Wrapper(tls),
            Security::StartTls => Tls::Required(tls),
        };
        let transport = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&ep.host)
            .port(ep.port)
            .tls(tls)
            .credentials(Credentials::new(user, secret))
            .authentication(mechanisms)
            .timeout(Some(Duration::from_secs(30)))
            .build();
        Ok(Smtp {
            transport,
            provider: account.provider,
        })
    }

    /// Sends a stored message. Recipients come from To, Cc and Bcc; the Bcc header does not
    /// go out.
    pub async fn send(&self, raw: &[u8]) -> Result<(), SendError> {
        let envelope = envelope(raw)?;
        self.transport
            .send_raw(&envelope, &strip_bcc(raw))
            .await
            .map(|_| ())
            .map_err(|e| self.classify(&e))
    }

    fn classify(&self, e: &SmtpError) -> SendError {
        let code = e.status().map(|c| c.to_string());
        let detail = std::error::Error::source(e).map_or_else(|| e.to_string(), |s| s.to_string());
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
