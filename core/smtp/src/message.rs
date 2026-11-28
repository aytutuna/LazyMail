use mail_builder::headers::address::Address as HeaderAddress;
use mail_builder::mime::MimePart;
use mail_builder::MessageBuilder;

use crate::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    pub name: Option<String>,
    pub email: String,
}

impl Address {
    pub fn new(email: &str) -> Address {
        Address {
            name: None,
            email: email.to_string(),
        }
    }

    pub fn named(name: &str, email: &str) -> Address {
        Address {
            name: Some(name.to_string()),
            email: email.to_string(),
        }
    }

    fn to_header(&self) -> HeaderAddress<'static> {
        match &self.name {
            Some(n) => HeaderAddress::from((n.clone(), self.email.clone())),
            None => HeaderAddress::from(self.email.clone()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attachment {
    pub filename: String,
    pub content_type: String,
    pub data: Vec<u8>,
}

/// An image referenced from the HTML as `cid:<cid>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InlineImage {
    pub cid: String,
    pub content_type: String,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct Draft {
    pub from: Option<Address>,
    pub to: Vec<Address>,
    pub cc: Vec<Address>,
    pub bcc: Vec<Address>,
    pub reply_to: Option<Address>,
    pub subject: String,
    pub text: Option<String>,
    pub html: Option<String>,
    pub attachments: Vec<Attachment>,
    pub inline: Vec<InlineImage>,
    /// Message-ID without angle brackets, of the mail being answered.
    pub in_reply_to: Option<String>,
    /// Message-IDs of the thread, oldest first, without angle brackets.
    pub references: Vec<String>,
    /// Message-ID without angle brackets. Scheduled mail fixes it when it is written, so the
    /// Sent folder can be searched for it before sending.
    pub message_id: Option<String>,
    /// Seconds since the epoch.
    pub date: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Built {
    /// With angle brackets, as it appears in the header and in an IMAP search.
    pub message_id: String,
    /// Includes the Bcc header; it is removed when the mail goes out.
    pub raw: Vec<u8>,
}

pub fn build(draft: &Draft) -> Result<Built, Error> {
    let from = draft.from.as_ref().ok_or(Error::Draft("no sender"))?;
    if draft.to.is_empty() && draft.cc.is_empty() && draft.bcc.is_empty() {
        return Err(Error::Draft("no recipients"));
    }
    if draft.text.is_none() && draft.html.is_none() {
        return Err(Error::Draft("no body"));
    }
    // mail-builder writes these values as they are, so a stray line break or '>' would add
    // headers or recipients.
    let addresses = [Some(from), draft.reply_to.as_ref()]
        .into_iter()
        .flatten()
        .chain(draft.to.iter().chain(&draft.cc).chain(&draft.bcc));
    for a in addresses {
        check_address(&a.email)?;
    }
    let ids = draft.in_reply_to.iter().chain(&draft.references);
    for id in ids.chain(draft.inline.iter().map(|i| &i.cid)) {
        check_id(id)?;
    }
    let id = match &draft.message_id {
        Some(id) => id.trim_matches(|c| c == '<' || c == '>').to_string(),
        None => new_message_id(&from.email)?,
    };
    check_id(&id)?;

    let mut m = MessageBuilder::new()
        .message_id(id.clone())
        .date(draft.date)
        .from(from.to_header())
        .subject(draft.subject.as_str());
    if !draft.to.is_empty() {
        m = m.to(draft.to.iter().map(Address::to_header).collect::<Vec<_>>());
    }
    if !draft.cc.is_empty() {
        m = m.cc(draft.cc.iter().map(Address::to_header).collect::<Vec<_>>());
    }
    if !draft.bcc.is_empty() {
        // mail-builder leaves Bcc out of its output; the stored copy keeps it so the
        // recipients can be read back when the mail is sent.
        let bcc = draft.bcc.iter().map(Address::to_header).collect::<Vec<_>>();
        m = m.header("Bcc", HeaderAddress::new_list(bcc));
    }
    if let Some(r) = &draft.reply_to {
        m = m.reply_to(r.to_header());
    }
    if let Some(r) = &draft.in_reply_to {
        m = m.in_reply_to(r.as_str());
    }
    if !draft.references.is_empty() {
        m = m.references(draft.references.clone());
    }
    m = m.body(body(draft));
    Ok(Built {
        message_id: format!("<{id}>"),
        raw: m
            .write_to_vec()
            .map_err(|_| Error::Draft("cannot write the message"))?,
    })
}

/// mixed[ related[ alternative[text, html], inline images ], attachments ], leaving out the
/// levels the draft does not need. mail-builder's own inline() puts images next to the
/// attachments, where mail clients do not resolve cid: links.
fn body(draft: &Draft) -> MimePart<'_> {
    let text = draft
        .text
        .as_ref()
        .map(|t| MimePart::new("text/plain", t.as_str()));
    let html = draft
        .html
        .as_ref()
        .map(|h| MimePart::new("text/html", h.as_str()));
    let mut part = match (text, html) {
        (Some(t), Some(h)) => MimePart::new("multipart/alternative", vec![t, h]),
        (Some(p), None) | (None, Some(p)) => p,
        (None, None) => unreachable!("build refuses a draft without a body"),
    };
    if !draft.inline.is_empty() {
        let mut parts = vec![part];
        for i in &draft.inline {
            parts.push(
                MimePart::new(i.content_type.as_str(), i.data.as_slice())
                    .inline()
                    .cid(i.cid.as_str()),
            );
        }
        part = MimePart::new("multipart/related", parts);
    }
    if !draft.attachments.is_empty() {
        let mut parts = vec![part];
        for a in &draft.attachments {
            parts.push(
                MimePart::new(a.content_type.as_str(), a.data.as_slice())
                    .attachment(a.filename.as_str()),
            );
        }
        part = MimePart::new("multipart/mixed", parts);
    }
    part
}

fn check_address(email: &str) -> Result<(), Error> {
    let plain = !email.contains(['<', '>', ',', ';', '"', '\r', '\n']);
    if plain && email.parse::<lettre::Address>().is_ok() {
        Ok(())
    } else {
        Err(Error::Draft("bad address"))
    }
}

fn check_id(id: &str) -> Result<(), Error> {
    let bad = |c: char| c.is_control() || c.is_whitespace() || c == '<' || c == '>';
    if id.is_empty() || id.contains(bad) {
        return Err(Error::Draft("bad message id"));
    }
    Ok(())
}

fn new_message_id(from: &str) -> Result<String, Error> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|_| Error::Draft("no randomness"))?;
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    let domain = from.rsplit_once('@').map_or("localhost", |(_, d)| d);
    Ok(format!("{hex}@{domain}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft() -> Draft {
        Draft {
            from: Some(Address::named("Ann", "ann@x.test")),
            to: vec![Address::new("bob@x.test")],
            subject: "Hello".into(),
            text: Some("plain".into()),
            date: 1_700_000_000,
            ..Draft::default()
        }
    }

    fn text(b: &Built) -> String {
        String::from_utf8(b.raw.clone()).unwrap()
    }

    #[test]
    fn plain_message_has_the_headers_and_crlf_lines() {
        let b = build(&draft()).unwrap();
        let t = text(&b);
        assert!(t.contains("From: \"Ann\" <ann@x.test>\r\n"), "{t}");
        assert!(t.contains("To: <bob@x.test>\r\n"), "{t}");
        assert!(t.contains("Subject: Hello\r\n"));
        assert!(t.contains("Date: Tue, 14 Nov 2023 22:13:20 +0000\r\n"));
        assert!(t.contains(&format!("Message-ID: {}\r\n", b.message_id)));
        assert!(b.message_id.starts_with('<') && b.message_id.ends_with("@x.test>"));
        assert!(!t.replace("\r\n", "").contains('\n'));
    }

    #[test]
    fn a_fixed_message_id_is_kept() {
        let mut d = draft();
        d.message_id = Some("fixed-1@x.test".into());
        let b = build(&d).unwrap();
        assert_eq!(b.message_id, "<fixed-1@x.test>");
        assert!(text(&b).contains("Message-ID: <fixed-1@x.test>\r\n"));
        d.message_id = Some("<fixed-1@x.test>".into());
        assert_eq!(build(&d).unwrap().message_id, "<fixed-1@x.test>");
    }

    #[test]
    fn generated_ids_differ() {
        assert_ne!(
            build(&draft()).unwrap().message_id,
            build(&draft()).unwrap().message_id
        );
    }

    #[test]
    fn threading_headers() {
        let mut d = draft();
        d.in_reply_to = Some("b@x.test".into());
        d.references = vec!["a@x.test".into(), "b@x.test".into()];
        let t = text(&build(&d).unwrap());
        assert!(t.contains("In-Reply-To: <b@x.test>\r\n"), "{t}");
        assert!(t.contains("References: <a@x.test> <b@x.test>\r\n"), "{t}");
    }

    #[test]
    fn text_and_html_make_an_alternative() {
        let mut d = draft();
        d.html = Some("<p>rich</p>".into());
        let t = text(&build(&d).unwrap());
        assert!(t.contains("multipart/alternative"), "{t}");
        assert!(t.contains("text/plain") && t.contains("text/html"));
    }

    #[test]
    fn attachments_and_inline_images() {
        let mut d = draft();
        d.html = Some("<img src=\"cid:logo\">".into());
        d.attachments.push(Attachment {
            filename: "a.pdf".into(),
            content_type: "application/pdf".into(),
            data: b"%PDF".to_vec(),
        });
        d.inline.push(InlineImage {
            cid: "logo".into(),
            content_type: "image/png".into(),
            data: vec![1, 2, 3],
        });
        let b = build(&d).unwrap();
        let t = text(&b);
        assert!(t.contains("filename=\"a.pdf\""), "{t}");
        assert!(t.contains("Content-ID: <logo>"), "{t}");
        assert!(t.contains("Content-Disposition: inline"), "{t}");
        assert_eq!(shape(&b), "mixed(related(alternative(plain,html),png),pdf)");

        d.attachments.clear();
        assert_eq!(
            shape(&build(&d).unwrap()),
            "related(alternative(plain,html),png)"
        );
        d.inline.clear();
        assert_eq!(shape(&build(&d).unwrap()), "alternative(plain,html)");
        d.html = None;
        assert_eq!(shape(&build(&d).unwrap()), "plain");
    }

    fn shape(b: &Built) -> String {
        fn walk(part: mail_parser::MessagePart) -> String {
            let name = part
                .content_type()
                .and_then(|c| c.subtype().map(String::from));
            let name = name.unwrap_or_else(|| "?".into());
            if part.is_multipart() {
                let kids: Vec<_> = part.children().map(walk).collect();
                format!("{name}({})", kids.join(","))
            } else {
                name
            }
        }
        let msg = mail_parser::MessageParser::default().parse(&b.raw).unwrap();
        walk(msg.part(0).unwrap())
    }

    #[test]
    fn non_ascii_headers_are_encoded() {
        let mut d = draft();
        d.subject = "Grüße".into();
        d.text = Some("Grüße".into());
        let t = text(&build(&d).unwrap());
        assert!(t.contains("Subject: =?utf-8?"), "{t}");
        assert!(t.is_ascii(), "{t}");
        assert!(t.contains("Content-Transfer-Encoding: "), "{t}");
    }

    #[test]
    fn bcc_is_in_the_stored_message() {
        let mut d = draft();
        d.bcc = vec![Address::new("hidden@x.test")];
        assert!(text(&build(&d).unwrap()).contains("Bcc: <hidden@x.test>"));
    }

    #[test]
    fn values_that_would_add_headers_or_recipients_are_refused() {
        let refused = |f: &dyn Fn(&mut Draft)| {
            let mut d = draft();
            f(&mut d);
            assert!(build(&d).is_err());
        };
        refused(&|d| d.message_id = Some("abc@x.test\r\nX-Evil: 1".into()));
        refused(&|d| d.message_id = Some("a b@x.test".into()));
        refused(&|d| d.in_reply_to = Some("a@x.test>\r\nX-Evil: 1".into()));
        refused(&|d| d.references = vec!["ok@x.test".into(), "<b@x.test".into()]);
        refused(&|d| {
            d.html = Some("<img src=\"cid:l\">".into());
            d.inline.push(InlineImage {
                cid: "l>\r\nX-Evil: 1".into(),
                content_type: "image/png".into(),
                data: vec![1],
            });
        });
        refused(&|d| d.to = vec![Address::new("bob@x.test>, <eve@y.test")]);
        refused(&|d| d.cc = vec![Address::new("bob@x.test\r\nBcc: eve@y.test")]);
        refused(&|d| d.bcc = vec![Address::new("\"a>,<b\"@x.test")]);
        refused(&|d| d.from = Some(Address::new("not an address")));
        refused(&|d| d.reply_to = Some(Address::new("a@x.test, b@y.test")));
    }

    #[test]
    fn incomplete_drafts_are_refused() {
        let mut d = draft();
        d.to.clear();
        assert!(build(&d).is_err());
        let mut d = draft();
        d.text = None;
        assert!(build(&d).is_err());
        let mut d = draft();
        d.from = None;
        assert!(build(&d).is_err());
    }
}
