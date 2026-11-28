use lazymail_store::NewAttachment;
use mail_parser::{MessageParser, MimeHeaders};

pub struct Parsed {
    pub references: Vec<String>,
    pub in_reply_to: Option<String>,
    pub headers: String,
    pub text: Option<String>,
    pub html: Option<String>,
    /// `part` is the attachment's position in the message's attachment list; the bytes are in
    /// `attachment_data`, one entry each, since the whole message was downloaded anyway.
    pub attachments: Vec<NewAttachment>,
    pub attachment_data: Vec<Vec<u8>>,
}

pub fn parse(raw: &[u8]) -> Option<Parsed> {
    let msg = MessageParser::default().parse(raw)?;
    let references = match msg.references().as_text_list() {
        Some(list) => list.iter().map(|r| r.to_string()).collect(),
        None => msg
            .references()
            .as_text()
            .map(|r| vec![r.to_string()])
            .unwrap_or_default(),
    };
    let attachments = msg
        .attachments()
        .enumerate()
        .map(|(i, p)| NewAttachment {
            filename: p.attachment_name().unwrap_or("attachment").to_string(),
            mime: p
                .content_type()
                .map(|c| format!("{}/{}", c.ctype(), c.subtype().unwrap_or("octet-stream")))
                .unwrap_or_else(|| "application/octet-stream".into()),
            size: p.len() as u32,
            content_id: p
                .content_id()
                .map(|c| c.trim_matches(['<', '>']).to_string()),
            inline: p
                .content_disposition()
                .is_some_and(|d| d.ctype().eq_ignore_ascii_case("inline")),
            part: i.to_string(),
        })
        .collect();
    let attachment_data = msg.attachments().map(|p| p.contents().to_vec()).collect();
    let text = msg
        .text_bodies()
        .find(|p| !p.is_text_html())
        .and_then(|p| p.text_contents())
        .map(str::to_string);
    let html = msg
        .html_bodies()
        .find(|p| p.is_text_html())
        .and_then(|p| p.text_contents())
        .map(str::to_string);
    Some(Parsed {
        references,
        in_reply_to: msg.in_reply_to().as_text().map(str::to_string),
        headers: header_block(raw),
        text,
        html,
        attachments,
        attachment_data,
    })
}

fn header_block(raw: &[u8]) -> String {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 2)
        .or_else(|| raw.windows(2).position(|w| w == b"\n\n").map(|i| i + 1))
        .unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}
