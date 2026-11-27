// Checks the servers from testdata/servers. Skipped unless start.sh's
// variables are set; run with `cargo test -- --include-ignored`.
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;

struct Conn {
    reader: BufReader<TcpStream>,
    out: TcpStream,
}

impl Conn {
    fn open(addr: &str) -> Conn {
        let stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        Conn {
            reader: BufReader::new(stream.try_clone().unwrap()),
            out: stream,
        }
    }

    fn line(&mut self) -> String {
        let mut s = String::new();
        let n = self.reader.read_line(&mut s).unwrap();
        assert!(n > 0, "server closed the connection");
        s.trim_end().to_string()
    }

    fn send(&mut self, s: &str) {
        self.out.write_all(s.as_bytes()).unwrap();
        self.out.write_all(b"\r\n").unwrap();
    }

    // Sends a tagged IMAP command and returns every line up to the tagged reply.
    fn imap(&mut self, tag: &str, cmd: &str) -> Vec<String> {
        self.send(&format!("{tag} {cmd}"));
        let mut lines = Vec::new();
        loop {
            let l = self.line();
            let done = l.starts_with(&format!("{tag} "));
            lines.push(l);
            if done {
                return lines;
            }
        }
    }
}

fn base64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk.iter().fold(0u32, |a, b| a << 8 | *b as u32) << (8 * (3 - chunk.len()));
        for i in 0..=chunk.len() {
            out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
        out.extend(std::iter::repeat_n('=', 3 - chunk.len()));
    }
    out
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

#[test]
#[ignore]
fn imap_login_append_fetch() {
    let (Some(addr), Some(user), Some(pass)) = (
        var("LAZYMAIL_TEST_IMAP"),
        var("LAZYMAIL_TEST_USER"),
        var("LAZYMAIL_TEST_PASS"),
    ) else {
        return;
    };
    let mut c = Conn::open(&addr);
    assert!(c.line().starts_with("* OK"));
    assert!(c.imap("a1", &format!("LOGIN {user} wrong"))[0].starts_with("a1 NO"));
    let r = c.imap("a2", &format!("LOGIN {user} {pass}"));
    assert!(r.last().unwrap().starts_with("a2 OK"), "{r:?}");
    let caps = c.imap("a3", "CAPABILITY").join(" ");
    for cap in [
        "CONDSTORE",
        "QRESYNC",
        "IDLE",
        "SPECIAL-USE",
        "MOVE",
        "UIDPLUS",
    ] {
        assert!(caps.contains(cap), "missing {cap}: {caps}");
    }

    let msg = "From: a@example.test\r\nSubject: smoke\r\n\r\nhello\r\n";
    c.send(&format!("a4 APPEND INBOX {{{}}}", msg.len()));
    assert!(c.line().starts_with('+'));
    c.send(msg);
    let r = c.line();
    assert!(r.starts_with("a4 OK") && r.contains("APPENDUID"), "{r}");

    let r = c.imap("a5", "SELECT INBOX");
    assert!(r.iter().any(|l| l.contains("EXISTS")), "{r:?}");
    c.send("a6 UID FETCH 1:* (FLAGS BODY.PEEK[])");
    let first = c.line();
    assert!(
        first.contains("FETCH") && first.contains("BODY[]"),
        "{first}"
    );
    let mut body = String::new();
    c.reader
        .by_ref()
        .take(msg.len() as u64)
        .read_to_string(&mut body)
        .unwrap();
    assert_eq!(body, msg);
    loop {
        let l = c.line();
        assert!(!l.starts_with("a6 NO") && !l.starts_with("a6 BAD"), "{l}");
        if l.starts_with("a6 OK") {
            break;
        }
    }

    let r = c
        .imap("a7", "LIST \"\" \"*\" RETURN (SPECIAL-USE)")
        .join(" ");
    assert!(r.contains(r"\Sent") && r.contains(r"\Drafts"), "{r}");
    c.imap("a8", "LOGOUT");
}

#[test]
#[ignore]
fn smtp_send_lands_in_the_sink() {
    let (Some(addr), Some(dir)) = (var("LAZYMAIL_TEST_SMTP"), var("LAZYMAIL_TEST_SMTP_DIR")) else {
        return;
    };
    let mut c = Conn::open(&addr);
    assert!(c.line().starts_with("220"));
    c.send("EHLO test");
    while c.line().starts_with("250-") {}
    let user = var("LAZYMAIL_TEST_USER").unwrap();
    let pass = var("LAZYMAIL_TEST_PASS").unwrap();
    let blob = base64(format!("\0{user}\0{pass}").as_bytes());
    c.send(&format!("AUTH PLAIN {blob}"));
    assert!(c.line().starts_with("235"));
    c.send("MAIL FROM:<alice@example.test>");
    assert!(c.line().starts_with("250"));
    c.send("RCPT TO:<bob@example.test>");
    assert!(c.line().starts_with("250"));
    c.send("DATA");
    assert!(c.line().starts_with("354"));
    c.send("Subject: sink smoke\r\n\r\nhello sink\r\n.");
    assert!(c.line().starts_with("250"));
    c.send("QUIT");

    let found = std::fs::read_dir(dir).unwrap().any(|e| {
        let text = std::fs::read_to_string(e.unwrap().path()).unwrap();
        text.contains("Subject: sink smoke")
            && text.contains("X-Sink-To: <bob@example.test>")
            && text.contains("X-Sink-Auth: yes")
            && text.contains("\r\nhello sink\r\n")
    });
    assert!(found);
}
