use lazymail_testserver::{ReplayServer, Step, Transcript};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::PathBuf;

fn transcripts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/imap")
}

// Plays the client side of a transcript against the server.
fn drive(t: &Transcript) -> Result<(), String> {
    let server = ReplayServer::start(t.clone()).unwrap();
    let stream = TcpStream::connect(server.addr()).unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut out = stream;
    let mut n = 0;
    for step in &t.steps {
        match step {
            Step::Client(line) => {
                if line.contains("<tag>") {
                    n += 1;
                }
                let tag = format!("a{n}");
                let line = line.replace("<tag>", &tag);
                if out.write_all(format!("{line}\r\n").as_bytes()).is_err() {
                    break;
                }
            }
            Step::Server(line) => {
                let mut got = String::new();
                if reader.read_line(&mut got).unwrap() == 0 {
                    break;
                }
                let want = line.replace("<tag>", &format!("a{n}"));
                assert_eq!(got.trim_end(), want);
            }
        }
    }
    drop(out);
    server.finish()
}

#[test]
fn every_shipped_transcript_plays() {
    let mut seen = 0;
    for entry in std::fs::read_dir(transcripts_dir()).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.lines().next().unwrap().contains("not recorded"),
            "{} lacks the provenance note",
            path.display()
        );
        let t = Transcript::load(&path).unwrap();
        drive(&t).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        seen += 1;
    }
    assert!(seen >= 4);
}

#[test]
fn wrong_client_line_is_reported() {
    let t = Transcript::parse("S: * OK hi\nC: <tag> NOOP\nS: <tag> OK done\n").unwrap();
    let server = ReplayServer::start(t).unwrap();
    let stream = TcpStream::connect(server.addr()).unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut greeting = String::new();
    reader.read_line(&mut greeting).unwrap();
    (&stream).write_all(b"a1 CHECK\r\n").unwrap();
    let err = server.finish().unwrap_err();
    assert!(err.contains("expected '<tag> NOOP'"), "{err}");
}

#[test]
fn early_close_is_reported() {
    let t = Transcript::parse("S: * OK hi\nC: <tag> NOOP\n").unwrap();
    let server = ReplayServer::start(t).unwrap();
    drop(TcpStream::connect(server.addr()).unwrap());
    assert!(server.finish().is_err());
}

#[test]
fn bad_line_is_a_parse_error() {
    assert!(Transcript::parse("X: nope\n").is_err());
}
