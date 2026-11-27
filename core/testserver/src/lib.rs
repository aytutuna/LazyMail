use std::io::{self, BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Client(String),
    Server(String),
}

/// A conversation as lines: `C: ` is what the client must send, `S: ` is what
/// the server answers, `#` lines are comments. `<tag>` in a client line stands
/// for whatever tag the client chose; in a server line it is replaced by that tag.
#[derive(Debug, Clone, Default)]
pub struct Transcript {
    pub steps: Vec<Step>,
}

impl Transcript {
    pub fn parse(text: &str) -> Result<Transcript, String> {
        let mut steps = Vec::new();
        for (n, line) in text.lines().enumerate() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line == "C:" {
                steps.push(Step::Client(String::new()));
            } else if let Some(rest) = line.strip_prefix("C: ") {
                steps.push(Step::Client(rest.to_string()));
            } else if let Some(rest) = line.strip_prefix("S: ") {
                steps.push(Step::Server(rest.to_string()));
            } else {
                return Err(format!("line {}: expected 'C: ', 'S: ' or '#'", n + 1));
            }
        }
        Ok(Transcript { steps })
    }

    pub fn load(path: impl AsRef<Path>) -> io::Result<Transcript> {
        let text = std::fs::read_to_string(path)?;
        Transcript::parse(&text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

pub struct ReplayServer {
    addr: SocketAddr,
    handle: JoinHandle<Result<(), String>>,
}

impl ReplayServer {
    /// Listens on a free local port and plays the transcript to the first client.
    pub fn start(transcript: Transcript) -> io::Result<ReplayServer> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let handle = thread::spawn(move || {
            let stream = accept(&listener)?;
            play(stream, &transcript)
        });
        Ok(ReplayServer { addr, handle })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Waits for the conversation to end; an error says where the client left the script.
    pub fn finish(self) -> Result<(), String> {
        self.handle
            .join()
            .map_err(|_| "server thread panicked".to_string())?
    }
}

fn accept(listener: &TcpListener) -> Result<TcpStream, String> {
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).map_err(|e| e.to_string())?;
                return Ok(stream);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(format!("no client connected: {e}")),
        }
    }
}

fn play(stream: TcpStream, transcript: &Transcript) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    let mut out = stream;
    let mut tag = String::new();
    for step in &transcript.steps {
        match step {
            Step::Server(line) => {
                let line = line.replace("<tag>", &tag);
                out.write_all(line.as_bytes())
                    .and_then(|_| out.write_all(b"\r\n"))
                    .map_err(|e| e.to_string())?;
            }
            Step::Client(want) => {
                let mut got = String::new();
                match reader.read_line(&mut got) {
                    Ok(0) => return Err(format!("client closed before sending: {want}")),
                    Ok(_) => {}
                    Err(e) => return Err(format!("waiting for '{want}': {e}")),
                }
                let got = got.trim_end_matches(['\r', '\n']);
                match want.strip_prefix("<tag>") {
                    Some(rest) => {
                        let (t, tail) = got.split_once(' ').unwrap_or((got, ""));
                        if format!(" {tail}") != rest {
                            return Err(format!("expected '{want}', got '{got}'"));
                        }
                        tag = t.to_string();
                    }
                    None if got != want => {
                        return Err(format!("expected '{want}', got '{got}'"));
                    }
                    None => {}
                }
            }
        }
    }
    // Anything the client sends after the script has ended is a mistake.
    out.set_read_timeout(Some(Duration::from_millis(200)))
        .map_err(|e| e.to_string())?;
    let mut extra = String::new();
    match reader.read_line(&mut extra) {
        Ok(n) if n > 0 => Err(format!("client sent past the end: '{}'", extra.trim_end())),
        _ => Ok(()),
    }
}
