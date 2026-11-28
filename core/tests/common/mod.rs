#![allow(dead_code)]

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use lazymail_core::{
    Core, CoreEvent, DevKey, EventListener, TokenFailure, TokenProvider, TokenResource,
};
use lazymail_sync::Clock;

/// Time every device in a test agrees on, which a test moves by hand.
#[derive(Clone)]
pub struct Time(Arc<AtomicU64>);

impl Time {
    pub fn now() -> Time {
        let ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        Time(Arc::new(AtomicU64::new(ms)))
    }

    pub fn advance_secs(&self, secs: u64) {
        self.0.fetch_add(secs * 1000, Ordering::SeqCst);
    }

    pub fn clock(&self) -> Clock {
        let t = self.0.clone();
        Arc::new(move || t.load(Ordering::SeqCst))
    }
}

struct NoTokens;

impl TokenProvider for NoTokens {
    fn access_token(&self, _: String, _: TokenResource) -> Result<String, TokenFailure> {
        Err(TokenFailure::InteractionRequired)
    }
}

/// Collects what the core reports.
#[derive(Clone, Default)]
pub struct Events(pub Arc<Mutex<Vec<CoreEvent>>>);

impl EventListener for Events {
    fn on_event(&self, event: CoreEvent) {
        self.0.lock().unwrap().push(event);
    }
}

impl Events {
    pub fn taken(&self) -> Vec<CoreEvent> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

pub fn open(dir: &Path, name: &str, time: &Time) -> Core {
    let key = DevKey::open(dir.join("dev.key")).unwrap();
    std::fs::create_dir_all(dir.join("data")).unwrap();
    Core::with_clock(
        &dir.join("data"),
        name,
        Box::new(key),
        Box::new(NoTokens),
        time.clock(),
    )
    .unwrap()
}
