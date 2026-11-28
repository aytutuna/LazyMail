use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lazymail_store::{Flags, Folder, Store, SyncState};

use crate::conn::{uid_set, Connection};
use crate::error::Result;
use crate::parse::{self, Fetched, Layout};

const HEADER_BATCH: usize = 100;
const BODY_BATCH: usize = 25;
const FLAG_RANGE: u32 = 5000;

/// What to keep. Computers keep every body; phones keep headers for everything and bodies for
/// the last days only.
// TODO: attachments are only fetched on demand. Section 8 also wants them fetched ahead on
// computers until free space is under 10 GB or a size cap is reached, and no sync below 2 GB
// free; both need a free-space reading per platform.
#[derive(Debug, Clone, Copy, Default)]
pub struct Policy {
    pub body_days: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Headers,
    Bodies,
}

/// How far a folder's first download has come.
#[derive(Debug, Clone, PartialEq)]
pub struct Progress {
    pub folder: String,
    pub phase: Phase,
    pub done: u32,
    pub total: u32,
    pub per_second: f64,
    pub remaining: Option<Duration>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    pub added: u32,
    pub removed: u32,
    pub changed: u32,
}

impl Summary {
    pub(crate) fn add(&mut self, o: Summary) {
        self.added += o.added;
        self.removed += o.removed;
        self.changed += o.changed;
    }
}

struct Meter {
    folder: String,
    phase: Phase,
    total: u32,
    done: u32,
    start: Instant,
}

impl Meter {
    fn new(folder: &str, phase: Phase, total: usize) -> Meter {
        Meter {
            folder: folder.to_string(),
            phase,
            total: total as u32,
            done: 0,
            start: Instant::now(),
        }
    }

    fn advance(&mut self, n: usize, out: &mut (dyn FnMut(Progress) + Send)) {
        self.done += n as u32;
        let secs = self.start.elapsed().as_secs_f64();
        let per_second = if secs > 0.0 {
            self.done as f64 / secs
        } else {
            0.0
        };
        let remaining = (per_second > 0.0).then(|| {
            Duration::from_secs_f64((self.total.saturating_sub(self.done)) as f64 / per_second)
        });
        out(Progress {
            folder: self.folder.clone(),
            phase: self.phase,
            done: self.done,
            total: self.total,
            per_second,
            remaining,
        });
    }
}

fn extra_items(gmail: bool) -> &'static str {
    if gmail {
        " X-GM-MSGID X-GM-LABELS"
    } else {
        ""
    }
}

/// Brings one folder in line with the server: flag changes and expunges of messages already
/// stored, new messages (headers first, newest first), then bodies inside the policy window.
/// The folder counts as complete only when all of that finished, so an interrupted run resumes
/// from what is stored.
pub(crate) async fn sync_folder(
    conn: &mut Connection,
    store: &Mutex<Store>,
    folder: &Folder,
    policy: &Policy,
    now: i64,
    progress: &mut (dyn FnMut(Progress) + Send),
) -> Result<Summary> {
    let sel = conn.select(&folder.name).await?;
    let gmail = conn.is_gmail() && conn.caps.gmail;
    let mut summary = Summary::default();

    let mut state = store
        .lock()
        .unwrap()
        .folder(folder.id)?
        .map(|f| f.sync)
        .unwrap_or_default();
    if state.uidvalidity.is_some() && state.uidvalidity != Some(sel.validity) {
        let s = store.lock().unwrap();
        s.reset_folder(folder.id)?;
        state = SyncState::default();
    }
    if state.uidvalidity.is_none() {
        state.uidvalidity = Some(sel.validity);
        store.lock().unwrap().set_sync_state(folder.id, &state)?;
    }
    let complete = state.uidnext.is_some();

    let stored: Vec<(u32, Flags)> = store.lock().unwrap().folder_uids(folder.id)?;
    let mut known: HashMap<u32, Flags> = stored.iter().copied().collect();
    let unchanged = complete
        && sel.modseq.is_some()
        && sel.modseq == state.highestmodseq
        && sel.uidnext == state.uidnext
        && sel.exists as usize == stored.len();

    let mut server_all: Option<HashSet<u32>> = None;
    if !complete {
        server_all = Some(conn.uid_search("ALL").await?.into_iter().collect());
    }
    let mut gone: Vec<u32> = Vec::new();

    if !stored.is_empty() && !unchanged {
        let items = format!("FLAGS{}", if gmail { " X-GM-LABELS" } else { "" });
        match (conn.qresync_on, conn.caps.condstore, state.highestmodseq) {
            (true, _, Some(m)) if complete => {
                let reply = conn
                    .exec(&format!(
                        "UID FETCH 1:* ({items}) (CHANGEDSINCE {m} VANISHED)"
                    ))
                    .await?;
                summary.changed += apply_changes(store, folder.id, &mut known, &reply.fetched)?;
                gone.extend(
                    known
                        .keys()
                        .copied()
                        .filter(|u| reply.vanished.iter().any(|r| r.contains(u))),
                );
            }
            (_, true, Some(m)) if complete => {
                let reply = conn
                    .exec(&format!("UID FETCH 1:* ({items}) (CHANGEDSINCE {m})"))
                    .await?;
                summary.changed += apply_changes(store, folder.id, &mut known, &reply.fetched)?;
            }
            _ => {
                let max = stored.last().map(|(u, _)| *u).unwrap_or(0);
                let mut seen = HashSet::new();
                let mut from = 1u32;
                while from <= max {
                    let to = from.saturating_add(FLAG_RANGE - 1).min(max);
                    let reply = conn
                        .exec(&format!("UID FETCH {from}:{to} ({items})"))
                        .await?;
                    let got = reply.fetched;
                    seen.extend(got.iter().map(|f| f.uid));
                    summary.changed += apply_changes(store, folder.id, &mut known, &got)?;
                    from = to + 1;
                }
                // Anything stored that no range returned is gone from the server.
                gone.extend(stored.iter().map(|(u, _)| *u).filter(|u| !seen.contains(u)));
            }
        }
    }

    let removed = remove_uids(store, folder.id, &mut known, &gone, gmail)?;
    summary.removed += removed;

    let new_uids: Vec<u32> = match &server_all {
        Some(all) => {
            let extra: Vec<u32> = known.keys().copied().filter(|u| !all.contains(u)).collect();
            summary.removed += remove_uids(store, folder.id, &mut known, &extra, gmail)?;
            all.iter()
                .copied()
                .filter(|u| !known.contains_key(u))
                .collect()
        }
        None if unchanged => Vec::new(),
        None => {
            let max = known.keys().copied().max().unwrap_or(0);
            let found = conn.uid_search(&format!("UID {}:*", max + 1)).await?;
            let new: Vec<u32> = found.into_iter().filter(|u| *u > max).collect();
            // A count that does not add up means expunges nothing reported.
            if sel.exists as usize != known.len() + new.len() {
                let all: HashSet<u32> = conn.uid_search("ALL").await?.into_iter().collect();
                let extra: Vec<u32> = known.keys().copied().filter(|u| !all.contains(u)).collect();
                summary.removed += remove_uids(store, folder.id, &mut known, &extra, gmail)?;
            }
            new
        }
    };

    let mut pending: Vec<Pending> = Vec::new();
    if !new_uids.is_empty() {
        let mut sorted = new_uids;
        sorted.sort_unstable_by(|a, b| b.cmp(a));
        let mut meter = Meter::new(&folder.name, Phase::Headers, sorted.len());
        for chunk in sorted.chunks(HEADER_BATCH) {
            let reply = conn
                .exec(&format!(
                    "UID FETCH {} (UID FLAGS RFC822.SIZE INTERNALDATE BODY.PEEK[HEADER] BODYSTRUCTURE{})",
                    uid_set(chunk),
                    extra_items(gmail)
                ))
                .await?;
            let mut got = reply.fetched_for(chunk);
            let s = store.lock().unwrap();
            let added = s.atomic(|s| {
                let mut added = 0;
                for f in chunk.iter().filter_map(|u| got.remove(u)) {
                    if let Some(p) = insert_header(s, folder.id, &f)? {
                        pending.push(p);
                        added += 1;
                    }
                }
                Ok(added)
            })?;
            drop(s);
            summary.added += added;
            meter.advance(chunk.len(), progress);
        }
    }

    // Saved before the bodies: a body that cannot be fetched must not keep the folder from
    // looking settled, and the scan below finds the rows still missing one.
    store.lock().unwrap().set_sync_state(
        folder.id,
        &SyncState {
            uidvalidity: Some(sel.validity),
            uidnext: sel.uidnext.or(Some(1)),
            highestmodseq: sel.modseq,
            delta_link: None,
        },
    )?;

    // An earlier run may have stopped between headers and bodies, in a folder that was already
    // complete as much as in a new one, so rows without a body are looked for every time.
    let since = policy.body_days.map(|d| now - i64::from(d) * 86400);
    let have: HashSet<i64> = pending.iter().map(|p| p.id).collect();
    for (id, uid, date) in store.lock().unwrap().without_bodies(folder.id, since)? {
        if !have.contains(&id) {
            pending.push(Pending {
                id,
                uid,
                date,
                layout: None,
            });
        }
    }
    pending.retain(|p| since.is_none_or(|s| p.date >= s));
    pending.sort_unstable_by_key(|p| std::cmp::Reverse(p.uid));
    if !pending.is_empty() {
        fetch_bodies(conn, store, &folder.name, pending, progress).await?;
    }
    if let Some(since) = since {
        store.lock().unwrap().prune_bodies(since)?;
    }
    Ok(summary)
}

// Messages that share the same text parts, so one FETCH serves them all.
type Group<'a> = ((Vec<String>, Vec<String>), Vec<&'a Pending>);

struct Pending {
    id: i64,
    uid: u32,
    date: i64,
    layout: Option<Layout>,
}

/// Stores one header row; Gmail messages that are already stored (seen in another folder, or
/// moved) keep their row.
fn insert_header(
    store: &Store,
    folder_id: i64,
    f: &Fetched,
) -> lazymail_store::Result<Option<Pending>> {
    if f.header.is_none() {
        return Ok(None);
    }
    if let Some(gm) = f.gm_msgid {
        if let Some(id) = store.find_by_gm_msgid(gm)? {
            store.move_message(id, folder_id, Some(f.uid))?;
            if let Some(fl) = f.flags {
                store.set_flags(id, fl)?;
            }
            if let Some(l) = &f.labels {
                store.set_labels(id, l)?;
            }
            return Ok(None);
        }
    }
    if store.find_by_uid(folder_id, f.uid)?.is_some() {
        return Ok(None);
    }
    let m = parse::new_message(folder_id, f);
    // A message moved here without a COPYUID has a row waiting for its UID.
    if let Some(id) = m
        .message_id
        .as_deref()
        .map(|mid| store.find_unplaced(folder_id, mid))
        .transpose()?
        .flatten()
    {
        store.set_ids(id, Some(f.uid), None)?;
        store.set_flags(id, m.flags)?;
        return Ok(None);
    }
    let id = store.insert_message(&m)?;
    Ok(Some(Pending {
        id,
        uid: f.uid,
        date: m.date,
        layout: f.layout.clone(),
    }))
}

fn apply_changes(
    store: &Mutex<Store>,
    folder_id: i64,
    known: &mut HashMap<u32, Flags>,
    got: &[Fetched],
) -> Result<u32> {
    let s = store.lock().unwrap();
    let mut changed = 0;
    s.atomic(|s| {
        for f in got {
            let Some(old) = known.get(&f.uid).copied() else {
                continue;
            };
            let Some(id) = s.find_by_uid(folder_id, f.uid)? else {
                continue;
            };
            let mut touched = false;
            if let Some(fl) = f.flags {
                if fl != old {
                    s.set_flags(id, fl)?;
                    known.insert(f.uid, fl);
                    touched = true;
                }
            }
            if let Some(l) = &f.labels {
                let mut new = l.clone();
                new.sort();
                new.dedup();
                if new != s.labels(id)? {
                    s.set_labels(id, l)?;
                    touched = true;
                }
            }
            changed += touched as u32;
        }
        Ok(())
    })?;
    Ok(changed)
}

/// Takes messages the server no longer lists in this folder out of the store. A Gmail message
/// deleted or marked spam in another client leaves All Mail before it shows up in Trash or
/// Spam, so its row is kept without a UID until the other folders have been looked at
/// (`drop_unplaced`); only rows deleted here are counted.
fn remove_uids(
    store: &Mutex<Store>,
    folder_id: i64,
    known: &mut HashMap<u32, Flags>,
    uids: &[u32],
    gmail: bool,
) -> Result<u32> {
    let s = store.lock().unwrap();
    let mut n = 0;
    s.atomic(|s| {
        for u in uids {
            known.remove(u);
            let Some(id) = s.find_by_uid(folder_id, *u)? else {
                continue;
            };
            if gmail && s.message(id)?.is_some_and(|m| m.gm_msgid.is_some()) {
                s.set_ids(id, None, None)?;
            } else {
                s.delete_message(id)?;
                n += 1;
            }
        }
        Ok(())
    })?;
    Ok(n)
}

async fn fetch_bodies(
    conn: &mut Connection,
    store: &Mutex<Store>,
    folder: &str,
    mut pending: Vec<Pending>,
    progress: &mut (dyn FnMut(Progress) + Send),
) -> Result<()> {
    let mut meter = Meter::new(folder, Phase::Bodies, pending.len());

    // The layout of a message is known when its header was just fetched; otherwise ask again.
    let unknown: Vec<u32> = pending
        .iter()
        .filter(|p| p.layout.is_none())
        .map(|p| p.uid)
        .collect();
    let mut layouts: HashMap<u32, Layout> = HashMap::new();
    for chunk in unknown.chunks(200) {
        for (uid, f) in fetch_each_on_refusal(conn, chunk, "BODYSTRUCTURE").await? {
            if let Some(l) = f.layout {
                layouts.insert(uid, l);
            }
        }
    }
    for p in &mut pending {
        if p.layout.is_none() {
            p.layout = layouts.remove(&p.uid);
        }
    }

    // Messages with the same text parts can share one FETCH.
    let mut groups: Vec<Group> = Vec::new();
    for p in &pending {
        let Some(l) = &p.layout else {
            meter.advance(1, progress);
            continue;
        };
        let key = (l.plain.clone(), l.html.clone());
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, v)) => v.push(p),
            None => groups.push((key, vec![p])),
        }
    }
    for ((plain, html), members) in groups {
        let parts: Vec<&String> = plain.iter().chain(&html).collect();
        for chunk in members.chunks(BODY_BATCH) {
            let mut got: HashMap<u32, Fetched> = HashMap::new();
            if !parts.is_empty() {
                let items = parse::part_items(parts.iter().copied());
                let uids: Vec<u32> = chunk.iter().map(|p| p.uid).collect();
                got = fetch_each_on_refusal(conn, &uids, &items).await?;
            }
            let s = store.lock().unwrap();
            s.atomic(|s| {
                for p in chunk {
                    if !parts.is_empty() && !got.contains_key(&p.uid) {
                        // No data came back for it; it stays without a body for the next run.
                        continue;
                    }
                    let text = join_parts(got.get(&p.uid), &plain);
                    let page = join_parts(got.get(&p.uid), &html);
                    s.set_bodies(
                        p.id,
                        Some(&text),
                        (!html.is_empty()).then_some(page.as_str()),
                    )?;
                }
                Ok(())
            })?;
            drop(s);
            meter.advance(chunk.len(), progress);
        }
    }
    Ok(())
}

/// UID FETCH of `items`. A server that refuses the batch (Exchange cannot convert some
/// corrupt messages) is asked again one message at a time, and the ones it still refuses are
/// left out, so one message does not hold back the rest.
async fn fetch_each_on_refusal(
    conn: &mut Connection,
    uids: &[u32],
    items: &str,
) -> Result<HashMap<u32, Fetched>> {
    match conn
        .exec(&format!("UID FETCH {} ({items})", uid_set(uids)))
        .await
    {
        Ok(reply) => Ok(reply.fetched_for(uids)),
        Err(crate::Error::Refused(_)) if uids.len() > 1 => {
            let mut got = HashMap::new();
            for uid in uids {
                match conn.exec(&format!("UID FETCH {uid} ({items})")).await {
                    Ok(reply) => got.extend(reply.fetched_for(&[*uid])),
                    Err(crate::Error::Refused(_)) => {}
                    Err(e) => return Err(e),
                }
            }
            Ok(got)
        }
        Err(crate::Error::Refused(_)) => Ok(HashMap::new()),
        Err(e) => Err(e),
    }
}

fn join_parts(f: Option<&Fetched>, parts: &[String]) -> String {
    let Some(f) = f else { return String::new() };
    let mut out = String::new();
    for p in parts {
        let path = parse::part_path(p);
        let Some((mime, body)) = f.part(&path) else {
            continue;
        };
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&parse::decode_text(mime, body));
    }
    out
}

/// The decoded bytes of one part of a message, fetched on demand.
pub(crate) async fn fetch_part(
    conn: &mut Connection,
    folder: &str,
    uid: u32,
    part: &str,
) -> Result<Vec<u8>> {
    conn.select(folder).await?;
    let reply = conn
        .exec(&format!(
            "UID FETCH {uid} ({})",
            parse::part_items([&part.to_string()])
        ))
        .await?;
    let path = parse::part_path(part);
    let got = reply.fetched_for(&[uid]);
    let f = got
        .get(&uid)
        .ok_or_else(|| crate::Error::Protocol("the message is gone".into()))?;
    let Some((mime, body)) = f.part(&path) else {
        return Err(crate::Error::Protocol("the part is missing".into()));
    };
    Ok(parse::decode_bytes(mime, body))
}

/// Deletes the Gmail rows that no folder listed again after `remove_uids` let go of their UID.
pub(crate) fn drop_unplaced(store: &Mutex<Store>) -> Result<u32> {
    let s = store.lock().unwrap();
    s.atomic(|s| {
        let ids = s.unplaced_gmail()?;
        for id in &ids {
            s.delete_message(*id)?;
        }
        Ok(ids.len() as u32)
    })
    .map_err(Into::into)
}
