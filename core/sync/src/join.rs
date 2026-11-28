use std::collections::HashMap;

use crate::crypto::{commit_to, join_code, random, unwrap_key, wrap_key};
use crate::identity::{verify, DeviceId};
use crate::replica::Meta;
use crate::wire::{Approval, JoinOffer, JoinRequest, JoinReveal, Wire};
use crate::{Error, Folder, Replica, Result};

/// A join request is shown for this long after this device first read it.
const REQUEST_TTL_MS: u64 = 60 * 60 * 1000;
const MAX_TRIES: u8 = 3;
/// What a device keeps of other people's join messages, so a flood in the
/// mailbox cannot grow it without end.
const MAX_OFFERS: usize = 16;
const MAX_APPROVALS: usize = 32;
const MAX_REVEALS: usize = 64;

/// The new device's side of one request.
pub(crate) struct Pending {
    pub nonce: [u8; 16],
    /// Kept until an offer arrives, then published. Its hash is in the request.
    pub secret: [u8; 16],
    pub commit: [u8; 32],
    pub revealed: Option<String>,
    pub wrong: u8,
    pub request_id: String,
}

pub(crate) struct Seen {
    pub request: JoinRequest,
    pub id: String,
    pub first_seen: u64,
}

#[derive(Default)]
pub(crate) struct JoinState {
    /// Requests seen in the folder.
    pub requests: HashMap<[u8; 16], Seen>,
    pub pending: Option<Pending>,
    pub offers: Vec<JoinOffer>,
    pub approvals: Vec<(Approval, String)>,
    /// Secrets other devices published for a request. Checked against the
    /// request's commitment where they are used.
    pub reveals: Vec<(JoinReveal, String)>,
    /// Approver: requests this device has offered to approve, with the
    /// random value it put in the offer.
    offered: HashMap<[u8; 16], [u8; 16]>,
    attempts: HashMap<[u8; 16], u8>,
}

/// A device asking to join, as shown on a device that already has the key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinRequestInfo {
    pub nonce: [u8; 16],
    pub device: DeviceId,
    pub name: String,
    pub at: u64,
    /// Another request waiting now has the same name. Look-alikes are how
    /// someone with access to the mailbox would try to be picked.
    pub look_alike: bool,
}

/// A device that offered to let this one in, with the code to compare with
/// the one that device shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinOffered {
    pub device: DeviceId,
    pub name: String,
    pub code: String,
}

impl<F: Folder> Replica<F> {
    pub(crate) fn ingest_join(&mut self, id: String, wire: Wire) {
        let now = (self.clock)();
        let meta = match wire {
            Wire::Join(r) => {
                if r.valid() {
                    self.join.requests.entry(r.nonce).or_insert(Seen {
                        request: r,
                        id: id.clone(),
                        first_seen: now,
                    });
                }
                Meta::Join
            }
            Wire::Offer(o) => {
                let nonce = o.nonce;
                if o.valid() {
                    if o.from == self.me.id() {
                        self.join.offered.insert(o.nonce, o.anonce);
                    } else if self.join.offers.len() < MAX_OFFERS
                        && self
                            .join
                            .pending
                            .as_ref()
                            .is_some_and(|p| p.nonce == o.nonce && p.commit == o.commit)
                        && !self.join.offers.iter().any(|x| x.from == o.from)
                    {
                        self.join.offers.push(o);
                    }
                }
                Meta::Offer { nonce }
            }
            Wire::Approval(a) => {
                let mine = self.join.pending.as_ref().map(|p| p.nonce) == Some(a.nonce)
                    && a.to == self.me.id();
                if mine
                    && self.join.approvals.len() < MAX_APPROVALS
                    && !self.join.approvals.iter().any(|(_, i)| *i == id)
                {
                    self.join.approvals.push((a, id.clone()));
                }
                Meta::Approval
            }
            Wire::Reveal(r) => {
                let nonce = r.nonce;
                if self.join.reveals.len() < MAX_REVEALS
                    && !self.join.reveals.iter().any(|(_, i)| *i == id)
                {
                    self.join.reveals.push((r, id.clone()));
                }
                Meta::Reveal { nonce }
            }
            _ => unreachable!("only join messages come here"),
        };
        self.seen.insert(id, meta);
    }

    /// New device: asks the person's devices to let it in. Call `pull` until
    /// `join_offers` lists a device, then `finish_join` with the code that
    /// device shows, once it has approved.
    pub async fn request_join(&mut self) -> Result<()> {
        if self.key.is_some() {
            return Err(Error::AlreadyJoined);
        }
        if let Some(old) = self.join.pending.take() {
            self.folder.delete(&old.request_id).await?;
            self.seen.remove(&old.request_id);
        }
        let secret: [u8; 16] = random();
        let commit = commit_to(&secret);
        let mut req = JoinRequest {
            id: self.me.id(),
            name: self.me.name().to_string(),
            x_pub: self.me.x_pub(),
            ed_pub: self.me.ed_pub(),
            nonce: random(),
            commit,
            at: (self.clock)(),
            sig: [0; 64],
        };
        req.sig = self.me.sign(&req.sig_bytes());
        let nonce = req.nonce;
        let request_id = self.append(&Wire::Join(req), Meta::Join).await?;
        self.join.offers.clear();
        self.join.approvals.clear();
        self.join.pending = Some(Pending {
            nonce,
            secret,
            commit,
            revealed: None,
            wrong: 0,
            request_id,
        });
        Ok(())
    }

    /// Publishes the secret behind the request's commitment once a device has
    /// offered. Before that nobody could have chosen a value to match it.
    pub(crate) async fn reveal_to_offers(&mut self) -> Result<()> {
        let Some(p) = &self.join.pending else {
            return Ok(());
        };
        if p.revealed.is_some() || self.join.offers.is_empty() {
            return Ok(());
        }
        let reveal = JoinReveal {
            nonce: p.nonce,
            secret: p.secret,
        };
        let nonce = p.nonce;
        let id = self
            .append(&Wire::Reveal(reveal), Meta::Reveal { nonce })
            .await?;
        if let Some(p) = &mut self.join.pending {
            p.revealed = Some(id);
        }
        Ok(())
    }

    fn offer_code(&self, p: &Pending, o: &JoinOffer) -> String {
        join_code(
            &p.secret,
            &o.anonce,
            &p.nonce,
            (&self.me.x_pub(), &self.me.ed_pub()),
            (&o.x_pub, &o.ed_pub),
        )
    }

    /// New device: devices that answered, each with the code that device
    /// shows on its own screen.
    pub fn join_offers(&self) -> Vec<JoinOffered> {
        let Some(p) = &self.join.pending else {
            return Vec::new();
        };
        self.join
            .offers
            .iter()
            .map(|o| JoinOffered {
                device: o.from,
                name: o.name.clone(),
                code: self.offer_code(p, o),
            })
            .collect()
    }

    /// Requests waiting for a device that has the key.
    pub fn join_requests(&self) -> Vec<JoinRequestInfo> {
        if self.key.is_none() {
            return Vec::new();
        }
        let now = (self.clock)();
        let live: Vec<&JoinRequest> = self
            .join
            .requests
            .values()
            .filter(|s| {
                s.request.id != self.me.id() && now.saturating_sub(s.first_seen) <= REQUEST_TTL_MS
            })
            .map(|s| &s.request)
            .collect();
        let mut all: Vec<_> = live
            .iter()
            .map(|r| JoinRequestInfo {
                nonce: r.nonce,
                device: r.id,
                name: r.name.clone(),
                at: r.at,
                look_alike: live
                    .iter()
                    .any(|o| o.nonce != r.nonce && o.name.eq_ignore_ascii_case(&r.name)),
            })
            .collect();
        all.sort_by_key(|r| (r.at, r.nonce));
        all
    }

    fn open_request(&self, nonce: [u8; 16]) -> Result<&JoinRequest> {
        let now = (self.clock)();
        self.join
            .requests
            .get(&nonce)
            .filter(|s| now.saturating_sub(s.first_seen) <= REQUEST_TTL_MS)
            .map(|s| &s.request)
            .ok_or(Error::UnknownRequest)
    }

    /// The code this device shows for a request, to be compared with the
    /// list on the new device. It exists only once the new device has
    /// answered this device's offer.
    pub fn join_code(&self, nonce: [u8; 16]) -> Result<String> {
        let r = self.open_request(nonce)?;
        let anonce = self.join.offered.get(&nonce).ok_or(Error::NoOffer)?;
        let secret = self
            .join
            .reveals
            .iter()
            .find(|(v, _)| v.nonce == nonce && commit_to(&v.secret) == r.commit)
            .map(|(v, _)| v.secret)
            .ok_or(Error::NotRevealed)?;
        Ok(join_code(
            &secret,
            anonce,
            &nonce,
            (&r.x_pub, &r.ed_pub),
            (&self.me.x_pub(), &self.me.ed_pub()),
        ))
    }

    /// Lets the new device see this one and its code.
    pub async fn offer_join(&mut self, nonce: [u8; 16]) -> Result<()> {
        self.writable()?;
        let commit = self.open_request(nonce)?.commit;
        if self.join.offered.contains_key(&nonce) {
            return Ok(());
        }
        let mut offer = JoinOffer {
            nonce,
            commit,
            anonce: random(),
            from: self.me.id(),
            name: self.me.name().to_string(),
            x_pub: self.me.x_pub(),
            ed_pub: self.me.ed_pub(),
            sig: [0; 64],
        };
        offer.sig = self.me.sign(&offer.sig_bytes());
        let anonce = offer.anonce;
        self.append(&Wire::Offer(offer), Meta::Offer { nonce })
            .await?;
        self.join.offered.insert(nonce, anonce);
        Ok(())
    }

    /// Gives the new device the settings key once `typed` is the code its
    /// screen shows. Three wrong codes void the request.
    pub async fn approve_join(&mut self, nonce: [u8; 16], typed: &str) -> Result<()> {
        let key = self.writable()?;
        let req = self.open_request(nonce)?.clone();
        let anonce = *self.join.offered.get(&nonce).ok_or(Error::NoOffer)?;
        if typed.trim() != self.join_code(nonce)? {
            let tries = self.join.attempts.entry(nonce).or_default();
            *tries += 1;
            if *tries >= MAX_TRIES {
                self.void_request(nonce).await?;
                return Err(Error::TooManyAttempts);
            }
            return Err(Error::WrongCode);
        }
        let mut approval = Approval {
            nonce,
            commit: req.commit,
            anonce,
            to: req.id,
            from: self.me.id(),
            wrap: wrap_key(req.id, &req.x_pub, &key),
            sig: [0; 64],
        };
        approval.sig = self.me.sign(&approval.sig_bytes());
        self.append(&Wire::Approval(approval), Meta::Approval)
            .await?;
        self.void_request(nonce).await
    }

    /// Turns a request down.
    pub async fn deny_join(&mut self, nonce: [u8; 16]) -> Result<()> {
        self.open_request(nonce)?;
        self.void_request(nonce).await
    }

    async fn void_request(&mut self, nonce: [u8; 16]) -> Result<()> {
        let mut ids = self.join_messages(nonce);
        if let Some(s) = self.join.requests.remove(&nonce) {
            ids.push(s.id);
        }
        self.join.offered.remove(&nonce);
        self.join.attempts.remove(&nonce);
        self.join.reveals.retain(|(r, _)| r.nonce != nonce);
        self.delete_all(&ids).await
    }

    /// The offers and the revealed secret written for a request.
    fn join_messages(&self, nonce: [u8; 16]) -> Vec<String> {
        self.seen
            .iter()
            .filter(|(_, m)| {
                matches!(m, Meta::Offer { nonce: n } | Meta::Reveal { nonce: n } if *n == nonce)
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// New device: takes the key from `approver`'s approval. `shown` is the
    /// code that device shows on its own screen; it has to match the one this
    /// device computed for that device's offer, and for no other offer.
    pub async fn finish_join(&mut self, approver: DeviceId, shown: &str) -> Result<()> {
        let p = self.join.pending.as_ref().ok_or(Error::UnknownRequest)?;
        let offer = self
            .join
            .offers
            .iter()
            .find(|o| o.from == approver)
            .ok_or(Error::NoOffer)?
            .clone();
        let codes: Vec<(DeviceId, String)> = self
            .join
            .offers
            .iter()
            .map(|o| (o.from, self.offer_code(p, o)))
            .collect();
        let shown = shown.trim();
        let matching: Vec<DeviceId> = codes
            .iter()
            .filter(|(_, c)| c == shown)
            .map(|(d, _)| *d)
            .collect();
        if matching.len() > 1 {
            return Err(Error::AmbiguousCode);
        }
        if matching != [approver] {
            let p = self.join.pending.as_mut().expect("checked above");
            p.wrong += 1;
            if p.wrong >= MAX_TRIES {
                self.cancel_join().await?;
                return Err(Error::TooManyAttempts);
            }
            return Err(Error::WrongCode);
        }
        let p = self.join.pending.as_ref().expect("checked above");
        let (approval, approval_id) = self
            .join
            .approvals
            .iter()
            .find(|(a, _)| {
                a.from == approver
                    && a.nonce == p.nonce
                    && a.commit == p.commit
                    && a.anonce == offer.anonce
                    && a.to == self.me.id()
                    && a.wrap.to == self.me.id()
                    && verify(&offer.ed_pub, &a.sig_bytes(), &a.sig)
            })
            .cloned()
            .ok_or(Error::NoApproval)?;
        let key = unwrap_key(&self.me, &approval.wrap)?;
        let epoch = key.epoch;
        self.set_key(key);
        self.pull().await?;
        // A real approver wrote its own record under this key, and nothing
        // newer is in the folder. A key someone made up has neither.
        let known = self
            .devices
            .get(&approver)
            .is_some_and(|d| d.x_pub == offer.x_pub && d.ed_pub == offer.ed_pub);
        let newer = self
            .seen
            .values()
            .any(|m| matches!(m, Meta::Foreign { epoch: e, .. } if *e > epoch));
        if !known || newer {
            self.forget_key();
            return Err(Error::UntrustedKey);
        }
        let p = self.join.pending.take().expect("checked above");
        let mut ids = self.join_messages(p.nonce);
        ids.push(p.request_id);
        ids.extend(self.join.approvals.iter().map(|(_, id)| id.clone()));
        ids.push(approval_id);
        ids.sort();
        ids.dedup();
        self.join = JoinState::default();
        self.delete_all(&ids).await?;
        self.publish_device().await
    }

    /// New device: gives up the request.
    async fn cancel_join(&mut self) -> Result<()> {
        let Some(p) = self.join.pending.take() else {
            return Ok(());
        };
        let mut ids = self.join_messages(p.nonce);
        ids.push(p.request_id);
        self.join.offers.clear();
        self.join.approvals.clear();
        self.delete_all(&ids).await
    }
}
