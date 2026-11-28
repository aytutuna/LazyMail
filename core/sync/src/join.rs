use std::collections::{HashMap, HashSet};

use crate::crypto::{join_code, random, unwrap_key, wrap_key};
use crate::identity::{verify, DeviceId};
use crate::replica::Meta;
use crate::wire::{Approval, JoinOffer, JoinRequest, Wire};
use crate::{Error, Folder, Replica, Result};

/// A join request older than this is ignored.
const REQUEST_TTL_MS: u64 = 60 * 60 * 1000;
const MAX_TRIES: u8 = 3;

#[derive(Default)]
pub(crate) struct JoinState {
    /// Requests seen in the folder, with the id of their message.
    pub requests: HashMap<[u8; 16], (JoinRequest, String)>,
    /// New device: the nonce of its own request, and the message it wrote.
    pub pending: Option<[u8; 16]>,
    pub request_id: Option<String>,
    pub offers: Vec<JoinOffer>,
    pub approval: Option<(Approval, String)>,
    /// Approver: requests this device has offered to approve.
    offered: HashSet<[u8; 16]>,
    attempts: HashMap<[u8; 16], u8>,
}

/// A device asking to join, as shown on a device that already has the key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinRequestInfo {
    pub nonce: [u8; 16],
    pub device: DeviceId,
    pub name: String,
    pub at: u64,
}

/// A device that offered to let this one in, with the code this screen shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinOffered {
    pub device: DeviceId,
    pub name: String,
    pub code: String,
}

impl<F: Folder> Replica<F> {
    /// New device: asks the person's devices to let it in. Call `pull` until
    /// `join_offers` lists a device, show its code, then `finish_join` once
    /// that device has approved.
    pub async fn request_join(&mut self) -> Result<()> {
        if self.key.is_some() {
            return Err(Error::AlreadyJoined);
        }
        if let Some(old) = self.join.request_id.take() {
            self.folder.delete(&old).await?;
            self.seen.remove(&old);
        }
        let mut req = JoinRequest {
            id: self.me.id(),
            name: self.me.name().to_string(),
            x_pub: self.me.x_pub(),
            ed_pub: self.me.ed_pub(),
            nonce: random(),
            at: (self.clock)(),
            sig: [0; 64],
        };
        req.sig = self.me.sign(&req.sig_bytes());
        let nonce = req.nonce;
        let id = self.append(&Wire::Join(req), Meta::Join).await?;
        self.join.pending = Some(nonce);
        self.join.request_id = Some(id);
        self.join.offers.clear();
        self.join.approval = None;
        Ok(())
    }

    /// New device: devices that answered, each with the code to compare.
    pub fn join_offers(&self) -> Vec<JoinOffered> {
        let Some(nonce) = self.join.pending else {
            return Vec::new();
        };
        self.join
            .offers
            .iter()
            .map(|o| JoinOffered {
                device: o.from,
                name: o.name.clone(),
                code: join_code(
                    &nonce,
                    (&self.me.x_pub(), &self.me.ed_pub()),
                    (&o.x_pub, &o.ed_pub),
                ),
            })
            .collect()
    }

    /// Requests waiting for a device that has the key.
    pub fn join_requests(&self) -> Vec<JoinRequestInfo> {
        if self.key.is_none() {
            return Vec::new();
        }
        let now = (self.clock)();
        let mut all: Vec<_> = self
            .join
            .requests
            .values()
            .filter(|(r, _)| r.id != self.me.id() && now.saturating_sub(r.at) <= REQUEST_TTL_MS)
            .map(|(r, _)| JoinRequestInfo {
                nonce: r.nonce,
                device: r.id,
                name: r.name.clone(),
                at: r.at,
            })
            .collect();
        all.sort_by_key(|r| (r.at, r.nonce));
        all
    }

    fn open_request(&self, nonce: [u8; 16]) -> Result<&(JoinRequest, String)> {
        let now = (self.clock)();
        self.join
            .requests
            .get(&nonce)
            .filter(|(r, _)| now.saturating_sub(r.at) <= REQUEST_TTL_MS)
            .ok_or(Error::UnknownRequest)
    }

    /// The code this device computes for a request, to show next to the one
    /// on the new device's screen.
    pub fn join_code(&self, nonce: [u8; 16]) -> Result<String> {
        let (r, _) = self.open_request(nonce)?;
        Ok(join_code(
            &nonce,
            (&r.x_pub, &r.ed_pub),
            (&self.me.x_pub(), &self.me.ed_pub()),
        ))
    }

    /// Lets the new device see this one and its code.
    pub async fn offer_join(&mut self, nonce: [u8; 16]) -> Result<()> {
        self.writable()?;
        self.open_request(nonce)?;
        if self.join.offered.contains(&nonce) {
            return Ok(());
        }
        let mut offer = JoinOffer {
            nonce,
            from: self.me.id(),
            name: self.me.name().to_string(),
            x_pub: self.me.x_pub(),
            ed_pub: self.me.ed_pub(),
            sig: [0; 64],
        };
        offer.sig = self.me.sign(&offer.sig_bytes());
        self.append(&Wire::Offer(offer), Meta::Offer { nonce })
            .await?;
        self.join.offered.insert(nonce);
        Ok(())
    }

    /// Gives the new device the settings key once `typed` is the code its
    /// screen shows. Three wrong codes void the request.
    pub async fn approve_join(&mut self, nonce: [u8; 16], typed: &str) -> Result<()> {
        let key = self.writable()?;
        let req = self.open_request(nonce)?.0.clone();
        if !self.join.offered.contains(&nonce) {
            return Err(Error::NoOffer);
        }
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
        let mut ids = self.offer_messages(nonce);
        if let Some((_, id)) = self.join.requests.remove(&nonce) {
            ids.push(id);
        }
        self.join.offered.remove(&nonce);
        self.join.attempts.remove(&nonce);
        self.delete_all(&ids).await
    }

    fn offer_messages(&self, nonce: [u8; 16]) -> Vec<String> {
        self.seen
            .iter()
            .filter(|(_, m)| matches!(m, Meta::Offer { nonce: n } if *n == nonce))
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// New device: takes the key from `approver`'s approval. The person has
    /// compared that device's code with the one shown here.
    pub async fn finish_join(&mut self, approver: DeviceId) -> Result<()> {
        let nonce = self.join.pending.ok_or(Error::UnknownRequest)?;
        let offer = self
            .join
            .offers
            .iter()
            .find(|o| o.from == approver)
            .ok_or(Error::NoOffer)?;
        let (approval, approval_id) = match &self.join.approval {
            Some((a, id)) if a.from == approver => (a.clone(), id.clone()),
            _ => return Err(Error::NoApproval),
        };
        if approval.to != self.me.id()
            || approval.wrap.to != self.me.id()
            || !verify(&offer.ed_pub, &approval.sig_bytes(), &approval.sig)
        {
            return Err(Error::Corrupt);
        }
        let key = unwrap_key(&self.me, &approval.wrap)?;
        let epoch = key.epoch;
        self.set_key(key);
        self.pull().await?;
        // A key that opens nothing in the folder did not come from a real member.
        if self
            .seen
            .values()
            .any(|m| matches!(m, Meta::Foreign { epoch: e, .. } if *e == epoch))
        {
            self.key = None;
            self.seen.clear();
            return Err(Error::Corrupt);
        }
        let mut ids = self.offer_messages(nonce);
        ids.extend(self.join.request_id.take());
        ids.push(approval_id);
        self.join = JoinState::default();
        self.delete_all(&ids).await?;
        self.publish_device().await
    }
}
