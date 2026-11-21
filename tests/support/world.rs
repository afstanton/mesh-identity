//! A small in-memory network of handles for the handle tests.

use ed25519_dalek::SigningKey;
use mesh_identity::groups::Policy;
use mesh_identity::groups::handle::*;
use mesh_identity::session::installation::Installation;
use rand::SeedableRng;
use rand::rngs::{OsRng, StdRng};

pub const DAY: u64 = 24 * 60 * 60 * 1000;

pub fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
pub fn pk(seed: u8) -> [u8; 32] {
    sk(seed).verifying_key().to_bytes()
}

pub fn flush(h: &mut GroupHandle) -> Vec<Event> {
    let (token, _) = h.save(10).unwrap();
    h.confirm_saved(token)
}

/// Handles by seed. `a` = 1 invites `candidate` = 9; members are 2 and 3.
pub struct World {
    pub handles: Vec<(u8, GroupHandle)>,
    pub group: u64,
    /// Events released by confirmed saves, by handle seed.
    pub events: Vec<(u8, Event)>,
}

impl World {
    pub fn new(members: &[u8]) -> Self {
        let mut rng = StdRng::seed_from_u64(7);
        let mut handles: Vec<(u8, GroupHandle)> = [&[1u8][..], members, &[9][..]]
            .concat()
            .into_iter()
            .map(|seed| (seed, GroupHandle::new(Installation::new(sk(seed)))))
            .collect();
        // The inviter and the candidate meet.
        let (left, right) = handles.split_at_mut(1);
        let candidate = right.last_mut().unwrap();
        super::meet(
            left[0].1.installation_mut(),
            candidate.1.installation_mut(),
            1,
            &mut rng,
        );
        let member_keys: Vec<[u8; 32]> = members.iter().map(|m| pk(*m)).collect();
        let a = &mut handles[0].1;
        a.create(Policy::InviterOnly, &member_keys, &mut OsRng)
            .unwrap();
        flush(a);
        let genesis = a.take_outgoing().remove(0);
        let group = a.group_ids()[0];
        let digest = genesis.authenticator.unwrap();
        for (seed, h) in handles.iter_mut().filter(|(s, _)| members.contains(s)) {
            h.import_genesis(&genesis.bytes, digest)
                .unwrap_or_else(|e| panic!("{seed}: {e:?}"));
            flush(h);
        }
        Self {
            handles,
            group,
            events: Vec::new(),
        }
    }

    pub fn h(&mut self, seed: u8) -> &mut GroupHandle {
        &mut self.handles.iter_mut().find(|(s, _)| *s == seed).unwrap().1
    }

    /// Flush every handle and deliver what it releases until nothing moves. Returns every
    /// refusal seen. `hold` lets a test keep back frames of one kind for one recipient.
    pub fn pump(
        &mut self,
        now: u64,
        hold: &mut Vec<(u8, Tag, Vec<u8>)>,
        hold_for: Option<(u8, Tag)>,
    ) -> Vec<Event> {
        let mut refused = Vec::new();
        for _ in 0..20 {
            let mut moved = false;
            for index in 0..self.handles.len() {
                let (from_seed, _) = self.handles[index];
                let released = flush(&mut self.handles[index].1);
                self.events
                    .extend(released.into_iter().map(|e| (from_seed, e)));
                for out in self.handles[index].1.take_outgoing() {
                    moved = true;
                    for to in &out.to {
                        let Some(target) = self.handles.iter().position(|(s, _)| pk(*s) == *to)
                        else {
                            continue;
                        };
                        let seed = self.handles[target].0;
                        if hold_for == Some((seed, out.kind)) {
                            hold.push((seed, out.kind, out.bytes.clone()));
                            continue;
                        }
                        refused.extend(
                            self.handles[target]
                                .1
                                .receive_bytes(out.from, &out.bytes, now),
                        );
                    }
                }
            }
            if !moved {
                break;
            }
        }
        refused
    }

    pub fn invite_and_accept(&mut self, now: u64) -> [u8; 32] {
        let group = self.group;
        self.h(1).invite(group, pk(9), DAY, now).unwrap();
        let mut none = Vec::new();
        assert!(self.pump(now, &mut none, None).is_empty());
        let invitation = self.h(9).pending_invitations()[0].0;
        self.h(9).accept(invitation, now).unwrap();
        invitation
    }
}
