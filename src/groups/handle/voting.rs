//! F3b: what a member does with an admission it has seen (`step4-f0-handle-contract.md`).
//!
//! A member that holds the invitation and the candidate's consent signs a roster prepare vote
//! for the admission child, sends it to the other members, and signs a commit vote once it has
//! seen a quorum of prepares. First round only: if a member already voted for another child on the
//! same roster, this admission cannot go forward, and no round change is attempted.
//! Every vote is a staged item, so it leaves only after the blob holding its lock is durable.

use super::*;
use crate::groups::evidence::{
    RosterVote, RosterVotePhase, RosterVoteRequest, VersionedCertificate,
};

/// Round numbering starts at 1: the lock table refuses round 0.
const FIRST_ROUND: u32 = 1;
const VOTE_BODY_LEN: usize = 8 + 32 + 32 + 4 + 1 + 96;

fn encode_vote_body(
    group: u64,
    parent: [u8; 32],
    child: [u8; 32],
    phase: u8,
    vote: &RosterVote,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(VOTE_BODY_LEN);
    body.extend_from_slice(&group.to_be_bytes());
    body.extend_from_slice(&parent);
    body.extend_from_slice(&child);
    body.extend_from_slice(&FIRST_ROUND.to_be_bytes());
    body.push(phase);
    body.extend_from_slice(&vote.to_bytes());
    body
}

impl Round {
    fn votes(&mut self, commit: bool) -> &mut Vec<VoteRec> {
        if commit {
            &mut self.commits
        } else {
            &mut self.prepares
        }
    }

    /// Returns whether the vote was new.
    fn add(&mut self, commit: bool, vote: VoteRec) -> bool {
        let votes = self.votes(commit);
        if votes.iter().any(|v| v.signer == vote.signer) {
            return false;
        }
        votes.push(vote);
        true
    }
}

impl GroupHandle {
    /// How far one admission's the first round has gone here: prepares seen, commits seen, and whether
    /// this member has signed each. `None` before the consent is in and a vote is signed.
    pub fn admission_progress(&self, invitation: [u8; 32]) -> Option<AdmissionProgress> {
        self.rounds
            .get(&(self.installation.selected(), invitation))
            .map(|r| AdmissionProgress {
                prepares: r.prepares.len(),
                commits: r.commits.len(),
                signed_prepare: r.signed_prepare,
                signed_commit: r.signed_commit,
            })
    }

    pub(super) fn observe_invitation(
        &mut self,
        from: Key,
        frame: &[u8],
        voucher_bytes: &[u8],
        facts: &crate::groups::evidence::InvitationFacts,
        nonce: [u8; 32],
        now: u64,
    ) -> Result<(), Reason> {
        if facts.deadline <= now {
            return Err(Reason::Expired);
        }
        if facts.deadline - now > MAX_LIFETIME_MS {
            return Err(Reason::Invalid);
        }
        let me = self.installation.selected();
        if self
            .left
            .contains(&(self.installation.selected(), facts.group))
        {
            return Ok(()); // we left: no messages, no votes
        }
        let group = self
            .groups
            .get_mut(&(self.installation.selected(), facts.group))
            .ok_or(Reason::Unknown)?;
        if group.membership(me).is_none() {
            return Err(Reason::Invalid);
        }
        group.advance_time(now);
        group
            .receive_invitation_frame(frame)
            .map_err(|error| match error {
                AdmissionError::InvitationExpired => Reason::Expired,
                AdmissionError::Roster(crate::groups::Error::StaleProposal) => Reason::Stale,
                _ => Reason::Invalid,
            })?;
        let voucher =
            DirectVoucher::from_admission_wire(voucher_bytes).map_err(|_| Reason::Invalid)?;
        if voucher.issuer() != facts.inviter
            || voucher.candidate() != facts.candidate
            || voucher.invitation_binding() != facts.binding
        {
            return Err(Reason::Invalid);
        }
        if self.observed.contains_key(&(me, facts.binding)) {
            return Ok(());
        }
        let from_inviter = self.observed.values().filter(|o| o.inviter == from).count();
        if self.observed.len() >= MAX_OBSERVED || from_inviter >= MAX_RECEIVED_PER_INVITER {
            return Err(Reason::Full);
        }
        self.observed.insert(
            (me, facts.binding),
            Observed {
                nonce,
                group: facts.group,
                inviter: from,
                deadline: facts.deadline,
                frame: frame.to_vec(),
                voucher: voucher_bytes.to_vec(),
                consent: None,
            },
        );
        Ok(())
    }

    pub(super) fn observe_consent(
        &mut self,
        from: Key,
        binding: [u8; 32],
        consent_bytes: &[u8],
        now: u64,
    ) -> Result<(), Reason> {
        let observed = self
            .observed
            .get(&(self.installation.selected(), binding))
            .ok_or(Reason::Unknown)?;
        if observed.inviter != from {
            return Err(Reason::Invalid);
        }
        if observed.consent.is_some() {
            return self.advance_admission(binding, now);
        }
        let group = self
            .groups
            .get_mut(&(self.installation.selected(), observed.group))
            .ok_or(Reason::Unknown)?;
        group.advance_time(now);
        let mut proposal = group
            .receive_invitation_frame(&observed.frame)
            .map_err(|error| match error {
                AdmissionError::InvitationExpired => Reason::Expired,
                AdmissionError::Roster(crate::groups::Error::StaleProposal) => Reason::Stale,
                _ => Reason::Invalid,
            })?;
        let consent =
            SignedAdmissionConsent::from_bytes(consent_bytes).map_err(|_| Reason::Malformed)?;
        group
            .apply_admission_consent(&mut proposal, &consent)
            .map_err(|_| Reason::Invalid)?;
        if let Some(observed) = self
            .observed
            .get_mut(&(self.installation.selected(), binding))
        {
            observed.consent = Some(consent_bytes.to_vec());
        }
        self.advance_admission(binding, now)
    }

    pub(super) fn receive_roster_vote(
        &mut self,
        from: Key,
        body: &[u8],
        now: u64,
    ) -> Result<(), Reason> {
        if body.len() != VOTE_BODY_LEN {
            return Err(Reason::Malformed);
        }
        let group_id = u64::from_be_bytes(body[..8].try_into().unwrap());
        let parent: [u8; 32] = body[8..40].try_into().unwrap();
        let child: [u8; 32] = body[40..72].try_into().unwrap();
        let round = u32::from_be_bytes(body[72..76].try_into().unwrap());
        let phase = match body[76] {
            1 => RosterVotePhase::Prepare,
            2 => RosterVotePhase::Commit,
            _ => return Err(Reason::Malformed),
        };
        if round != FIRST_ROUND {
            return Err(Reason::Unsupported);
        }
        let vote = RosterVote::from_bytes(&body[77..]).map_err(|_| Reason::Malformed)?;
        if vote.signer != from {
            return Err(Reason::Invalid);
        }
        if self
            .left
            .contains(&(self.installation.selected(), group_id))
        {
            return Ok(());
        }
        let group = self
            .groups
            .get(&(self.installation.selected(), group_id))
            .ok_or(Reason::Unknown)?;
        if group.rotation_context().1 != parent {
            // Votes for a roster the group already left arrive after every completed admission
            // (the quorum is smaller than the group). They can no longer matter: drop quietly.
            return Ok(());
        }
        group
            .check_roster_vote(&vote, child, FIRST_ROUND, phase)
            .map_err(|_| Reason::Invalid)?;
        let commit = matches!(phase, RosterVotePhase::Commit);
        let record = VoteRec {
            signer: vote.signer,
            signature: vote.signature.to_vec(),
        };
        let known = self
            .rounds
            .iter()
            .find(|((owner, _), r)| {
                *owner == self.installation.selected()
                    && r.group == group_id
                    && r.child == child
                    && r.parent == parent
            })
            .map(|((_, binding), _)| *binding);
        match known {
            Some(binding) => {
                let round = self
                    .rounds
                    .get_mut(&(self.installation.selected(), binding))
                    .ok_or(Reason::Unknown)?;
                round.add(commit, record);
                self.advance_admission(binding, now)
            }
            None => {
                let duplicate = self.strays.iter().any(|s| {
                    s.owner == self.installation.selected()
                        && s.group == group_id
                        && s.child == child
                        && s.commit == commit
                        && s.vote.signer == from
                });
                if duplicate {
                    return Ok(());
                }
                if self.strays.len() >= MAX_STRAY_VOTES {
                    return Err(Reason::Full);
                }
                self.strays.push(Stray {
                    owner: self.installation.selected(),
                    group: group_id,
                    parent,
                    child,
                    commit,
                    vote: record,
                    deadline: now.saturating_add(MAX_LIFETIME_MS),
                });
                Ok(())
            }
        }
    }

    /// Take whatever steps the votes seen so far allow for one admission: our prepare, then our
    /// commit once a quorum prepared. Safe to call again at any time.
    pub(super) fn advance_admission(&mut self, binding: [u8; 32], now: u64) -> Result<(), Reason> {
        let _ = now;
        if self.staged.len() > MAX_STAGED_ITEMS - 3 {
            return Err(Reason::Full);
        }
        let (group_id, frame, voucher_bytes, consent_bytes, deadline, op) =
            if let Some(sent) = self.sent.get(&(self.installation.selected(), binding)) {
                (
                    sent.group,
                    sent.frame.clone(),
                    sent.voucher.clone(),
                    sent.consent.clone(),
                    sent.deadline,
                    Some(sent.op),
                )
            } else if let Some(o) = self.observed.get(&(self.installation.selected(), binding)) {
                (
                    o.group,
                    o.frame.clone(),
                    o.voucher.clone(),
                    o.consent.clone(),
                    o.deadline,
                    None,
                )
            } else {
                return Err(Reason::Unknown);
            };
        let Some(consent_bytes) = consent_bytes else {
            return Ok(());
        };
        if self
            .left
            .contains(&(self.installation.selected(), group_id))
        {
            return Ok(());
        }
        let group = self
            .groups
            .get(&(self.installation.selected(), group_id))
            .ok_or(Reason::Unknown)?;
        let mut proposal = group
            .receive_invitation_frame(&frame)
            .map_err(|_| Reason::Stale)?;
        let consent =
            SignedAdmissionConsent::from_bytes(&consent_bytes).map_err(|_| Reason::Malformed)?;
        group
            .apply_admission_consent(&mut proposal, &consent)
            .map_err(|_| Reason::Invalid)?;
        let voucher =
            DirectVoucher::from_admission_wire(&voucher_bytes).map_err(|_| Reason::Invalid)?;
        let child = group
            .admission_child(&proposal, &voucher)
            .map_err(|_| Reason::Invalid)?;
        let (gid, parent) = group.rotation_context();
        let nonce = self
            .sent
            .get(&(self.installation.selected(), binding))
            .map(|s| s.nonce)
            .or_else(|| {
                self.observed
                    .get(&(self.installation.selected(), binding))
                    .map(|o| o.nonce)
            })
            .ok_or(Reason::Unknown)?;
        let facts = SignedInvitation::inspect_frame(&frame).map_err(|_| Reason::Invalid)?;
        joining::check_parent(&facts, nonce, group)?;
        let me = self.installation.selected();
        let others: Vec<Key> = group
            .export_roster(&self.installation)
            .map_err(|_| Reason::Invalid)?
            .members
            .into_iter()
            .filter(|key| *key != me)
            .collect();
        let quorum = group.roster_vote_quorum().map_err(|_| Reason::Invalid)?;

        if !self
            .rounds
            .contains_key(&(self.installation.selected(), binding))
            && self.rounds.len() >= MAX_OBSERVED + MAX_PENDING_OPS
        {
            return Err(Reason::Full);
        }
        let round = self
            .rounds
            .entry((self.installation.selected(), binding))
            .or_insert_with(|| Round {
                group: gid,
                parent,
                child,
                deadline,
                signed_prepare: false,
                signed_commit: false,
                prepares: Vec::new(),
                commits: Vec::new(),
            });
        if round.parent != parent || round.child != child {
            return Err(Reason::Stale);
        }
        // Votes that arrived before we knew this admission.
        let mut index = 0;
        while index < self.strays.len() {
            let stray = &self.strays[index];
            if stray.owner == self.installation.selected()
                && stray.group == gid
                && stray.parent == parent
                && stray.child == child
            {
                let stray = self.strays.remove(index);
                round.add(stray.commit, stray.vote);
            } else {
                index += 1;
            }
        }

        let mut staged = Vec::new();
        let mut failure = None;
        for phase in [RosterVotePhase::Prepare, RosterVotePhase::Commit] {
            let commit = matches!(phase, RosterVotePhase::Commit);
            let ready = if commit {
                !round.signed_commit && round.prepares.len() >= quorum
            } else {
                !round.signed_prepare
            };
            if !ready {
                continue;
            }
            let signed = group.sign_roster_vote_durable(
                &self.local,
                RosterVoteRequest {
                    parent,
                    child,
                    round: FIRST_ROUND,
                    phase,
                },
                &mut self.installation,
                |_, _| Ok(()),
            );
            match signed {
                Ok(vote) => {
                    if commit {
                        round.signed_commit = true;
                    } else {
                        round.signed_prepare = true;
                    }
                    round.add(
                        commit,
                        VoteRec {
                            signer: vote.signer,
                            signature: vote.signature.to_vec(),
                        },
                    );
                    if !others.is_empty() {
                        let body = encode_vote_body(gid, parent, child, phase as u8, &vote);
                        staged.push(Outgoing {
                            from: self.installation.selected(),
                            to: others.clone(),
                            kind: Tag::RosterVote,
                            bytes: encode_frame(Tag::RosterVote, &body)
                                .map_err(|_| Reason::Invalid)?,
                            authenticator: None,
                        });
                    }
                }
                Err(crate::groups::Error::AlreadyVoted) => {
                    failure = Some(Reason::Conflict);
                    break;
                }
                Err(_) => {
                    failure = Some(Reason::Invalid);
                    break;
                }
            }
        }
        if !staged.is_empty() {
            if self.staged.len() + staged.len() > MAX_STAGED_ITEMS {
                return Err(Reason::Full);
            }
            for outgoing in staged {
                if let Some(id) = op {
                    self.ops
                        .get_mut(&id)
                        .ok_or(Reason::Unknown)?
                        .frames
                        .push(outgoing.clone());
                }
                self.push_item(op, vec![outgoing], Vec::new(), false);
            }
        }
        if let Some(reason) = failure {
            if let Some(op) = op {
                self.reject_if_pending(op, reason);
            }
            return Err(reason);
        }
        if let Some(op) = op {
            self.complete_admission(binding, op, &proposal, &voucher, child, quorum, &others)?;
        }
        Ok(())
    }

    /// The inviter's last step: with a quorum of commits in hand, assemble the certificate,
    /// apply the admission, and stage the certificate for the members and a snapshot for the
    /// candidate. Nothing changes unless every frame can be built first.
    #[allow(clippy::too_many_arguments)]
    fn complete_admission(
        &mut self,
        binding: [u8; 32],
        op: u64,
        proposal: &crate::groups::evidence::VouchedProposal,
        voucher: &DirectVoucher,
        child: [u8; 32],
        quorum: usize,
        others: &[Key],
    ) -> Result<(), Reason> {
        let Some(round) = self.rounds.get(&(self.installation.selected(), binding)) else {
            return Ok(());
        };
        if round.commits.len() < quorum {
            return Ok(());
        }
        let as_votes = |records: &[VoteRec]| -> Result<Vec<RosterVote>, Reason> {
            records
                .iter()
                .map(|r| {
                    Ok(RosterVote {
                        signer: r.signer,
                        signature: r
                            .signature
                            .as_slice()
                            .try_into()
                            .map_err(|_| Reason::Invalid)?,
                    })
                })
                .collect()
        };
        let prepares = as_votes(&round.prepares)?;
        let commits = as_votes(&round.commits)?;
        let group = self
            .groups
            .get(&(self.installation.selected(), round.group))
            .ok_or(Reason::Unknown)?;
        let Ok(certificate) =
            group.assemble_certificate(child, FIRST_ROUND, &prepares, &commits, &[])
        else {
            return Ok(()); // not enough usable votes yet
        };
        let certificate = VersionedCertificate::V1(certificate);
        let mut next = group.clone();
        let update = next
            .apply_certified_admission(proposal, voucher.clone(), &certificate)
            .map_err(|_| Reason::Invalid)?;
        let candidate = proposal.candidate();
        let _ = update;
        let sent = self
            .sent
            .get(&(self.installation.selected(), binding))
            .ok_or(Reason::Unknown)?;
        let admission = joining::Admission {
            nonce: sent.nonce,
            invitation: sent.frame.clone(),
            voucher: sent.voucher.clone(),
            consent: sent.consent.clone().ok_or(Reason::Unknown)?,
            certificate: certificate.to_bytes().map_err(|_| Reason::Invalid)?,
        };
        let group_id = round.group;
        let mut certificate_body = binding.to_vec();
        certificate_body.extend_from_slice(&certificate.to_bytes().map_err(|_| Reason::Invalid)?);
        let mut snapshot_body = binding.to_vec();
        snapshot_body.extend_from_slice(&admission.certificate);
        let mut frames = Vec::new();
        if !others.is_empty() {
            frames.push(Outgoing {
                from: self.installation.selected(),
                to: others.to_vec(),
                kind: Tag::Certificate,
                bytes: encode_frame(Tag::Certificate, &certificate_body)
                    .map_err(|_| Reason::TooLarge)?,
                authenticator: None,
            });
        }
        frames.push(Outgoing {
            from: self.installation.selected(),
            to: vec![candidate],
            kind: Tag::GroupSnapshot,
            bytes: encode_frame(Tag::GroupSnapshot, &snapshot_body)
                .map_err(|_| Reason::TooLarge)?,
            authenticator: None,
        });
        if self.staged.len() >= MAX_STAGED_ITEMS {
            return Err(Reason::Full);
        }
        self.histories
            .get_mut(&(self.installation.selected(), group_id))
            .ok_or(Reason::Unknown)?
            .append(admission);
        self.groups
            .insert((self.installation.selected(), group_id), next);
        self.sent.remove(&(self.installation.selected(), binding));
        self.rounds.remove(&(self.installation.selected(), binding));
        self.prune_stale(group_id);
        self.ops.get_mut(&op).ok_or(Reason::Unknown)?.frames = frames.clone();
        self.push_item(Some(op), frames, vec![Event::Admitted(OpId(op))], true);
        Ok(())
    }

    /// Forget admissions built on a roster the group has moved past.
    fn prune_stale(&mut self, group_id: u64) {
        let Some(head) = self
            .groups
            .get(&(self.installation.selected(), group_id))
            .map(|g| g.rotation_context().1)
        else {
            return;
        };
        let parent_of = |frame: &[u8]| {
            SignedInvitation::inspect_frame(frame)
                .ok()
                .map(|f| f.parent)
        };
        let stale_sent: Vec<LocalBinding> = self
            .sent
            .iter()
            .filter(|((owner, _), s)| {
                *owner == self.installation.selected()
                    && s.group == group_id
                    && parent_of(&s.frame) != Some(head)
            })
            .map(|(b, _)| *b)
            .collect();
        for binding in stale_sent {
            if let Some(sent) = self.sent.remove(&binding) {
                self.reject_if_pending(sent.op, Reason::Stale);
            }
            self.rounds.remove(&binding);
        }
        self.observed.retain(|(owner, _), o| {
            *owner != self.installation.selected()
                || o.group != group_id
                || parent_of(&o.frame) == Some(head)
        });
        self.rounds.retain(|(owner, _), r| {
            *owner != self.installation.selected() || r.group != group_id || r.parent == head
        });
        self.strays.retain(|s| {
            s.owner != self.installation.selected() || s.group != group_id || s.parent == head
        });
    }

    /// A member applies the certificate the inviter assembled.
    pub(super) fn receive_certificate(
        &mut self,
        from: Key,
        body: &[u8],
        now: u64,
    ) -> Result<(), Reason> {
        if body.len() <= 32 {
            return Err(Reason::Malformed);
        }
        let binding: [u8; 32] = body[..32].try_into().unwrap();
        let observed = self
            .observed
            .get(&(self.installation.selected(), binding))
            .ok_or(Reason::Unknown)?;
        if observed.inviter != from {
            return Err(Reason::Invalid);
        }
        let Some(consent_bytes) = observed.consent.clone() else {
            return Err(Reason::Unknown);
        };
        let facts =
            SignedInvitation::inspect_frame(&observed.frame).map_err(|_| Reason::Invalid)?;
        let voucher =
            DirectVoucher::from_admission_wire(&observed.voucher).map_err(|_| Reason::Invalid)?;
        let certificate =
            VersionedCertificate::from_bytes(&body[32..]).map_err(|_| Reason::Malformed)?;
        let group_id = observed.group;
        let group = self
            .groups
            .get_mut(&(self.installation.selected(), group_id))
            .ok_or(Reason::Unknown)?;
        group.advance_time(now);
        let mut proposal = group
            .receive_invitation_frame(&observed.frame)
            .map_err(|_| Reason::Stale)?;
        let consent =
            SignedAdmissionConsent::from_bytes(&consent_bytes).map_err(|_| Reason::Malformed)?;
        group
            .apply_admission_consent(&mut proposal, &consent)
            .map_err(|_| Reason::Invalid)?;
        if self.staged.len() >= MAX_STAGED_ITEMS {
            return Err(Reason::Full);
        }
        let mut next = group.clone();
        next.apply_certified_admission(&proposal, voucher, &certificate)
            .map_err(|error| match error {
                AdmissionError::Roster(crate::groups::Error::StaleProposal) => Reason::Stale,
                _ => Reason::Invalid,
            })?;
        let admission = joining::Admission {
            nonce: observed.nonce,
            invitation: observed.frame.clone(),
            voucher: observed.voucher.clone(),
            consent: consent_bytes,
            certificate: body[32..].to_vec(),
        };
        self.histories
            .get_mut(&(self.installation.selected(), group_id))
            .ok_or(Reason::Unknown)?
            .append(admission);
        *group = next;
        self.observed
            .remove(&(self.installation.selected(), binding));
        self.rounds.remove(&(self.installation.selected(), binding));
        self.prune_stale(group_id);
        self.push_item(
            None,
            Vec::new(),
            vec![Event::MemberAdmitted {
                group: group_id,
                member: facts.candidate,
            }],
            false,
        );
        Ok(())
    }

    /// The candidate becomes a member from the snapshot the inviter sent, if it is exactly the
    /// roster that its own consent and the voucher produce.
    pub(super) fn receive_snapshot(
        &mut self,
        from: Key,
        body: &[u8],
        now: u64,
    ) -> Result<(), Reason> {
        if body.len() <= 32 {
            return Err(Reason::Malformed);
        }
        let binding: [u8; 32] = body[..32].try_into().unwrap();
        let received = self
            .received
            .get(&(self.installation.selected(), binding))
            .ok_or(Reason::Unknown)?;
        let Some(accepted) = received.accepted.as_ref() else {
            return Err(Reason::Invalid);
        };
        if received.inviter != from {
            return Err(Reason::Invalid);
        }
        let me = self.installation.selected();
        let voucher =
            DirectVoucher::from_admission_wire(&received.voucher).map_err(|_| Reason::Invalid)?;
        let mut history = received.history.clone();
        let mut group = history.replay()?;
        joining::check_parent(
            &SignedInvitation::inspect_frame(&received.frame).map_err(|_| Reason::Invalid)?,
            received.nonce,
            &group,
        )?;
        // Reject legacy raw snapshots and malformed certificates before any state changes.
        VersionedCertificate::from_bytes(&body[32..]).map_err(|_| Reason::Malformed)?;
        let admission = joining::Admission {
            nonce: received.nonce,
            invitation: received.frame.clone(),
            voucher: received.voucher.clone(),
            consent: accepted.consent.clone(),
            certificate: body[32..].to_vec(),
        };
        admission.apply(&mut group)?;
        history.append(admission);
        let group_id = received.group;
        let op = accepted.op;
        if group.id() != group_id || !group.admitted_by(me, binding, &voucher) {
            return Err(Reason::Invalid);
        }
        if self
            .groups
            .contains_key(&(self.installation.selected(), group_id))
        {
            return Ok(()); // a redelivery
        }
        if self.groups.len() >= MAX_GROUPS || self.staged.len() >= MAX_STAGED_ITEMS {
            return Err(Reason::Full);
        }
        group.advance_time(now);
        self.histories
            .insert((self.installation.selected(), group_id), history);
        self.groups
            .insert((self.installation.selected(), group_id), group);
        self.register_local(group_id);
        // Other invitations to the same group are moot now.
        let moot: Vec<LocalBinding> = self
            .received
            .iter()
            .filter(|((owner, _), r)| *owner == me && r.group == group_id)
            .map(|(b, _)| *b)
            .collect();
        for other in moot {
            if let Some(record) = self.received.remove(&other) {
                if other.1 != binding {
                    if let Some(accepted) = record.accepted {
                        self.reject_if_pending(accepted.op, Reason::Stale);
                    }
                }
            }
        }
        self.push_item(Some(op), Vec::new(), vec![Event::Joined(group_id)], true);
        Ok(())
    }
}
