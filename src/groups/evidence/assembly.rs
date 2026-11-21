//! Collector assembly (W4d-1 in `docs/architecture/proof-carrying-w4d-plan.md`).
//!
//! `plan_assembly` is pure: it chooses which of the held new proofs to attach. Attaching every
//! proof is not always best, because a proof for a member that voted removes that member's
//! vote from the count (`CollectorAssembly.tla`). The choice collapses to counts per voting
//! class: keys are interchangeable within a class (voted in neither phase, prepare only, commit
//! only, or both), so only a count per class is searched, and the smallest certificate wins. The differential test checks this against exhaustive
//! subset enumeration.
//!
//! `VouchedGroup::assemble_certificate` wraps it with signature and proof checks. It treats all
//! input as untrusted, returns only certificates that pass verification, and changes no state.

use super::electorate::quorum_for;
use super::proof::{EquivocationProof, ProofContext, verify_equivocation};
use super::wire::{CertificateV1, MAX_CERTIFICATE_PROOFS};
use super::{Key, MAX_CERTIFICATE_SIGNERS, RosterCertificate, RosterVote, VouchedGroup};
use crate::session::installation::group_roster_vote_message;
use std::collections::{BTreeMap, BTreeSet};

/// Wire bytes of one proof and of one signer (a prepare and a commit vote).
const PROOF_BYTES: usize = 229;
const SIGNER_BYTES: usize = 192;

/// No choice of proofs reaches quorum. Reports the closest one found: how many eligible votes
/// each phase has and how many it needs, with that choice's proofs attached.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssemblyShortfall {
    pub prepares: usize,
    pub commits: usize,
    pub required: usize,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct AssemblyPlan<K> {
    /// The new proofs to attach, by subject key.
    pub include: BTreeSet<K>,
    /// Signers needed in each phase.
    pub required: usize,
}

struct ProofCounts {
    silent: usize,
    prepare_only: usize,
    commit_only: usize,
    both: usize,
}

struct AssemblyCandidate {
    cost: usize,
    counts: ProofCounts,
    required: usize,
}

/// Choose the proofs to attach. `proofs` are subject keys of verified new proofs on `roster`
/// and outside `inherited`; the signer sets are the keys that voted in each phase.
pub(crate) fn plan_assembly<K: Ord + Copy>(
    roster: &BTreeSet<K>,
    inherited: &BTreeSet<K>,
    prepare_signers: &BTreeSet<K>,
    commit_signers: &BTreeSet<K>,
    proofs: &BTreeSet<K>,
) -> Result<AssemblyPlan<K>, AssemblyShortfall> {
    let eligible_base: BTreeSet<K> = roster.difference(inherited).copied().collect();
    let prepares: BTreeSet<K> = prepare_signers
        .intersection(&eligible_base)
        .copied()
        .collect();
    let commits: BTreeSet<K> = commit_signers
        .intersection(&eligible_base)
        .copied()
        .collect();
    let proofs: BTreeSet<K> = proofs.intersection(&eligible_base).copied().collect();

    let mut silent = Vec::new();
    let (mut prepare_only, mut commit_only, mut both) = (Vec::new(), Vec::new(), Vec::new());
    for key in &proofs {
        match (prepares.contains(key), commits.contains(key)) {
            (false, false) => silent.push(*key),
            (true, false) => prepare_only.push(*key),
            (false, true) => commit_only.push(*key),
            (true, true) => both.push(*key),
        }
    }

    let mut best: Option<AssemblyCandidate> = None;
    let mut closest: Option<(i64, AssemblyShortfall)> = None;
    for s in 0..=silent.len() {
        for a in 0..=prepare_only.len() {
            for b in 0..=commit_only.len() {
                for c in 0..=both.len() {
                    let removed = s + a + b + c;
                    let electorate = eligible_base.len() - removed;
                    let Some(required) = quorum_for(electorate) else {
                        continue;
                    };
                    let excluded = |key: &K| {
                        silent[..s].contains(key)
                            || prepare_only[..a].contains(key)
                            || commit_only[..b].contains(key)
                            || both[..c].contains(key)
                    };
                    let prepare_votes = prepares.iter().filter(|key| !excluded(key)).count();
                    let commit_votes = commits.iter().filter(|key| !excluded(key)).count();
                    let slack = prepare_votes.min(commit_votes) as i64 - required as i64;
                    if closest.is_none_or(|(best_slack, _)| slack > best_slack) {
                        closest = Some((
                            slack,
                            AssemblyShortfall {
                                prepares: prepare_votes,
                                commits: commit_votes,
                                required,
                            },
                        ));
                    }
                    let encodable =
                        removed <= MAX_CERTIFICATE_PROOFS && required <= MAX_CERTIFICATE_SIGNERS;
                    if slack >= 0 && encodable {
                        let cost = removed * PROOF_BYTES + required * SIGNER_BYTES;
                        if best.as_ref().is_none_or(|best| cost < best.cost) {
                            best = Some(AssemblyCandidate {
                                cost,
                                counts: ProofCounts {
                                    silent: s,
                                    prepare_only: a,
                                    commit_only: b,
                                    both: c,
                                },
                                required,
                            });
                        }
                    }
                }
            }
        }
    }

    match best {
        Some(candidate) => {
            let counts = candidate.counts;
            let include = silent[..counts.silent]
                .iter()
                .chain(&prepare_only[..counts.prepare_only])
                .chain(&commit_only[..counts.commit_only])
                .chain(&both[..counts.both])
                .copied()
                .collect();
            Ok(AssemblyPlan {
                include,
                required: candidate.required,
            })
        }
        None => Err(closest.map_or(
            AssemblyShortfall {
                prepares: 0,
                commits: 0,
                required: 0,
            },
            |(_, shortfall)| shortfall,
        )),
    }
}

impl VouchedGroup {
    /// Assemble the smallest valid version-1 certificate for `child` at `round` from votes and
    /// proofs a collector holds. Every input is checked: a vote must verify for this exact
    /// child, round and phase and come from an eligible member, and a proof must verify against
    /// this parent and not already be on the chain. Unusable inputs are dropped. The result has
    /// exactly the required signers per phase in ascending key order, the proofs in ascending
    /// subject order, and the chain digest, so it is deterministic. No state changes.
    pub fn assemble_certificate(
        &self,
        child: [u8; 32],
        round: u32,
        prepares: &[RosterVote],
        commits: &[RosterVote],
        proofs: &[EquivocationProof],
    ) -> Result<CertificateV1, AssemblyShortfall> {
        let (group, parent) = self.rotation_context();
        let roster: BTreeSet<Key> = self
            .identities
            .keys()
            .copied()
            .filter(|key| self.membership(*key).is_some())
            .collect();
        let inherited = self.inherited_proof_keys();

        let valid_votes = |votes: &[RosterVote], phase: u8| -> BTreeMap<Key, RosterVote> {
            let message = group_roster_vote_message(group, parent, child, round, phase);
            let mut valid = BTreeMap::new();
            for vote in votes {
                if !inherited.contains(&vote.signer)
                    && self.verify_roster_vote(vote, &message).is_ok()
                {
                    valid
                        .entry(vote.signer)
                        .and_modify(|chosen: &mut RosterVote| {
                            if vote.signature < chosen.signature {
                                *chosen = *vote;
                            }
                        })
                        .or_insert(*vote);
                }
            }
            valid
        };
        let prepares = valid_votes(prepares, 1);
        let commits = valid_votes(commits, 2);

        let context = ProofContext {
            group,
            parent,
            roster: &roster,
        };
        let mut verified: BTreeMap<Key, &EquivocationProof> = BTreeMap::new();
        for proof in proofs {
            if let Ok(subject) = verify_equivocation(proof, &context) {
                if !inherited.contains(&subject) {
                    verified
                        .entry(subject)
                        .and_modify(|chosen| {
                            if proof < *chosen {
                                *chosen = proof;
                            }
                        })
                        .or_insert(proof);
                }
            }
        }

        let plan = plan_assembly(
            &roster,
            inherited,
            &prepares.keys().copied().collect(),
            &commits.keys().copied().collect(),
            &verified.keys().copied().collect(),
        )?;
        let pick = |votes: &BTreeMap<Key, RosterVote>| -> Vec<RosterVote> {
            votes
                .iter()
                .filter(|(key, _)| !plan.include.contains(*key))
                .take(plan.required)
                .map(|(_, vote)| *vote)
                .collect()
        };
        Ok(CertificateV1 {
            certificate: RosterCertificate {
                group,
                parent,
                child,
                round,
                prepares: pick(&prepares),
                commits: pick(&commits),
            },
            chain_digest: self.chain_digest(),
            proofs: plan
                .include
                .iter()
                .map(|key| (*verified[key]).clone())
                .collect(),
        })
    }
}
