//! Self-verifying equivocation proofs (decision C, W4a in
//! `docs/architecture/proof-carrying-w4-plan.md`).
//!
//! A proof is two signatures by one key over two different children for the same group,
//! parent, round and phase. Nothing else is needed to check it, so it applies without a vote.
//! The scope (group and parent) is stored once, so a proof whose two statements disagree about
//! scope cannot be represented.
//!
//! **Not wired in.** Nothing in the agreement path calls this yet. The verifier returns only
//! the subject key; it grants no authority, stores nothing and does not touch `suspect`.
//!
//! **Trusted-input boundary.** The caller supplies the exact authenticated parent roster. The
//! verifier does not decide that the parent is the right one, does not check inheritance, and
//! does not enforce the fault bound.

use super::{Key, parse_verifying_key};
use crate::session::installation::group_roster_vote_message;
use ed25519_dalek::Signature;
use std::collections::BTreeSet;

/// Prepare, commit and round-change report: the three signed phases that exist today.
const KNOWN_PHASES: [u8; 3] = [1, 2, 3];

/// Two conflicting signed statements by one key. Children are in canonical (ascending) order.
// Lexicographic ordering selects a deterministic representative when multiple valid
// proofs name the same subject. It expresses no trust or authorization precedence.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EquivocationProof {
    pub signer: Key,
    pub group: u64,
    pub parent: [u8; 32],
    pub round: u32,
    pub phase: u8,
    pub first: ([u8; 32], [u8; 64]),
    pub second: ([u8; 32], [u8; 64]),
}

/// A proof as carried by a node on the roster chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CarriedProof {
    /// A verified, self-contained equivocation proof.
    Equivocation(Box<EquivocationProof>),
    /// Simulation shortcut: the simulation's roster authority reported this key. Constructed
    /// only by `mark_suspect`; it carries no evidence and exists so the chain records a subject.
    SimulationReport(Key),
}

impl CarriedProof {
    pub(crate) fn subject(&self) -> Key {
        match self {
            Self::Equivocation(proof) => proof.signer,
            Self::SimulationReport(key) => *key,
        }
    }
}

/// A descendant must carry every proof subject its authenticated chain already carries.
pub(crate) fn check_inheritance(
    inherited: &BTreeSet<Key>,
    carried: &BTreeSet<Key>,
) -> Result<(), ProofRejection> {
    if inherited.is_subset(carried) {
        Ok(())
    } else {
        Err(ProofRejection::DropsInheritedProof)
    }
}

/// The authenticated parent the proof must be scoped to.
pub(crate) struct ProofContext<'a> {
    pub group: u64,
    pub parent: [u8; 32],
    /// Keys on the parent roster, including keys already proven: a proven key stays on the
    /// roster and may be proven again by the same evidence.
    pub roster: &'a BTreeSet<Key>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProofRejection {
    WrongGroup,
    WrongParent,
    UnknownPhase,
    /// The two statements name the same child, so they do not conflict.
    SameStatement,
    /// Children are not in canonical order.
    NotCanonical,
    NotOnRoster,
    BadSignature,
    /// A certificate's carried set omits a proof its authenticated chain carries.
    DropsInheritedProof,
}

impl EquivocationProof {
    /// Build a proof from two statements in either order. Equal children are kept as given
    /// and rejected on verification.
    pub fn new(
        signer: Key,
        group: u64,
        parent: [u8; 32],
        round: u32,
        phase: u8,
        a: ([u8; 32], [u8; 64]),
        b: ([u8; 32], [u8; 64]),
    ) -> Self {
        let (first, second) = if a.0 <= b.0 { (a, b) } else { (b, a) };
        Self {
            signer,
            group,
            parent,
            round,
            phase,
            first,
            second,
        }
    }

    /// The subject key and the scope the proof applies to. Evidence is never scoped to a
    /// person, only to this key in this group at this parent.
    pub(crate) fn scope(&self) -> (Key, u64, [u8; 32]) {
        (self.signer, self.group, self.parent)
    }
}

/// Check a proof against its authenticated parent; return the subject key.
pub(crate) fn verify_equivocation(
    proof: &EquivocationProof,
    context: &ProofContext<'_>,
) -> Result<Key, ProofRejection> {
    if proof.group != context.group {
        return Err(ProofRejection::WrongGroup);
    }
    if proof.parent != context.parent {
        return Err(ProofRejection::WrongParent);
    }
    if !KNOWN_PHASES.contains(&proof.phase) {
        return Err(ProofRejection::UnknownPhase);
    }
    if proof.first.0 == proof.second.0 {
        return Err(ProofRejection::SameStatement);
    }
    if proof.first.0 > proof.second.0 {
        return Err(ProofRejection::NotCanonical);
    }
    if !context.roster.contains(&proof.signer) {
        return Err(ProofRejection::NotOnRoster);
    }
    let key = parse_verifying_key(&proof.signer).map_err(|_| ProofRejection::BadSignature)?;
    for (child, signature) in [&proof.first, &proof.second] {
        let message =
            group_roster_vote_message(proof.group, proof.parent, *child, proof.round, proof.phase);
        key.verify_strict(&message, &Signature::from_bytes(signature))
            .map_err(|_| ProofRejection::BadSignature)?;
    }
    Ok(proof.signer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const GROUP: u64 = 7;
    const PARENT: [u8; 32] = [9; 32];

    fn signing(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn key(seed: u8) -> Key {
        signing(seed).verifying_key().to_bytes()
    }

    fn sign(
        seed: u8,
        group: u64,
        parent: [u8; 32],
        child: [u8; 32],
        round: u32,
        phase: u8,
    ) -> ([u8; 32], [u8; 64]) {
        let message = group_roster_vote_message(group, parent, child, round, phase);
        (child, signing(seed).sign(&message).to_bytes())
    }

    fn roster() -> BTreeSet<Key> {
        (1..=4).map(key).collect()
    }

    fn valid(seed: u8) -> EquivocationProof {
        EquivocationProof::new(
            key(seed),
            GROUP,
            PARENT,
            0,
            1,
            sign(seed, GROUP, PARENT, [1; 32], 0, 1),
            sign(seed, GROUP, PARENT, [2; 32], 0, 1),
        )
    }

    fn check(proof: &EquivocationProof) -> Result<Key, ProofRejection> {
        let roster = roster();
        verify_equivocation(
            proof,
            &ProofContext {
                group: GROUP,
                parent: PARENT,
                roster: &roster,
            },
        )
    }

    #[test]
    fn valid_proof_returns_the_subject_key() {
        assert_eq!(check(&valid(1)), Ok(key(1)));
    }

    #[test]
    fn every_known_phase_and_round_verifies() {
        for phase in KNOWN_PHASES {
            for round in [0, 1, 5] {
                let proof = EquivocationProof::new(
                    key(2),
                    GROUP,
                    PARENT,
                    round,
                    phase,
                    sign(2, GROUP, PARENT, [3; 32], round, phase),
                    sign(2, GROUP, PARENT, [4; 32], round, phase),
                );
                assert_eq!(check(&proof), Ok(key(2)), "phase {phase} round {round}");
            }
        }
    }

    #[test]
    fn argument_order_does_not_change_the_proof() {
        let a = sign(1, GROUP, PARENT, [1; 32], 0, 1);
        let b = sign(1, GROUP, PARENT, [2; 32], 0, 1);
        let one = EquivocationProof::new(key(1), GROUP, PARENT, 0, 1, a, b);
        let two = EquivocationProof::new(key(1), GROUP, PARENT, 0, 1, b, a);
        assert_eq!(one, two);
        assert_eq!(check(&two), Ok(key(1)));
    }

    #[test]
    fn the_same_statement_twice_is_not_a_conflict() {
        let a = sign(1, GROUP, PARENT, [1; 32], 0, 1);
        let proof = EquivocationProof::new(key(1), GROUP, PARENT, 0, 1, a, a);
        assert_eq!(check(&proof), Err(ProofRejection::SameStatement));
    }

    #[test]
    fn non_canonical_order_is_rejected() {
        let mut proof = valid(1);
        std::mem::swap(&mut proof.first, &mut proof.second);
        assert_eq!(check(&proof), Err(ProofRejection::NotCanonical));
    }

    #[test]
    fn a_proof_for_another_group_or_parent_is_rejected() {
        let other_group = EquivocationProof::new(
            key(1),
            GROUP + 1,
            PARENT,
            0,
            1,
            sign(1, GROUP + 1, PARENT, [1; 32], 0, 1),
            sign(1, GROUP + 1, PARENT, [2; 32], 0, 1),
        );
        assert_eq!(check(&other_group), Err(ProofRejection::WrongGroup));
        let other_parent = EquivocationProof::new(
            key(1),
            GROUP,
            [8; 32],
            0,
            1,
            sign(1, GROUP, [8; 32], [1; 32], 0, 1),
            sign(1, GROUP, [8; 32], [2; 32], 0, 1),
        );
        assert_eq!(check(&other_parent), Err(ProofRejection::WrongParent));
    }

    #[test]
    fn statements_in_different_rounds_or_phases_do_not_combine() {
        // One signature from round 0 and one from round 1, both honest: relabelling the round
        // or phase on a valid pair breaks the signature, so the pair cannot be forged.
        let a = sign(1, GROUP, PARENT, [1; 32], 0, 1);
        let b = sign(1, GROUP, PARENT, [2; 32], 1, 1);
        let mixed_round = EquivocationProof::new(key(1), GROUP, PARENT, 0, 1, a, b);
        assert_eq!(check(&mixed_round), Err(ProofRejection::BadSignature));
        let c = sign(1, GROUP, PARENT, [2; 32], 0, 2);
        let mixed_phase = EquivocationProof::new(key(1), GROUP, PARENT, 0, 1, a, c);
        assert_eq!(check(&mixed_phase), Err(ProofRejection::BadSignature));
    }

    #[test]
    fn unknown_phase_is_rejected() {
        let proof = EquivocationProof::new(
            key(1),
            GROUP,
            PARENT,
            0,
            9,
            sign(1, GROUP, PARENT, [1; 32], 0, 9),
            sign(1, GROUP, PARENT, [2; 32], 0, 9),
        );
        assert_eq!(check(&proof), Err(ProofRejection::UnknownPhase));
    }

    #[test]
    fn a_key_off_the_roster_is_rejected() {
        let proof = valid(9);
        assert_eq!(check(&proof), Err(ProofRejection::NotOnRoster));
    }

    #[test]
    fn bad_signature_or_wrong_signer_is_rejected() {
        let mut tampered = valid(1);
        tampered.first.1[0] ^= 1;
        assert_eq!(check(&tampered), Err(ProofRejection::BadSignature));
        // Statements signed by key 2 attributed to key 1.
        let mut forged = valid(2);
        forged.signer = key(1);
        assert_eq!(check(&forged), Err(ProofRejection::BadSignature));
    }

    #[test]
    fn a_proof_against_one_key_names_only_that_key() {
        // Tenure scope: the proof's subject is exactly the signer. A replacement key of the
        // same person is a different key and is not named.
        let proof = valid(1);
        assert_eq!(proof.scope(), (key(1), GROUP, PARENT));
        assert_ne!(check(&proof), Ok(key(5)));
    }

    #[test]
    fn a_proven_key_that_already_left_the_roster_is_not_accepted_here() {
        // Inheritance keeps the retained proof; this verifier judges only against the parent
        // it is scoped to. A key not on that parent's roster is out of scope.
        let mut small = roster();
        small.remove(&key(1));
        let result = verify_equivocation(
            &valid(1),
            &ProofContext {
                group: GROUP,
                parent: PARENT,
                roster: &small,
            },
        );
        assert_eq!(result, Err(ProofRejection::NotOnRoster));
    }

    #[test]
    fn a_weak_key_is_rejected_without_panicking() {
        let weak = [0u8; 32];
        let mut roster = roster();
        roster.insert(weak);
        let proof = EquivocationProof::new(
            weak,
            GROUP,
            PARENT,
            0,
            1,
            ([1; 32], [0; 64]),
            ([2; 32], [0; 64]),
        );
        let result = verify_equivocation(
            &proof,
            &ProofContext {
                group: GROUP,
                parent: PARENT,
                roster: &roster,
            },
        );
        assert_eq!(result, Err(ProofRejection::BadSignature));
    }
}
