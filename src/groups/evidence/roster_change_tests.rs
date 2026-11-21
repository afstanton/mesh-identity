//! Checks for admission, removal, readmission and proof scope. Bounded enumerations over the real code
//! and the real helper; not a proof for every roster chain, and the per-parent fault bound stays
//! an assumption.

use super::electorate::{
    ElectorateQuorumCheck, QuorumRejection, check_electorate_quorum, quorum_for,
};
use std::collections::BTreeSet;

/// Declared per-parent fault bound: one for rosters of 2 and 3, `(n - 1) / 3` from 4 up.
fn fault_bound(n: usize) -> usize {
    if n <= 3 { 1 } else { (n - 1) / 3 }
}

/// The required quorum through the real helper: a roster of `m` keys, `present` proven keys on
/// it and `departed` proven keys that already left. Returns (eligible, required).
fn required(m: usize, present: usize, departed: usize) -> (usize, usize) {
    let roster: BTreeSet<u16> = (0..m as u16).collect();
    let carried: BTreeSet<u16> = (0..present as u16)
        .chain((0..departed as u16).map(|i| 1000 + i))
        .collect();
    match check_electorate_quorum(&ElectorateQuorumCheck {
        roster: &roster,
        inherited: &BTreeSet::new(),
        carried: &carried,
        reported: &BTreeSet::new(),
        signers: &BTreeSet::new(),
    }) {
        Err(QuorumRejection::BelowQuorum { required, .. }) => (m - present, required),
        other => panic!("m {m} present {present} departed {departed}: {other:?}"),
    }
}

/// Required quorum per (roster size, present proofs), taken from the real helper, with the
/// helper also run with three departed proof keys to show they change nothing.
fn quorum_table() -> Vec<Vec<usize>> {
    let mut table = vec![Vec::new(); 402];
    for (m, row) in table.iter_mut().enumerate().skip(3) {
        for p in 0..=fault_bound(m).min(m - 1) {
            let (eligible, req) = required(m, p, 0);
            assert_eq!(eligible, m - p);
            let (eligible_d, req_d) = required(m, p, 3);
            assert_eq!(
                (eligible_d, req_d),
                (eligible, req),
                "departed keys must not reduce the electorate: m {m} p {p}"
            );
            row.push(req);
        }
    }
    table
}

/// E5. Every roster size reachable from a base of 4 to 400 by one admission or one removal is a
/// roster of 3 to 401. Each parent is checked on its own roster with its own fault bound: the
/// honest-intersection bound holds for every pair of sound proof sets, and the result does not
/// depend on how many proven keys already departed.
#[test]
fn bound_holds_at_every_parent_after_an_admission_or_removal() {
    let table = quorum_table();
    let mut pairs = 0u64;
    for (m, row) in table.iter().enumerate().skip(3) {
        let f = fault_bound(m);
        for (a, &quorum_a) in row.iter().enumerate() {
            for (b, &quorum_b) in row.iter().enumerate() {
                let lhs =
                    quorum_a as i64 + quorum_b as i64 - m as i64 - f as i64 + a as i64 + b as i64;
                assert!(lhs > 0, "m {m} f {f} a {a} b {b}: {lhs}");
                pairs += 1;
            }
        }
    }
    assert!(pairs > 100_000);
}

/// E5 control. The unsafe arithmetic (roster size minus the whole carried set, counting a
/// departed offender a second time) must break the same bound somewhere, or the check above
/// proves nothing. This records the first break instead of assuming one exists.
#[test]
fn double_subtraction_breaks_the_bound_somewhere() {
    let table = quorum_table();
    let mut first: Option<(usize, usize, usize, usize)> = None;
    'search: for (m, row) in table.iter().enumerate().skip(4) {
        let f = fault_bound(m);
        for departed in 1..=3usize {
            for a in 0..row.len() {
                let Some(unsafe_eligible) = (m - a).checked_sub(departed) else {
                    continue;
                };
                let Some(unsafe_req) = quorum_for(unsafe_eligible) else {
                    continue;
                };
                for (b, &quorum_b) in row.iter().enumerate() {
                    let lhs = unsafe_req as i64 + quorum_b as i64 - m as i64 - f as i64
                        + a as i64
                        + b as i64;
                    if lhs <= 0 {
                        first = Some((m, a, b, departed));
                        break 'search;
                    }
                }
            }
        }
    }
    let (m, a, b, departed) = first.expect("double subtraction never broke the bound");
    println!("first break: m {m} a {a} b {b} departed {departed}");
}

mod roster {
    use super::super::{Error, Key, VouchedGroup};
    use ed25519_dalek::SigningKey;

    pub fn key(seed: u8) -> Key {
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
    }

    pub fn group(n: u8) -> VouchedGroup {
        VouchedGroup::new(
            7,
            (0..n).map(|i| key(10 + i)),
            crate::groups::Policy::InviterOnly,
        )
    }

    pub fn remove(group: &mut VouchedGroup, who: Key) {
        let tenure = group.membership(who).expect("member");
        group.apply_departure(who, tenure).unwrap();
    }

    pub fn is(result: Result<impl Sized, Error>, error: Error) -> bool {
        matches!(result, Err(e) if e == error)
    }
}

/// E3. A suspect key that is removed is retired: every path that could bring a key back
/// rejects it. Decision C says such a key would return still suspended; the code is stricter
/// and never lets it return, so the difference is only in strictness.
#[test]
fn a_removed_suspect_key_is_rejected_on_every_readmission_path() {
    use roster::*;
    let mut g = group(5);
    let (inviter, offender, other) = (key(10), key(11), key(12));
    g.mark_suspect(offender).unwrap();
    remove(&mut g, offender);
    assert!(g.retired.contains(&offender));

    // Ordinary invitation.
    assert!(is(g.invite(inviter, offender), super::Error::Ineligible));
    // Rotation and recovery replacement onto the retired key.
    let revision = g.revision();
    assert!(is(
        g.rotate_key(revision, other, offender),
        super::Error::AlreadyMember
    ));
    assert!(is(
        g.replace_key(revision, other, offender, [9; 32]),
        super::Error::AlreadyMember
    ));
    assert!(is(
        g.request_recovery(other, offender),
        super::Error::AlreadyMember
    ));
    // Nothing moved.
    assert_eq!(g.revision(), revision);
}

/// E3. A removed key that was not suspect is not retired. It may be invited again through the
/// ordinary path, which carries no continuity claim and has no proof against it.
#[test]
fn a_removed_honest_key_may_be_invited_again_with_no_proof() {
    use roster::*;
    let mut g = group(5);
    let (inviter, leaver) = (key(10), key(11));
    remove(&mut g, leaver);
    assert!(!g.retired.contains(&leaver));
    assert!(g.invite(inviter, leaver).is_ok());
    assert!(!g.inherited_proof_keys().contains(&leaver));
}

/// E3. A fresh key for the same person is a new key: it is invitable and carries no proof,
/// whatever the removed key was proven for.
#[test]
fn a_fresh_key_for_a_removed_offenders_person_carries_no_proof() {
    use roster::*;
    let mut g = group(5);
    let (inviter, offender, fresh) = (key(10), key(11), key(99));
    g.mark_suspect(offender).unwrap();
    remove(&mut g, offender);
    assert!(g.invite(inviter, fresh).is_ok());
    assert!(g.inherited_proof_keys().contains(&offender));
    assert!(!g.inherited_proof_keys().contains(&fresh));
    assert!(!g.suspect.contains(&fresh));
}

/// A suspect key cannot rotate, and a suspect inviter cannot invite: the only route to a new
/// key for a suspect member is recovery.
#[test]
fn a_suspect_key_cannot_rotate_or_invite() {
    use roster::*;
    let mut g = group(5);
    let (suspect, fresh) = (key(11), key(99));
    g.mark_suspect(suspect).unwrap();
    let revision = g.revision();
    assert!(is(
        g.rotate_key(revision, suspect, fresh),
        super::Error::Ineligible
    ));
    assert!(is(g.invite(suspect, fresh), super::Error::Ineligible));
    assert_eq!(g.revision(), revision);
}

mod transitions {
    use super::super::{Key, VouchedGroup};
    use super::roster::{group, key, remove};
    use super::*;
    use crate::groups::Vote;

    /// The group's own electorate and quorum against the helper, fed the parent roster and the
    /// keys the chain carries (including departed ones). Returns (eligible, required).
    pub fn agree_with_helper(g: &VouchedGroup, context: &str) -> (usize, usize) {
        let roster: BTreeSet<Key> = g
            .identities
            .keys()
            .copied()
            .filter(|k| g.membership(*k).is_some())
            .collect();
        let carried = g.inherited_proof_keys().clone();
        let satisfied = match check_electorate_quorum(&ElectorateQuorumCheck {
            roster: &roster,
            inherited: &carried,
            carried: &carried,
            reported: &BTreeSet::new(),
            signers: &BTreeSet::new(),
        }) {
            Err(QuorumRejection::BelowQuorum { required, .. }) => {
                (roster.difference(&carried).count(), required)
            }
            // An empty roster or an empty electorate has no quorum; the group must agree.
            Err(QuorumRejection::EmptyRoster | QuorumRejection::EmptyElectorate) => {
                assert!(g.roster_quorum().is_err(), "no quorum expected, {context}");
                return (g.group.electorate_size(), 0);
            }
            other => panic!("{context}: {other:?}"),
        };
        assert_eq!(
            g.group.electorate_size(),
            satisfied.0,
            "electorate, {context}"
        );
        assert_eq!(g.roster_quorum().unwrap(), satisfied.1, "quorum, {context}");
        satisfied
    }

    /// Admit `candidate` through the group's own invitation, vote and admission rules, then
    /// record the history child as `commit_admission` does. The voucher and signature layers are
    /// not exercised here; the roster rules are.
    pub fn admit(g: &mut VouchedGroup, inviter: Key, candidate: Key) {
        let inviter_id = g.identities[&inviter];
        let candidate_id =
            crate::groups::Identity(g.identities.values().map(|i| i.0).max().unwrap() + 1);
        let mut p = g.group.invite(inviter_id, candidate_id).unwrap();
        let voters: Vec<_> = g
            .identities
            .iter()
            .filter(|(k, id)| {
                g.membership(**k).is_some() && !g.suspect.contains(*k) && **id != inviter_id
            })
            .map(|(_, id)| *id)
            .collect();
        for voter in voters {
            g.group.vote(&mut p, voter, Vote::Approve).unwrap();
        }
        p.accepted = true;
        let child = g.derived_child(b"test-admit", &[&candidate]);
        g.group.admit(&p).unwrap();
        g.record_roster_child(child);
        g.identities.insert(candidate, candidate_id);
    }

    /// E2. Removal, every combination of proven offenders and departures in groups of 4 to 6.
    #[test]
    fn removal_agrees_with_the_helper_and_never_subtracts_twice() {
        let mut checked = 0u32;
        for n in 4u8..=6 {
            let nu = n as usize;
            for suspects in 0u32..1 << nu {
                for removals in 0u32..1 << nu {
                    let mut g = group(n);
                    let ctx = format!("n {n} suspects {suspects:b} removals {removals:b}");
                    for i in 0..nu {
                        if suspects >> i & 1 == 1 {
                            g.mark_suspect(key(10 + i as u8)).unwrap();
                        }
                    }
                    agree_with_helper(&g, &ctx);
                    for i in 0..nu {
                        if removals >> i & 1 == 0 {
                            continue;
                        }
                        let who = key(10 + i as u8);
                        let was_proven = g.suspect.contains(&who);
                        let before = g.group.electorate_size();
                        remove(&mut g, who);
                        let after = g.group.electorate_size();
                        if was_proven {
                            assert_eq!(after, before, "proven offender, {ctx}");
                        } else {
                            assert_eq!(after, before - 1, "honest member, {ctx}");
                        }
                        assert!(g.inherited_proof_keys().contains(&who) == was_proven);
                        agree_with_helper(&g, &ctx);
                    }
                    checked += 1;
                }
            }
        }
        assert!(checked > 1000);
    }

    /// E1. Admission: the electorate grows by one, the new key carries no proof, the inherited
    /// set is unchanged, and the quorum is the helper's for the larger roster.
    #[test]
    fn admission_grows_the_electorate_and_inherits_without_blaming_the_newcomer() {
        for n in 4u8..=6 {
            let nu = n as usize;
            for suspects in 0u32..1 << nu {
                // Keep at least one honest inviter and a workable electorate.
                if (0..nu).filter(|i| suspects >> i & 1 == 0).count() < 2 {
                    continue;
                }
                let mut g = group(n);
                let ctx = format!("n {n} suspects {suspects:b}");
                for i in 0..nu {
                    if suspects >> i & 1 == 1 {
                        g.mark_suspect(key(10 + i as u8)).unwrap();
                    }
                }
                let inviter = (0..nu)
                    .find(|i| suspects >> i & 1 == 0)
                    .map(|i| key(10 + i as u8))
                    .unwrap();
                for newcomer in [key(100), key(101)] {
                    let before_size = g.group.electorate_size();
                    let before_chain = g.inherited_proof_keys().clone();
                    admit(&mut g, inviter, newcomer);
                    assert_eq!(g.group.electorate_size(), before_size + 1, "{ctx}");
                    assert_eq!(g.inherited_proof_keys(), &before_chain, "{ctx}");
                    assert!(!g.suspect.contains(&newcomer), "{ctx}");
                    assert!(g.membership(newcomer).is_some(), "{ctx}");
                    agree_with_helper(&g, &ctx);
                }
            }
        }
    }

    /// E1 with removal after admission: each parent's quorum comes from its own roster, and the
    /// result does not depend on the order of an admission and a departure.
    #[test]
    fn quorum_is_recomputed_from_each_parent_roster() {
        let mut g = group(5);
        let inviter = key(10);
        g.mark_suspect(key(11)).unwrap();
        let mut seen = vec![agree_with_helper(&g, "start")];
        admit(&mut g, inviter, key(100));
        seen.push(agree_with_helper(&g, "after admit"));
        remove(&mut g, key(11));
        seen.push(agree_with_helper(&g, "after removing the offender"));
        remove(&mut g, key(12));
        seen.push(agree_with_helper(&g, "after removing an honest member"));
        // 5 members, 1 proven: 4 eligible. Admit: 5. Remove offender: still 5. Remove honest: 4.
        let sizes: Vec<usize> = seen.iter().map(|s| s.0).collect();
        assert_eq!(sizes, vec![4, 5, 5, 4]);
    }
}

mod scope {
    use super::super::proof::{
        EquivocationProof, ProofContext, ProofRejection, verify_equivocation,
    };
    use super::super::{Key, VouchedGroup};
    use super::roster::{group, key, remove};
    use crate::session::installation::group_roster_vote_message;
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeSet;

    fn members(g: &VouchedGroup) -> BTreeSet<Key> {
        g.identities
            .keys()
            .copied()
            .filter(|k| g.membership(*k).is_some())
            .collect()
    }

    /// A real proof by `seed`'s key at the group's current head: two children, round 0, prepare.
    fn proof_at_head(g: &VouchedGroup, seed: u8) -> EquivocationProof {
        let (group_id, parent) = g.rotation_context();
        let sign = |child: [u8; 32]| {
            let message = group_roster_vote_message(group_id, parent, child, 0, 1);
            (
                child,
                SigningKey::from_bytes(&[seed; 32])
                    .sign(&message)
                    .to_bytes(),
            )
        };
        EquivocationProof::new(
            key(seed),
            group_id,
            parent,
            0,
            1,
            sign([1; 32]),
            sign([2; 32]),
        )
    }

    fn verify(g: &VouchedGroup, proof: &EquivocationProof) -> Result<Key, ProofRejection> {
        let (group_id, parent) = g.rotation_context();
        verify_equivocation(
            proof,
            &ProofContext {
                group: group_id,
                parent,
                roster: &members(g),
            },
        )
    }

    /// E4. A proof is scoped to the parent it names. It verifies there and only there: not at a
    /// descendant, not on a fork with a different history.
    #[test]
    fn a_proof_verifies_at_its_parent_and_not_at_a_descendant_or_fork() {
        let g = group(5);
        let proof = proof_at_head(&g, 11);
        assert_eq!(verify(&g, &proof), Ok(key(11)));

        let mut descendant = g.clone();
        descendant.mark_suspect(key(12)).unwrap();
        assert_eq!(
            verify(&descendant, &proof),
            Err(ProofRejection::WrongParent)
        );

        let mut fork_a = g.clone();
        let mut fork_b = g.clone();
        fork_a.mark_suspect(key(12)).unwrap();
        fork_b.mark_suspect(key(13)).unwrap();
        let on_a = proof_at_head(&fork_a, 11);
        assert_eq!(verify(&fork_a, &on_a), Ok(key(11)));
        assert_eq!(verify(&fork_b, &on_a), Err(ProofRejection::WrongParent));
    }

    /// E4. A proof against a key that has left is out of scope for a roster without it.
    #[test]
    fn a_proof_for_a_removed_key_is_not_on_the_new_roster() {
        let mut g = group(5);
        let proof = proof_at_head(&g, 11);
        assert_eq!(verify(&g, &proof), Ok(key(11)));
        remove(&mut g, key(11));
        let (group_id, _) = g.rotation_context();
        // Against the old parent's roster the proof is fine; the new head names another parent.
        let mut old_roster = members(&g);
        old_roster.insert(key(11));
        let old_parent = proof.parent;
        let result = verify_equivocation(
            &proof,
            &ProofContext {
                group: group_id,
                parent: old_parent,
                roster: &old_roster,
            },
        );
        assert_eq!(result, Ok(key(11)));
        assert_eq!(verify(&g, &proof), Err(ProofRejection::WrongParent));
        let after_removal = proof_at_head(&g, 11);
        assert_eq!(verify(&g, &after_removal), Err(ProofRejection::NotOnRoster));
    }

    /// E4 and E3. Recovery replaces a proven key. The proof names only the old key; the
    /// replacement counts toward the electorate and is not in the chain's proof set.
    #[test]
    fn a_recovered_replacement_key_is_not_named_by_the_old_keys_proof() {
        let mut g = group(5);
        let (old, new) = (key(11), key(99));
        let proof = proof_at_head(&g, 11);
        assert_eq!(verify(&g, &proof), Ok(old));
        g.mark_suspect(old).unwrap();
        assert_eq!(g.group.electorate_size(), 4);
        let revision = g.revision();
        g.apply_recovered_key(revision, old, new).unwrap();
        assert!(g.inherited_proof_keys().contains(&old));
        assert!(!g.inherited_proof_keys().contains(&new));
        assert!(!g.suspect.contains(&new));
        assert!(g.membership(old).is_none());
        // Five members, the old key replaced: the replacement votes.
        assert_eq!(g.group.electorate_size(), 5);
        let after = proof_at_head(&g, 99);
        assert_eq!(verify(&g, &after), Ok(new));
        assert_ne!(proof.scope().0, new);
    }
}
