//! W4d-1: the assembler against exhaustive enumeration, then with real keys and signatures.

use super::assembly::{AssemblyShortfall, plan_assembly};
use super::certificate_v1_tests::{group, key, proof_at_head, signing};
use super::electorate::{ElectorateQuorumCheck, check_electorate_quorum, quorum_for};
use super::proof::EquivocationProof;
use super::wire::{CertificateV1, VersionedCertificate};
use super::{Key, RosterVote, VouchedGroup};
use crate::session::installation::group_roster_vote_message;
use ed25519_dalek::Signer;
use std::collections::BTreeSet;

fn subsets(universe: &[u8], max_size: usize) -> Vec<BTreeSet<u8>> {
    let mut all = Vec::new();
    for mask in 0u32..1 << universe.len() {
        if mask.count_ones() as usize <= max_size {
            all.push(
                (0..universe.len())
                    .filter(|i| mask >> i & 1 == 1)
                    .map(|i| universe[i])
                    .collect(),
            );
        }
    }
    all
}

/// The best certificate by brute force: over every subset of the proofs, with every eligible
/// vote offered, the cheapest one the electorate helper accepts for both phases.
fn brute_force(
    roster: &BTreeSet<u8>,
    inherited: &BTreeSet<u8>,
    prepares: &BTreeSet<u8>,
    commits: &BTreeSet<u8>,
    proofs: &BTreeSet<u8>,
) -> Option<usize> {
    let proofs: Vec<u8> = proofs
        .iter()
        .copied()
        .filter(|p| roster.contains(p) && !inherited.contains(p))
        .collect();
    let mut best: Option<usize> = None;
    for chosen in subsets(&proofs, proofs.len()) {
        let carried: BTreeSet<u8> = inherited.union(&chosen).copied().collect();
        let eligible = roster.difference(&carried).count();
        let Some(required) = quorum_for(eligible) else {
            continue;
        };
        let accepted = [prepares, commits].iter().all(|signers| {
            let signers: BTreeSet<u8> = signers.difference(&carried).copied().collect();
            let signers: BTreeSet<u8> = signers.intersection(roster).copied().collect();
            check_electorate_quorum(&ElectorateQuorumCheck {
                roster,
                inherited,
                carried: &carried,
                reported: &BTreeSet::new(),
                signers: &signers,
            })
            .is_ok()
        });
        if accepted {
            let cost = chosen.len() * 229 + required * 192;
            best = Some(best.map_or(cost, |b| b.min(cost)));
        }
    }
    best
}

fn plan_cost(
    roster: &BTreeSet<u8>,
    inherited: &BTreeSet<u8>,
    prepares: &BTreeSet<u8>,
    commits: &BTreeSet<u8>,
    proofs: &BTreeSet<u8>,
) -> Option<usize> {
    let plan = plan_assembly(roster, inherited, prepares, commits, proofs).ok()?;
    // The plan's own proof set must be acceptable to the helper, not just cheap.
    let carried: BTreeSet<u8> = inherited.union(&plan.include).copied().collect();
    for signers in [prepares, commits] {
        let signers: BTreeSet<u8> = signers
            .difference(&carried)
            .copied()
            .filter(|s| roster.contains(s))
            .collect();
        assert!(
            check_electorate_quorum(&ElectorateQuorumCheck {
                roster,
                inherited,
                carried: &carried,
                reported: &BTreeSet::new(),
                signers: &signers,
            })
            .is_ok(),
            "plan {plan:?} is not acceptable"
        );
    }
    assert_eq!(
        quorum_for(roster.difference(&carried).count()),
        Some(plan.required)
    );
    Some(plan.include.len() * 229 + plan.required * 192)
}

/// Exhaustive over every vote pattern in both phases, every inherited set of up to two keys
/// and every held proof set of up to three keys, for rosters of 3 to 5. The class-count
/// search finds a certificate exactly when one exists and always finds the cheapest.
#[test]
fn class_count_search_matches_exhaustive_enumeration() {
    let mut checked = 0u32;
    let mut feasible = 0u32;
    let mut omission_needed = 0u32;
    for n in 3u8..=5 {
        let universe: Vec<u8> = (0..n).collect();
        let roster: BTreeSet<u8> = universe.iter().copied().collect();
        let all = subsets(&universe, universe.len());
        for inherited in subsets(&universe, 2) {
            for proofs in subsets(&universe, 3) {
                for prepares in &all {
                    for commits in &all {
                        let expected = brute_force(&roster, &inherited, prepares, commits, &proofs);
                        let got = plan_cost(&roster, &inherited, prepares, commits, &proofs);
                        assert_eq!(
                            got, expected,
                            "n {n} inherited {inherited:?} proofs {proofs:?} prepares {prepares:?} commits {commits:?}"
                        );
                        checked += 1;
                        if got.is_some() {
                            feasible += 1;
                        }
                        if let Ok(plan) =
                            plan_assembly(&roster, &inherited, prepares, commits, &proofs)
                        {
                            let usable: BTreeSet<u8> = proofs
                                .iter()
                                .copied()
                                .filter(|p| roster.contains(p) && !inherited.contains(p))
                                .collect();
                            if plan.include != usable {
                                omission_needed += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(checked > 100_000, "{checked}");
    assert!(feasible > 1_000, "{feasible}");
    // The model's point: sometimes the best certificate leaves a proof out.
    assert!(omission_needed > 0);
}

/// Larger rosters, spot-checked with the same oracle on structured inputs.
#[test]
fn larger_rosters_agree_with_the_oracle_on_structured_inputs() {
    for n in [7u8, 10, 13] {
        let universe: Vec<u8> = (0..n).collect();
        let roster: BTreeSet<u8> = universe.iter().copied().collect();
        let f = ((n as usize) - 1) / 3;
        for offenders in 0..=f {
            for voted_offenders in 0..=offenders {
                for honest_votes in 0..=(n as usize - offenders) {
                    let proofs: BTreeSet<u8> = (0..offenders as u8).collect();
                    let voters: BTreeSet<u8> = (0..voted_offenders as u8)
                        .chain(offenders as u8..(offenders + honest_votes) as u8)
                        .collect();
                    let none = BTreeSet::new();
                    assert_eq!(
                        plan_cost(&roster, &none, &voters, &voters, &proofs),
                        brute_force(&roster, &none, &voters, &voters, &proofs),
                        "n {n} offenders {offenders} voted {voted_offenders} honest {honest_votes}"
                    );
                }
            }
        }
    }
}

#[test]
fn certificates_that_cannot_be_encoded_are_not_planned() {
    // 200 members need 134 signers at the declared fault bound: more than a certificate holds.
    let roster: BTreeSet<u16> = (0..200).collect();
    let all = roster.clone();
    let none = BTreeSet::new();
    assert!(plan_assembly(&roster, &none, &all, &all, &none).is_err());
    // 192 members need exactly 128.
    let roster: BTreeSet<u16> = (0..192).collect();
    let plan = plan_assembly(&roster, &none, &roster, &roster, &none).unwrap();
    assert_eq!(plan.required, 128);
}

// ---------------------------------------------------------------------------------------------
// Real keys and signatures. Seven members, seeds 10 to 16; quorum 5, or 4 with one proof, or 4
// with two (five eligible).

const CHILD: [u8; 32] = [5; 32];

fn votes(g: &VouchedGroup, seeds: &[u8], phase: u8) -> Vec<RosterVote> {
    let (group_id, parent) = g.rotation_context();
    let message = group_roster_vote_message(group_id, parent, CHILD, 1, phase);
    seeds
        .iter()
        .map(|&seed| RosterVote {
            signer: key(seed),
            signature: signing(seed).sign(&message).to_bytes(),
        })
        .collect()
}

fn assemble(
    g: &VouchedGroup,
    voters: &[u8],
    offenders: &[u8],
) -> Result<CertificateV1, AssemblyShortfall> {
    let proofs: Vec<EquivocationProof> = offenders.iter().map(|&o| proof_at_head(g, o)).collect();
    g.assemble_certificate(
        CHILD,
        1,
        &votes(g, voters, 1),
        &votes(g, voters, 2),
        &proofs,
    )
}

fn passes(g: &VouchedGroup, certificate: &CertificateV1) {
    assert_eq!(
        g.verify_certificate_v1(CHILD, certificate).map(|_| ()),
        Ok(())
    );
}

#[test]
fn four_honest_votes_and_both_proofs_assemble_one_honest_member_offline() {
    let g = group();
    let certificate = assemble(&g, &[10, 11, 12, 13], &[15, 16]).unwrap();
    // One proof already brings the quorum to four of six, and the smallest certificate wins.
    assert_eq!(certificate.proofs.len(), 1);
    assert_eq!(certificate.certificate.prepares.len(), 4);
    passes(&g, &certificate);
}

#[test]
fn without_proofs_four_honest_votes_stall_and_three_never_suffice() {
    let g = group();
    assert_eq!(
        assemble(&g, &[10, 11, 12, 13], &[]).err(),
        Some(AssemblyShortfall {
            prepares: 4,
            commits: 4,
            required: 5
        })
    );
    assert_eq!(
        assemble(&g, &[10, 11, 12], &[15, 16]).err(),
        Some(AssemblyShortfall {
            prepares: 3,
            commits: 3,
            required: 4
        })
    );
}

#[test]
fn a_collector_leaves_out_a_proof_when_the_offender_voted_and_that_is_what_makes_quorum() {
    let g = group();
    // Offenders 15 and 16 voted alongside three honest members: five votes.
    let voters = [10, 11, 12, 15, 16];
    let certificate = assemble(&g, &voters, &[15, 16]).unwrap();
    // Attaching both proofs would leave three votes against a quorum of four, so it does not.
    assert!(certificate.proofs.len() < 2);
    passes(&g, &certificate);
    // With the proof for 16 only, six eligible need four votes and four are held; that is the
    // cheapest valid certificate, and it carries just that one proof.
    let signers: Vec<Key> = certificate
        .certificate
        .prepares
        .iter()
        .map(|v| v.signer)
        .collect();
    assert_eq!(signers.len(), 4 + 1 - certificate.proofs.len());
}

#[test]
fn unusable_inputs_are_dropped_not_trusted() {
    let g = group();
    let mut proofs = vec![proof_at_head(&g, 16), proof_at_head(&g, 99)];
    proofs[0].first.1[0] ^= 1; // a tampered proof is dropped
    let mut prepares = votes(&g, &[10, 11, 12, 13, 14], 1);
    let mut commits = votes(&g, &[10, 11, 12, 13, 14], 2);
    prepares[0].signature[0] ^= 1; // a bad signature
    commits.push(commits[1]); // a repeated vote
    commits.extend(votes(&g, &[99], 2)); // a non-member
    // Four good prepare votes against a quorum of five, no usable proof: a shortfall.
    assert_eq!(
        g.assemble_certificate(CHILD, 1, &prepares, &commits, &proofs)
            .err(),
        Some(AssemblyShortfall {
            prepares: 4,
            commits: 5,
            required: 5
        })
    );
    // A vote for another child does not count either.
    let (group_id, parent) = g.rotation_context();
    let other = group_roster_vote_message(group_id, parent, [6; 32], 1, 1);
    let wrong_child = RosterVote {
        signer: key(14),
        signature: signing(14).sign(&other).to_bytes(),
    };
    prepares[0] = wrong_child;
    assert!(
        g.assemble_certificate(CHILD, 1, &prepares, &commits, &[])
            .is_err()
    );
}

#[test]
fn proofs_already_on_the_chain_and_inherited_signers_are_left_out() {
    let mut g = group();
    g.mark_suspect(key(16)).unwrap();
    // Key 16 is inherited: its proof is redundant and its vote does not count.
    let certificate = assemble(&g, &[10, 11, 12, 13, 16], &[16]).unwrap();
    assert!(certificate.proofs.is_empty());
    assert!(
        certificate
            .certificate
            .prepares
            .iter()
            .all(|vote| vote.signer != key(16))
    );
    passes(&g, &certificate);
}

#[test]
fn output_is_deterministic_and_does_not_depend_on_input_order() {
    let g = group();
    let voters = [10, 11, 12, 13, 14, 15];
    let proofs = [proof_at_head(&g, 16), proof_at_head(&g, 15)];
    let forward = g
        .assemble_certificate(
            CHILD,
            1,
            &votes(&g, &voters, 1),
            &votes(&g, &voters, 2),
            &proofs,
        )
        .unwrap();
    let mut reversed_votes = votes(&g, &voters, 1);
    reversed_votes.reverse();
    let mut reversed_commits = votes(&g, &voters, 2);
    reversed_commits.reverse();
    let reversed = g
        .assemble_certificate(
            CHILD,
            1,
            &reversed_votes,
            &reversed_commits,
            &[proofs[1].clone(), proofs[0].clone()],
        )
        .unwrap();
    let encode = |c: CertificateV1| VersionedCertificate::V1(c).to_bytes().unwrap();
    assert_eq!(encode(forward), encode(reversed));
}

#[test]
fn assembling_changes_no_state() {
    let g = group();
    let before = (g.revision(), g.rotation_context(), g.chain_digest());
    let _ = assemble(&g, &[10, 11, 12, 13], &[15, 16]);
    assert_eq!(
        before,
        (g.revision(), g.rotation_context(), g.chain_digest())
    );
}

#[test]
fn an_assembled_certificate_survives_the_wire_and_is_applied() {
    let mut g = group();
    let (group_id, parent) = g.rotation_context();
    let message =
        crate::session::installation::group_rotation_message(group_id, parent, key(10), key(50));
    let rotation = super::SignedRotation::new(
        (group_id, parent),
        key(10),
        key(50),
        [10, 50].map(|seed| signing(seed).sign(&message).to_bytes()),
    );
    let child = g.rotation_child(&rotation).unwrap();
    let votes = |phase: u8| -> Vec<RosterVote> {
        let message = group_roster_vote_message(group_id, parent, child, 1, phase);
        [11u8, 12, 13, 14]
            .iter()
            .map(|&seed| RosterVote {
                signer: key(seed),
                signature: signing(seed).sign(&message).to_bytes(),
            })
            .collect()
    };
    let assembled = g
        .assemble_certificate(
            child,
            1,
            &votes(1),
            &votes(2),
            &[proof_at_head(&g, 15), proof_at_head(&g, 16)],
        )
        .unwrap();
    let bytes = VersionedCertificate::V1(assembled).to_bytes().unwrap();
    let VersionedCertificate::V1(received) = VersionedCertificate::from_bytes(&bytes).unwrap()
    else {
        panic!("expected version 1");
    };
    g.apply_certified_rotation(&rotation, &received).unwrap();
    assert!(g.membership(key(50)).is_some());
    assert_eq!(g.inherited_proof_keys().len(), 1);
    assert!(
        g.inherited_proof_keys()
            .is_subset(&BTreeSet::from([key(15), key(16)]))
    );
    assert_eq!(g.group.electorate_size(), 6);
}

#[test]
fn alternative_proofs_for_one_subject_are_chosen_independently_of_input_order() {
    let g = group();
    let first = proof_at_head(&g, 16);
    let (group_id, parent) = g.rotation_context();
    let sign = |child| {
        let message = group_roster_vote_message(group_id, parent, child, 1, 2);
        (child, signing(16).sign(&message).to_bytes())
    };
    let second = EquivocationProof::new(
        key(16),
        group_id,
        parent,
        1,
        2,
        sign([3; 32]),
        sign([4; 32]),
    );
    let prepares = votes(&g, &[10, 11, 12, 13], 1);
    let commits = votes(&g, &[10, 11, 12, 13], 2);
    // Four of seven needs a proof, so the selected representative reaches the wire.
    let expected_proof = first.clone().min(second.clone());
    let mut expected_bytes = None;
    for proofs in [
        vec![first.clone(), second.clone()],
        vec![second.clone(), first.clone()],
        vec![second.clone(), first.clone(), second],
    ] {
        let certificate = g
            .assemble_certificate(CHILD, 1, &prepares, &commits, &proofs)
            .unwrap();
        passes(&g, &certificate);
        assert_eq!(certificate.proofs, vec![expected_proof.clone()]);
        let bytes = VersionedCertificate::V1(certificate).to_bytes().unwrap();
        match &expected_bytes {
            None => expected_bytes = Some(bytes),
            Some(expected) => assert_eq!(&bytes, expected),
        }
    }
}
