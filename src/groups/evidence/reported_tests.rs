//! AS-2: reported keys on the chain (`docs/architecture/step2-agreed-suspension-plan.md`). A
//! reported key cannot vote but stays in the denominator. Nothing authorizes a report yet
//! (AS-3), so these tests record one directly.

use super::apply_v1_tests::{cert, snapshot, v1};
use super::certificate_v1_tests::{digest_of, group, key, proof_at_head};
use super::electorate::{ElectorateQuorumCheck, QuorumRejection, check_electorate_quorum};
use super::{CatchUp, Error, Key, VouchedGroup};
use crate::groups::Policy;
use std::collections::BTreeSet;

const FIVE: [u8; 5] = [11, 12, 13, 14, 15];

fn set(keys: &[u8]) -> BTreeSet<u8> {
    keys.iter().copied().collect()
}

fn run(
    roster: &[u8],
    carried: &[u8],
    reported: &[u8],
    signers: &[u8],
) -> Result<(usize, usize), QuorumRejection> {
    check_electorate_quorum(&ElectorateQuorumCheck {
        roster: &set(roster),
        inherited: &BTreeSet::new(),
        carried: &set(carried),
        reported: &set(reported),
        signers: &set(signers),
    })
    .map(|ok| (ok.eligible, ok.required))
}

#[test]
fn the_helper_keeps_reported_keys_in_the_denominator_and_out_of_the_signers() {
    let roster = [0, 1, 2, 3, 4, 5, 6];
    // Seven members need five whether or not any are reported.
    assert_eq!(run(&roster, &[], &[], &[0, 1, 2, 3, 4]), Ok((7, 5)));
    assert_eq!(run(&roster, &[], &[6], &[0, 1, 2, 3, 4]), Ok((7, 5)));
    assert_eq!(run(&roster, &[], &[5, 6], &[0, 1, 2, 3, 4]), Ok((7, 5)));
    // Four honest signers of the remaining six is short, as it would be unreported.
    assert_eq!(
        run(&roster, &[], &[6], &[0, 1, 2, 3]),
        Err(QuorumRejection::BelowQuorum {
            signers: 4,
            required: 5
        })
    );
    // A reported signer is not eligible, even when the count would reach the quorum.
    assert_eq!(
        run(&roster, &[], &[6], &[0, 1, 2, 3, 6]),
        Err(QuorumRejection::IneligibleSigner)
    );
    // A key that is reported and proven leaves the denominator as a proven key does.
    assert_eq!(run(&roster, &[6], &[6], &[0, 1, 2, 3]), Ok((6, 4)));
    // Three reported of seven leaves four voters for a quorum of five: no certificate.
    assert_eq!(
        run(&roster, &[], &[4, 5, 6], &[0, 1, 2, 3]),
        Err(QuorumRejection::BelowQuorum {
            signers: 4,
            required: 5
        })
    );
}

#[test]
fn a_certificate_counts_a_reported_key_in_the_denominator_but_never_as_a_signer() {
    let mut g = group();
    g.report_key_unauthorized(key(16));
    assert_eq!(g.reported_keys(), &BTreeSet::from([key(16)]));
    assert!(g.is_barred(&key(16)) && !g.suspect.contains(&key(16)));
    // The denominator is unchanged: seven members, five required.
    assert_eq!(g.group.electorate_size(), 7);
    assert_eq!(g.roster_quorum(), Ok(5));
    let policy = Policy::Majority;
    let child = g.policy_child(policy).unwrap();

    let mut ok = g.clone();
    ok.apply_certified_policy_change(policy, &cert(&g, child, &FIVE))
        .unwrap();
    // Four is short, and a reported signer is refused outright.
    for seeds in [&[11u8, 12, 13, 14][..], &[11, 12, 13, 14, 16][..]] {
        let mut h = g.clone();
        let before = snapshot(&h);
        assert_eq!(
            h.apply_certified_policy_change(policy, &cert(&g, child, seeds)),
            Err(Error::Ineligible)
        );
        assert_eq!(snapshot(&h), before);
    }
    // The reported key stays reported on the descendant.
    assert_eq!(ok.reported_keys(), &BTreeSet::from([key(16)]));
}

#[test]
fn a_proof_against_a_reported_key_moves_it_out_of_the_denominator() {
    let mut g = group();
    g.report_key_unauthorized(key(16));
    let child = g.policy_child(Policy::Majority).unwrap();
    // Proven and reported: six members remain in the count, four required, four available.
    let certificate = v1(&g, child, &[11, 12, 13, 14], vec![proof_at_head(&g, 16)]);
    let mut h = g.clone();
    h.apply_certified_policy_change(Policy::Majority, &certificate)
        .unwrap();
    assert!(h.inherited_proof_keys().contains(&key(16)));
    assert_eq!(h.group.electorate_size(), 6);
    // Without the proof the same four fall short.
    let mut control = g.clone();
    assert_eq!(
        control.apply_certified_policy_change(
            Policy::Majority,
            &v1(&g, child, &[11, 12, 13, 14], vec![])
        ),
        Err(Error::Ineligible)
    );
}

#[test]
fn the_digest_is_unchanged_without_reports_and_differs_with_them() {
    let plain = group();
    assert_eq!(plain.chain_digest(), digest_of(&plain));
    let mut a = plain.clone();
    a.report_key_unauthorized(key(16));
    let mut b = plain.clone();
    b.report_key_unauthorized(key(15));
    assert_ne!(a.chain_digest(), digest_of(&a));
    assert_ne!(a.chain_digest(), b.chain_digest());
    // A certificate built on the chain without the report is told to catch up.
    let child = a.policy_child(Policy::Majority).unwrap();
    let mut stale = v1(&a, child, &FIVE, vec![]);
    stale.chain_digest = digest_of(&a);
    let mut h = a.clone();
    assert_eq!(
        h.apply_certified_policy_change(Policy::Majority, &stale),
        Err(Error::ChainMismatch)
    );
}

#[test]
fn reports_are_inherited_by_descendants_and_not_leaked_to_forks() {
    let base = group();
    let mut reporting = base.clone();
    reporting.report_key_unauthorized(key(16));
    let fork = base.clone();
    assert!(fork.reported_keys().is_empty());
    let child = reporting.policy_child(Policy::Majority).unwrap();
    reporting
        .apply_certified_policy_change(Policy::Majority, &cert(&reporting, child, &FIVE))
        .unwrap();
    assert_eq!(reporting.reported_keys(), &BTreeSet::from([key(16)]));
    assert!(fork.reported_keys().is_empty());
    // A lagging replica catches up across the report and gains it.
    let mut lagging = base;
    assert_eq!(lagging.catch_up(&reporting), CatchUp::Applied);
    assert_eq!(lagging.reported_keys(), &BTreeSet::from([key(16)]));
}

#[test]
fn equal_heads_with_different_reports_are_not_the_same_chain() {
    let base = group();
    let id = [0xAB; 32];
    let (mut richer, mut poorer) = (base.clone(), base.clone());
    for (g, reports) in [
        (&mut richer, vec![key(16)]),
        (&mut poorer, Vec::<Key>::new()),
    ] {
        g.group.advance().unwrap();
        g.record_roster_child_reporting(id, Vec::new(), reports);
    }
    assert_eq!(richer.rotation_context(), poorer.rotation_context());
    assert_ne!(richer.chain_digest(), poorer.chain_digest());
    assert_eq!(richer.catch_up(&poorer), CatchUp::ConflictingHistory);
    assert_eq!(poorer.catch_up(&richer), CatchUp::ConflictingHistory);
}

#[test]
fn the_assembler_drops_reported_votes_and_still_builds_a_valid_certificate() {
    let mut g = group();
    g.report_key_unauthorized(key(16));
    let child = g.policy_child(Policy::Majority).unwrap();
    // The reported key's votes are among those held.
    let held = cert(&g, child, &[11, 12, 13, 14, 15, 16]);
    let certificate = g
        .assemble_certificate(child, 1, &held.prepares, &held.commits, &[])
        .unwrap();
    assert_eq!(certificate.certificate.prepares.len(), 5);
    assert!(
        certificate
            .certificate
            .prepares
            .iter()
            .all(|vote| vote.signer != key(16))
    );
    g.verify_certificate_v1(child, &certificate).unwrap();
    assert_eq!(certificate.chain_digest, g.chain_digest());
    // Four honest votes plus the reported one is still a shortfall.
    let short = cert(&g, child, &[11, 12, 13, 14, 16]);
    assert!(
        g.assemble_certificate(child, 1, &short.prepares, &short.commits, &[])
            .is_err()
    );
}

#[test]
fn reports_use_the_availability_budget_that_offline_members_use() {
    // Seven members: five required. Two reported leaves exactly five voters.
    let mut g: VouchedGroup = group();
    g.report_key_unauthorized(key(16));
    g.report_key_unauthorized(key(15));
    let child = g.policy_child(Policy::Majority).unwrap();
    let mut ok = g.clone();
    ok.apply_certified_policy_change(Policy::Majority, &cert(&g, child, &[10, 11, 12, 13, 14]))
        .unwrap();
    // One offline voter as well and no certificate can form.
    assert!(
        g.assemble_certificate(
            child,
            1,
            &cert(&g, child, &[10, 11, 12, 13]).prepares,
            &cert(&g, child, &[10, 11, 12, 13]).commits,
            &[],
        )
        .is_err()
    );
}

#[test]
fn a_merge_view_lists_each_report_at_the_revision_that_carried_it() {
    use crate::groups::merge::{MarkKind, SourceView};
    let mut g = group();
    let root = g.history_root();
    g.group.advance().unwrap();
    g.record_roster_child_reporting([0xA1; 32], Vec::new(), vec![key(16)]);
    g.group.advance().unwrap();
    g.record_roster_child([0xA2; 32]);
    g.group.advance().unwrap();
    g.record_roster_child_reporting([0xA3; 32], Vec::new(), vec![key(15)]);
    let mut reports = g.reports_by_revision();
    reports.sort_by_key(|(_, at)| *at);
    assert_eq!(reports, vec![(key(16), 1), (key(15), 3)]);
    assert_eq!(g.history_root(), root);
    let view = SourceView::from_group(&g);
    assert_eq!(view.head_revision, 3);
    assert_eq!(view.history, root);
    assert!(view.marks.iter().all(|m| m.kind == MarkKind::Reported));
    assert_eq!(view.marks.len(), 2);
}
