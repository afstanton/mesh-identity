//! W4b: the chain-borne proof store must leave today's behaviour unchanged. The suspension
//! mirrors (`suspect`, `excluded`) are compared against what the chain carries, on current
//! members, over enumerated operation sequences.

use super::proof::{CarriedProof, ProofRejection, check_inheritance};
use super::{Key, VouchedGroup};
use ed25519_dalek::SigningKey;
use std::collections::BTreeSet;
use std::sync::Arc;

fn key(seed: u8) -> Key {
    SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes()
}

fn group(n: u8) -> VouchedGroup {
    VouchedGroup::new(
        7,
        (0..n).map(|i| key(10 + i)),
        crate::groups::Policy::InviterOnly,
    )
}

/// The mirrors agree with the chain, restricted to current members and roster identities.
fn assert_mirrors_match_chain(group: &VouchedGroup, context: &str) {
    let members: BTreeSet<Key> = group
        .identities
        .keys()
        .copied()
        .filter(|k| group.membership(*k).is_some())
        .collect();
    let chain: BTreeSet<Key> = group
        .inherited_proof_keys()
        .intersection(&members)
        .copied()
        .collect();
    let mirror: BTreeSet<Key> = group.suspect.intersection(&members).copied().collect();
    assert_eq!(mirror, chain, "suspect mirror, {context}");
    let excluded_identities: BTreeSet<_> = group
        .group
        .excluded
        .iter()
        .copied()
        .filter(|id| group.group.roster.contains_key(id))
        .collect();
    let expected: BTreeSet<_> = chain
        .iter()
        .filter_map(|k| group.identities.get(k).copied())
        .collect();
    assert_eq!(excluded_identities, expected, "excluded mirror, {context}");
    assert_eq!(
        group.group.electorate_size(),
        members.len() - chain.len(),
        "electorate size, {context}"
    );
}

#[test]
fn mirrors_match_the_chain_over_enumerated_sequences() {
    let fresh = key(100);
    let mut checked = 0u32;
    for n in 2u8..=6 {
        let base: Vec<Key> = (0..n).map(|i| key(10 + i)).collect();
        let nu = n as usize;
        for suspect_mask in 0u32..1 << nu {
            for replaced in 0..=nu {
                for departed in 0..=nu {
                    let mut g = group(n);
                    let ctx = format!(
                        "n={n} mask={suspect_mask} replaced={replaced} departed={departed}"
                    );
                    assert_mirrors_match_chain(&g, &ctx);
                    for (i, k) in base.iter().enumerate() {
                        if suspect_mask >> i & 1 == 1 {
                            g.mark_suspect(*k).unwrap();
                            assert_mirrors_match_chain(&g, &ctx);
                        }
                    }
                    let mut current = base.clone();
                    if replaced < nu {
                        let child = g.derived_child(b"test-replace", &[&base[replaced]]);
                        g.replace_key(g.revision(), base[replaced], fresh, child)
                            .unwrap();
                        current[replaced] = fresh;
                        assert_mirrors_match_chain(&g, &ctx);
                    }
                    if departed < nu {
                        let who = current[departed];
                        if let Some(tenure) = g.membership(who) {
                            g.apply_departure(who, tenure).unwrap();
                            assert_mirrors_match_chain(&g, &ctx);
                        }
                    }
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 1000);
}

#[test]
fn a_descendant_inherits_every_ancestor_proof() {
    let mut g = group(5);
    let (a, b) = (key(10), key(11));
    g.mark_suspect(a).unwrap();
    let after_a = g.inherited_proof_keys().clone();
    g.mark_suspect(b).unwrap();
    assert_eq!(after_a, BTreeSet::from([a]));
    assert_eq!(g.inherited_proof_keys(), &BTreeSet::from([a, b]));
    // Ordinary nodes carry nothing and share the parent's set.
    let before = Arc::clone(&g.history.inherited);
    g.record_roster_child([5; 32]);
    assert!(Arc::ptr_eq(&before, &g.history.inherited));
    assert!(g.history.carried.is_empty());
    // The node that carried `b` retains it.
    let parent = g.history.parent.as_ref().unwrap();
    assert_eq!(parent.carried, vec![CarriedProof::SimulationReport(b)]);
}

#[test]
fn a_proof_on_one_fork_does_not_reach_a_sibling_or_the_ancestor() {
    let mut g = group(5);
    g.mark_suspect(key(10)).unwrap();
    let mut left = g.clone();
    let mut right = g.clone();
    left.mark_suspect(key(11)).unwrap();
    right.mark_suspect(key(12)).unwrap();
    assert_eq!(g.inherited_proof_keys(), &BTreeSet::from([key(10)]));
    assert_eq!(
        left.inherited_proof_keys(),
        &BTreeSet::from([key(10), key(11)])
    );
    assert_eq!(
        right.inherited_proof_keys(),
        &BTreeSet::from([key(10), key(12)])
    );
    assert!(!g.suspect.contains(&key(11)) && !right.suspect.contains(&key(11)));
}

#[test]
fn catch_up_adopts_the_remote_store_and_ignores_older_snapshots() {
    let mut behind = group(5);
    let mut ahead = behind.clone();
    ahead.mark_suspect(key(11)).unwrap();
    assert_eq!(behind.catch_up(&ahead), super::CatchUp::Applied);
    assert_eq!(behind.inherited_proof_keys(), &BTreeSet::from([key(11)]));
    assert!(behind.suspect.contains(&key(11)));
    assert_mirrors_match_chain(&behind, "after catch_up");

    let older = group(5);
    let mut current = behind.clone();
    assert_ne!(current.catch_up(&older), super::CatchUp::Applied);
    assert_eq!(current.inherited_proof_keys(), &BTreeSet::from([key(11)]));
}

#[test]
fn removed_suspect_keeps_its_proof_on_the_chain_and_cannot_return() {
    let mut g = group(5);
    let who = key(11);
    g.mark_suspect(who).unwrap();
    let tenure = g.membership(who).unwrap();
    g.apply_departure(who, tenure).unwrap();
    assert!(g.inherited_proof_keys().contains(&who));
    assert!(g.retired.contains(&who));
    assert!(g.membership(who).is_none());
}

#[test]
fn check_inheritance_rejects_a_carried_set_that_drops_a_proof() {
    let inherited = BTreeSet::from([key(1), key(2)]);
    assert_eq!(check_inheritance(&inherited, &inherited), Ok(()));
    let more = BTreeSet::from([key(1), key(2), key(3)]);
    assert_eq!(check_inheritance(&inherited, &more), Ok(()));
    let fewer = BTreeSet::from([key(1)]);
    assert_eq!(
        check_inheritance(&inherited, &fewer),
        Err(ProofRejection::DropsInheritedProof)
    );
    assert_eq!(
        check_inheritance(&BTreeSet::new(), &BTreeSet::new()),
        Ok(())
    );
}

#[test]
fn a_very_long_history_drops_without_overflowing_the_stack() {
    let mut g = group(3);
    g.mark_suspect(key(10)).unwrap();
    for i in 0..20_000u32 {
        let mut id = [0u8; 32];
        id[..4].copy_from_slice(&i.to_be_bytes());
        g.record_roster_child(id);
    }
    drop(g);
}
