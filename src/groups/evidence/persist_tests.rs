//! F1: the group format round-trips byte for byte over enumerated histories, keeps catch-up
//! working against the original, and refuses every damaged or impossible input.

use super::persist::{GROUP_FORMAT_VERSION, GroupSnapshotError, MAX_GROUP_BYTES};
use super::{CatchUp, Key, VouchedGroup};
use ed25519_dalek::SigningKey;

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

fn round_trip(g: &VouchedGroup, context: &str) -> VouchedGroup {
    let bytes = g.to_bytes().unwrap();
    assert_eq!(bytes, g.to_bytes().unwrap(), "deterministic, {context}");
    let restored = VouchedGroup::from_bytes(&bytes).unwrap_or_else(|e| panic!("{context}: {e:?}"));
    assert_eq!(bytes, restored.to_bytes().unwrap(), "stable, {context}");
    assert_eq!(restored.revision(), g.revision(), "{context}");
    assert_eq!(restored.suspect, g.suspect, "{context}");
    assert_eq!(restored.group.excluded, g.group.excluded, "{context}");
    assert_eq!(
        restored.group.electorate_size(),
        g.group.electorate_size(),
        "{context}"
    );
    assert_eq!(restored.recognitions(), g.recognitions(), "{context}");
    let mut copy = restored.clone();
    assert_eq!(copy.catch_up(g), CatchUp::AlreadyCurrent, "{context}");
    restored
}

#[test]
fn enumerated_histories_round_trip() {
    let fresh = key(100);
    let mut checked = 0u32;
    for n in 2u8..=5 {
        let base: Vec<Key> = (0..n).map(|i| key(10 + i)).collect();
        let nu = n as usize;
        for suspect_mask in 0u32..1 << nu {
            for replaced in 0..=nu {
                for departed in 0..=nu {
                    let ctx = format!(
                        "n={n} mask={suspect_mask} replaced={replaced} departed={departed}"
                    );
                    let mut g = group(n);
                    round_trip(&g, &ctx);
                    for (i, k) in base.iter().enumerate() {
                        if suspect_mask >> i & 1 == 1 {
                            g.mark_suspect(*k).unwrap();
                            round_trip(&g, &ctx);
                        }
                    }
                    let mut current = base.clone();
                    if replaced < nu {
                        let child = g.derived_child(b"test-replace", &[&base[replaced]]);
                        g.replace_key(g.revision(), base[replaced], fresh, child)
                            .unwrap();
                        current[replaced] = fresh;
                        round_trip(&g, &ctx);
                    }
                    if departed < nu {
                        if let Some(tenure) = g.membership(current[departed]) {
                            g.apply_departure(current[departed], tenure).unwrap();
                            round_trip(&g, &ctx);
                        }
                    }
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 300);
}

#[test]
fn a_restored_group_keeps_working_after_the_restore() {
    let mut g = group(4);
    g.mark_suspect(key(10)).unwrap();
    let mut restored = round_trip(&g, "base");
    // The same next change on both lands on the same history.
    g.mark_suspect(key(11)).unwrap();
    restored.mark_suspect(key(11)).unwrap();
    assert_eq!(g.to_bytes().unwrap(), restored.to_bytes().unwrap());
}

#[test]
fn damaged_and_impossible_inputs_are_refused() {
    let mut g = group(4);
    g.mark_suspect(key(10)).unwrap();
    let bytes = g.to_bytes().unwrap();

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        VouchedGroup::from_bytes(&trailing).err(),
        Some(GroupSnapshotError::Malformed)
    );
    assert_eq!(
        VouchedGroup::from_bytes(&vec![0; MAX_GROUP_BYTES + 1]).err(),
        Some(GroupSnapshotError::TooLarge)
    );
    for len in 0..bytes.len() {
        assert!(
            VouchedGroup::from_bytes(&bytes[..len]).is_err(),
            "len {len}"
        );
    }
    for index in 0..bytes.len() {
        for bit in 0..8 {
            let mut damaged = bytes.clone();
            damaged[index] ^= 1 << bit;
            if let Ok(parsed) = VouchedGroup::from_bytes(&damaged) {
                // Whatever parses must itself save and restore cleanly.
                let again = parsed.to_bytes().unwrap();
                assert!(VouchedGroup::from_bytes(&again).is_ok());
            }
        }
    }
    assert_eq!(GROUP_FORMAT_VERSION, 1);
}
