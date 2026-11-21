//! Electorate and quorum arithmetic for proof-carrying certificates (decision C in
//! `docs/architecture/group-and-facade-design-intent.md`).
//!
//! One pure function answers one question: given the parent roster, the proof subjects a
//! certificate carries, the proof subjects inherited from its authenticated parent chain, and
//! the signers named on it, do the signers reach the quorum for the remaining electorate?
//!
//! **Trusted-input boundary.** The result is arithmetic only. It is *not* authority to apply a
//! transition, and it cannot establish signature validity, proof soundness or scope, operation
//! authorization, the fault bound, parent selection or signing-lock safety. The caller must
//! guarantee that:
//! - `roster` is the exact authenticated parent roster;
//! - `inherited` holds the subject keys of verified proofs on the selected authenticated chain;
//! - `carried` holds only subject keys of verified proofs with the required group and parent
//!   scope (unchecked keys can shrink the electorate and the quorum arbitrarily);
//! - `signers` are unique, signature-verified keys for one exact signed context. A caller that
//!   starts from a list must reject duplicate entries *before* building the set, because a
//!   `BTreeSet` silently removes them.
//!
//! Approval policies (inviter-only, ejection targets, contact levels, presence) never edit the
//! roster passed here, and a satisfied threshold does not authorize a transition.
//!
//! Used by `VouchedGroup::check_vote_quorum` (wiring slice W1,
//! `docs/architecture/proof-carrying-wiring-plan.md`).

use std::collections::BTreeSet;

/// Everything a certificate's quorum check may depend on, and nothing else.
pub(crate) struct ElectorateQuorumCheck<'a, K: Ord + Copy> {
    /// The exact authenticated parent roster.
    pub roster: &'a BTreeSet<K>,
    /// Subject keys of proofs carried by the authenticated parent chain.
    pub inherited: &'a BTreeSet<K>,
    /// Subject keys of proofs this certificate carries.
    pub carried: &'a BTreeSet<K>,
    /// Keys reported on the authenticated chain. They lose their vote but stay in the
    /// denominator, so the quorum is the one for the roster without them removed: a report
    /// proves nothing, and shrinking the count for a possibly honest key breaks the
    /// honest-intersection bound (`suspension_arithmetic_tests`, AS-1). A key that is also in
    /// `carried` leaves the denominator as a proven key does.
    pub reported: &'a BTreeSet<K>,
    /// Unique, verified signers of one exact signed context.
    pub signers: &'a BTreeSet<K>,
}

/// The arithmetic that was applied. Carries no authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct QuorumSatisfied {
    pub eligible: usize,
    pub required: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QuorumRejection {
    EmptyRoster,
    /// `carried` does not contain every inherited subject key (checked before any roster filter,
    /// so a proof against a departed key must still be carried).
    DropsInheritedProof,
    /// No member remains once the carried keys are excluded. A zero quorum never authorizes an
    /// empty certificate.
    EmptyElectorate,
    /// A signer is outside the roster, excluded by `carried`, or reported.
    IneligibleSigner,
    BelowQuorum {
        signers: usize,
        required: usize,
    },
}

/// Quorum for an electorate of `eligible` members: all of them for 1 to 3, otherwise
/// `(e + (e - 1) / 3) / 2 + 1`. Same arithmetic as `Group::roster_quorum`.
pub(crate) fn quorum_for(eligible: usize) -> Option<usize> {
    match eligible {
        0 => None,
        1..=3 => Some(eligible),
        _ => Some((eligible + (eligible - 1) / 3) / 2 + 1),
    }
}

/// Checks that the signers reach the quorum for the roster minus the carried proof subjects.
/// Error precedence: empty roster, dropped inherited proof, empty electorate, ineligible signer,
/// below quorum.
pub(crate) fn check_electorate_quorum<K: Ord + Copy>(
    check: &ElectorateQuorumCheck<'_, K>,
) -> Result<QuorumSatisfied, QuorumRejection> {
    if check.roster.is_empty() {
        return Err(QuorumRejection::EmptyRoster);
    }
    // Inheritance first, against the full carried set: a departed offender's proof stays carried
    // even though it excludes nobody from the current roster.
    if !check.inherited.is_subset(check.carried) {
        return Err(QuorumRejection::DropsInheritedProof);
    }
    // Set difference ignores carried keys outside the roster, so a departed key never reduces the
    // electorate again.
    let eligible: BTreeSet<K> = check.roster.difference(check.carried).copied().collect();
    let required = quorum_for(eligible.len()).ok_or(QuorumRejection::EmptyElectorate)?;
    if check
        .signers
        .iter()
        .any(|signer| !eligible.contains(signer) || check.reported.contains(signer))
    {
        return Err(QuorumRejection::IneligibleSigner);
    }
    if check.signers.len() < required {
        return Err(QuorumRejection::BelowQuorum {
            signers: check.signers.len(),
            required,
        });
    }
    Ok(QuorumSatisfied {
        eligible: eligible.len(),
        required,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(keys: impl IntoIterator<Item = u8>) -> BTreeSet<u8> {
        keys.into_iter().collect()
    }

    fn run(
        roster: &[u8],
        inherited: &[u8],
        carried: &[u8],
        signers: &[u8],
    ) -> Result<QuorumSatisfied, QuorumRejection> {
        check_electorate_quorum(&ElectorateQuorumCheck {
            roster: &set(roster.iter().copied()),
            inherited: &set(inherited.iter().copied()),
            carried: &set(carried.iter().copied()),
            reported: &BTreeSet::new(),
            signers: &set(signers.iter().copied()),
        })
    }

    /// Independent definition: the smallest quorum such that two quorums of an electorate overlap
    /// in more than the faulty members the electorate tolerates, with all of an electorate of
    /// 1 to 3. Searched, not copied from the production expression.
    fn reference_quorum(eligible: usize) -> usize {
        if eligible <= 3 {
            return eligible;
        }
        let faulty = (eligible - 1) / 3;
        (1..=eligible).find(|q| 2 * q > eligible + faulty).unwrap()
    }

    /// Straight-line reference for the whole check, written separately from the helper.
    fn reference(
        roster: &[u8],
        inherited: &[u8],
        carried: &[u8],
        signers: &[u8],
    ) -> Result<(usize, usize), QuorumRejection> {
        if roster.is_empty() {
            return Err(QuorumRejection::EmptyRoster);
        }
        if inherited.iter().any(|k| !carried.contains(k)) {
            return Err(QuorumRejection::DropsInheritedProof);
        }
        let eligible: Vec<u8> = roster
            .iter()
            .copied()
            .filter(|k| !carried.contains(k))
            .collect();
        if eligible.is_empty() {
            return Err(QuorumRejection::EmptyElectorate);
        }
        if signers.iter().any(|s| !eligible.contains(s)) {
            return Err(QuorumRejection::IneligibleSigner);
        }
        let required = reference_quorum(eligible.len());
        if signers.len() < required {
            return Err(QuorumRejection::BelowQuorum {
                signers: signers.len(),
                required,
            });
        }
        Ok((eligible.len(), required))
    }

    #[test]
    fn quorum_matches_independent_reference_and_known_values() {
        assert_eq!(quorum_for(0), None);
        for e in 1..=400 {
            assert_eq!(quorum_for(e), Some(reference_quorum(e)), "eligible {e}");
        }
        // Fixed cross-checks, including the arithmetic in `Group::roster_quorum`.
        let known = [
            (1, 1),
            (2, 2),
            (3, 3),
            (4, 3),
            (5, 4),
            (6, 4),
            (7, 5),
            (10, 7),
            (13, 9),
        ];
        for (e, q) in known {
            assert_eq!(quorum_for(e), Some(q), "eligible {e}");
        }
    }

    #[test]
    fn complete_enumeration_matches_reference_at_small_sizes() {
        const FOREIGN: u8 = 200;
        for n in [2u8, 3, 4, 5, 7] {
            let roster: Vec<u8> = (0..n).collect();
            let mut universe = roster.clone();
            universe.push(FOREIGN);
            let bits = universe.len();
            let pick = |mask: u32| -> Vec<u8> {
                (0..bits)
                    .filter(|i| mask >> i & 1 == 1)
                    .map(|i| universe[i])
                    .collect()
            };
            for carried_mask in 0..1u32 << bits {
                let carried = pick(carried_mask);
                // every inherited subset of carried
                let mut inherited_mask = carried_mask;
                loop {
                    let inherited = pick(inherited_mask);
                    for signer_mask in 0..1u32 << bits {
                        let signers = pick(signer_mask);
                        let got = run(&roster, &inherited, &carried, &signers)
                            .map(|ok| (ok.eligible, ok.required));
                        assert_eq!(
                            got,
                            reference(&roster, &inherited, &carried, &signers),
                            "n {n} inherited {inherited:?} carried {carried:?} signers {signers:?}"
                        );
                    }
                    if inherited_mask == 0 {
                        break;
                    }
                    inherited_mask = (inherited_mask - 1) & carried_mask;
                }
            }
        }
    }

    #[test]
    fn named_boundary_cases() {
        // Empty roster, all keys carried, empty signer set.
        assert_eq!(run(&[], &[], &[], &[]), Err(QuorumRejection::EmptyRoster));
        assert_eq!(
            run(&[1, 2, 3], &[], &[1, 2, 3], &[]),
            Err(QuorumRejection::EmptyElectorate)
        );
        assert_eq!(
            run(&[1, 2, 3], &[], &[], &[]),
            Err(QuorumRejection::BelowQuorum {
                signers: 0,
                required: 3
            })
        );
        // Inherited proof against a departed key must still be carried; carrying it excludes nobody.
        assert_eq!(
            run(&[1, 2, 3, 4], &[9], &[], &[1, 2, 3]),
            Err(QuorumRejection::DropsInheritedProof)
        );
        let ok = run(&[1, 2, 3, 4], &[9], &[9], &[1, 2, 3]).unwrap();
        assert_eq!((ok.eligible, ok.required), (4, 3));
        // A signer outside the roster, or a carried key, is ineligible even with enough signers.
        assert_eq!(
            run(&[1, 2, 3, 4], &[], &[], &[1, 2, 3, 77]),
            Err(QuorumRejection::IneligibleSigner)
        );
        assert_eq!(
            run(&[1, 2, 3, 4], &[], &[4], &[1, 2, 4]),
            Err(QuorumRejection::IneligibleSigner)
        );
        // Carrying only nonmember keys never shrinks the electorate.
        assert_eq!(
            run(&[1, 2, 3, 4], &[], &[50, 51], &[1, 2, 3])
                .unwrap()
                .eligible,
            4
        );
        // Exact quorum, one below, and extra eligible signers.
        assert!(run(&[1, 2, 3, 4, 5, 6, 7], &[], &[], &[1, 2, 3, 4, 5]).is_ok());
        assert_eq!(
            run(&[1, 2, 3, 4, 5, 6, 7], &[], &[], &[1, 2, 3, 4]),
            Err(QuorumRejection::BelowQuorum {
                signers: 4,
                required: 5
            })
        );
        assert!(run(&[1, 2, 3, 4, 5, 6, 7], &[], &[], &[1, 2, 3, 4, 5, 6, 7]).is_ok());
        // Several departed proof keys together with newly excluded current keys.
        let ok = run(
            &[1, 2, 3, 4, 5, 6, 7],
            &[90, 91],
            &[90, 91, 6, 7],
            &[1, 2, 3, 4],
        )
        .unwrap();
        assert_eq!((ok.eligible, ok.required), (5, 4));
        // Seven members, both offenders carried: four honest signatures suffice.
        assert!(run(&[1, 2, 3, 4, 5, 6, 7], &[], &[6, 7], &[1, 2, 3, 4]).is_ok());
        // Four members, one offender carried: every honest member must sign (no spare).
        assert_eq!(
            run(&[1, 2, 3, 4], &[], &[4], &[1, 2]),
            Err(QuorumRejection::BelowQuorum {
                signers: 2,
                required: 3
            })
        );
    }

    #[test]
    fn departed_key_is_not_subtracted_twice() {
        // Seven members, one carried current key and two departed proof keys.
        let roster: Vec<u8> = (1..=7).collect();
        let carried = [7, 90, 91];
        let ok = run(&roster, &[90, 91], &carried, &[1, 2, 3, 4]).unwrap();
        let double_subtraction = roster.len() - carried.len();
        assert_eq!(ok.eligible, 6);
        assert_ne!(ok.eligible, double_subtraction);
        // The double-subtraction arithmetic would have set a lower quorum than the correct one.
        assert!(quorum_for(double_subtraction).unwrap() < ok.required);
    }

    #[test]
    fn result_depends_only_on_the_four_inputs() {
        let a = run(&[3, 1, 2, 5, 4, 7, 6], &[9], &[9, 6, 7], &[4, 3, 2, 1]);
        let b = run(&[1, 2, 3, 4, 5, 6, 7], &[9], &[7, 9, 6], &[1, 2, 3, 4]);
        assert_eq!(a, b);
        assert_eq!(
            a,
            run(&[1, 2, 3, 4, 5, 6, 7], &[9], &[9, 6, 7], &[1, 2, 3, 4])
        );
    }

    /// Two certificates on one parent, with sound proof sets of sizes `a` and `b` and at most `f`
    /// faulty keys, always share an honest signer when
    /// `q(n - a) + q(n - b) - n - f + a + b > 0`. This is a sufficient arithmetic bound under sound
    /// proofs, the fault bound, distinct eligible signers and one operation per honest voter. It is
    /// not a proof about every concrete certificate. A false or foreign proof set is a
    /// caller-validation failure and is outside what this helper can guarantee.
    #[test]
    fn honest_intersection_bound_holds_for_helper_quorums() {
        // Quorums come from the real helper, via the `required` it reports for an empty signer set.
        let required_for = |n: usize, carried: usize| -> i64 {
            let roster = set(0..n as u8);
            let carried = set(0..carried as u8);
            match check_electorate_quorum(&ElectorateQuorumCheck {
                roster: &roster,
                inherited: &BTreeSet::new(),
                carried: &carried,
                reported: &BTreeSet::new(),
                signers: &BTreeSet::new(),
            }) {
                Err(QuorumRejection::BelowQuorum { required, .. }) => required as i64,
                other => panic!("n {n} carried {carried:?}: {other:?}"),
            }
        };
        // For n = 2 and 3 the declared assumption is one faulty member, because
        // `(n - 1) / 3` would give zero there. For 4 and up it is `(n - 1) / 3`.
        for n in 2usize..=45 {
            let f: usize = if n <= 3 { 1 } else { (n - 1) / 3 };
            for a in 0..=f.min(n - 1) {
                for b in 0..=f.min(n - 1) {
                    let lhs = required_for(n, a) + required_for(n, b) - n as i64 - f as i64
                        + a as i64
                        + b as i64;
                    assert!(lhs > 0, "n {n} f {f} a {a} b {b}: {lhs}");
                }
            }
        }
    }

    #[test]
    fn offline_tolerance_after_all_offenders_are_carried() {
        // Honest members who may be offline once every faulty key is carried (decision C).
        let tolerance = |n: usize| -> usize {
            let f = if n <= 3 { 1 } else { (n - 1) / 3 };
            let eligible = n - f;
            eligible - quorum_for(eligible).unwrap()
        };
        for n in [2, 3, 4] {
            assert_eq!(tolerance(n), 0, "n {n}");
        }
        for n in [5, 6, 7] {
            assert_eq!(tolerance(n), 1, "n {n}");
        }
        assert_eq!(tolerance(10), 2);
        assert_eq!(tolerance(13), 3);
        assert_eq!(tolerance(100), 22);
    }
}
