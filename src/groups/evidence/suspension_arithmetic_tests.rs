//! AS-1: arithmetic for agreed suspension (`docs/architecture/step2-agreed-suspension-plan.md`).
//! No production code. A reported key loses its vote; the question is whether it also leaves
//! the denominator. Bounded enumeration through the real electorate helper, not a proof for
//! every roster chain; the per-parent fault bound stays an assumption.
//!
//! Model. A parent roster has `m` keys and fault bound `f(m)`. Proven keys `P` are faulty and
//! leave the denominator. Reported keys `R` (count `r`) may be honest. Two certificates for
//! one parent share `R` (it is on the chain) and differ in newly carried proofs, `a` and `b`
//! keys. Their signers come from `m - r` keys. With disjoint proof sets and the proven keys
//! outside the overlap, the honest overlap is at least
//! `q_a + q_b - (m - r) - f(m) + a + b`, and safety needs that to be positive.

use super::electorate::{ElectorateQuorumCheck, QuorumRejection, check_electorate_quorum};
use std::collections::BTreeSet;

fn fault_bound(n: usize) -> usize {
    if n <= 3 { 1 } else { (n - 1) / 3 }
}

/// The quorum the real helper requires for a roster of `m` keys with `excluded` of them taken
/// out of the denominator.
fn quorum(m: usize, excluded: usize) -> usize {
    let roster: BTreeSet<u16> = (0..m as u16).collect();
    let carried: BTreeSet<u16> = (0..excluded as u16).collect();
    match check_electorate_quorum(&ElectorateQuorumCheck {
        roster: &roster,
        inherited: &BTreeSet::new(),
        carried: &carried,
        reported: &BTreeSet::new(),
        signers: &BTreeSet::new(),
    }) {
        Err(QuorumRejection::BelowQuorum { required, .. }) => required,
        other => panic!("m {m} excluded {excluded}: {other:?}"),
    }
}

/// Quorum table `[m][excluded]` for `m` up to 400 and `excluded` up to `m - 1`.
fn table() -> Vec<Vec<usize>> {
    (0..=400usize)
        .map(|m| {
            if m < 4 {
                Vec::new()
            } else {
                (0..m).map(|e| quorum(m, e)).collect()
            }
        })
        .collect()
}

/// Smallest `r` for which a certificate can still exist: the voters left after the reported
/// and the proven keys must reach the quorum.
fn can_reach(
    table: &[Vec<usize>],
    m: usize,
    r: usize,
    a: usize,
    denominator_excludes_r: bool,
) -> bool {
    let voters = m.saturating_sub(r + a);
    let q = if denominator_excludes_r {
        table[m].get(r + a).copied()
    } else {
        table[m].get(a).copied()
    };
    q.is_some_and(|q| voters >= q)
}

#[test]
fn option_a_keeps_the_honest_intersection_bound_and_is_stronger_with_reports() {
    option_a_sweep(120, 100_000);
}

/// The full sweep to 400 members; about forty seconds, so it runs on request:
/// `cargo test --all-features -- --ignored option_a_full`.
#[test]
#[ignore]
fn option_a_full_sweep_to_four_hundred() {
    option_a_sweep(400, 100_000_000);
}

fn option_a_sweep(max_m: usize, min_reports: u64) {
    let table = table();
    let (mut cases, mut with_reports) = (0u64, 0u64);
    for m in 4..=max_m {
        let f = fault_bound(m);
        for a in 0..=f.min(m - 1) {
            for b in 0..=f.min(m - 1) {
                for r in 0..m {
                    if !can_reach(&table, m, r, a, false) || !can_reach(&table, m, r, b, false) {
                        continue;
                    }
                    let (qa, qb) = (table[m][a] as i64, table[m][b] as i64);
                    let lhs = qa + qb - (m - r) as i64 - f as i64 + (a + b) as i64;
                    // The same bound with no reports, which earlier work already pinned.
                    let without = qa + qb - m as i64 - f as i64 + (a + b) as i64;
                    assert!(without > 0, "baseline m {m} a {a} b {b}");
                    assert_eq!(lhs, without + r as i64);
                    assert!(lhs > 0, "option A: m {m} f {f} a {a} b {b} r {r}: {lhs}");
                    cases += 1;
                    with_reports += (r > 0) as u64;
                }
            }
        }
    }
    println!("AS-1 option A: {cases} cases ({with_reports} with reports), bound held in every one");
    assert!(with_reports > min_reports);
}

/// Control. Shrinking the denominator for reported keys (option B) must break the same bound
/// somewhere, and only where there is at least one report, or the check above proves nothing.
#[test]
fn option_b_breaks_the_bound_so_the_check_is_a_real_control() {
    let table = table();
    let (mut broken, mut cases) = (0u64, 0u64);
    let mut first: Option<(usize, usize, usize, usize, i64)> = None;
    let mut first_single: Option<(usize, usize, usize, usize, i64)> = None;
    for m in 4..=120usize {
        let f = fault_bound(m);
        for a in 0..=f.min(m - 1) {
            for b in 0..=f.min(m - 1) {
                for r in 0..m {
                    if !can_reach(&table, m, r, a, true) || !can_reach(&table, m, r, b, true) {
                        continue;
                    }
                    let (qa, qb) = (table[m][r + a] as i64, table[m][r + b] as i64);
                    let lhs = qa + qb - (m - r) as i64 - f as i64 + (a + b) as i64;
                    cases += 1;
                    if lhs <= 0 {
                        assert!(r > 0, "no reports must never break: m {m} a {a} b {b}");
                        broken += 1;
                        first.get_or_insert((m, a, b, r, lhs));
                        if r == 1 {
                            first_single.get_or_insert((m, a, b, r, lhs));
                        }
                    }
                }
            }
        }
    }
    let (m, a, b, r, lhs) = first.expect("option B never broke the bound");
    println!(
        "AS-1 option B: {broken} of {cases} cases break; first at m {m} a {a} b {b} r {r} ({lhs})"
    );
    let (m, a, b, r, lhs) = first_single.expect("a single report never broke the bound");
    println!("AS-1 option B, one report: first at m {m} a {a} b {b} r {r} ({lhs})");
    assert!(broken > 0);
}

/// Liveness. Under option A a group of `m` with `a` proven keys needs `q(m - a)` votes from
/// `m - a - r` keys. This tabulates how many members can be reported, and how many honest
/// members can additionally be offline, before no certificate can form.
#[test]
fn liveness_cost_of_option_a() {
    let table = table();
    println!("AS-1 liveness (a = 0): m, quorum, max reports r, then offline tolerance at r");
    for m in [4usize, 5, 6, 7, 10, 13, 16, 25, 50, 100, 192] {
        let q = table[m][0];
        // Stalled exactly when m - r - offline < q, so the budget for r + offline is m - q.
        let budget = m - q;
        println!(
            "  m {m:>3}  q {q:>3}  r + offline <= {budget:>3}  fault bound {}",
            fault_bound(m)
        );
        // The budget never exceeds the fault bound by more than the rounding in the quorum.
        assert!(budget >= fault_bound(m));
        // At the budget a certificate can still form, one past it cannot.
        assert!(can_reach(&table, m, budget, 0, false));
        assert!(!can_reach(&table, m, budget + 1, 0, false));
    }
    // A proven key costs the same single vote but also lowers the quorum; a reported key
    // never lowers it. For every size, one proven key leaves a larger budget than one report.
    for (m, row) in table.iter().enumerate().take(401).skip(7) {
        let proven = (m - 1) - row[1];
        let reported = m - 1 - row[0];
        assert!(
            proven >= reported,
            "m {m}: proven budget {proven} reported {reported}"
        );
    }
}
