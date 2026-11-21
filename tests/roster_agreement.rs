#![cfg(all(feature = "groups", feature = "test-support"))]
//! Safety experiment for finalizing one child of a fixed parent roster.
//! The fixture assumes authenticated votes and durable honest voter locks.

fn quorum(roster_size: u32, max_equivocators: u32) -> u32 {
    assert!(roster_size > 3 * max_equivocators);
    (roster_size + max_equivocators) / 2 + 1
}

#[test]
fn conflicting_finalizations_require_more_equivocators_than_allowed() {
    for (members, faults) in [(3, 0), (4, 1), (5, 1), (7, 2)] {
        let required = quorum(members, faults);
        let quorums: Vec<_> = (0..(1_u32 << members))
            .filter(|set| set.count_ones() >= required)
            .collect();
        for &left in &quorums {
            for &right in &quorums {
                // A vote appearing on both children would have to equivocate.
                assert!((left & right).count_ones() > faults);
            }
        }
        assert!(members - faults >= required);
    }
}

#[test]
fn four_member_partition_waits_for_three_votes() {
    let required = quorum(4, 1);
    let left = 0b0011_u32;
    let right = 0b1100_u32;
    assert!(left.count_ones() < required);
    assert!(right.count_ones() < required);

    // Even if a voter on the left also votes on the right, only the right
    // can finalize. Duplicate delivery contributes no additional vote.
    let right_with_equivocator = right | 0b0001;
    assert_eq!(right_with_equivocator.count_ones(), required);
    assert_eq!(right_with_equivocator | 0b0001, right_with_equivocator);
    assert!(left.count_ones() < required);
}

#[test]
fn split_honest_locks_can_stall_even_after_reconnect() {
    let required = quorum(4, 1);
    let left = 0b0011_u32;
    let right = 0b1100_u32;

    // Delivery of both sets after reconnect gives everyone the same view,
    // but neither proposal can gain a vote without changing an honest lock.
    assert_eq!((left | right).count_ones(), 4);
    assert_eq!(left & right, 0);
    assert!(left.count_ones() < required && right.count_ones() < required);
}

// These masks represent distinct authenticated signing keys. The supplied
// parent and child tags stand in for authenticated statement bindings.
struct Finalization<'a> {
    parent: u32,
    child: u32,
    votes: &'a [(u32, u32, u32)],
}

impl Finalization<'_> {
    fn meets_quorum(&self, electorate: u32, faults: u32) -> bool {
        let votes = self
            .votes
            .iter()
            .fold(0, |accepted, &(key, parent, child)| {
                if key.is_power_of_two() && parent == self.parent && child == self.child {
                    accepted | (key & electorate)
                } else {
                    accepted
                }
            });
        votes.count_ones() >= quorum(electorate.count_ones(), faults)
    }
}

#[test]
fn replacement_key_votes_only_after_its_roster_is_finalized() {
    let old_electorate = 0b01111;
    let new_electorate = 0b10111;
    let invalid_rotation = Finalization {
        parent: 0,
        child: 1,
        votes: &[(1, 0, 1), (2, 0, 1), (16, 0, 1)],
    };
    assert!(!invalid_rotation.meets_quorum(old_electorate, 1));

    let rotation = Finalization {
        parent: 0,
        child: 1,
        votes: &[(1, 0, 1), (2, 0, 1), (4, 0, 1)],
    };
    assert!(rotation.meets_quorum(old_electorate, 1));

    let stale_votes = Finalization {
        parent: 1,
        child: 2,
        votes: &[
            (1, 1, 2),
            (1, 1, 2),
            (2, 1, 2),
            (8, 1, 2),
            (4, 0, 1),
            (16, 1, 3),
        ],
    };
    assert!(!stale_votes.meets_quorum(new_electorate, 1));
    let next = Finalization {
        parent: 1,
        child: 2,
        votes: &[(1, 1, 2), (2, 1, 2), (16, 1, 2)],
    };
    assert!(next.meets_quorum(new_electorate, 1));
}

#[derive(Clone, Copy)]
struct PrepareVote {
    voter: u32,
    parent: Roster,
    round: u32,
    child: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Roster {
    group: u32,
    parent: u32,
    electorate: u32,
}

impl Roster {
    fn child_value(self) -> u64 {
        (u64::from(self.parent) << 32) | u64::from(self.electorate)
    }
}

const INITIAL_ROSTER: Roster = Roster {
    group: 1,
    parent: 10,
    electorate: 0b1111,
};

#[derive(Clone, Copy)]
struct Prepared {
    round: u32,
    child: u64,
    parent: Roster,
    votes: [PrepareVote; 3],
}

impl Prepared {
    fn has_quorum(self, roster: Roster, next_round: u32) -> bool {
        if self.parent != roster || self.round >= next_round {
            return false;
        }
        let mut voters = 0;
        for vote in self.votes {
            if !vote.voter.is_power_of_two()
                || vote.voter & roster.electorate == 0
                || voters & vote.voter != 0
                || (vote.parent, vote.round, vote.child) != (self.parent, self.round, self.child)
            {
                return false;
            }
            voters |= vote.voter;
        }
        voters.count_ones() >= quorum(roster.electorate.count_ones(), 1)
    }
}

fn prepared(round: u32, child: u64) -> Prepared {
    let parent = INITIAL_ROSTER;
    Prepared {
        round,
        child,
        parent,
        votes: [1, 2, 4].map(|voter| PrepareVote {
            voter,
            parent,
            round,
            child,
        }),
    }
}

#[derive(Clone, Copy)]
struct RoundChange {
    voter: u32,
    parent: Roster,
    round: u32,
    prepared: Option<Prepared>,
}

impl RoundChange {
    fn valid(self, roster: Roster, round: u32) -> bool {
        self.voter.is_power_of_two()
            && self.voter & roster.electorate != 0
            && self.parent == roster
            && self.round == round
            && self
                .prepared
                .is_none_or(|proof| proof.has_quorum(roster, round))
    }

    fn prepared_claim(self) -> Option<(u32, u64)> {
        self.prepared.map(|proof| (proof.round, proof.child))
    }
}

struct RoundReports {
    roster: Roster,
    round: u32,
    reports: Vec<RoundChange>,
    conflicting: u32,
}

impl RoundReports {
    fn record(&mut self, report: RoundChange) {
        if !report.valid(self.roster, self.round) || self.conflicting & report.voter != 0 {
            return;
        }
        if let Some(index) = self
            .reports
            .iter()
            .position(|prior| prior.voter == report.voter)
        {
            if self.reports[index].prepared_claim() != report.prepared_claim() {
                self.conflicting |= report.voter;
                self.reports.swap_remove(index);
            }
        } else {
            self.reports.push(report);
        }
    }
}

fn next_round_child(
    roster: Roster,
    round: u32,
    reports: &[RoundChange],
    fresh_child: u64,
) -> Option<u64> {
    let mut voters = 0;
    let mut highest: Option<Prepared> = None;
    let mut highest_conflicts = false;
    for report in reports {
        if !report.valid(roster, round) || voters & report.voter != 0 {
            return None;
        }
        voters |= report.voter;
        if let Some(prepared) = report.prepared {
            match highest {
                Some(previous) if previous.round > prepared.round => {}
                Some(previous) if previous.round == prepared.round => {
                    highest_conflicts |= previous.child != prepared.child;
                }
                _ => {
                    highest = Some(prepared);
                    highest_conflicts = false;
                }
            }
        }
    }
    if highest_conflicts || voters.count_ones() < quorum(roster.electorate.count_ones(), 1) {
        return None;
    }
    Some(highest.map_or(fresh_child, |prepared| prepared.child))
}

#[test]
fn round_change_can_select_a_fresh_child_after_an_unprepared_split() {
    let reports = [1, 2, 4].map(|voter| RoundChange {
        voter,
        parent: INITIAL_ROSTER,
        round: 1,
        prepared: None,
    });
    assert_eq!(next_round_child(INITIAL_ROSTER, 1, &reports[..2], 20), None);
    assert_eq!(next_round_child(INITIAL_ROSTER, 1, &reports, 20), Some(20));
}

#[test]
fn round_change_carries_forward_the_highest_prepared_child() {
    let mut reports = [1, 2, 4].map(|voter| RoundChange {
        voter,
        parent: INITIAL_ROSTER,
        round: 3,
        prepared: None,
    });
    reports[0].prepared = Some(prepared(2, 21));
    reports[1].prepared = Some(prepared(1, 22));
    assert_eq!(next_round_child(INITIAL_ROSTER, 3, &reports, 20), Some(21));
    reports.swap(0, 1);
    assert_eq!(next_round_child(INITIAL_ROSTER, 3, &reports, 20), Some(21));

    reports[2].prepared = Some(prepared(2, 23));
    assert_eq!(next_round_child(INITIAL_ROSTER, 3, &reports, 20), None);
    reports[2].prepared = None;
    reports[2].voter = reports[1].voter;
    assert_eq!(next_round_child(INITIAL_ROSTER, 3, &reports, 20), None);
    reports[2].voter = 4;
    reports[2].parent.parent = 11;
    assert_eq!(next_round_child(INITIAL_ROSTER, 3, &reports, 20), None);
    reports[2].parent = INITIAL_ROSTER;
    reports[2].prepared = Some(prepared(3, 23));
    assert_eq!(next_round_child(INITIAL_ROSTER, 3, &reports, 20), None);
}

#[test]
fn conflicting_reports_from_one_voter_do_not_prevent_an_honest_quorum() {
    let mut voters = [1, 2, 4, 8].map(|key| Voter {
        roster: INITIAL_ROSTER,
        key,
        round: 0,
        proposal: Some(21),
        prepared: None,
        finalized: None,
        round_report: None,
    });
    let certificate = commit_current_round(voters.first_chunk_mut::<3>().unwrap(), 0, 21);
    let [alice, bob, carol, dan] = &mut voters;
    let [equivocating, bob_report, carol_report, dan_report] =
        [alice, bob, carol, dan].map(|voter| voter.request_round(1).unwrap());
    let omission = RoundChange {
        prepared: None,
        ..equivocating
    };
    let honest_reports = [bob_report, carol_report, dan_report];

    // Even a bundle that contains a full honest quorum cannot count the
    // conflicting reports as part of the same round-change proof.
    let mut bundled = [equivocating, bob_report, omission, carol_report, dan_report];
    for _ in 0..bundled.len() {
        assert!(!voters[3].enter_round(&bundled, 22, 21));
        bundled.rotate_left(1);
    }

    for voter in &mut voters[1..] {
        assert!(!voter.enter_round(&honest_reports, 22, 22));
        assert!(voter.enter_round(&honest_reports, 22, 21));
        assert!(voter.finalize(&certificate));
        assert_eq!(voter.finalized, Some(21));
    }
}

#[test]
fn report_collection_keeps_an_honest_quorum_after_conflicting_delivery() {
    let proof = prepared(0, 21);
    let [alice, bob, carol, dan] = [1, 2, 4, 8].map(|voter| RoundChange {
        voter,
        parent: INITIAL_ROSTER,
        round: 1,
        prepared: Some(proof),
    });
    let omission = RoundChange {
        prepared: None,
        ..alice
    };

    // Reordering prepare votes leaves Bob's claim unchanged.
    let mut reordered = proof;
    reordered.votes.reverse();
    let bob_duplicate = RoundChange {
        prepared: Some(reordered),
        ..bob
    };

    // A stale report from Carol cannot disqualify her current report.
    let stale = RoundChange {
        round: 0,
        prepared: None,
        ..carol
    };
    let mut delivery = [
        alice,
        bob,
        omission,
        carol,
        alice,
        bob_duplicate,
        stale,
        dan,
    ];
    for _ in 0..2 {
        for _ in 0..delivery.len() {
            let mut collected = RoundReports {
                roster: INITIAL_ROSTER,
                round: 1,
                reports: Vec::new(),
                conflicting: 0,
            };
            for report in delivery {
                collected.record(report);
            }

            assert_eq!(collected.conflicting, alice.voter);
            assert_eq!(collected.reports.len(), 3);
            assert_eq!(
                next_round_child(INITIAL_ROSTER, 1, &collected.reports, 22),
                Some(21)
            );
            delivery.rotate_left(1);
        }
        delivery.reverse();
    }
}

#[test]
fn late_conflicting_report_can_split_proposals_until_the_next_round() {
    let [mut reporter, mut early, mut late, mut last] = [1, 2, 4, 8].map(|key| Voter {
        roster: INITIAL_ROSTER,
        key,
        round: 0,
        proposal: Some(21),
        prepared: None,
        finalized: None,
        round_report: None,
    });
    let proof = Prepared {
        votes: [&reporter, &early, &late].map(|voter| voter.prepare(21).unwrap()),
        ..prepared(0, 21)
    };
    // The reporting voter alone assembled the prepare proof. No commit quorum exists.
    assert!(reporter.record_prepared(proof));

    let [claim, early_report, late_report, last_report] =
        [&mut reporter, &mut early, &mut late, &mut last]
            .map(|voter| voter.request_round(1).unwrap());
    let mut collected = RoundReports {
        roster: INITIAL_ROSTER,
        round: 1,
        reports: Vec::new(),
        conflicting: 0,
    };
    for report in [claim, early_report, late_report] {
        collected.record(report);
    }
    assert!(early.enter_round(&collected.reports, 22, 21));
    assert!(early.prepare(21).is_some());

    collected.record(RoundChange {
        prepared: None,
        ..claim
    });
    collected.record(last_report);
    assert_eq!(collected.conflicting, reporter.key);
    assert!(!early.enter_round(&collected.reports, 22, 22));
    for voter in [&mut late, &mut last] {
        assert!(voter.enter_round(&collected.reports, 22, 22));
        assert!(voter.prepare(22).is_some());
    }
    let mut honest = [early, late, last];
    assert!(honest.iter().all(|voter| voter.commit().is_none()));

    let reports = honest
        .each_mut()
        .map(|voter| voter.request_round(2).unwrap());
    for voter in &mut honest {
        assert!(voter.enter_round(&reports, 22, 22));
    }
    let certificate = commit_current_round(&mut honest, 2, 22);
    for voter in &mut honest {
        assert!(voter.finalize(&certificate));
        assert_eq!(voter.finalized, Some(22));
    }
}

#[test]
fn peers_in_different_rounds_catch_up_after_reconnect() {
    let mut voters = [1, 2, 4].map(|key| Voter {
        roster: INITIAL_ROSTER,
        key,
        round: 0,
        proposal: Some(21),
        prepared: None,
        finalized: None,
        round_report: None,
    });
    let [alice, bob, lagging] = &mut voters;
    let alice_report = alice.request_round(3).unwrap();
    let bob_report = bob.request_round(3).unwrap();
    lagging.request_round(1).unwrap();

    let mut collected = RoundReports {
        roster: INITIAL_ROSTER,
        round: 3,
        reports: Vec::new(),
        conflicting: 0,
    };
    for (roster, round) in [
        (
            Roster {
                group: 2,
                ..INITIAL_ROSTER
            },
            3,
        ),
        (
            Roster {
                parent: 11,
                ..INITIAL_ROSTER
            },
            3,
        ),
        (INITIAL_ROSTER, 0),
    ] {
        let mut unrelated = RoundReports {
            roster,
            round,
            reports: Vec::new(),
            conflicting: 0,
        };
        for report in [alice_report, bob_report] {
            unrelated.record(RoundChange {
                parent: roster,
                round,
                ..report
            });
        }
        assert_eq!(unrelated.reports.len(), 2);
        assert!(lagging.catch_up_round(&unrelated).is_none());
        assert_eq!(lagging.round, 1);
        assert!(lagging.proposal.is_none());
    }

    collected.record(alice_report);
    collected.record(alice_report);
    assert!(lagging.catch_up_round(&collected).is_none());
    assert_eq!(lagging.round, 1);

    collected.record(bob_report);
    let lagging_report = lagging.catch_up_round(&collected).unwrap();
    assert_eq!(lagging.round, 3);
    assert!(lagging.prepare(22).is_none());
    assert!(!lagging.enter_round(&collected.reports, 22, 22));
    assert!(lagging.catch_up_round(&collected).is_none());

    collected.record(lagging_report);
    for voter in &mut voters {
        assert!(voter.enter_round(&collected.reports, 22, 22));
    }
    let certificate = commit_current_round(&mut voters, 3, 22);
    for voter in &mut voters {
        assert!(voter.finalize(&certificate));
    }
}

#[test]
fn retry_resends_the_original_round_report_after_preparing_a_child() {
    let mut voters = [1, 2, 4].map(|key| Voter {
        roster: INITIAL_ROSTER,
        key,
        round: 0,
        proposal: Some(21),
        prepared: None,
        finalized: None,
        round_report: None,
    });
    let reports = voters
        .each_mut()
        .map(|voter| voter.request_round(1).unwrap());
    for voter in &mut voters {
        assert!(voter.enter_round(&reports, 22, 22));
    }
    let certificate = commit_current_round(&mut voters, 1, 22);

    // A peer missed Alice's report. Her new prepare proof is for round one
    // and belongs in a later round's report.
    let retry = voters[0].retry_round_report().unwrap();
    assert_eq!((retry.voter, retry.round), (reports[0].voter, 1));
    assert!(retry.parent == reports[0].parent);
    assert_eq!(retry.prepared_claim(), reports[0].prepared_claim());
    assert_eq!(next_round_child(INITIAL_ROSTER, 1, &reports[1..], 22), None);
    assert_eq!(
        next_round_child(INITIAL_ROSTER, 1, &[reports[1], retry, reports[2]], 22),
        Some(22)
    );

    let later = voters[0].request_round(2).unwrap();
    let later_retry = voters[0].retry_round_report().unwrap();
    assert_eq!(later_retry.round, 2);
    assert_eq!(later_retry.prepared_claim(), Some((1, 22)));
    assert_eq!(later_retry.prepared_claim(), later.prepared_claim());

    let bob = voters[1].request_round(2).unwrap();
    let carol = voters[2].request_round(2).unwrap();
    for delivery in [
        [retry, bob, later_retry, carol],
        [later_retry, carol, retry, bob],
    ] {
        let mut collected = RoundReports {
            roster: INITIAL_ROSTER,
            round: 2,
            reports: Vec::new(),
            conflicting: 0,
        };
        for report in delivery {
            collected.record(report);
        }
        assert_eq!(collected.conflicting, 0);
        assert_eq!(collected.reports.len(), 3);
        assert_eq!(
            next_round_child(INITIAL_ROSTER, 2, &collected.reports, 23),
            Some(22)
        );
    }

    assert!(voters[0].finalize(&certificate));
    assert!(voters[0].retry_round_report().is_none());
}

#[test]
fn skipping_rounds_preserves_prepared_evidence_for_a_delayed_commit() {
    let mut voters = [1, 2, 4].map(|key| Voter {
        roster: INITIAL_ROSTER,
        key,
        round: 0,
        proposal: Some(21),
        prepared: None,
        finalized: None,
        round_report: None,
    });
    let certificate = commit_current_round(&mut voters, 0, 21);
    let [reporter, lagging, _] = &mut voters;
    let omission = RoundChange {
        prepared: None,
        ..reporter.request_round(3).unwrap()
    };
    let fourth = RoundChange {
        voter: 8,
        ..omission
    };

    let first_report = lagging.request_round(1).unwrap();
    assert_eq!(first_report.prepared.unwrap().round, 0);
    let mut collected = RoundReports {
        roster: INITIAL_ROSTER,
        round: 3,
        reports: Vec::new(),
        conflicting: 0,
    };
    collected.record(omission);
    collected.record(fourth);

    let forwarded = lagging.catch_up_round(&collected).unwrap();
    assert_eq!(forwarded.round, 3);
    let retained = forwarded.prepared.unwrap();
    assert_eq!(retained.round, 0);
    assert_eq!(retained.child, 21);
    assert!(retained.has_quorum(INITIAL_ROSTER, 3));
    assert!(lagging.commit().is_none());
    collected.record(forwarded);

    assert!(!lagging.enter_round(&collected.reports, 22, 22));
    assert!(lagging.enter_round(&collected.reports, 22, 21));
    assert!(lagging.finalize(&certificate));
    assert_eq!(lagging.finalized, Some(21));
}

#[test]
fn round_change_rejects_prepare_evidence_without_a_matching_quorum() {
    let mut reports = [1, 2, 4].map(|voter| RoundChange {
        voter,
        parent: INITIAL_ROSTER,
        round: 3,
        prepared: None,
    });
    let valid = prepared(2, 21);
    reports[0].prepared = Some(valid);
    assert_eq!(next_round_child(INITIAL_ROSTER, 3, &reports, 20), Some(21));

    let mut foreign = valid;
    foreign.parent.parent = 11;
    reports[0].prepared = Some(foreign);
    assert_eq!(next_round_child(INITIAL_ROSTER, 3, &reports, 20), None);

    for bad_vote in [
        PrepareVote {
            voter: 1,
            ..valid.votes[2]
        },
        PrepareVote {
            voter: 16,
            ..valid.votes[2]
        },
        PrepareVote {
            voter: 12,
            ..valid.votes[2]
        },
        PrepareVote {
            parent: Roster {
                parent: 11,
                ..INITIAL_ROSTER
            },
            ..valid.votes[2]
        },
        PrepareVote {
            round: 1,
            ..valid.votes[2]
        },
        PrepareVote {
            child: 22,
            ..valid.votes[2]
        },
    ] {
        let mut invalid = valid;
        invalid.votes[2] = bad_vote;
        reports[0].prepared = Some(invalid);
        assert_eq!(next_round_child(INITIAL_ROSTER, 3, &reports, 20), None);
    }
}

#[derive(Clone, Copy)]
struct CommitVote {
    voter: u32,
    parent: Roster,
    round: u32,
    child: u64,
}

struct CommitCertificate {
    prepared: Prepared,
    votes: [CommitVote; 3],
}

impl CommitCertificate {
    fn valid(&self, roster: Roster) -> bool {
        let Some(next_round) = self.prepared.round.checked_add(1) else {
            return false;
        };
        if !self.prepared.has_quorum(roster, next_round) {
            return false;
        }
        let mut seen = 0;
        for vote in self.votes {
            if !vote.voter.is_power_of_two()
                || vote.voter & roster.electorate == 0
                || vote.voter & seen != 0
                || (vote.parent, vote.round, vote.child)
                    != (
                        self.prepared.parent,
                        self.prepared.round,
                        self.prepared.child,
                    )
            {
                return false;
            }
            seen |= vote.voter;
        }
        seen.count_ones() >= quorum(roster.electorate.count_ones(), 1)
    }
}

/// One honest voter's in-memory state for a fixed parent.
struct Voter {
    roster: Roster,
    key: u32,
    round: u32,
    proposal: Option<u64>,
    prepared: Option<Prepared>,
    finalized: Option<u64>,
    round_report: Option<RoundChange>,
}

impl Voter {
    fn prepare(&self, child: u64) -> Option<PrepareVote> {
        (self.finalized.is_none() && self.proposal == Some(child)).then_some(PrepareVote {
            voter: self.key,
            parent: self.roster,
            round: self.round,
            child,
        })
    }

    fn record_prepared(&mut self, proof: Prepared) -> bool {
        if self.finalized.is_some()
            || proof.round != self.round
            || self.proposal != Some(proof.child)
            || !self
                .round
                .checked_add(1)
                .is_some_and(|next| proof.has_quorum(self.roster, next))
        {
            return false;
        }
        self.prepared = Some(proof);
        true
    }

    fn commit(&self) -> Option<CommitVote> {
        let prepared = self.prepared?;
        if self.finalized.is_some() || prepared.round != self.round {
            return None;
        }
        Some(CommitVote {
            voter: self.key,
            parent: prepared.parent,
            round: prepared.round,
            child: prepared.child,
        })
    }

    fn finalize(&mut self, certificate: &CommitCertificate) -> bool {
        certificate.valid(self.roster)
            && match self.finalized {
                Some(child) => child == certificate.prepared.child,
                None => {
                    self.finalized = Some(certificate.prepared.child);
                    true
                }
            }
    }

    fn request_round(&mut self, round: u32) -> Option<RoundChange> {
        if self.finalized.is_some() || round <= self.round {
            return None;
        }
        self.round = round;
        self.proposal = None;
        let report = RoundChange {
            voter: self.key,
            parent: self.roster,
            round,
            prepared: self.prepared,
        };
        self.round_report = Some(report);
        Some(report)
    }

    fn retry_round_report(&self) -> Option<RoundChange> {
        self.round_report.filter(|_| self.finalized.is_none())
    }

    fn catch_up_round(&mut self, collected: &RoundReports) -> Option<RoundChange> {
        // With one possible equivocator, two distinct reporters justify
        // moving to the round. Entering it still requires a full quorum.
        if collected.roster != self.roster || collected.reports.len() < 2 {
            return None;
        }
        self.request_round(collected.round)
    }

    fn enter_round(&mut self, reports: &[RoundChange], fresh_child: u64, proposed: u64) -> bool {
        if self.finalized.is_some()
            || self.proposal.is_some()
            || next_round_child(self.roster, self.round, reports, fresh_child) != Some(proposed)
        {
            return false;
        }
        self.proposal = Some(proposed);
        true
    }
}

#[test]
fn prepared_voter_reports_its_proof_and_stops_preparing_in_the_old_round() {
    let mut voters = [1, 2, 4].map(|key| Voter {
        roster: INITIAL_ROSTER,
        key,
        round: 0,
        proposal: Some(21),
        prepared: None,
        finalized: None,
        round_report: None,
    });
    let proof = Prepared {
        parent: INITIAL_ROSTER,
        round: 0,
        child: 21,
        votes: voters.each_ref().map(|voter| voter.prepare(21).unwrap()),
    };
    assert!(voters[0].record_prepared(proof));

    let [alice, bob, carol] = &mut voters;
    let reports = [alice, bob, carol].map(|voter| voter.request_round(1).unwrap());
    assert!(reports[0].prepared.is_some());
    for voter in &mut voters {
        assert!(voter.prepare(21).is_none());
        assert!(!voter.record_prepared(proof));
        assert!(!voter.enter_round(&reports, 22, 22));
        assert!(voter.enter_round(&reports, 22, 21));
        assert!(!voter.enter_round(&reports, 22, 21));
        let vote = voter.prepare(21).unwrap();
        assert_eq!((vote.round, vote.child), (1, 21));
        assert!(voter.prepare(22).is_none());
    }
}

#[test]
fn unprepared_voters_finalize_after_reconnect_even_with_delayed_commit_delivery() {
    let mut voters = [1, 2, 4, 8].map(|key| Voter {
        roster: INITIAL_ROSTER,
        key,
        round: 0,
        proposal: Some(if key <= 2 { 21 } else { 22 }),
        prepared: None,
        finalized: None,
        round_report: None,
    });
    let mut reports = voters
        .iter_mut()
        .map(|voter| voter.request_round(1).unwrap());
    let reports: [_; 4] = std::array::from_fn(|_| reports.next().unwrap());
    assert!(!voters[0].enter_round(&reports[..2], 23, 23));

    let votes = std::array::from_fn(|index| {
        let voter = &mut voters[index];
        assert!(voter.enter_round(&reports[..3], 23, 23));
        voter.prepare(23).unwrap()
    });
    let prepared = Prepared {
        parent: INITIAL_ROSTER,
        round: 1,
        child: 23,
        votes,
    };
    let commits = std::array::from_fn(|index| {
        assert!(voters[index].record_prepared(prepared));
        voters[index].commit().unwrap()
    });
    assert!(voters[0].request_round(2).unwrap().prepared.is_some());
    assert!(voters[0].commit().is_none());

    let certificate = CommitCertificate {
        prepared,
        votes: commits,
    };
    let mut duplicate = commits;
    duplicate[2] = duplicate[1];
    let mut wrong_round = commits;
    wrong_round[2].round = 0;
    for votes in [duplicate, wrong_round] {
        let invalid = CommitCertificate { prepared, votes };
        assert!(!voters[0].finalize(&invalid));
        assert!(voters[0].finalized.is_none());
    }

    // An already-issued certificate can arrive after a round change.
    for voter in &mut voters {
        assert!(voter.finalize(&certificate));
        assert!(voter.finalize(&certificate));
        assert_eq!(voter.finalized, Some(23));
        assert!(voter.request_round(3).is_none());
        assert!(voter.commit().is_none());
        assert!(voter.prepare(23).is_none());
    }
}

#[test]
fn delayed_commit_child_survives_every_report_quorum_with_one_omission() {
    // Three voters issued commits after seeing the prepare proof. The fourth
    // voter did not prepare. Allow any one voter to omit its proof.
    let proof = prepared(0, 21);
    let certificate = CommitCertificate {
        prepared: proof,
        votes: [1, 2, 4].map(|voter| CommitVote {
            voter,
            parent: INITIAL_ROSTER,
            round: 0,
            child: 21,
        }),
    };

    for omitted in [1, 2, 4, 8] {
        for absent in [1, 2, 4, 8] {
            let reports: Vec<_> = [1, 2, 4, 8]
                .into_iter()
                .filter(|&key| key != absent)
                .map(|key| {
                    let mut voter = Voter {
                        roster: INITIAL_ROSTER,
                        key,
                        round: 0,
                        proposal: Some(21),
                        prepared: (key != 8).then_some(proof),
                        finalized: None,
                        round_report: None,
                    };
                    let mut report = voter.request_round(1).unwrap();
                    if key == omitted {
                        report.prepared = None;
                    }
                    report
                })
                .collect();

            let mut lagging = Voter {
                roster: INITIAL_ROSTER,
                key: 8,
                round: 0,
                proposal: None,
                prepared: None,
                finalized: None,
                round_report: None,
            };
            lagging.request_round(1).unwrap();
            assert!(!lagging.enter_round(&reports, 22, 22));
            assert!(lagging.enter_round(&reports, 22, 21));
            assert!(lagging.finalize(&certificate));
            assert_eq!(lagging.finalized, Some(21));
        }
    }
}

#[test]
fn independent_report_quorums_keep_a_committed_child_after_reconnect() {
    let mut voters = [1, 2, 4, 8].map(|key| Voter {
        roster: INITIAL_ROSTER,
        key,
        round: 0,
        proposal: Some(21),
        prepared: None,
        finalized: None,
        round_report: None,
    });
    let certificate = commit_current_round(voters.first_chunk_mut::<3>().unwrap(), 0, 21);
    let [alice, bob, carol, dan] = voters
        .each_mut()
        .map(|voter| voter.request_round(1).unwrap());
    let alice_omits = RoundChange {
        prepared: None,
        ..alice
    };

    // Both peers receive Dan's report without a proof, plus one honest
    // prepared report. Alice gives the peers different claims.
    let deliveries = [[alice_omits, dan, bob], [dan, carol, alice]];
    let collectors = deliveries.map(|delivery| {
        let mut collector = RoundReports {
            roster: INITIAL_ROSTER,
            round: 1,
            reports: Vec::new(),
            conflicting: 0,
        };
        for report in delivery {
            collector.record(report);
        }
        collector
    });

    for (voter, collector) in voters[1..3].iter_mut().zip(&collectors) {
        assert_eq!(collector.conflicting, 0);
        assert!(!voter.enter_round(&collector.reports, 22, 22));
        assert!(voter.enter_round(&collector.reports, 22, 21));
        assert!(voter.finalize(&certificate));
        assert_eq!(voter.finalized, Some(21));
    }
}

#[test]
fn same_identifier_parent_with_a_different_electorate_rejects_shared_voters_evidence() {
    // All three participating keys belong to both rosters and meet either quorum.
    let other_roster = Roster {
        electorate: 0b10111,
        ..INITIAL_ROSTER
    };
    let mut voters = [1, 2, 4].map(|key| Voter {
        roster: INITIAL_ROSTER,
        key,
        round: 0,
        proposal: Some(21),
        prepared: None,
        finalized: None,
        round_report: None,
    });
    let certificate = commit_current_round(&mut voters, 0, 21);
    assert!(certificate.valid(INITIAL_ROSTER));
    assert!(!certificate.valid(other_roster));
    assert!(!certificate.prepared.has_quorum(other_roster, 1));

    let [alice, bob, carol] = &mut voters;
    let reports = [alice, bob, carol].map(|voter| voter.request_round(1).unwrap());
    assert_eq!(next_round_child(INITIAL_ROSTER, 1, &reports, 22), Some(21));
    assert_eq!(next_round_child(other_roster, 1, &reports, 22), None);
}

#[test]
fn agreement_evidence_is_scoped_to_one_group() {
    let other_group = Roster {
        group: 2,
        ..INITIAL_ROSTER
    };
    let successor = Roster {
        parent: 11,
        ..INITIAL_ROSTER
    };
    let mut voters = [1, 2, 4].map(|key| Voter {
        roster: INITIAL_ROSTER,
        key,
        round: 0,
        proposal: Some(successor.child_value()),
        prepared: None,
        finalized: None,
        round_report: None,
    });
    let certificate = commit_current_round(&mut voters, 0, successor.child_value());
    let [alice, bob, carol] = &mut voters;
    let reports = [alice, bob, carol].map(|voter| voter.request_round(1).unwrap());
    assert!(!certificate.prepared.has_quorum(other_group, 1));
    assert_eq!(next_round_child(other_group, 1, &reports, 22), None);
    assert_eq!(
        next_round_child(INITIAL_ROSTER, 1, &reports, 22),
        Some(successor.child_value())
    );

    let other_successor = Roster {
        group: other_group.group,
        ..successor
    };
    let mut current = other_group;
    assert!(!apply_roster_certificate(
        &mut current,
        &certificate,
        other_successor
    ));
    assert!(current == other_group);

    current = INITIAL_ROSTER;
    assert!(!apply_roster_certificate(
        &mut current,
        &certificate,
        other_successor
    ));
    assert!(current == INITIAL_ROSTER);
    assert!(apply_roster_certificate(
        &mut current,
        &certificate,
        successor
    ));
    assert!(current == successor);
}

#[test]
fn repeated_round_changes_preserve_the_child_under_reordered_commit_delivery() {
    let mut voters = [1, 2, 4].map(|key| Voter {
        roster: INITIAL_ROSTER,
        key,
        round: 0,
        proposal: Some(21),
        prepared: None,
        finalized: None,
        round_report: None,
    });
    let first = commit_current_round(&mut voters, 0, 21);
    let second = {
        let [alice, bob, carol] = &mut voters;
        let reports = [alice, bob, carol].map(|voter| voter.request_round(1).unwrap());
        for voter in &mut voters {
            assert!(voter.enter_round(&reports, 22, 21));
        }
        commit_current_round(&mut voters, 1, 21)
    };

    let [alice, bob, carol] = &mut voters;
    let mut reports = [alice, bob, carol].map(|voter| voter.request_round(2).unwrap());
    // Mix a retained older proof with a newer one and an omitted proof.
    reports[0].prepared = Some(first.prepared);
    reports[1].prepared = None;
    assert_eq!(reports[2].prepared.unwrap().round, 1);

    for (index, voter) in voters.iter_mut().enumerate() {
        assert!(!voter.enter_round(&reports, 22, 22));
        assert!(voter.enter_round(&reports, 22, 21));
        assert!(!voter.record_prepared(first.prepared));
        assert!(!voter.record_prepared(second.prepared));
        assert!(voter.commit().is_none());

        let delivery = if index == 0 {
            [&first, &second]
        } else {
            [&second, &first]
        };
        for certificate in delivery {
            assert!(voter.finalize(certificate));
            assert_eq!(voter.finalized, Some(21));
        }
        assert!(voter.prepare(21).is_none());
    }
}

#[test]
fn replacement_roster_rejects_prior_evidence_and_retired_votes() {
    let mut old_voters = [1, 2, 4].map(|key| Voter {
        roster: INITIAL_ROSTER,
        key,
        round: 0,
        proposal: Some(11),
        prepared: None,
        finalized: None,
        round_report: None,
    });
    let replacement = commit_current_round(&mut old_voters, 0, 11);
    assert!(old_voters[0].finalize(&replacement));

    let new_roster = Roster {
        group: INITIAL_ROSTER.group,
        parent: 11,
        electorate: 0b11011,
    };
    let mut new_voters = [1, 2, 16].map(|key| Voter {
        roster: new_roster,
        key,
        round: 0,
        proposal: Some(12),
        prepared: None,
        finalized: None,
        round_report: None,
    });
    let mut successor = commit_current_round(&mut new_voters, 0, 12);
    let delayed_report = old_voters[2].request_round(1).unwrap();
    let [alice, bob, rotated] = &mut new_voters;
    let reports = [alice, bob, rotated].map(|voter| voter.request_round(1).unwrap());

    let mut stale_parent = reports;
    stale_parent[0].parent = delayed_report.parent;
    let mut retired_reporter = reports;
    retired_reporter[2].voter = delayed_report.voter;
    let mut prior_proof = reports;
    prior_proof[0].prepared = delayed_report.prepared;
    assert!(prior_proof[0].prepared.is_some());
    let mut retired_prepare_voter = reports;
    retired_prepare_voter[2].prepared.as_mut().unwrap().votes[2].voter = 4;

    for voter in &mut new_voters {
        for invalid_reports in [
            &stale_parent,
            &retired_reporter,
            &prior_proof,
            &retired_prepare_voter,
        ] {
            assert!(!voter.enter_round(invalid_reports, 13, 12));
        }
        assert!(!voter.enter_round(&reports, 13, 13));
        assert!(voter.enter_round(&reports, 13, 12));
        assert!(!voter.finalize(&replacement));

        let replacement_prepare = successor.prepared.votes[2].voter;
        successor.prepared.votes[2].voter = 4;
        assert!(!voter.finalize(&successor));
        successor.prepared.votes[2].voter = replacement_prepare;

        let replacement_commit = successor.votes[2].voter;
        successor.votes[2].voter = 4;
        assert!(!voter.finalize(&successor));
        successor.votes[2].voter = replacement_commit;

        assert_eq!(voter.finalized, None);
        assert!(voter.finalize(&successor));
        assert_eq!(voter.finalized, Some(12));
    }
    assert!(!old_voters[1].finalize(&successor));
    assert_eq!(old_voters[1].finalized, None);
}

#[test]
fn lagging_peer_requires_the_roster_handoff_before_finalizing_the_successor() {
    // Votes for a roster bind both its identifier and electorate.
    let replacement_roster = Roster {
        group: INITIAL_ROSTER.group,
        parent: 11,
        electorate: 0b11011,
    };
    let final_roster = Roster {
        group: INITIAL_ROSTER.group,
        parent: 12,
        electorate: replacement_roster.electorate,
    };
    let mut old_voters = [1, 2, 4].map(|key| Voter {
        roster: INITIAL_ROSTER,
        key,
        round: 0,
        proposal: Some(replacement_roster.child_value()),
        prepared: None,
        finalized: None,
        round_report: None,
    });
    let replacement = commit_current_round(&mut old_voters, 0, replacement_roster.child_value());
    for voter in &mut old_voters[..2] {
        assert!(voter.finalize(&replacement));
    }

    let mut current_voters = [1, 2, 16].map(|key| Voter {
        roster: replacement_roster,
        key,
        round: 0,
        proposal: Some(final_roster.child_value()),
        prepared: None,
        finalized: None,
        round_report: None,
    });
    let successor = commit_current_round(&mut current_voters, 0, final_roster.child_value());

    let [mut early, mut lagging] = [INITIAL_ROSTER; 2];
    assert!(apply_roster_certificate(
        &mut early,
        &replacement,
        replacement_roster
    ));
    assert!(apply_roster_certificate(
        &mut early,
        &successor,
        final_roster
    ));

    assert!(!apply_roster_certificate(
        &mut lagging,
        &successor,
        final_roster
    ));
    assert_eq!(lagging.parent, INITIAL_ROSTER.parent);
    assert_eq!(lagging.electorate, INITIAL_ROSTER.electorate);
    assert!(!apply_roster_certificate(
        &mut lagging,
        &replacement,
        final_roster
    ));
    let different_electorate = Roster {
        electorate: INITIAL_ROSTER.electorate,
        ..replacement_roster
    };
    assert!(!apply_roster_certificate(
        &mut lagging,
        &replacement,
        different_electorate
    ));
    assert_eq!(lagging.parent, INITIAL_ROSTER.parent);
    assert_eq!(lagging.electorate, INITIAL_ROSTER.electorate);
    assert!(apply_roster_certificate(
        &mut lagging,
        &replacement,
        replacement_roster
    ));
    assert_eq!(lagging.parent, replacement_roster.parent);
    assert_eq!(lagging.electorate, replacement_roster.electorate);
    assert!(apply_roster_certificate(
        &mut lagging,
        &successor,
        final_roster
    ));

    for roster in [&mut early, &mut lagging] {
        assert!(!apply_roster_certificate(
            roster,
            &replacement,
            replacement_roster
        ));
        assert!(!apply_roster_certificate(roster, &successor, final_roster));
        assert_eq!(roster.parent, final_roster.parent);
        assert_eq!(roster.electorate, final_roster.electorate);
    }
}

#[test]
fn catch_up_across_two_key_replacements_requires_contiguous_certificates() {
    let first_replacement = Roster {
        group: INITIAL_ROSTER.group,
        parent: 11,
        electorate: 0b11011,
    };
    let second_replacement = Roster {
        group: INITIAL_ROSTER.group,
        parent: 12,
        electorate: 0b111001,
    };
    let tip = Roster {
        group: INITIAL_ROSTER.group,
        parent: 13,
        electorate: second_replacement.electorate,
    };

    let certificates = [
        (INITIAL_ROSTER, first_replacement, [1, 2, 4]),
        (first_replacement, second_replacement, [1, 2, 16]),
        (second_replacement, tip, [1, 16, 32]),
    ]
    .map(|(roster, next, keys)| {
        let mut voters = keys.map(|key| Voter {
            roster,
            key,
            round: 0,
            proposal: Some(next.child_value()),
            prepared: None,
            finalized: None,
            round_report: None,
        });
        commit_current_round(&mut voters, 0, next.child_value())
    });
    let [first, second, third] = &certificates;
    let first_step = (first, first_replacement);
    let second_step = (second, second_replacement);
    let third_step = (third, tip);

    let wrong_tip_electorate = Roster {
        electorate: first_replacement.electorate,
        ..tip
    };
    for chain in [
        [first_step, second_step, (third, wrong_tip_electorate)].as_slice(),
        [first_step, third_step].as_slice(),
        [first_step, third_step, second_step].as_slice(),
        [first_step, second_step, (third, first_replacement)].as_slice(),
    ] {
        let mut lagging = INITIAL_ROSTER;
        assert!(!apply_roster_chain(&mut lagging, chain));
        assert_eq!(lagging.parent, INITIAL_ROSTER.parent);
        assert_eq!(lagging.electorate, INITIAL_ROSTER.electorate);
    }

    let mut lagging = INITIAL_ROSTER;
    assert!(apply_roster_chain(
        &mut lagging,
        &[first_step, second_step, third_step]
    ));
    let mut partially_caught_up = first_replacement;
    assert!(apply_roster_chain(
        &mut partially_caught_up,
        &[second_step, third_step]
    ));
    for roster in [lagging, partially_caught_up] {
        assert_eq!(roster.parent, tip.parent);
        assert_eq!(roster.electorate, tip.electorate);
    }
}

fn apply_roster_chain(current: &mut Roster, chain: &[(&CommitCertificate, Roster)]) -> bool {
    let mut candidate = *current;
    for &(certificate, next) in chain {
        if !apply_roster_certificate(&mut candidate, certificate, next) {
            return false;
        }
    }
    *current = candidate;
    true
}

fn apply_roster_certificate(
    current: &mut Roster,
    certificate: &CommitCertificate,
    proposed: Roster,
) -> bool {
    if proposed.group != current.group
        || certificate.prepared.child != proposed.child_value()
        || !certificate.valid(*current)
    {
        return false;
    }
    *current = proposed;
    true
}

fn commit_current_round(voters: &mut [Voter; 3], round: u32, child: u64) -> CommitCertificate {
    let prepared = Prepared {
        parent: voters[0].roster,
        round,
        child,
        votes: voters.each_ref().map(|voter| voter.prepare(child).unwrap()),
    };
    let votes = std::array::from_fn(|index| {
        assert!(voters[index].record_prepared(prepared));
        voters[index].commit().unwrap()
    });
    CommitCertificate { prepared, votes }
}

#[allow(dead_code)]
mod support;

use mesh_identity::groups::evidence::RosterVote as SignedRosterVote;

#[derive(Clone, Copy)]
struct RosterStatement {
    group: u64,
    parent: [u8; 32],
    child: [u8; 32],
    round: u32,
}

impl RosterStatement {
    fn verify_quorum(
        self,
        phase: u8,
        votes: &[SignedRosterVote],
        electorate: &[[u8; 32]; 4],
    ) -> bool {
        let mut seen = std::collections::BTreeSet::new();
        votes.len() >= quorum(electorate.len() as u32, 1) as usize
            && votes
                .iter()
                .all(|vote| seen.insert(vote.signer) && self.verify_vote(phase, vote, electorate))
    }

    fn verify_vote(self, phase: u8, vote: &SignedRosterVote, electorate: &[[u8; 32]; 4]) -> bool {
        use ed25519_dalek::{Signature, VerifyingKey};
        use mesh_identity::session::installation::group_roster_vote_message;

        let message =
            group_roster_vote_message(self.group, self.parent, self.child, self.round, phase);
        electorate.contains(&vote.signer)
            && VerifyingKey::from_bytes(&vote.signer).is_ok_and(|key| {
                key.verify_strict(&message, &Signature::from_bytes(&vote.signature))
                    .is_ok()
            })
    }

    fn sign(
        self,
        phase: u8,
        member: &mesh_identity::session::installation::Installation,
    ) -> SignedRosterVote {
        SignedRosterVote {
            signer: member.selected(),
            signature: member.sign_group_roster_vote_unchecked(
                self.group,
                self.parent,
                self.child,
                self.round,
                phase,
            ),
        }
    }
}

const PREPARE_PHASE: u8 = 1;
const COMMIT_PHASE: u8 = 2;
#[test]
fn peers_with_competing_recoveries_apply_only_the_agreed_child() {
    use ed25519_dalek::SigningKey;
    use mesh_identity::groups::{
        Error, Policy,
        evidence::{
            CatchUp, RECOVERY_VETO_WINDOW_MS, RecoveryCertificate, RosterPrepareProof,
            RosterRoundChange, RoundChangeCollector, SimulatedAuthority as _,
        },
    };
    use support::{Scenario, meet};

    for winner in [0, 1] {
        let mut s = Scenario::new(169, Policy::InviterOnly);
        let old = s.carol.selected();
        let tenure = s.group.membership(old).unwrap();
        s.group
            .enroll_recovery(old, [s.alice.selected(), s.dave.selected()])
            .unwrap();

        let requests = [21, 22].map(|child| {
            let key = s
                .carol
                .add_identity(SigningKey::generate(&mut s.rng))
                .unwrap();
            s.carol.select(key, child).unwrap();
            meet(&mut s.alice, &mut s.carol, child, &mut s.rng);
            meet(&mut s.dave, &mut s.carol, child, &mut s.rng);
            let mut request = s.group.request_recovery(old, key).unwrap();
            let consent = s.group.recovery_consent(&request, &s.carol).unwrap();
            s.group
                .apply_recovery_consent(&mut request, &consent)
                .unwrap();
            for witness in [&s.alice, &s.dave] {
                let approval = s.group.recovery_approval(&request, witness).unwrap();
                s.group
                    .apply_recovery_decision(&mut request, &approval)
                    .unwrap();
            }
            // Both candidates are independently authorized before agreement.
            let mut preview = s.group.clone();
            preview.advance_time(RECOVERY_VETO_WINDOW_MS);
            preview.recover_lost_key(&request).unwrap();
            assert_eq!(preview.membership(key), Some(tenure));
            (child, key, request, preview.rotation_context())
        });
        s.group.advance_time(RECOVERY_VETO_WINDOW_MS);
        assert_ne!(requests[0].3, requests[1].3);

        // Child labels refer to the exact authorized recovery in this fixture.
        // The four parent members can vote on agreement, including the two witnesses.
        let mut voters = [1, 2, 4, 8].map(|key| Voter {
            roster: INITIAL_ROSTER,
            key,
            round: 0,
            proposal: Some(if key <= 2 { 21 } else { 22 }),
            prepared: None,
            finalized: None,
            round_report: None,
        });
        for (child, _, _, _) in &requests {
            assert_eq!(
                voters
                    .iter()
                    .filter_map(|voter| voter.prepare(*child))
                    .count(),
                2
            );
        }
        assert!(voters.iter().all(|voter| voter.commit().is_none()));
        s.carol.select(old, 23).unwrap();
        let members = [&s.alice, &s.carol, &s.dave, &s.eve];
        let electorate = members.map(|member| member.selected());
        let (group, parent) = s.group.rotation_context();
        let sign_report = |report: RoundChange| {
            assert!(report.prepared.is_none());
            RosterRoundChange::new_unchecked(
                (group, parent),
                report.round,
                None,
                members[report.voter.trailing_zeros() as usize],
            )
            .to_bytes()
            .unwrap()
        };
        let decode = |bytes: &[u8]| RosterRoundChange::from_bytes(bytes).unwrap();
        // Across the partition only two voters time out. Their signed reports
        // reach the other side after reconnect and let it request the same round.
        let first = voters[0].request_round(1).unwrap();
        let second = voters[1].request_round(1).unwrap();
        let initial = [sign_report(first), sign_report(second)];
        let mut collector = RoundChangeCollector::new(&s.group, 1).unwrap();
        for _ in 0..2 {
            collector.record(&s.group, decode(&initial[0])).unwrap();
        }
        assert_eq!(
            collector.catch_up_round(&s.group, voters[2].round),
            Ok(None)
        );
        collector.record(&s.group, decode(&initial[1])).unwrap();
        assert_eq!(
            collector.prepared_child(&s.group),
            Err(Error::ApprovalRequired)
        );

        let caught_up = voters
            .last_chunk_mut::<2>()
            .unwrap()
            .each_mut()
            .map(|voter| {
                let round = collector
                    .catch_up_round(&s.group, voter.round)
                    .unwrap()
                    .unwrap();
                voter.request_round(round).unwrap()
            });
        let reports = [first, second, caught_up[0], caught_up[1]];
        let signed_reports = reports.map(sign_report);
        collector
            .record(&s.group, decode(&signed_reports[2]))
            .unwrap();
        assert_eq!(collector.catch_up_round(&s.group, 1), Ok(None));
        assert_eq!(collector.prepared_child(&s.group), Ok(None));
        let decoded = signed_reports.each_ref().map(|bytes| decode(bytes));
        assert_eq!(s.group.round_change_child(1, &decoded[..3]), Ok(None));
        assert_eq!(
            s.group.round_change_child(2, &decoded[..3]),
            Err(Error::Ineligible)
        );
        assert_eq!(
            s.group.round_change_child(1, &decoded[..2]),
            Err(Error::Ineligible)
        );
        let duplicate = [
            decode(&signed_reports[0]),
            decode(&signed_reports[0]),
            decode(&signed_reports[2]),
        ];
        assert_eq!(
            s.group.round_change_child(1, &duplicate),
            Err(Error::Ineligible)
        );

        // The fixture delivers candidates to the round's proposer in either
        // order. With no prepare proof the proposer chooses the first authorized one.
        let candidate_order = [winner, 1 - winner];
        let (child, replacement, _, context) = candidate_order
            .into_iter()
            .map(|index| &requests[index])
            .find(|(_, _, request, _)| s.group.recovery_child(request).is_ok())
            .unwrap();
        for voter in &mut voters {
            assert!(voter.enter_round(&reports[..3], *child, *child));
        }
        let certificate = commit_current_round(voters.first_chunk_mut::<3>().unwrap(), 1, *child);
        assert!(certificate.valid(INITIAL_ROSTER));

        let statement = RosterStatement {
            group,
            parent,
            child: context.1,
            round: 1,
        };
        let prepares = certificate.prepared.votes.map(|vote| {
            statement.sign(PREPARE_PHASE, members[vote.voter.trailing_zeros() as usize])
        });
        let commits = certificate.votes.map(|vote| {
            statement.sign(COMMIT_PHASE, members[vote.voter.trailing_zeros() as usize])
        });
        let proof = RosterPrepareProof {
            round: 1,
            child: context.1,
            votes: prepares.to_vec(),
        };
        let later =
            RosterRoundChange::new_unchecked((group, parent), 2, Some(proof.clone()), &s.alice)
                .to_bytes()
                .unwrap();
        let bare = [&s.carol, &s.dave].map(|member| {
            RosterRoundChange::new_unchecked((group, parent), 2, None, member)
                .to_bytes()
                .unwrap()
        });
        let quorum_with = |report| [report, decode(&bare[0]), decode(&bare[1])];
        assert_eq!(
            s.group.round_change_child(2, &quorum_with(decode(&later))),
            Ok(Some(context.1))
        );
        assert_eq!(decode(&later).to_bytes().unwrap(), later);
        assert!(RosterRoundChange::from_bytes(&later[..later.len() - 1]).is_err());
        assert_eq!(
            s.group
                .round_change_child(2, &quorum_with(decode(&later[..140]))),
            Err(Error::Ineligible)
        );
        for offset in [0, 8, 40, 44, 76, 140, 144, 176, 208] {
            let mut changed = later.clone();
            changed[offset] ^= 1;
            assert_eq!(
                s.group
                    .round_change_child(2, &quorum_with(decode(&changed))),
                Err(Error::Ineligible)
            );
        }
        let wrong_proof = RosterPrepareProof {
            votes: commits.to_vec(),
            ..proof
        };
        let wrong =
            RosterRoundChange::new_unchecked((group, parent), 2, Some(wrong_proof), &s.alice);
        assert_eq!(
            s.group.round_change_child(2, &quorum_with(wrong)),
            Err(Error::Ineligible)
        );

        assert!(statement.verify_quorum(1, &prepares, &electorate));
        assert!(!statement.verify_quorum(2, &prepares, &electorate));
        assert!(!statement.verify_quorum(2, &commits[..2], &electorate));
        assert!(!statement.verify_quorum(2, &[commits[0], commits[0], commits[1]], &electorate));
        for other in [
            RosterStatement {
                group: group + 1,
                ..statement
            },
            RosterStatement {
                parent: context.1,
                ..statement
            },
            RosterStatement {
                child: requests[1 - winner].3.1,
                ..statement
            },
            RosterStatement {
                round: 2,
                ..statement
            },
        ] {
            assert!(!other.verify_quorum(2, &commits, &electorate));
        }

        let outsider = SignedRosterVote {
            signer: s.bob.selected(),
            signature: s
                .bob
                .sign_group_roster_vote_unchecked(group, parent, context.1, 1, 2),
        };
        assert!(!statement.verify_quorum(2, &[commits[0], commits[1], outsider], &electorate));

        let mut signed_certificate = RecoveryCertificate {
            group,
            parent,
            child: context.1,
            round: statement.round,
            prepares: prepares.to_vec(),
            commits: commits.to_vec(),
        };
        let chosen = &requests[winner].2;
        let losing = &requests[1 - winner].2;
        assert_eq!(
            s.group
                .apply_certified_recovery(losing, &signed_certificate),
            Err(Error::Ineligible)
        );
        signed_certificate.commits = [commits[0], commits[0], commits[1]].to_vec();
        assert_eq!(
            s.group
                .apply_certified_recovery(chosen, &signed_certificate),
            Err(Error::Ineligible)
        );
        signed_certificate.commits = prepares.to_vec();
        assert_eq!(
            s.group
                .apply_certified_recovery(chosen, &signed_certificate),
            Err(Error::Ineligible)
        );
        signed_certificate.commits = [commits[0], commits[1], outsider].to_vec();
        assert_eq!(
            s.group
                .apply_certified_recovery(chosen, &signed_certificate),
            Err(Error::Ineligible)
        );
        signed_certificate.commits = commits.to_vec();
        signed_certificate.prepares = commits.to_vec();
        assert_eq!(
            s.group
                .apply_certified_recovery(chosen, &signed_certificate),
            Err(Error::Ineligible)
        );
        signed_certificate.prepares = prepares.to_vec();
        signed_certificate.round += 1;
        assert_eq!(
            s.group
                .apply_certified_recovery(chosen, &signed_certificate),
            Err(Error::Ineligible)
        );
        signed_certificate.round = statement.round;
        assert_eq!(s.group.rotation_context(), (group, parent));
        assert_eq!(s.group.membership(old), Some(tenure));

        let bytes = signed_certificate.to_bytes().unwrap();
        assert!(RecoveryCertificate::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        assert!(RecoveryCertificate::from_bytes(&[0; 653]).is_err());
        for offset in [0, 8, 40, 72, 76, 108, 364, 396] {
            let mut altered = bytes.clone();
            altered[offset] ^= 1;
            let certificate = RecoveryCertificate::from_bytes(&altered).unwrap();
            assert!(
                s.group
                    .apply_certified_recovery(chosen, &certificate)
                    .is_err()
            );
            assert_eq!(s.group.rotation_context(), (group, parent));
            assert_eq!(s.group.membership(old), Some(tenure));
        }
        let signed_certificate = RecoveryCertificate::from_bytes(&bytes).unwrap();
        assert_eq!(signed_certificate.to_bytes().unwrap(), bytes);

        let mut delayed = s.alice_offline;
        assert_eq!(
            delayed.apply_certified_recovery(chosen, &signed_certificate),
            Err(Error::StaleProposal)
        );
        assert_eq!(delayed.membership(old), Some(tenure));
        assert_eq!(delayed.catch_up(&s.group), CatchUp::Applied);
        // Roster synchronization preserves the receiver's local clock.
        assert_eq!(
            delayed.apply_certified_recovery(chosen, &signed_certificate),
            Err(Error::ApprovalRequired)
        );
        delayed.advance_time(RECOVERY_VETO_WINDOW_MS);
        delayed
            .apply_certified_recovery(chosen, &signed_certificate)
            .unwrap();

        let mut peers = [s.group.clone(), s.group];
        for ((peer, voter), delivery) in
            peers.iter_mut().zip(&mut voters[..2]).zip([[0, 1], [1, 0]])
        {
            assert!(voter.finalize(&certificate));
            let (_, _, request, candidate_context) = delivery
                .into_iter()
                .map(|index| &requests[index])
                .find(|(label, _, _, _)| Some(*label) == voter.finalized)
                .unwrap();
            let (group, parent) = peer.rotation_context();
            let received = RosterStatement {
                group,
                parent,
                child: candidate_context.1,
                ..statement
            };
            assert!(received.verify_quorum(1, &prepares, &electorate));
            assert!(received.verify_quorum(2, &commits, &electorate));
            peer.apply_certified_recovery(request, &signed_certificate)
                .unwrap();
            assert_eq!(
                peer.apply_certified_recovery(request, &signed_certificate),
                Err(Error::StaleProposal)
            );
            assert_eq!(peer.rotation_context(), *context);
            assert_eq!(peer.membership(*replacement), Some(tenure));
            let (_, losing_key, losing_request, _) = &requests[1 - winner];
            assert_eq!(
                peer.apply_certified_recovery(losing_request, &signed_certificate),
                Err(Error::StaleProposal)
            );
            assert!(peer.membership(*losing_key).is_none());
            assert!(peer.membership(old).is_none());
        }
        let [left, right] = &mut peers;
        assert_eq!(left.catch_up(right), CatchUp::AlreadyCurrent);
        assert_eq!(delayed.catch_up(left), CatchUp::AlreadyCurrent);
    }
}

#[test]
fn certified_rotation_requires_dual_key_consent_and_parent_quorums() {
    use ed25519_dalek::SigningKey;
    use mesh_identity::groups::{
        Error, Policy,
        evidence::{CatchUp, RosterCertificate, SignedRotation},
    };
    use support::Scenario;

    let mut s = Scenario::new(170, Policy::InviterOnly);
    let old = s.carol.selected();
    let tenure = s.group.membership(old).unwrap();
    let context = s.group.rotation_context();
    let [first, second] = [1, 2].map(|now| {
        let new = s
            .carol
            .add_identity(SigningKey::generate(&mut s.rng))
            .unwrap();
        s.carol.select(old, now).unwrap();
        let old_consent = s
            .carol
            .sign_group_rotation(context.0, context.1, old, new)
            .unwrap();
        s.carol.select(new, now).unwrap();
        let new_consent = s
            .carol
            .sign_group_rotation(context.0, context.1, old, new)
            .unwrap();
        (
            new,
            SignedRotation::new(context, old, new, [old_consent, new_consent]),
        )
    });
    let (new, rotation) = first;
    let child = s.group.rotation_child(&rotation).unwrap();
    assert_ne!(child, s.group.rotation_child(&second.1).unwrap());
    let statement = RosterStatement {
        group: context.0,
        parent: context.1,
        child,
        round: 1,
    };
    let signers = [&s.alice, &s.dave, &s.eve];
    let prepares = signers.map(|signer| statement.sign(PREPARE_PHASE, signer));
    let commits = signers.map(|signer| statement.sign(COMMIT_PHASE, signer));
    let mut certificate = RosterCertificate {
        group: context.0,
        parent: context.1,
        child,
        round: statement.round,
        prepares: prepares.to_vec(),
        commits: prepares.to_vec(),
    };
    assert_eq!(
        s.group.apply_certified_rotation(&rotation, &certificate),
        Err(Error::Ineligible)
    );
    certificate.commits = commits.to_vec();
    assert_eq!(
        s.group.apply_certified_rotation(&second.1, &certificate),
        Err(Error::Ineligible)
    );

    let unauthenticated = SignedRotation::new(context, old, new, [[0; 64]; 2]);
    assert_eq!(
        s.group
            .apply_certified_rotation(&unauthenticated, &certificate),
        Err(Error::Ineligible)
    );
    assert_eq!(s.group.rotation_context(), context);
    assert_eq!(s.group.membership(old), Some(tenure));
    assert!(s.group.membership(new).is_none());

    let rotation = SignedRotation::from_bytes(&rotation.to_bytes()).unwrap();
    let certificate = RosterCertificate::from_bytes(&certificate.to_bytes().unwrap()).unwrap();
    for peer in [&mut s.group, &mut s.alice_offline] {
        peer.apply_certified_rotation(&rotation, &certificate)
            .unwrap();
        assert_eq!(peer.membership(new), Some(tenure));
        assert!(peer.membership(old).is_none());
        assert_eq!(
            peer.apply_certified_rotation(&rotation, &certificate),
            Err(Error::StaleProposal)
        );
    }
    assert_eq!(s.alice_offline.catch_up(&s.group), CatchUp::AlreadyCurrent);
}

#[test]
fn first_join_requires_certified_admission_on_its_trusted_parent() {
    use mesh_identity::groups::{
        LocalInstallation, Policy,
        evidence::{
            RosterCertificate, RosterFreshnessChallenge, RosterFreshnessError,
            SignedAdmissionConsent, SignedInvitation, VouchedGroup,
        },
    };
    use std::time::Instant;
    use support::{Scenario, meet};

    let mut s = Scenario::new(172, Policy::InviterOnly);
    let (alice, bob) = (s.alice.selected(), s.bob.selected());
    meet(&mut s.alice, &mut s.bob, 1, &mut s.rng);
    let proposal = s.group.invite_until(alice, bob, 100).unwrap();
    let voucher = s.group.vouch(&proposal, &s.alice, [], 100).unwrap();
    let invitation = SignedInvitation::new(&proposal, &s.alice).unwrap();
    let invitation = SignedInvitation::from_bytes(&invitation.to_bytes()).unwrap();

    // The fixture authenticates the starting roster out of band.
    let mut candidate_view = s.group.clone();
    let mut pending = candidate_view.receive_invitation(&invitation).unwrap();
    let consent = SignedAdmissionConsent::new(&pending, &s.bob).unwrap();
    candidate_view
        .apply_admission_consent(&mut pending, &consent)
        .unwrap();
    assert!(candidate_view.membership(bob).is_none());
    assert!(candidate_view.export_roster(&s.bob).is_err());

    let (group, parent) = s.group.rotation_context();
    let child = candidate_view.admission_child(&pending, &voucher).unwrap();
    let statement = RosterStatement {
        group,
        parent,
        child,
        round: 1,
    };
    let signers = [&s.alice, &s.dave, &s.eve];
    let mut certificate = RosterCertificate {
        group,
        parent,
        child,
        round: statement.round,
        prepares: signers
            .map(|signer| statement.sign(PREPARE_PHASE, signer))
            .to_vec(),
        commits: signers
            .map(|signer| statement.sign(COMMIT_PHASE, signer))
            .to_vec(),
    };
    let last_commit = certificate.commits.pop().unwrap();
    assert!(
        candidate_view
            .apply_certified_admission(&pending, voucher.clone(), &certificate)
            .is_err()
    );
    assert_eq!(candidate_view.rotation_context(), (group, parent));
    assert!(candidate_view.membership(bob).is_none());
    certificate.commits.push(last_commit);
    let certificate = RosterCertificate::from_bytes(&certificate.to_bytes().unwrap()).unwrap();

    let mut other_parent = VouchedGroup::new(
        group,
        [
            alice,
            s.carol.selected(),
            s.dave.selected(),
            s.eve.selected(),
        ],
        Policy::InviterOnly,
    );
    assert!(
        other_parent
            .apply_certified_admission(&pending, voucher.clone(), &certificate)
            .is_err()
    );
    assert!(other_parent.membership(bob).is_none());

    candidate_view
        .apply_certified_admission(&pending, voucher.clone(), &certificate)
        .unwrap();
    let now = Instant::now();
    let challenge = RosterFreshnessChallenge::new(group, now);
    assert_eq!(
        candidate_view.confirmed_membership(&s.bob, &challenge, &[], now),
        Err(RosterFreshnessError::Unconfirmed)
    );
    s.group
        .apply_certified_admission(&pending, voucher, &certificate)
        .unwrap();
    let responses = [&s.alice, &s.carol, &s.dave, &s.eve].map(|signer| {
        let mut local = LocalInstallation::default();
        let tenure = s.group.membership(signer.selected()).unwrap();
        local.add_identity(tenure.identity(), "Member".into());
        s.group
            .attest_roster_freshness(&local, challenge.query(), signer)
            .unwrap()
    });
    let confirmed = candidate_view
        .confirmed_membership(&s.bob, &challenge, &responses, now)
        .unwrap();
    assert!(confirmed.is_some());
    assert_eq!(candidate_view.membership(bob), confirmed);
    assert!(candidate_view.export_roster(&s.bob).is_ok());
}

#[test]
fn certified_admission_and_ejection_cannot_commit_from_the_same_parent() {
    use mesh_identity::groups::{
        Error, Policy, Vote,
        evidence::{
            AdmissionError, CatchUp, RosterCertificate, SignedAdmissionConsent,
            SignedAdmissionVote, SignedEjectionVote,
        },
    };
    use support::{Scenario, meet};

    for admit_first in [true, false] {
        let mut s = Scenario::new(171, Policy::Majority);
        let (alice, bob, carol) = (s.alice.selected(), s.bob.selected(), s.carol.selected());
        let tenure = s.group.membership(carol).unwrap();
        meet(&mut s.alice, &mut s.bob, 1, &mut s.rng);
        let mut invitation = s.group.invite(alice, bob).unwrap();
        let voucher = s.group.vouch(&invitation, &s.alice, [alice], 100).unwrap();
        let alternate_voucher = s.group.vouch(&invitation, &s.alice, [alice], 100).unwrap();
        assert_eq!(
            s.group.admission_child(&invitation, &voucher),
            Err(AdmissionError::Roster(Error::AcceptanceRequired))
        );
        let consent = SignedAdmissionConsent::new(&invitation, &s.bob).unwrap();
        s.group
            .apply_admission_consent(&mut invitation, &consent)
            .unwrap();
        for signer in [&s.dave, &s.eve] {
            let vote = SignedAdmissionVote::new(&invitation, signer, Vote::Approve).unwrap();
            s.group
                .apply_admission_vote(&mut invitation, &vote)
                .unwrap();
        }

        let mut ejection = s.group.propose_signed_ejection(&s.alice, carol).unwrap();
        assert_eq!(
            s.group.ejection_child(&ejection),
            Err(Error::ApprovalRequired)
        );
        let vote = SignedEjectionVote::new(&ejection, &s.dave).unwrap();
        s.group.apply_ejection_vote(&mut ejection, &vote).unwrap();

        let (group, parent) = s.group.rotation_context();
        let signers = [&s.alice, &s.dave, &s.eve];
        let child = if admit_first {
            s.group.admission_child(&invitation, &voucher).unwrap()
        } else {
            s.group.ejection_child(&ejection).unwrap()
        };
        let statement = RosterStatement {
            group,
            parent,
            child,
            round: 1,
        };
        let certificate = RosterCertificate {
            group,
            parent,
            child,
            round: statement.round,
            prepares: signers
                .map(|signer| statement.sign(PREPARE_PHASE, signer))
                .to_vec(),
            commits: signers
                .map(|signer| statement.sign(COMMIT_PHASE, signer))
                .to_vec(),
        };
        let certificate = RosterCertificate::from_bytes(&certificate.to_bytes().unwrap()).unwrap();

        for peer in [&mut s.group, &mut s.alice_offline] {
            let plan = peer.plan_distribution();
            if admit_first {
                assert_eq!(
                    peer.apply_certified_ejection(&ejection, &certificate),
                    Err(Error::Ineligible)
                );
                assert!(matches!(
                    peer.apply_certified_admission(
                        &invitation,
                        alternate_voucher.clone(),
                        &certificate
                    ),
                    Err(AdmissionError::Roster(Error::Ineligible))
                ));
                assert_eq!(peer.rotation_context(), (group, parent));
                peer.apply_certified_admission(&invitation, voucher.clone(), &certificate)
                    .unwrap();
                assert_eq!(
                    peer.apply_certified_ejection(&ejection, &certificate),
                    Err(Error::StaleProposal)
                );
                assert!(peer.membership(bob).is_some());
                assert_eq!(peer.membership(carol), Some(tenure));
            } else {
                assert!(matches!(
                    peer.apply_certified_admission(&invitation, voucher.clone(), &certificate),
                    Err(AdmissionError::Roster(Error::Ineligible))
                ));
                assert_eq!(peer.rotation_context(), (group, parent));
                peer.apply_certified_ejection(&ejection, &certificate)
                    .unwrap();
                assert!(matches!(
                    peer.apply_certified_admission(&invitation, voucher.clone(), &certificate),
                    Err(AdmissionError::Roster(Error::StaleProposal))
                ));
                assert!(peer.membership(bob).is_none());
                assert!(peer.membership(carol).is_none());
                assert!(
                    !peer
                        .distribution_recipients(&peer.plan_distribution())
                        .unwrap()
                        .contains(&carol)
                );
            }
            assert_eq!(
                peer.distribution_recipients(&plan),
                Err(Error::StaleProposal)
            );
            assert_eq!(peer.rotation_context(), (group, child));
        }
        assert_eq!(s.alice_offline.catch_up(&s.group), CatchUp::AlreadyCurrent);
        if admit_first {
            certify_ejection_from_five_member_roster(&mut s);
        }
    }
}

#[test]
fn certified_rotation_chain_changes_the_electorate_at_each_step() {
    use ed25519_dalek::SigningKey;
    use mesh_identity::groups::{
        Error, Policy,
        evidence::{CatchUp, RosterCertificate, SignedRotation},
    };
    use support::Scenario;

    let mut s = Scenario::new(172, Policy::InviterOnly);
    let old_carol = s.carol.selected();
    let old_dave = s.dave.selected();
    let alice = s.alice.selected();
    let carol_tenure = s.group.membership(old_carol);
    let dave_tenure = s.group.membership(old_dave);
    let original = s.group.rotation_context();
    let carol = s
        .carol
        .add_identity(SigningKey::generate(&mut s.rng))
        .unwrap();
    let dave = s
        .dave
        .add_identity(SigningKey::generate(&mut s.rng))
        .unwrap();

    let sign_rotation = |member: &mut mesh_identity::session::installation::Installation,
                         context: (u64, [u8; 32]),
                         new| {
        let old = member.selected();
        let first = member
            .sign_group_rotation(context.0, context.1, old, new)
            .unwrap();
        member.select(new, 1).unwrap();
        let second = member
            .sign_group_rotation(context.0, context.1, old, new)
            .unwrap();
        SignedRotation::new(context, old, new, [first, second])
    };
    let first = sign_rotation(&mut s.carol, original, carol);
    s.carol.select(old_carol, 2).unwrap();

    let certify =
        |context: (u64, [u8; 32]),
         child,
         signers: [&mesh_identity::session::installation::Installation; 3]| {
            let statement = RosterStatement {
                group: context.0,
                parent: context.1,
                child,
                round: 1,
            };
            RosterCertificate {
                group: statement.group,
                parent: statement.parent,
                child,
                round: statement.round,
                prepares: signers
                    .map(|signer| statement.sign(PREPARE_PHASE, signer))
                    .to_vec(),
                commits: signers
                    .map(|signer| statement.sign(COMMIT_PHASE, signer))
                    .to_vec(),
            }
        };

    let first_child = s.group.rotation_child(&first).unwrap();
    let first_certificate = certify(original, first_child, [&s.alice, &s.carol, &s.eve]);
    s.group
        .apply_certified_rotation(&first, &first_certificate)
        .unwrap();
    let intermediate = s.group.rotation_context();
    let second = sign_rotation(&mut s.dave, intermediate, dave);
    let second_child = s.group.rotation_child(&second).unwrap();
    let wrong = certify(intermediate, second_child, [&s.alice, &s.carol, &s.eve]);
    s.carol.select(carol, 3).unwrap();
    let second_certificate = certify(intermediate, second_child, [&s.alice, &s.carol, &s.eve]);

    let first = SignedRotation::from_bytes(&first.to_bytes()).unwrap();
    let second = SignedRotation::from_bytes(&second.to_bytes()).unwrap();
    let first_certificate =
        RosterCertificate::from_bytes(&first_certificate.to_bytes().unwrap()).unwrap();
    let second_certificate =
        RosterCertificate::from_bytes(&second_certificate.to_bytes().unwrap()).unwrap();
    let first_step = (&first, &first_certificate);
    let second_step = (&second, &second_certificate);
    let peer = &mut s.alice_offline;
    assert_eq!(
        peer.apply_certified_rotation_chain(&[second_step, first_step]),
        Err(Error::StaleProposal)
    );
    assert_eq!(
        peer.apply_certified_rotation_chain(&[first_step, (&second, &wrong)]),
        Err(Error::Ineligible)
    );
    assert_eq!(peer.rotation_context(), original);
    assert_eq!(peer.membership(old_carol), carol_tenure);
    assert_eq!(peer.membership(old_dave), dave_tenure);
    assert!(peer.membership(carol).is_none());
    assert!(peer.membership(dave).is_none());

    peer.apply_certified_rotation_chain(&[first_step, second_step])
        .unwrap();
    s.group
        .apply_certified_rotation(&second, &second_certificate)
        .unwrap();
    assert_eq!(peer.catch_up(&s.group), CatchUp::AlreadyCurrent);
    assert_eq!(peer.membership(carol), carol_tenure);
    assert_eq!(peer.membership(dave), dave_tenure);
    assert!(peer.membership(old_carol).is_none());
    assert!(peer.membership(old_dave).is_none());
    assert!(
        peer.distribution_recipients(&peer.plan_distribution())
            .unwrap()
            .contains(&alice)
    );
    assert_eq!(
        peer.apply_certified_rotation_chain(&[first_step, second_step]),
        Err(Error::StaleProposal)
    );
    assert_eq!(peer.rotation_context(), s.group.rotation_context());
}

fn certify_ejection_from_five_member_roster(s: &mut support::Scenario) {
    use mesh_identity::groups::Error;
    use mesh_identity::groups::evidence::{
        CatchUp, RosterCertificate, RosterPrepareProof, RosterRoundChange, SignedEjectionVote,
    };

    let target = s.carol.selected();
    let newcomer = s.bob.selected();
    let mut ejection = s.group.propose_signed_ejection(&s.alice, target).unwrap();
    for signer in [&s.dave, &s.eve] {
        let vote = SignedEjectionVote::new(&ejection, signer).unwrap();
        s.group.apply_ejection_vote(&mut ejection, &vote).unwrap();
    }
    let (group, parent) = s.group.rotation_context();
    let child = s.group.ejection_child(&ejection).unwrap();
    let statement = RosterStatement {
        group,
        parent,
        child,
        round: 1,
    };
    // The newly admitted member can now supply the fourth eligible signature.
    let signers = [&s.alice, &s.dave, &s.eve, &s.bob];
    let mut certificate = RosterCertificate {
        group,
        parent,
        child,
        round: statement.round,
        prepares: signers[..3]
            .iter()
            .map(|signer| statement.sign(PREPARE_PHASE, signer))
            .collect(),
        commits: signers[..3]
            .iter()
            .map(|signer| statement.sign(COMMIT_PHASE, signer))
            .collect(),
    };
    assert_eq!(
        s.group.apply_certified_ejection(&ejection, &certificate),
        Err(Error::Ineligible)
    );
    assert_eq!(s.group.rotation_context(), (group, parent));

    let mut proof = RosterPrepareProof {
        round: 1,
        child,
        votes: certificate.prepares.clone(),
    };
    let mut reports: Vec<_> = [&s.dave, &s.eve, &s.bob]
        .map(|member| RosterRoundChange::new_unchecked((group, parent), 2, None, member))
        .into_iter()
        .collect();
    assert_eq!(
        s.group.round_change_child(2, &reports),
        Err(Error::Ineligible)
    );
    reports.push(RosterRoundChange::new_unchecked(
        (group, parent),
        2,
        Some(proof.clone()),
        &s.alice,
    ));
    assert_eq!(
        s.group.round_change_child(2, &reports),
        Err(Error::Ineligible)
    );

    let prepare = statement.sign(PREPARE_PHASE, &s.bob);
    certificate.prepares.push(prepare);
    assert!(certificate.to_bytes().is_err());
    certificate
        .commits
        .push(statement.sign(COMMIT_PHASE, &s.bob));
    proof.votes.push(prepare);
    let report = RosterRoundChange::new_unchecked((group, parent), 2, Some(proof), &s.alice);
    reports[3] = RosterRoundChange::from_bytes(&report.to_bytes().unwrap()).unwrap();
    assert_eq!(s.group.round_change_child(2, &reports), Ok(Some(child)));

    let certificate = RosterCertificate::from_bytes(&certificate.to_bytes().unwrap()).unwrap();
    for peer in [&mut s.group, &mut s.alice_offline] {
        peer.apply_certified_ejection(&ejection, &certificate)
            .unwrap();
        assert!(peer.membership(target).is_none());
        assert!(peer.membership(newcomer).is_some());
        let context = peer.rotation_context();
        let reports = [&s.alice, &s.dave, &s.bob]
            .map(|member| RosterRoundChange::new_unchecked(context, 1, None, member));
        assert_eq!(peer.round_change_child(1, &reports), Ok(None));
    }
    assert_eq!(s.alice_offline.catch_up(&s.group), CatchUp::AlreadyCurrent);
}

#[test]
fn authenticated_report_collection_recovers_a_quorum_after_conflicting_delivery() {
    use mesh_identity::groups::{
        Error, Policy,
        evidence::{
            RosterPrepareProof, RosterRoundChange, RoundChangeCollector, RoundReportDelivery,
            SimulatedAuthority as _,
        },
    };
    use support::Scenario;

    let s = Scenario::new(173, Policy::InviterOnly);
    let context = s.group.rotation_context();
    let child = [17; 32];
    let prepared = RosterStatement {
        group: context.0,
        parent: context.1,
        child,
        round: 1,
    };
    let proof = RosterPrepareProof {
        round: prepared.round,
        child,
        votes: [&s.alice, &s.carol, &s.dave]
            .map(|signer| prepared.sign(PREPARE_PHASE, signer))
            .to_vec(),
    };
    let claim = RosterRoundChange::new_unchecked(context, 2, Some(proof.clone()), &s.alice)
        .to_bytes()
        .unwrap();
    let omission = RosterRoundChange::new_unchecked(context, 2, None, &s.alice)
        .to_bytes()
        .unwrap();
    let honest = [
        RosterRoundChange::new_unchecked(context, 2, Some(proof), &s.carol),
        RosterRoundChange::new_unchecked(context, 2, None, &s.dave),
        RosterRoundChange::new_unchecked(context, 2, None, &s.eve),
    ]
    .map(|report| report.to_bytes().unwrap());

    for deliveries in [[&claim, &omission], [&omission, &claim]] {
        let mut collector = RoundChangeCollector::new(&s.group, 2).unwrap();
        let decode = |bytes: &[u8]| RosterRoundChange::from_bytes(bytes).unwrap();
        let [first, second] = deliveries;
        assert_eq!(
            collector.record(&s.group, decode(first)),
            Ok(RoundReportDelivery::Recorded)
        );
        assert_eq!(
            collector.record(&s.group, decode(first)),
            Ok(RoundReportDelivery::Duplicate)
        );
        let mut corrupted = second.clone();
        corrupted[76] ^= 1;
        assert_eq!(
            collector.record(&s.group, decode(&corrupted)),
            Err(Error::Ineligible)
        );
        assert_eq!(
            collector.record(&s.group, decode(&honest[0])),
            Ok(RoundReportDelivery::Recorded)
        );
        assert_eq!(
            collector.record(&s.group, decode(&honest[1])),
            Ok(RoundReportDelivery::Recorded)
        );
        assert_eq!(collector.prepared_child(&s.group), Ok(Some(child)));
        assert_eq!(
            collector.record(&s.group, decode(second)),
            Ok(RoundReportDelivery::Conflicting)
        );
        assert_eq!(
            collector.prepared_child(&s.group),
            Err(Error::ApprovalRequired)
        );
        assert_eq!(
            collector.record(&s.group, decode(first)),
            Ok(RoundReportDelivery::Conflicting)
        );
        assert_eq!(
            collector.record(&s.group, decode(&honest[2])),
            Ok(RoundReportDelivery::Recorded)
        );
        assert_eq!(collector.prepared_child(&s.group), Ok(Some(child)));

        let mut descendant = s.group.clone();
        descendant.mark_suspect(s.eve.selected()).unwrap();
        assert_eq!(
            collector.prepared_child(&descendant),
            Err(Error::StaleProposal)
        );
        assert_eq!(
            collector.record(&descendant, decode(first)),
            Err(Error::StaleProposal)
        );
    }
}
