#![cfg(feature = "groups")]
use mesh_identity::groups::{Error, Group, Identity, MemberLocalState, Policy, Vote};
use std::num::NonZeroUsize;

const GAME: Identity = Identity(1);
const PRIVATE: Identity = Identity(2);
const PEER: Identity = Identity(3);
const CANDIDATE: Identity = Identity(4);

#[test]
fn local_leave_survives_restart_and_affects_only_one_membership() {
    let mut local = MemberLocalState::default();
    assert!(local.add_identity(GAME, "Bob".into()));
    assert!(local.add_identity(PRIVATE, "Bob".into()));
    assert!(!local.add_identity(GAME, "duplicate key".into()));
    let mut group = Group::new(1, [GAME, PRIVATE, PEER], Policy::InviterOnly);
    let another_group = Group::new(2, [GAME], Policy::InviterOnly);
    let queued = group.membership(GAME).unwrap();
    let private = group.membership(PRIVATE).unwrap();
    let other = another_group.membership(GAME).unwrap();

    assert!(local.may_present(queued, &group));
    assert_eq!(
        local.leave(group.membership(PEER).unwrap()),
        Err(Error::Ineligible)
    );
    local.leave(queued).unwrap();
    let local = MemberLocalState::restore(&local.snapshot().unwrap()).unwrap();
    assert_eq!(local.identities().count(), 2);
    assert_eq!(group.membership(GAME), Some(queued));
    assert!(!local.may_present(queued, &group));
    assert!(local.may_present(private, &group));
    assert!(local.may_present(other, &another_group));

    for intent in local.departure_intents() {
        assert!(group.apply_departure(intent).unwrap());
    }
    assert!(!local.may_present(queued, &group));

    let mut rejoin = group.invite(PEER, GAME).unwrap();
    rejoin.accept(GAME).unwrap();
    group.admit(&rejoin).unwrap();
    assert!(!group.apply_departure(queued).unwrap());
    let current = group.membership(GAME).unwrap();
    assert!(local.may_present(current, &group));
    assert!(!local.may_present(queued, &group));
}

#[test]
fn departure_and_admission_can_be_ordered_either_way() {
    for leave_first in [false, true] {
        let mut group = Group::new(1, [GAME, PRIVATE, PEER], Policy::Majority);
        let leaving = group.membership(GAME).unwrap();
        let mut proposal = group.invite(GAME, CANDIDATE).unwrap();
        group.vote(&mut proposal, PRIVATE, Vote::Approve).unwrap();
        proposal.accept(CANDIDATE).unwrap();

        if leave_first {
            assert!(group.apply_departure(leaving).unwrap());
            assert_eq!(group.admit(&proposal), Err(Error::StaleProposal));
            assert!(matches!(
                group.invite(GAME, CANDIDATE),
                Err(Error::Ineligible)
            ));
            let mut fresh = group.invite(PRIVATE, CANDIDATE).unwrap();
            fresh.accept(CANDIDATE).unwrap();
            assert_eq!(group.admit(&fresh), Err(Error::ApprovalRequired));
            group.vote(&mut fresh, PEER, Vote::Approve).unwrap();
            group.admit(&fresh).unwrap();
        } else {
            group.admit(&proposal).unwrap();
            assert!(group.apply_departure(leaving).unwrap());
        }

        assert!(group.membership(GAME).is_none());
        assert!(group.membership(PRIVATE).is_some());
        assert!(group.membership(CANDIDATE).is_some());
    }
}

#[test]
fn competing_admissions_require_fresh_decisions() {
    let mut group = Group::new(1, [GAME, PRIVATE], Policy::InviterOnly);
    let mut first = group.invite(GAME, CANDIDATE).unwrap();
    let mut second = group.invite(PRIVATE, PEER).unwrap();
    first.accept(CANDIDATE).unwrap();
    second.accept(PEER).unwrap();
    group.admit(&first).unwrap();
    assert_eq!(group.admit(&second), Err(Error::StaleProposal));
    let fresh = group.invite(PRIVATE, PEER).unwrap();
    assert_eq!(group.admit(&fresh), Err(Error::AcceptanceRequired));
}

#[test]
fn approvals_count_by_eligible_identity_under_each_policy() {
    let members = [GAME, PRIVATE, PEER, Identity(5), Identity(6)];
    for (policy, threshold) in [
        (Policy::InviterOnly, 1),
        (Policy::Fixed(NonZeroUsize::new(2).unwrap()), 2),
        (Policy::Majority, 3),
        (Policy::TwoThirds, 4),
        (Policy::Unanimous, 5),
    ] {
        let mut group = Group::new(1, members, policy);
        let mut proposal = group.invite(GAME, CANDIDATE).unwrap();
        assert_eq!(proposal.accept(PRIVATE), Err(Error::Ineligible));
        assert_eq!(group.admit(&proposal), Err(Error::AcceptanceRequired));
        proposal.accept(CANDIDATE).unwrap();
        assert_eq!(
            group.vote(&mut proposal, GAME, Vote::Approve),
            Err(Error::AlreadyVoted)
        );
        assert_eq!(
            group.vote(&mut proposal, CANDIDATE, Vote::Approve),
            Err(Error::Ineligible)
        );
        for voter in members.iter().take(threshold).skip(1) {
            assert_eq!(group.admit(&proposal), Err(Error::ApprovalRequired));
            group.vote(&mut proposal, *voter, Vote::Approve).unwrap();
        }
        group.admit(&proposal).unwrap();
    }
}

#[test]
fn objections_and_abstentions_do_not_approve() {
    let mut group = Group::new(
        1,
        [GAME, PRIVATE, PEER, Identity(5), Identity(6)],
        Policy::Majority,
    );
    let mut proposal = group.invite(GAME, CANDIDATE).unwrap();
    proposal.accept(CANDIDATE).unwrap();
    group.vote(&mut proposal, PRIVATE, Vote::Abstain).unwrap();
    group.vote(&mut proposal, PEER, Vote::Object).unwrap();
    group
        .vote(&mut proposal, Identity(5), Vote::Approve)
        .unwrap();
    assert_eq!(group.admit(&proposal), Err(Error::ApprovalRequired));
}

#[test]
fn identity_collection_grows_and_restores_with_duplicate_labels() {
    let mut local = MemberLocalState::default();
    for number in 0..2048 {
        assert!(local.add_identity(Identity(number), "Bob".into()));
    }
    let restored = MemberLocalState::restore(&local.snapshot().unwrap()).unwrap();
    assert!(local.identities().eq(restored.identities()));
}

#[test]
fn departing_member_is_gated_locally_and_applied_intents_are_pruned() {
    let mut local = MemberLocalState::default();
    local.add_identity(GAME, "Bob".into());
    let mut group = Group::new(1, [GAME, PRIVATE, PEER], Policy::Unanimous);
    let leaving = group.membership(GAME).unwrap();
    local.leave(leaving).unwrap();
    // Group alone still accepts the vote; the local gate is what stops it.
    assert!(!local.may_vote(leaving, &group));
    let mut proposal = group.invite(PEER, CANDIDATE).unwrap();
    assert_eq!(group.vote(&mut proposal, GAME, Vote::Approve), Ok(()));
    // Once applied, the intent can be pruned without resurrecting the old tenure.
    assert!(group.apply_departure(leaving).unwrap());
    local.prune_departures(&group);
    assert_eq!(local.departure_intents().count(), 0);
    assert!(!local.may_present(leaving, &group));
    // A lagging group view where the member is still recorded active cannot resurrect presentation:
    let lagging_view = Group::new(1, [GAME, PRIVATE, PEER], Policy::Unanimous);
    assert!(!local.may_present(leaving, &lagging_view));
    // An unapplied intent for a current tenure is kept.
    let private = group.membership(PRIVATE).unwrap();
    let mut other = MemberLocalState::default();
    other.add_identity(PRIVATE, "p".into());
    other.leave(private).unwrap();
    other.prune_departures(&group);
    assert_eq!(other.departure_intents().count(), 1);
}

#[test]
fn legacy_departure_stays_hidden_before_and_after_pruning() {
    let mut group = Group::new(1, [GAME], Policy::InviterOnly);
    let member = group.membership(GAME).unwrap();
    let legacy =
        br#"{"identities":{"1":"Bob"},"departures":[{"group":1,"identity":1,"joined_at":0}]}"#;
    let mut local = MemberLocalState::restore(legacy).unwrap();
    assert!(!local.may_present(member, &group));
    assert!(!local.may_vote(member, &group));
    assert!(group.apply_departure(member).unwrap());
    local.prune_departures(&group);
    assert_eq!(local.departure_intents().count(), 0);

    let lagging = Group::new(1, [GAME], Policy::InviterOnly);
    let restored = MemberLocalState::restore(&local.snapshot().unwrap()).unwrap();
    assert!(!restored.may_present(member, &lagging));
}

#[test]
fn roster_from_before_join_cannot_prune_pending_departure() {
    let view_before_join = Group::new(1, [PEER], Policy::InviterOnly);
    let mut group = Group::new(1, [PEER], Policy::InviterOnly);
    let mut invite = group.invite(PEER, GAME).unwrap();
    invite.accept(GAME).unwrap();
    group.admit(&invite).unwrap();
    let member = group.membership(GAME).unwrap();

    let mut local = MemberLocalState::default();
    local.add_identity(GAME, "Bob".into());
    local.leave(member).unwrap();
    local.prune_departures(&view_before_join);
    assert_eq!(local.departure_intents().collect::<Vec<_>>(), [member]);
    assert!(group.apply_departure(member).unwrap());
    local.prune_departures(&group);
    assert_eq!(local.departure_intents().count(), 0);
}

#[test]
fn configurable_supermajority_uses_full_roster_and_rounds_up() {
    use mesh_identity::groups::Supermajority;

    for (numerator, denominator) in [(0, 0), (1, 2), (4, 3)] {
        assert!(Supermajority::new(numerator, denominator).is_none());
    }
    for (numerator, denominator, eligible, required) in [(2, 3, 6, 4), (2, 3, 7, 5), (3, 4, 7, 6)] {
        let policy = Policy::Supermajority(Supermajority::new(numerator, denominator).unwrap());
        let mut group = Group::new(1, (0..eligible).map(Identity), policy);
        let candidate = Identity(eligible);
        let mut proposal = group.invite(Identity(0), candidate).unwrap();
        proposal.accept(candidate).unwrap();
        for voter in 1..required {
            assert_eq!(group.admit(&proposal), Err(Error::ApprovalRequired));
            group
                .vote(&mut proposal, Identity(voter), Vote::Approve)
                .unwrap();
        }
        group.admit(&proposal).unwrap();
        assert!(group.membership(candidate).is_some());
    }
}
