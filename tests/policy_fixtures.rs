#![cfg(all(feature = "groups", feature = "test-support"))]
use mesh_identity::groups::evidence::SimulatedAuthority as _;
use mesh_identity::groups::{
    Error, Group, Identity, Policy, Supermajority, Vote, evidence::VouchedGroup,
};
use std::num::NonZeroUsize;

struct PolicyCase {
    name: &'static str,
    policy: Policy,
    members: usize,
    admission: usize,
    ejection: Option<usize>,
}

#[test]
fn admission_and_ejection_follow_policy_boundaries() {
    let cases = [
        PolicyCase {
            name: "inviter only",
            policy: Policy::InviterOnly,
            members: 5,
            admission: 1,
            ejection: None,
        },
        PolicyCase {
            name: "fixed two",
            policy: Policy::Fixed(NonZeroUsize::new(2).unwrap()),
            members: 5,
            admission: 2,
            ejection: Some(3),
        },
        PolicyCase {
            name: "fixed exceeds remaining roster",
            policy: Policy::Fixed(NonZeroUsize::new(3).unwrap()),
            members: 3,
            admission: 3,
            ejection: None,
        },
        PolicyCase {
            name: "even majority",
            policy: Policy::Majority,
            members: 4,
            admission: 3,
            ejection: Some(2),
        },
        PolicyCase {
            name: "odd majority",
            policy: Policy::Majority,
            members: 5,
            admission: 3,
            ejection: Some(3),
        },
        PolicyCase {
            name: "two thirds",
            policy: Policy::TwoThirds,
            members: 6,
            admission: 4,
            ejection: Some(3),
        },
        PolicyCase {
            name: "three quarters",
            policy: Policy::Supermajority(Supermajority::new(3, 4).unwrap()),
            members: 7,
            admission: 6,
            ejection: Some(4),
        },
        PolicyCase {
            name: "unanimous",
            policy: Policy::Unanimous,
            members: 5,
            admission: 5,
            ejection: Some(3),
        },
        PolicyCase {
            name: "two-member unanimous",
            policy: Policy::Unanimous,
            members: 2,
            admission: 2,
            ejection: Some(1),
        },
        PolicyCase {
            name: "last member",
            policy: Policy::Unanimous,
            members: 1,
            admission: 1,
            ejection: None,
        },
    ];

    for case in cases {
        check_admission(&case);
        check_ejection(&case);
    }
}

fn check_admission(case: &PolicyCase) {
    let members: Vec<_> = (0..case.members as u64).map(Identity).collect();
    let candidate = Identity(case.members as u64);
    let mut group = Group::new(1, members.iter().copied(), case.policy);
    let mut proposal = group.invite(members[0], candidate).unwrap();
    proposal.accept(candidate).unwrap();
    for voter in members.iter().take(case.admission).skip(1) {
        assert_eq!(
            group.admit(&proposal),
            Err(Error::ApprovalRequired),
            "{}",
            case.name
        );
        group.vote(&mut proposal, *voter, Vote::Approve).unwrap();
    }
    assert_eq!(group.admit(&proposal), Ok(()), "{}", case.name);
    assert!(group.membership(candidate).is_some(), "{}", case.name);
}

fn check_ejection(case: &PolicyCase) {
    // These are opaque identity labels for the ordered roster fixture.
    let members: Vec<_> = (0..case.members).map(|index| [index as u8; 32]).collect();
    let target = members[0];
    let proposer = members.get(1).copied().unwrap_or(target);
    let mut group = VouchedGroup::new(1, members.iter().copied(), case.policy);
    let proposal = group.propose_ejection(proposer, target);
    let Some(required) = case.ejection else {
        assert!(matches!(proposal, Err(Error::Ineligible)), "{}", case.name);
        return;
    };
    let mut proposal = proposal.unwrap_or_else(|error| panic!("{}: {error:?}", case.name));
    assert_eq!(
        group.approve_removal(&mut proposal, target),
        Err(Error::Ineligible)
    );
    assert_eq!(
        group.approve_removal(&mut proposal, proposer),
        Err(Error::AlreadyVoted)
    );
    for voter in members.iter().skip(2).take(required - 1) {
        assert_eq!(
            group.apply_removal(&proposal),
            Err(Error::ApprovalRequired),
            "{}",
            case.name
        );
        group.approve_removal(&mut proposal, *voter).unwrap();
    }
    assert_eq!(group.apply_removal(&proposal), Ok(()), "{}", case.name);
    assert!(group.membership(target).is_none(), "{}", case.name);
    assert!(group.membership(proposer).is_some(), "{}", case.name);
}
