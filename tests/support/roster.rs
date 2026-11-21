use mesh_identity::groups::{
    MemberLocalState,
    evidence::{RosterCertificate, RosterVotePhase, VouchedGroup},
};
use mesh_identity::session::installation::Installation;

pub fn local_for(group: &VouchedGroup, member: &Installation) -> MemberLocalState {
    let mut local = MemberLocalState::default();
    let tenure = group.membership(member.selected()).unwrap();
    local.add_identity(tenure.identity(), "Member".into());
    local
}

pub fn certify(
    group: &VouchedGroup,
    child: [u8; 32],
    voters: &[&Installation],
) -> RosterCertificate {
    let (id, parent) = group.rotation_context();
    let votes = |phase| {
        voters
            .iter()
            .map(|voter| {
                group
                    .sign_roster_vote(&local_for(group, voter), parent, child, 1, phase, voter)
                    .unwrap()
            })
            .collect()
    };
    RosterCertificate {
        group: id,
        parent,
        child,
        round: 1,
        prepares: votes(RosterVotePhase::Prepare),
        commits: votes(RosterVotePhase::Commit),
    }
}
