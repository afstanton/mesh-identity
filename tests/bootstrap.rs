#![cfg(feature = "groups")]
#[path = "support/roster.rs"]
mod roster;
#[allow(dead_code)]
mod support;

use mesh_identity::groups::{
    Policy,
    evidence::{
        DirectVoucher, RosterCertificate, RosterFreshnessChallenge, RosterFreshnessError,
        RosterFreshnessQuery, RosterVote, SignedAdmissionConsent, SignedDeparture,
        SignedInvitation, VouchedGroup,
    },
};
use roster::{certify, local_for};
use sha2::{Digest, Sha256};
use std::time::Instant;
use support::{Scenario, meet};

#[test]
fn first_join_from_bytes_waits_for_a_fresh_observation_of_certified_admission() {
    let mut s = Scenario::new(201, Policy::InviterOnly);
    let alice = s.alice.selected();
    let bob = s.bob.selected();
    let mut group = VouchedGroup::new(201, [alice, s.carol.selected()], Policy::InviterOnly);
    let (id, _) = group.rotation_context();
    let genesis = group.genesis_bytes().unwrap();
    // The simulated introduction supplies this digest over its own authenticated channel.
    let trusted_digest = Sha256::digest(&genesis).into();
    let mut changed = genesis.clone();
    changed[12] ^= 1;
    assert!(VouchedGroup::from_authenticated_genesis(&changed, trusted_digest).is_err());
    let mut candidate = VouchedGroup::from_authenticated_genesis(&genesis, trusted_digest).unwrap();

    meet(&mut s.alice, &mut s.bob, 1, &mut s.rng);
    let now = Instant::now();
    let challenge = RosterFreshnessChallenge::new(id, now);
    let query = RosterFreshnessQuery::from_bytes(&challenge.query().to_bytes()).unwrap();
    let observers = [&s.alice, &s.carol];
    let stale = observers.map(|member| {
        let response = group
            .attest_roster_freshness(&local_for(&group, member), query, member)
            .unwrap();
        RosterVote::from_bytes(&response.to_bytes()).unwrap()
    });
    assert_eq!(
        candidate.confirmed_membership(&s.bob, &challenge, &stale, now),
        Ok(None)
    );

    let mut proposed = group.invite_until(alice, bob, 100).unwrap();
    let voucher = group.vouch(&proposed, &s.alice, [alice], 100).unwrap();
    let invite = SignedInvitation::new(&proposed, &s.alice)
        .unwrap()
        .to_bytes();
    let imported = SignedInvitation::from_bytes(&invite).unwrap();
    let mut incoming = candidate.receive_invitation(&imported).unwrap();
    let consent = SignedAdmissionConsent::new(&incoming, &s.bob)
        .unwrap()
        .to_bytes();
    let consent = SignedAdmissionConsent::from_bytes(&consent).unwrap();
    group
        .apply_admission_consent(&mut proposed, &consent)
        .unwrap();
    candidate
        .apply_admission_consent(&mut incoming, &consent)
        .unwrap();
    let voucher_bytes = voucher.admission_wire(&s.alice).unwrap();
    let mut altered = voucher_bytes;
    altered[71] ^= 1;
    assert!(DirectVoucher::from_admission_wire(&altered).is_err());
    let mut invalid_candidate = voucher_bytes;
    invalid_candidate[120..152].fill(0xFF);
    assert!(DirectVoucher::from_admission_wire(&invalid_candidate).is_err());
    let imported_voucher = DirectVoucher::from_admission_wire(&voucher_bytes).unwrap();
    let mut excessive = voucher_bytes;
    excessive[64..72]
        .copy_from_slice(&(mesh_identity::groups::evidence::MAX_LIFETIME_MS + 1).to_be_bytes());
    let binding = Sha256::digest(&excessive[..152]).into();
    excessive[152..].copy_from_slice(&s.alice.sign_admission_voucher(binding).unwrap());
    let excessive = DirectVoucher::from_admission_wire(&excessive).unwrap();
    assert_eq!(
        candidate.admission_child(&incoming, &excessive),
        Err(mesh_identity::groups::evidence::AdmissionError::InvalidExpiry)
    );
    let child = group.admission_child(&proposed, &voucher).unwrap();
    let mut certificate = certify(&group, child, &observers);
    let last_commit = certificate.commits.pop().unwrap();
    assert!(
        candidate
            .apply_certified_admission(&incoming, imported_voucher.clone(), &certificate)
            .is_err()
    );
    assert!(candidate.membership(bob).is_none());
    certificate.commits.push(last_commit);
    let certificate = RosterCertificate::from_bytes(&certificate.to_bytes().unwrap()).unwrap();
    candidate
        .apply_certified_admission(&incoming, imported_voucher, &certificate)
        .unwrap();
    group
        .apply_certified_admission(&proposed, voucher, &certificate)
        .unwrap();
    assert_eq!(
        candidate.confirmed_membership(&s.bob, &challenge, &stale, now),
        Err(RosterFreshnessError::Unconfirmed)
    );
    assert!(candidate.receive_invitation(&imported).is_err());

    let fresh = [&s.alice, &s.carol, &s.bob].map(|member| {
        let response = group
            .attest_roster_freshness(&local_for(&group, member), query, member)
            .unwrap();
        RosterVote::from_bytes(&response.to_bytes()).unwrap()
    });
    assert_eq!(
        candidate.confirmed_membership(&s.bob, &challenge, &fresh[..2], now),
        Err(RosterFreshnessError::Unconfirmed)
    );
    assert_eq!(
        candidate.confirmed_membership(&s.bob, &challenge, &fresh, now),
        Ok(group.membership(bob))
    );
    assert!(group.membership(bob).is_some());
}

#[test]
fn a_four_member_group_continues_making_certified_changes_after_departure() {
    let mut s = Scenario::new(202, Policy::Majority);
    let initial = [&s.alice, &s.carol, &s.dave, &s.eve];
    let mut peer = s.group.clone();

    for (departing, voters) in [
        (&s.eve, &initial[..3]),
        (&s.dave, &initial[..3]),
        (&s.carol, &initial[..2]),
        (&s.alice, &initial[..1]),
    ] {
        let context = s.group.departure_context(departing.selected()).unwrap();
        let departure = SignedDeparture::new(context, departing).unwrap();
        let child = s.group.signed_departure_child(&departure).unwrap();
        let certificate = certify(&s.group, child, voters);
        let certificate = RosterCertificate::from_bytes(&certificate.to_bytes().unwrap()).unwrap();
        s.group
            .apply_certified_signed_departure(&departure, &certificate)
            .unwrap();
        peer.apply_certified_signed_departure(&departure, &certificate)
            .unwrap();
        assert!(peer.membership(departing.selected()).is_none());
        assert_eq!(s.group.rotation_context(), peer.rotation_context());
    }
    assert!(peer.required_roster_freshness_votes().is_err());
}
