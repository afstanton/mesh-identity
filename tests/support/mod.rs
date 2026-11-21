#![cfg(feature = "groups")]
#[allow(dead_code)]
pub mod world;
use ed25519_dalek::SigningKey;
use mesh_identity::groups::{Policy, evidence::VouchedGroup};
use mesh_identity::session::installation::Installation;
use rand::{SeedableRng, rngs::StdRng};

#[allow(dead_code)] // Not every integration-test target uses this fixture.
pub struct Scenario {
    pub alice: Installation,
    pub carol: Installation,
    pub bob: Installation,
    pub dave: Installation,
    pub eve: Installation,
    pub group: VouchedGroup,
    pub alice_offline: VouchedGroup,
    pub rng: StdRng,
}

#[allow(dead_code)] // Not every integration-test target uses this fixture.
impl Scenario {
    pub fn new(seed: u64, policy: Policy) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut peer = || Installation::new(SigningKey::generate(&mut rng));
        let (alice, carol, bob, dave, eve) = (peer(), peer(), peer(), peer(), peer());
        let group = VouchedGroup::new(
            1,
            [
                alice.selected(),
                carol.selected(),
                dave.selected(),
                eve.selected(),
            ],
            policy,
        );
        Self {
            alice,
            carol,
            bob,
            dave,
            eve,
            alice_offline: group.clone(),
            group,
            rng,
        }
    }
}

/// Runs the actual offer, response, reveal and both local confirmation callbacks.
pub fn meet(left: &mut Installation, right: &mut Installation, now: u64, rng: &mut StdRng) {
    let (initiator, offer) = left.start(now, rng).unwrap();
    let responder = right.open_scanner(now).unwrap();
    let response = right.scan_offer(&responder, &offer, now, rng).unwrap();
    let reveal = left.scan_response(&initiator, &response, now).unwrap();
    right.scan_reveal(&responder, &reveal, now).unwrap();
    let a = left.comparison(&initiator, now).unwrap().unwrap();
    let b = right.comparison(&responder, now).unwrap().unwrap();
    assert_eq!(a.code, b.code);
    left.confirm_and_save(&initiator, a, b.code, now, now, rng)
        .unwrap();
    right
        .confirm_and_save(&responder, b, a.code, now, now, rng)
        .unwrap();
}

#[derive(Debug, Default, PartialEq, Eq)]
#[allow(dead_code)] // Not every integration-test target uses this fixture.
pub struct Inbox {
    visible: usize,
    notifications: usize,
    unread: usize,
}

#[allow(dead_code)] // Not every integration-test target uses this fixture.
impl Inbox {
    pub fn one_message() -> Self {
        Self {
            visible: 1,
            notifications: 1,
            unread: 1,
        }
    }

    pub fn deliver(
        &mut self,
        group: &VouchedGroup,
        local: &mesh_identity::groups::MemberLocalState,
        recipient: &Installation,
        tenure: mesh_identity::groups::Membership,
        sender: [u8; 32],
    ) {
        if group.may_present_from(local, recipient, tenure, sender) {
            self.visible += 1;
            self.notifications += 1;
            self.unread += 1;
        }
    }
}
