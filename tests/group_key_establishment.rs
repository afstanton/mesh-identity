#![cfg(feature = "groups")]
//! One distributor and one fresh key per agreed roster in this experiment.
#[path = "support/roster.rs"]
mod roster;
#[allow(dead_code)]
mod support;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use mesh_identity::groups::{
    Error, Policy,
    evidence::{DistributionPlan, VouchedGroup},
};
use mesh_identity::session::installation::Installation;
use ring::{
    aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey},
    agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519},
    error::Unspecified,
    hkdf,
    rand::{SecureRandom, SystemRandom},
};
use roster::certify;
use std::collections::BTreeMap;

type Key = [u8; 32];

fn epoch_context(group: &VouchedGroup) -> Vec<u8> {
    let (id, roster) = group.rotation_context();
    [id.to_be_bytes().as_slice(), &roster].concat()
}

fn offer_message(context: &[u8], recipient: Key, public: &[u8]) -> Vec<u8> {
    [
        b"mesh/test/group-recipient/v1".as_slice(),
        context,
        &recipient,
        public,
    ]
    .concat()
}

fn verify_offer(
    context: &[u8],
    recipient: Key,
    public: &[u8],
    signature: &Signature,
) -> Result<(), ed25519_dalek::SignatureError> {
    VerifyingKey::from_bytes(&recipient)?
        .verify_strict(&offer_message(context, recipient, public), signature)
}

fn wrapping_key(
    secret: EphemeralPrivateKey,
    peer: &[u8],
    transcript: &[u8],
) -> Result<LessSafeKey, Unspecified> {
    agreement::agree_ephemeral(secret, &UnparsedPublicKey::new(&X25519, peer), |shared| {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"mesh/test/group-wrap/v1");
        let prk = salt.extract(shared);
        let info = [transcript];
        let mut key = [0; 32];
        prk.expand(&info, &CHACHA20_POLY1305)?.fill(&mut key)?;
        Ok(LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &key)?))
    })?
}

struct RecipientOffer {
    recipient: Key,
    public: Key,
    signature: Signature,
}

impl RecipientOffer {
    fn create(
        group: &VouchedGroup,
        identity: &SigningKey,
        rng: &SystemRandom,
    ) -> (Self, EphemeralPrivateKey) {
        let secret = EphemeralPrivateKey::generate(&X25519, rng).unwrap();
        let public: Key = secret
            .compute_public_key()
            .unwrap()
            .as_ref()
            .try_into()
            .unwrap();
        let recipient = identity.verifying_key().to_bytes();
        let signature = identity.sign(&offer_message(&epoch_context(group), recipient, &public));
        (
            Self {
                recipient,
                public,
                signature,
            },
            secret,
        )
    }
}

struct WrappedEpoch {
    public: Key,
    ciphertext: Vec<u8>,
}

impl WrappedEpoch {
    fn open(
        mut self,
        group: &VouchedGroup,
        offer: &RecipientOffer,
        secret: EphemeralPrivateKey,
    ) -> Result<Key, Unspecified> {
        let transcript = epoch_transcript(group, offer, &self.public);
        let key = wrapping_key(secret, &self.public, &transcript)?;
        let bytes = key.open_in_place(
            Nonce::assume_unique_for_key([0; 12]),
            Aad::from(&transcript),
            &mut self.ciphertext,
        )?;
        bytes.try_into().map_err(|_| Unspecified)
    }
}

fn epoch_transcript(group: &VouchedGroup, offer: &RecipientOffer, sender: &Key) -> Vec<u8> {
    let offer = offer_message(&epoch_context(group), offer.recipient, &offer.public);
    [offer.as_slice(), sender].concat()
}

struct EpochDistribution {
    plan: DistributionPlan,
    key: Key,
}

impl EpochDistribution {
    fn new(group: &VouchedGroup, rng: &SystemRandom) -> Self {
        let mut key = [0; 32];
        rng.fill(&mut key).unwrap();
        Self {
            plan: group.plan_distribution(),
            key,
        }
    }

    fn wrap(
        &self,
        group: &VouchedGroup,
        offer: &RecipientOffer,
        rng: &SystemRandom,
    ) -> Result<WrappedEpoch, Error> {
        if !group
            .distribution_recipients(&self.plan)?
            .contains(&offer.recipient)
        {
            return Err(Error::Ineligible);
        }
        verify_offer(
            &epoch_context(group),
            offer.recipient,
            &offer.public,
            &offer.signature,
        )
        .map_err(|_| Error::Ineligible)?;

        let secret = EphemeralPrivateKey::generate(&X25519, rng).unwrap();
        let public: Key = secret
            .compute_public_key()
            .unwrap()
            .as_ref()
            .try_into()
            .unwrap();
        // The fixture treats the distributor's public share as authenticated.
        let transcript = epoch_transcript(group, offer, &public);
        let sender =
            wrapping_key(secret, &offer.public, &transcript).map_err(|_| Error::Ineligible)?;
        let mut ciphertext = self.key.to_vec();
        sender
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key([0; 12]),
                Aad::from(&transcript),
                &mut ciphertext,
            )
            .unwrap();
        Ok(WrappedEpoch { public, ciphertext })
    }
}

fn establish_epoch(
    group: &VouchedGroup,
    identities: &[SigningKey],
    rng: &SystemRandom,
) -> BTreeMap<Key, Key> {
    deliver_epoch(&EpochDistribution::new(group, rng), group, identities, rng)
}

fn deliver_epoch(
    epoch: &EpochDistribution,
    group: &VouchedGroup,
    identities: &[SigningKey],
    rng: &SystemRandom,
) -> BTreeMap<Key, Key> {
    group
        .distribution_recipients(&epoch.plan)
        .unwrap()
        .into_iter()
        .map(|recipient| {
            let identity = identities
                .iter()
                .find(|key| key.verifying_key().to_bytes() == recipient)
                .unwrap();
            let (offer, secret) = RecipientOffer::create(group, identity, rng);
            let delivered = epoch.wrap(group, &offer, rng).unwrap();
            (recipient, delivered.open(group, &offer, secret).unwrap())
        })
        .collect()
}

fn content_key(key: &Key) -> LessSafeKey {
    LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key).unwrap())
}

fn seal_material(group: &VouchedGroup, key: &Key, plaintext: &[u8]) -> Vec<u8> {
    let mut bytes = plaintext.to_vec();
    content_key(key)
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key([0; 12]),
            Aad::from(epoch_context(group)),
            &mut bytes,
        )
        .unwrap();
    bytes
}

fn open_material<'a>(
    group: &VouchedGroup,
    key: &Key,
    bytes: &'a mut [u8],
) -> Result<&'a mut [u8], Unspecified> {
    content_key(key).open_in_place(
        Nonce::assume_unique_for_key([0; 12]),
        Aad::from(epoch_context(group)),
        bytes,
    )
}

#[test]
fn certified_departure_establishes_a_fresh_key_for_the_remaining_members() {
    use mesh_identity::groups::evidence::SignedDeparture;

    let rng = SystemRandom::new();
    let identities = [1, 2, 3, 4].map(|seed| SigningKey::from_bytes(&[seed; 32]));
    let members = identities
        .each_ref()
        .map(|key| key.verifying_key().to_bytes());
    let mut group = VouchedGroup::new(1, members, Policy::InviterOnly);
    let leaving = Installation::new(identities[0].clone());
    let leaver = leaving.selected();
    let stale_epoch = EpochDistribution::new(&group, &rng);
    let previous = deliver_epoch(&stale_epoch, &group, &identities, &rng);
    let old_key = previous[&leaver];
    assert!(members.iter().all(|member| previous[member] == old_key));

    let mut offline = group.clone();
    let (stale_offer, _) = RecipientOffer::create(&offline, &identities[1], &rng);

    let stale = group.plan_distribution();
    let departure =
        SignedDeparture::new(group.departure_context(leaver).unwrap(), &leaving).unwrap();
    let child = group.signed_departure_child(&departure).unwrap();
    let signers = [1, 2, 3].map(|index| Installation::new(identities[index].clone()));
    let certificate = certify(&group, child, &signers.each_ref());
    group
        .apply_certified_signed_departure(&departure, &certificate)
        .unwrap();
    assert_eq!(
        group.distribution_recipients(&stale),
        Err(Error::StaleProposal)
    );

    let next = EpochDistribution::new(&group, &rng);
    assert!(matches!(
        next.wrap(&group, &stale_offer, &rng),
        Err(Error::Ineligible)
    ));
    let (departed_offer, _) = RecipientOffer::create(&group, &identities[0], &rng);
    assert!(matches!(
        next.wrap(&group, &departed_offer, &rng),
        Err(Error::Ineligible)
    ));
    assert!(matches!(
        stale_epoch.wrap(&group, &departed_offer, &rng),
        Err(Error::StaleProposal)
    ));
    assert_ne!(next.key, old_key);

    let material = seal_material(&group, &next.key, b"new group material");
    for identity in &identities[2..] {
        let (offer, secret) = RecipientOffer::create(&group, identity, &rng);
        let delivered = next.wrap(&group, &offer, &rng).unwrap();
        let key = delivered.open(&group, &offer, secret).unwrap();
        assert_eq!(
            open_material(&group, &key, &mut material.clone()).unwrap(),
            b"new group material"
        );
    }
    assert!(open_material(&group, &old_key, &mut material.clone()).is_err());

    let (offer, secret) = RecipientOffer::create(&group, &identities[1], &rng);
    let delivered = next.wrap(&group, &offer, &rng).unwrap();
    assert!(delivered.open(&offline, &offer, secret).is_err());
    assert_eq!(
        offline.catch_up(&group),
        mesh_identity::groups::evidence::CatchUp::Applied
    );

    // A retry uses a fresh pairwise exchange to deliver the same epoch key.
    let (offer, secret) = RecipientOffer::create(&offline, &identities[1], &rng);
    let retry = next.wrap(&group, &offer, &rng).unwrap();
    let caught_up = retry.open(&offline, &offer, secret).unwrap();
    assert_eq!(caught_up, next.key);
    assert_eq!(
        open_material(&offline, &caught_up, &mut material.clone()).unwrap(),
        b"new group material"
    );
}

#[test]
fn certified_admission_ejection_and_readmission_bound_group_key_access() {
    use mesh_identity::groups::Vote;
    use mesh_identity::groups::evidence::{
        SignedAdmissionConsent, SignedAdmissionVote, SignedEjectionVote,
    };
    use rand::{SeedableRng, rngs::StdRng};

    let rng = SystemRandom::new();
    let mut encounter_rng = StdRng::seed_from_u64(175);
    let identities = [11, 12, 13, 14, 15].map(|seed| SigningKey::from_bytes(&[seed; 32]));
    let members = identities
        .each_ref()
        .map(|key| key.verifying_key().to_bytes());
    let [mut inviter, second, third, fourth, mut candidate] = identities
        .each_ref()
        .map(|key| Installation::new(key.clone()));
    let newcomer = candidate.selected();
    let mut group = VouchedGroup::new(1, members[..4].iter().copied(), Policy::Majority);
    let before = group.clone();
    let before_keys = establish_epoch(&before, &identities, &rng);
    let history = seal_material(&before, &before_keys[&members[0]], b"before admission");

    support::meet(&mut inviter, &mut candidate, 1, &mut encounter_rng);
    let admit = |group: &mut VouchedGroup| {
        let mut invitation = group.invite(inviter.selected(), newcomer).unwrap();
        let consent = SignedAdmissionConsent::new(&invitation, &candidate).unwrap();
        group
            .apply_admission_consent(&mut invitation, &consent)
            .unwrap();
        for signer in [&second, &third] {
            let vote = SignedAdmissionVote::new(&invitation, signer, Vote::Approve).unwrap();
            group.apply_admission_vote(&mut invitation, &vote).unwrap();
        }
        let voucher = group.vouch(&invitation, &inviter, [], 100).unwrap();
        let child = group.admission_child(&invitation, &voucher).unwrap();
        let certificate = certify(group, child, &[&inviter, &second, &third]);
        group
            .apply_certified_admission(&invitation, voucher, &certificate)
            .unwrap();
    };

    admit(&mut group);
    let first_tenure = group.membership(newcomer).unwrap();
    let joined_keys = establish_epoch(&group, &identities, &rng);
    let joined_key = joined_keys[&newcomer];
    assert!(!before_keys.contains_key(&newcomer));
    assert!(open_material(&before, &joined_key, &mut history.clone()).is_err());
    let joined = seal_material(&group, &joined_keys[&members[0]], b"after admission");
    assert_eq!(
        open_material(&group, &joined_key, &mut joined.clone()).unwrap(),
        b"after admission"
    );

    let mut ejection = group.propose_signed_ejection(&inviter, newcomer).unwrap();
    for signer in [&second, &third] {
        let vote = SignedEjectionVote::new(&ejection, signer).unwrap();
        group.apply_ejection_vote(&mut ejection, &vote).unwrap();
    }
    let child = group.ejection_child(&ejection).unwrap();
    let certificate = certify(&group, child, &[&inviter, &second, &third, &fourth]);
    group
        .apply_certified_ejection(&ejection, &certificate)
        .unwrap();
    let absent = group.clone();
    let absent_keys = establish_epoch(&absent, &identities, &rng);
    let withheld = seal_material(&absent, &absent_keys[&members[0]], b"while absent");
    assert!(!absent_keys.contains_key(&newcomer));
    assert!(open_material(&absent, &joined_key, &mut withheld.clone()).is_err());

    admit(&mut group);
    assert_ne!(group.membership(newcomer).unwrap(), first_tenure);
    let returned_keys = establish_epoch(&group, &identities, &rng);
    let returned = seal_material(&group, &returned_keys[&members[0]], b"after readmission");
    assert_eq!(
        open_material(&group, &returned_keys[&newcomer], &mut returned.clone()).unwrap(),
        b"after readmission"
    );
    assert!(open_material(&absent, &returned_keys[&newcomer], &mut withheld.clone()).is_err());
}

#[test]
fn distributor_loss_recovers_future_access_at_the_next_certified_roster() {
    use mesh_identity::groups::evidence::SignedRotation;

    let rng = SystemRandom::new();
    let identities = [21, 22, 23, 24, 25].map(|seed| SigningKey::from_bytes(&[seed; 32]));
    let members = identities
        .each_ref()
        .map(|key| key.verifying_key().to_bytes());
    let mut group = VouchedGroup::new(1, members[..4].iter().copied(), Policy::InviterOnly);
    let historical = group.clone();
    let old_epoch = EpochDistribution::new(&group, &rng);
    let (offer, secret) = RecipientOffer::create(&group, &identities[1], &rng);
    let retained_key = old_epoch
        .wrap(&group, &offer, &rng)
        .unwrap()
        .open(&group, &offer, secret)
        .unwrap();
    let history = seal_material(&group, &retained_key, b"before distributor loss");

    // Only member 1 received this epoch. The distributor loses its copy.
    drop(old_epoch);
    assert_eq!(
        open_material(&historical, &retained_key, &mut history.clone()).unwrap(),
        b"before distributor loss"
    );

    let mut rotating = Installation::new(identities[0].clone());
    let old = rotating.selected();
    let new = rotating.add_identity(identities[4].clone()).unwrap();
    let (id, parent) = group.rotation_context();
    let first = rotating.sign_group_rotation(id, parent, old, new).unwrap();
    rotating.select(new, 1).unwrap();
    let second = rotating.sign_group_rotation(id, parent, old, new).unwrap();
    let rotation = SignedRotation::new((id, parent), old, new, [first, second]);
    let child = group.rotation_child(&rotation).unwrap();
    let signers = [1, 2, 3].map(|index| Installation::new(identities[index].clone()));
    let certificate = certify(&group, child, &signers.each_ref());
    group
        .apply_certified_rotation(&rotation, &certificate)
        .unwrap();

    // A replacement distributor starts only once a new roster state is agreed.
    let recovered = EpochDistribution::new(&group, &rng);
    let (retired, _) = RecipientOffer::create(&group, &identities[0], &rng);
    assert!(matches!(
        recovered.wrap(&group, &retired, &rng),
        Err(Error::Ineligible)
    ));
    let material = seal_material(&group, &recovered.key, b"after distributor recovery");
    for index in [1, 2, 3, 4] {
        let (offer, secret) = RecipientOffer::create(&group, &identities[index], &rng);
        let key = recovered
            .wrap(&group, &offer, &rng)
            .unwrap()
            .open(&group, &offer, secret)
            .unwrap();
        assert_eq!(
            open_material(&group, &key, &mut material.clone()).unwrap(),
            b"after distributor recovery"
        );
        assert!(open_material(&historical, &key, &mut history.clone()).is_err());
    }
    assert!(open_material(&group, &retained_key, &mut material.clone()).is_err());
}
