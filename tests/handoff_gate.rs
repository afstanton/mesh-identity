#![cfg(feature = "groups")]
//! A device that handed off its voting role cannot sign through the group layer.

use ed25519_dalek::SigningKey;
use mesh_identity::groups::Error;
use mesh_identity::groups::evidence::SignedDeparture;
use mesh_identity::session::installation::Installation;

#[test]
fn a_stopped_device_cannot_sign_a_departure_and_the_new_one_can_after_the_handoff() {
    let key = SigningKey::from_bytes(&[3; 32]);
    let mut old = Installation::new(key.clone());
    let mut new = Installation::new(key);
    new.gate_voting();
    let context = (1, [4; 32]);
    assert!(SignedDeparture::new(context, &old).is_ok());
    assert!(matches!(
        SignedDeparture::new(context, &new),
        Err(Error::NotVotingDevice)
    ));
    let nonce = new.device_nonce(&mut rand::rngs::OsRng);
    let bundle = old.begin_handoff(nonce, |_, _| Ok(())).unwrap();
    assert!(matches!(
        SignedDeparture::new(context, &old),
        Err(Error::NotVotingDevice)
    ));
    new.accept_handoff(&bundle, |_| Ok(())).unwrap();
    assert!(SignedDeparture::new(context, &new).is_ok());
}
