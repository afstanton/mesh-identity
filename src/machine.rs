//! Frozen-state session machines.
//!
//! These wrap the single-step protocol functions with the state rules the spec requires:
//! - only the expected frame for the current state is accepted;
//! - an identical rescan of an earlier frame is idempotent (same output, no new randomness,
//!   no second confirmation);
//! - a changed earlier frame, an out-of-order frame or any failed check aborts the session;
//! - a finished or aborted session accepts nothing; a new attempt needs a new machine;
//! - confirmation happens once, and a double tap returns the same confirmed value.
//!
//! Normal drop releases the secret-bearing state through its zeroizing destructors.
//! The machine does not write contact records.

use crate::protocol::*;
use ed25519_dalek::SigningKey;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

// ----------------- Initiator (Alice) -----------------

enum IPhase {
    Idle,
    OfferShown(InitiatorWaitingForResponse),
    RevealShown {
        awaiting: InitiatorAwaitingConfirmation,
        response_digest: [u8; 32],
        reveal: Vec<u8>,
    },
    Confirmed(InitiatorConfirmed),
    Aborted,
}

pub struct InitiatorMachine {
    phase: IPhase,
}

impl Default for InitiatorMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl InitiatorMachine {
    pub fn new() -> Self {
        Self {
            phase: IPhase::Idle,
        }
    }

    pub fn phase_name(&self) -> &'static str {
        match self.phase {
            IPhase::Idle => "Idle",
            IPhase::OfferShown(_) => "OfferShown",
            IPhase::RevealShown { .. } => "RevealShown/AwaitingComparison",
            IPhase::Confirmed(_) => "LocallyConfirmed",
            IPhase::Aborted => "Aborted",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self.phase, IPhase::Confirmed(_) | IPhase::Aborted)
    }

    /// Show QR1. Only valid from `Idle`.
    pub fn start<R: CryptoRng + RngCore>(
        &mut self,
        signing_key: SigningKey,
        rng: &mut R,
    ) -> Result<Vec<u8>, EncounterError> {
        match self.phase {
            IPhase::Idle => {
                let (state, offer) = Initiator::start(signing_key, rng);
                let bytes = offer.to_bytes();
                self.phase = IPhase::OfferShown(state);
                Ok(bytes)
            }
            IPhase::Confirmed(_) | IPhase::Aborted => Err(EncounterError::SessionClosed),
            _ => Err(EncounterError::OutOfOrder),
        }
    }

    /// Accept QR2 and return QR3. An identical rescan returns the same QR3.
    pub fn on_response(&mut self, bytes: &[u8]) -> Result<Vec<u8>, EncounterError> {
        match std::mem::replace(&mut self.phase, IPhase::Aborted) {
            IPhase::OfferShown(state) => {
                // A QR2 that fails a check is ignored: nothing was emitted, so the same offer stays
                // live and a different QR2 may still be accepted (a bystander cannot end the session).
                let (awaiting, reveal) = match state.try_handle_response(bytes) {
                    Ok(done) => done,
                    Err((state, e)) => {
                        self.phase = IPhase::OfferShown(state);
                        return Err(e);
                    }
                };
                let reveal = reveal.to_bytes();
                self.phase = IPhase::RevealShown {
                    awaiting,
                    response_digest: digest(bytes),
                    reveal: reveal.clone(),
                };
                Ok(reveal)
            }
            IPhase::RevealShown {
                awaiting,
                response_digest,
                reveal,
            } => {
                if digest(bytes) == response_digest {
                    self.phase = IPhase::RevealShown {
                        awaiting,
                        response_digest,
                        reveal: reveal.clone(),
                    };
                    Ok(reveal)
                } else {
                    Err(EncounterError::SessionMismatch) // a changed QR2 aborts; state dropped and wiped
                }
            }
            IPhase::Idle => {
                self.phase = IPhase::Idle;
                Err(EncounterError::OutOfOrder)
            }
            other @ (IPhase::Confirmed(_) | IPhase::Aborted) => {
                self.phase = other;
                Err(EncounterError::SessionClosed)
            }
        }
    }

    /// True when a QR2 has been accepted and `bytes` is a different frame. Lets a caller ignore a
    /// stray or hostile second response without ending the live session.
    pub fn conflicts_with_accepted_response(&self, bytes: &[u8]) -> bool {
        matches!(&self.phase, IPhase::RevealShown { response_digest, .. } if digest(bytes) != *response_digest)
    }

    /// The six-digit code to show, once QR3 has been produced.
    pub(crate) fn comparison_transcript(&self) -> Option<[u8; 32]> {
        match &self.phase {
            IPhase::RevealShown { awaiting, .. } => Some(awaiting.transcript()),
            _ => None,
        }
    }

    pub fn sas_code(&self) -> Option<u32> {
        match &self.phase {
            IPhase::RevealShown { awaiting, .. } => Some(awaiting.sas_code()),
            _ => None,
        }
    }

    /// The user reports the code on the other device. A mismatch aborts. A repeat call after success
    /// returns the same confirmed value.
    pub fn confirm(
        &mut self,
        code_seen_on_peer: u32,
    ) -> Result<InitiatorConfirmed, EncounterError> {
        match std::mem::replace(&mut self.phase, IPhase::Aborted) {
            IPhase::RevealShown { awaiting, .. } => {
                let confirmed = awaiting.confirm(code_seen_on_peer)?; // mismatch leaves the machine Aborted
                self.phase = IPhase::Confirmed(confirmed.clone());
                Ok(confirmed)
            }
            IPhase::Confirmed(c) => {
                self.phase = IPhase::Confirmed(c.clone());
                Ok(c)
            }
            IPhase::Idle => {
                self.phase = IPhase::Idle;
                Err(EncounterError::OutOfOrder)
            }
            IPhase::OfferShown(s) => {
                self.phase = IPhase::OfferShown(s);
                Err(EncounterError::OutOfOrder)
            }
            IPhase::Aborted => Err(EncounterError::SessionClosed),
        }
    }

    /// Local cancel before saving. Leaves any existing contact unchanged; a confirmed session stays confirmed.
    pub fn cancel(&mut self) {
        if !matches!(self.phase, IPhase::Confirmed(_)) {
            self.phase = IPhase::Aborted;
        }
    }
}

// ----------------- Responder (Bob) -----------------

enum RPhase {
    Idle,
    ResponseShown(Box<ResponderAwaitingReveal>),
    AwaitingComparison {
        awaiting: ResponderAwaitingConfirmation,
        reveal_digest: [u8; 32],
    },
    Confirmed(ResponderConfirmed),
    Aborted,
}

pub struct ResponderMachine {
    phase: RPhase,
    /// Digest of the accepted QR1 and the QR2 produced for it, kept so an identical rescan is idempotent.
    first: Option<([u8; 32], Vec<u8>)>,
}

impl Default for ResponderMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl ResponderMachine {
    pub fn new() -> Self {
        Self {
            phase: RPhase::Idle,
            first: None,
        }
    }

    pub fn phase_name(&self) -> &'static str {
        match self.phase {
            RPhase::Idle => "Idle",
            RPhase::ResponseShown(_) => "ResponseShown",
            RPhase::AwaitingComparison { .. } => "RevealAccepted/AwaitingComparison",
            RPhase::Confirmed(_) => "LocallyConfirmed",
            RPhase::Aborted => "Aborted",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self.phase, RPhase::Confirmed(_) | RPhase::Aborted)
    }

    /// Accept QR1 and return QR2. An identical rescan returns the same QR2 with no new nonce.
    pub fn on_offer<R: CryptoRng + RngCore>(
        &mut self,
        signing_key: SigningKey,
        bytes: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, EncounterError> {
        match std::mem::replace(&mut self.phase, RPhase::Aborted) {
            RPhase::Idle => {
                let (state, resp) = Responder::handle_offer(signing_key, bytes, rng)?;
                let resp = resp.to_bytes();
                self.first = Some((digest(bytes), resp.clone()));
                self.phase = RPhase::ResponseShown(Box::new(state));
                Ok(resp)
            }
            same_or_later @ (RPhase::ResponseShown(_) | RPhase::AwaitingComparison { .. }) => {
                let (d, resp) = self.first.clone().expect("first frame recorded");
                if digest(bytes) == d {
                    self.phase = same_or_later;
                    Ok(resp)
                } else {
                    Err(EncounterError::SessionMismatch)
                }
            }
            other @ (RPhase::Confirmed(_) | RPhase::Aborted) => {
                self.phase = other;
                Err(EncounterError::SessionClosed)
            }
        }
    }

    /// Accept QR3. An identical rescan is a no-op.
    pub fn on_reveal(&mut self, bytes: &[u8]) -> Result<(), EncounterError> {
        match std::mem::replace(&mut self.phase, RPhase::Aborted) {
            RPhase::ResponseShown(state) => {
                // As above: a QR3 that fails a check is ignored and the session stays live.
                let awaiting = match state.try_handle_reveal(bytes) {
                    Ok(done) => done,
                    Err((state, e)) => {
                        self.phase = RPhase::ResponseShown(Box::new(state));
                        return Err(e);
                    }
                };
                self.phase = RPhase::AwaitingComparison {
                    awaiting,
                    reveal_digest: digest(bytes),
                };
                Ok(())
            }
            RPhase::AwaitingComparison {
                awaiting,
                reveal_digest,
            } => {
                if digest(bytes) == reveal_digest {
                    self.phase = RPhase::AwaitingComparison {
                        awaiting,
                        reveal_digest,
                    };
                    Ok(())
                } else {
                    Err(EncounterError::SessionMismatch)
                }
            }
            RPhase::Idle => {
                self.phase = RPhase::Idle;
                Err(EncounterError::OutOfOrder)
            }
            other @ (RPhase::Confirmed(_) | RPhase::Aborted) => {
                self.phase = other;
                Err(EncounterError::SessionClosed)
            }
        }
    }

    /// True when a QR1 has been accepted and `bytes` is a different offer (a stray scan).
    pub fn conflicts_with_accepted_offer(&self, bytes: &[u8]) -> bool {
        matches!(
            &self.phase,
            RPhase::ResponseShown(_) | RPhase::AwaitingComparison { .. }
        ) && self
            .first
            .as_ref()
            .is_some_and(|(d, _)| digest(bytes) != *d)
    }

    /// True when a QR3 has been accepted and `bytes` is a different frame.
    pub fn conflicts_with_accepted_reveal(&self, bytes: &[u8]) -> bool {
        matches!(&self.phase, RPhase::AwaitingComparison { reveal_digest, .. } if digest(bytes) != *reveal_digest)
    }

    pub(crate) fn comparison_transcript(&self) -> Option<[u8; 32]> {
        match &self.phase {
            RPhase::AwaitingComparison { awaiting, .. } => Some(awaiting.transcript()),
            _ => None,
        }
    }

    pub fn sas_code(&self) -> Option<u32> {
        match &self.phase {
            RPhase::AwaitingComparison { awaiting, .. } => Some(awaiting.sas_code()),
            _ => None,
        }
    }

    pub fn confirm(
        &mut self,
        code_seen_on_peer: u32,
    ) -> Result<ResponderConfirmed, EncounterError> {
        match std::mem::replace(&mut self.phase, RPhase::Aborted) {
            RPhase::AwaitingComparison { awaiting, .. } => {
                let confirmed = awaiting.confirm(code_seen_on_peer)?;
                self.phase = RPhase::Confirmed(confirmed.clone());
                Ok(confirmed)
            }
            RPhase::Confirmed(c) => {
                self.phase = RPhase::Confirmed(c.clone());
                Ok(c)
            }
            RPhase::Idle => {
                self.phase = RPhase::Idle;
                Err(EncounterError::OutOfOrder)
            }
            RPhase::ResponseShown(s) => {
                self.phase = RPhase::ResponseShown(s);
                Err(EncounterError::OutOfOrder)
            }
            RPhase::Aborted => Err(EncounterError::SessionClosed),
        }
    }

    pub fn cancel(&mut self) {
        if !matches!(self.phase, RPhase::Confirmed(_)) {
            self.phase = RPhase::Aborted;
        }
    }
}
