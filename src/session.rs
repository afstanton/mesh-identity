//! Attempt policy: each abandoned half-session is an attacker guess, so repeated
//! incomplete sessions trigger a warning and a pause, and a live session expires.
//! Time is an injected monotonic millisecond counter, never wall-clock time.

pub const MAX_CONSECUTIVE_INCOMPLETE: u32 = 3;
pub const PAUSE_MS: u64 = 60_000;
pub const SESSION_TIMEOUT_MS: u64 = 120_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttemptError {
    /// A session is already live; a new one needs an explicit abort or completion first.
    SessionAlreadyLive,
    /// Too many incomplete sessions; wait until `until_ms`. The UI shows the interference warning.
    Paused { until_ms: u64 },
}

impl std::fmt::Display for AttemptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionAlreadyLive => write!(f, "session already live"),
            Self::Paused { until_ms } => write!(f, "attempt paused until {until_ms} ms"),
        }
    }
}

impl std::error::Error for AttemptError {}

#[derive(Debug, Default)]
pub struct AttemptPolicy {
    consecutive_incomplete: u32,
    paused_until_ms: Option<u64>,
    /// Pause time left from a restored snapshot, not yet anchored to this boot's clock.
    restored_pause_remaining_ms: Option<u64>,
    live_started_ms: Option<u64>,
}

impl AttemptPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn consecutive_incomplete(&self) -> u32 {
        self.consecutive_incomplete
    }

    /// True when the interference warning should be displayed.
    pub fn warning_active(&self) -> bool {
        self.consecutive_incomplete >= MAX_CONSECUTIVE_INCOMPLETE
    }

    /// Begin a session (one live session per device).
    pub fn begin(&mut self, now_ms: u64) -> Result<(), AttemptError> {
        self.rebase(now_ms);
        self.expire(now_ms);
        if self.live_started_ms.is_some() {
            return Err(AttemptError::SessionAlreadyLive);
        }
        if let Some(until) = self.paused_until_ms {
            if now_ms < until {
                return Err(AttemptError::Paused { until_ms: until });
            }
            self.paused_until_ms = None;
        }
        self.live_started_ms = Some(now_ms);
        Ok(())
    }

    /// The live session ended without a locally confirmed contact (abort, timeout, mismatch).
    pub fn record_incomplete(&mut self, now_ms: u64) {
        if self.live_started_ms.take().is_none() {
            return;
        }
        self.consecutive_incomplete = self.consecutive_incomplete.saturating_add(1);
        if self.consecutive_incomplete >= MAX_CONSECUTIVE_INCOMPLETE {
            self.paused_until_ms = Some(now_ms.saturating_add(PAUSE_MS));
        }
    }

    /// The live session ended with a locally confirmed contact; resets the count.
    pub fn record_complete(&mut self) {
        if self.live_started_ms.take().is_some() {
            self.consecutive_incomplete = 0;
            self.paused_until_ms = None;
        }
    }

    /// Expire a live session that has outlived the timeout; counts as incomplete.
    pub fn expire(&mut self, now_ms: u64) {
        if let Some(start) = self.live_started_ms
            && now_ms.saturating_sub(start) >= SESSION_TIMEOUT_MS
        {
            self.record_incomplete(now_ms);
        }
    }

    pub fn is_live(&self) -> bool {
        self.live_started_ms.is_some()
    }

    /// Anchor a restored pause duration to the current clock.
    fn rebase(&mut self, now_ms: u64) {
        if let Some(rem) = self.restored_pause_remaining_ms.take()
            && rem > 0
        {
            self.paused_until_ms = Some(now_ms.saturating_add(rem.min(PAUSE_MS)));
        }
    }

    /// Pause time left, as a duration (safe to save across a restart).
    pub fn pause_remaining_ms(&self, now_ms: u64) -> Option<u64> {
        if let Some(rem) = self.restored_pause_remaining_ms {
            return Some(rem.min(PAUSE_MS));
        }
        self.paused_until_ms
            .map(|u| u.saturating_sub(now_ms))
            .filter(|r| *r > 0)
    }

    pub fn restore_state(&mut self, consecutive_incomplete: u32, pause_remaining_ms: Option<u64>) {
        self.consecutive_incomplete = consecutive_incomplete;
        self.paused_until_ms = None;
        self.restored_pause_remaining_ms = pause_remaining_ms;
    }
}

use crate::contact::{ContactRecordV1, ContactStore, StoreError};
use crate::machine::{InitiatorMachine, ResponderMachine};
use crate::protocol::{ConfirmedEncounter, EncounterError};
use ed25519_dalek::SigningKey;
use rand::{CryptoRng, RngCore};

enum LiveEncounter {
    Initiator(InitiatorMachine),
    Responder(ResponderMachine),
}

#[derive(Debug, PartialEq, Eq)]
pub enum SessionError {
    Attempt(AttemptError),
    Protocol(EncounterError),
    Store(StoreError),
    NoLiveSession,
    StaleComparison,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Attempt(e) => write!(f, "attempt error: {e}"),
            Self::Protocol(e) => write!(f, "protocol error: {e}"),
            Self::Store(e) => write!(f, "store error: {e}"),
            Self::NoLiveSession => write!(f, "no live session"),
            Self::StaleComparison => write!(f, "stale comparison"),
        }
    }
}

impl std::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Attempt(e) => Some(e),
            Self::Protocol(e) => Some(e),
            Self::Store(e) => Some(e),
            _ => None,
        }
    }
}

/// The code and the local attempt it was displayed for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Comparison {
    transcript: [u8; 32],
    local_identity: [u8; 32],
    pub code: u32,
}

/// One controller per local identity. All timestamps supplied to session methods
/// come from the same monotonic clock.
pub struct EncounterController {
    key: SigningKey,
    policy: AttemptPolicy,
    live: Option<LiveEncounter>,
    contacts: ContactStore,
    response_seen: bool,
}

impl EncounterController {
    pub fn new(key: SigningKey) -> Self {
        let contacts = ContactStore::for_identity(key.verifying_key().to_bytes());
        Self::with_store(key, contacts).expect("new store belongs to the supplied key")
    }

    /// Restore a store belonging to the signing identity. An unfinished attempt
    /// whose response was exposed or accepted is counted once on restore.
    pub fn with_store(key: SigningKey, mut contacts: ContactStore) -> Result<Self, StoreError> {
        if key.verifying_key().to_bytes() != contacts.local_identity_pk() {
            return Err(StoreError::WrongLocalIdentity);
        }
        let mut state = contacts.attempt_policy_state();
        if state.pending_response {
            state.pending_response = false;
            state.consecutive_incomplete = state.consecutive_incomplete.saturating_add(1);
            if state.consecutive_incomplete >= MAX_CONSECUTIVE_INCOMPLETE {
                state.pause_remaining_ms = Some(PAUSE_MS);
            }
            contacts.update_attempt_policy_state(state);
        }
        let mut policy = AttemptPolicy::new();
        policy.restore_state(state.consecutive_incomplete, state.pause_remaining_ms);
        Ok(Self {
            key,
            policy,
            live: None,
            contacts,
            response_seen: false,
        })
    }

    pub fn contacts(&self) -> &ContactStore {
        &self.contacts
    }

    pub fn contacts_mut(&mut self) -> &mut ContactStore {
        &mut self.contacts
    }

    pub fn into_contacts(self) -> ContactStore {
        self.contacts
    }

    fn sync_policy_to_store(&mut self, now: u64) {
        self.contacts
            .update_attempt_policy_state(crate::contact::AttemptPolicyState {
                consecutive_incomplete: self.policy.consecutive_incomplete(),
                pending_response: self.response_seen,
                pause_remaining_ms: self.policy.pause_remaining_ms(now),
            });
    }

    pub fn warning_active(&self) -> bool {
        self.policy.warning_active()
    }

    pub fn expire(&mut self, now: u64) {
        if self
            .policy
            .live_started_ms
            .is_some_and(|start| now.saturating_sub(start) >= SESSION_TIMEOUT_MS)
        {
            self.end_incomplete(now);
        }
    }

    pub fn cancel(&mut self, now: u64) {
        self.expire(now);
        self.end_incomplete(now);
    }

    fn end_incomplete(&mut self, now: u64) {
        self.live = None;
        if std::mem::take(&mut self.response_seen) {
            self.policy.record_incomplete(now);
            self.sync_policy_to_store(now);
        } else {
            self.policy.live_started_ms = None;
        }
        self.response_seen = false;
    }

    fn begin(&mut self, now: u64) -> Result<(), SessionError> {
        self.expire(now);
        self.policy.begin(now).map_err(SessionError::Attempt)
    }

    pub fn start(
        &mut self,
        now: u64,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Vec<u8>, SessionError> {
        self.begin(now)?;
        let mut machine = InitiatorMachine::new();
        let offer = machine
            .start(self.key.clone(), rng)
            .map_err(SessionError::Protocol)?;
        self.live = Some(LiveEncounter::Initiator(machine));
        Ok(offer)
    }

    pub fn scan_offer(
        &mut self,
        bytes: &[u8],
        now: u64,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Vec<u8>, SessionError> {
        self.expire(now);
        if let Some(LiveEncounter::Responder(machine)) = &mut self.live {
            // A different QR1 while a session is live is a stray scan (a poster, someone else's
            // screen). Ignore it: it neither ends the live session nor counts as an attempt.
            if machine.conflicts_with_accepted_offer(bytes) {
                return Err(SessionError::Protocol(EncounterError::SessionMismatch));
            }
            let result = machine.on_offer(self.key.clone(), bytes, rng);
            return self.handle_scan(result, now);
        }
        self.begin(now)?;
        let mut machine = ResponderMachine::new();
        let response = machine.on_offer(self.key.clone(), bytes, rng);
        if response.is_ok() {
            self.response_seen = true;
            self.sync_policy_to_store(now);
        }
        self.live = Some(LiveEncounter::Responder(machine));
        self.handle_scan(response, now)
    }

    pub fn scan_response(&mut self, bytes: &[u8], now: u64) -> Result<Vec<u8>, SessionError> {
        self.expire(now);
        let result = match &mut self.live {
            Some(LiveEncounter::Initiator(machine)) => {
                // A second, different QR2 is ignored; it cannot end or replace the live session.
                if machine.conflicts_with_accepted_response(bytes) {
                    return Err(SessionError::Protocol(EncounterError::SessionMismatch));
                }
                machine.on_response(bytes)
            }
            Some(_) => Err(EncounterError::OutOfOrder),
            None => return Err(SessionError::NoLiveSession),
        };
        if result.is_ok() && !self.response_seen {
            self.response_seen = true;
            self.sync_policy_to_store(now);
        }
        self.handle_scan(result, now)
    }

    pub fn scan_reveal(&mut self, bytes: &[u8], now: u64) -> Result<(), SessionError> {
        self.expire(now);
        let result = match &mut self.live {
            Some(LiveEncounter::Responder(machine)) => {
                if machine.conflicts_with_accepted_reveal(bytes) {
                    return Err(SessionError::Protocol(EncounterError::SessionMismatch));
                }
                machine.on_reveal(bytes)
            }
            Some(_) => Err(EncounterError::OutOfOrder),
            None => return Err(SessionError::NoLiveSession),
        };
        self.handle_scan(result, now)
    }

    fn handle_scan<T>(
        &mut self,
        result: Result<T, EncounterError>,
        now: u64,
    ) -> Result<T, SessionError> {
        // A frame that failed a check but left the machine live (an invalid QR2 or QR3) is ignored.
        // Only a machine that ended itself (a changed frame, a failed first QR1) ends the session.
        if result.is_err() && self.live_machine_ended() {
            self.cancel(now);
        }
        result.map_err(SessionError::Protocol)
    }

    fn live_machine_ended(&self) -> bool {
        match &self.live {
            Some(LiveEncounter::Initiator(m)) => m.is_terminal(),
            Some(LiveEncounter::Responder(m)) => m.is_terminal(),
            None => false,
        }
    }

    pub fn comparison(&mut self, now: u64) -> Option<Comparison> {
        self.expire(now);
        let (code, transcript) = match self.live.as_ref()? {
            LiveEncounter::Initiator(machine) => {
                (machine.sas_code(), machine.comparison_transcript())
            }
            LiveEncounter::Responder(machine) => {
                (machine.sas_code(), machine.comparison_transcript())
            }
        };
        Some(Comparison {
            transcript: transcript?,
            code: code?,
            local_identity: self.key.verifying_key().to_bytes(),
        })
    }

    pub fn confirm_and_save(
        &mut self,
        comparison: Comparison,
        peer_code: u32,
        now: u64,
        timestamp: u64,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<ContactRecordV1, SessionError> {
        self.expire(now);
        if self.live.is_none() {
            return Err(SessionError::NoLiveSession);
        }
        if self.comparison(now) != Some(comparison) {
            return Err(SessionError::StaleComparison);
        }
        // Consume the session before saving, so a duplicate callback cannot save again.
        let result = match self.live.take().ok_or(SessionError::NoLiveSession)? {
            LiveEncounter::Initiator(mut machine) => machine
                .confirm(peer_code)
                .map_err(SessionError::Protocol)
                .and_then(|token| self.save(&token, timestamp, rng)),
            LiveEncounter::Responder(mut machine) => machine
                .confirm(peer_code)
                .map_err(SessionError::Protocol)
                .and_then(|token| self.save(&token, timestamp, rng)),
        };
        if result.is_ok() {
            self.policy.record_complete();
            self.response_seen = false;
            self.sync_policy_to_store(now);
        } else {
            self.end_incomplete(now);
        }
        result
    }

    fn save(
        &mut self,
        token: &impl ConfirmedEncounter,
        timestamp: u64,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<ContactRecordV1, SessionError> {
        self.contacts
            .record_confirmed_encounter(token, timestamp, rng)
            .cloned()
            .map_err(SessionError::Store)
    }
}

pub mod installation;
