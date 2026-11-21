//! Optional OpenPGP adapter for `mesh-identity` (feature `openpgp`).
//!
//! Note: Full OpenPGP key import and detached signing using `rpgp` is scheduled
//! for extraction in Milestone X4. This module currently provides the interface
//! types and snapshot revocation memory contracts.

use pgp as _;

#[derive(Clone, Debug, Default)]
pub struct PeerRevocations {}

impl PeerRevocations {
    pub fn is_empty(&self) -> bool {
        true
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PendingExport {}
