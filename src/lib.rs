//! `mesh-identity`: Peer identity, offline in-person encounters, and Byzantine group admission.

pub mod cbor;
pub mod contact;
pub mod machine;
#[cfg(feature = "openpgp")]
pub mod openpgp;
pub mod protocol;
pub mod session;
pub mod transport;
pub mod ui_text;
#[cfg(any(test, feature = "test-support"))]
pub mod vectors;

#[cfg(feature = "groups")]
pub mod groups;
