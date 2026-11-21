//! User-visible strings the spec requires. A UI must show these
//! next to the corresponding states; this crate only fixes their wording and tests that the states
//! that need them can be told apart.

/// Shown with any "verified" result. Not colocation proof.
pub const PROXIMITY_DISCLAIMER: &str = "Verified matching keys. This does not prove physical proximity if the QR codes were forwarded.";

/// Shown after the local user confirms. Each device confirms only for itself.
pub const LOCAL_ONLY_CONFIRMATION: &str = "Saved on this device only. The other device may not have saved you, and cancelling there cannot undo this.";

/// Shown after repeated incomplete sessions. Must never suggest retrying until the codes match.
pub const INTERFERENCE_WARNING: &str = "Several attempts did not finish. This can mean something is interfering with the exchange. Wait before trying again.";

/// Shown when a new key arrives under an alias already used by a different key.
pub const ALIAS_CONFLICT_WARNING: &str =
    "Different cryptographic identity from previously saved contact with this name.";

/// Not unique-human or legal identity.
pub const NOT_IDENTITY_PROOF: &str =
    "This confirms a key, not who a person is. One person can have several keys.";

/// Interactive SAS comparison instruction to mitigate human glance-and-confirm complacency.
pub const SAS_COMPARISON_INSTRUCTION: &str = "Compare the 6-digit code with your peer. Check every digit carefully. Do not confirm if any digit differs.";
