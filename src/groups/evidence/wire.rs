//! Versioned certificate envelope.
//!
//! Codec only: nothing here verifies a proof or a digest, and nothing in the agreement path
//! calls it yet. `RosterCertificate::to_bytes` and `from_bytes` are unchanged; the envelope
//! wraps them with a leading tag byte.
//!
//! - Tag 0: the current layout, byte for byte.
//! - Tag 1: the current 76-byte header, a 32-byte chain digest, a one-byte proof count, the
//!   proofs, then the current vote lists. Proofs are scoped to the certificate's own group and
//!   parent, so those fields are implicit on the wire.
//! - Any other tag fails closed.
//!
//! One certificate has one encoding: proofs are in strictly ascending signer order, a proof's
//! two children are in strictly ascending order, and every successful decode re-encodes to the
//! exact input.

use super::proof::EquivocationProof;
use super::{Error, Key, RosterCertificate};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Most proofs one certificate carries: a roster of up to 192 has a fault bound of at most 63.
pub const MAX_CERTIFICATE_PROOFS: usize = 64;

const HEADER_LEN: usize = 76;
const DIGEST_LEN: usize = 32;
/// signer 32, round 4, phase 1, then two (child 32, signature 64) pairs.
const PROOF_WIRE_LEN: usize = 32 + 4 + 1 + 2 * (32 + 64);

/// Digest of the proof-subject set a collector built on: what a receiver compares with its own
/// chain to tell "behind or elsewhere" from "invalid". The keys are in ascending order, so
/// the digest depends only on the set.
pub(crate) fn chain_digest(group: u64, parent: [u8; 32], inherited: &BTreeSet<Key>) -> [u8; 32] {
    let mut hash = Sha256::new()
        .chain_update(b"mesh/group-admission/chain-digest/v1\0")
        .chain_update(group.to_be_bytes())
        .chain_update(parent)
        .chain_update((inherited.len() as u32).to_be_bytes());
    for key in inherited {
        hash.update(key);
    }
    hash.finalize().into()
}

/// The digest for a chain that also carries reported keys. With no reports it is exactly
/// `chain_digest`, so every digest and certificate from before reports existed is unchanged;
/// with reports it uses its own domain tag and appends the reported keys in ascending order.
pub(crate) fn chain_digest_with_reports(
    group: u64,
    parent: [u8; 32],
    inherited: &BTreeSet<Key>,
    reported: &BTreeSet<Key>,
    recognized: &std::collections::BTreeMap<Key, (u64, [u8; 32])>,
) -> [u8; 32] {
    if !recognized.is_empty() {
        // Its own domain, used only when a device recognition is on the chain.
        let mut hash = Sha256::new()
            .chain_update(b"mesh/group-admission/chain-digest/v3\0")
            .chain_update(group.to_be_bytes())
            .chain_update(parent)
            .chain_update((inherited.len() as u32).to_be_bytes());
        for key in inherited {
            hash.update(key);
        }
        hash.update((reported.len() as u32).to_be_bytes());
        for key in reported {
            hash.update(key);
        }
        hash.update((recognized.len() as u32).to_be_bytes());
        for (key, (counter, nonce)) in recognized {
            hash.update(key);
            hash.update(counter.to_be_bytes());
            hash.update(nonce);
        }
        return hash.finalize().into();
    }
    if reported.is_empty() {
        return chain_digest(group, parent, inherited);
    }
    let mut hash = Sha256::new()
        .chain_update(b"mesh/group-admission/chain-digest/v2\0")
        .chain_update(group.to_be_bytes())
        .chain_update(parent)
        .chain_update((inherited.len() as u32).to_be_bytes());
    for key in inherited {
        hash.update(key);
    }
    hash.update((reported.len() as u32).to_be_bytes());
    for key in reported {
        hash.update(key);
    }
    hash.finalize().into()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireError {
    /// The envelope tag is not one this build understands.
    UnsupportedVersion(u8),
    /// Empty, truncated, over-long, or not in canonical form.
    Malformed,
}

/// A version-1 certificate: the base certificate, the digest of the inherited proof set the
/// collector built on, and the proofs new at this parent.
pub struct CertificateV1 {
    pub certificate: RosterCertificate,
    pub chain_digest: [u8; 32],
    pub proofs: Vec<EquivocationProof>,
}

pub enum VersionedCertificate {
    V0(RosterCertificate),
    V1(CertificateV1),
}

impl VersionedCertificate {
    pub fn to_bytes(&self) -> Result<Vec<u8>, WireError> {
        match self {
            Self::V0(certificate) => {
                let base = certificate
                    .to_bytes()
                    .map_err(|_: Error| WireError::Malformed)?;
                let mut bytes = Vec::with_capacity(1 + base.len());
                bytes.push(0);
                bytes.extend_from_slice(&base);
                Ok(bytes)
            }
            Self::V1(v1) => v1.to_bytes(),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        let (&tag, rest) = bytes.split_first().ok_or(WireError::Malformed)?;
        match tag {
            0 => RosterCertificate::from_bytes(rest)
                .map(Self::V0)
                .map_err(|_| WireError::Malformed),
            1 => CertificateV1::from_body(rest).map(Self::V1),
            other => Err(WireError::UnsupportedVersion(other)),
        }
    }
}

/// A certificate as the certified transitions accept it: version 0 (no new proofs; it carries
/// exactly the receiver's inherited set) or version 1 (with a chain digest and new proofs).
#[derive(Clone, Copy)]
pub struct CertificateRef<'a>(CertificateKind<'a>);

#[derive(Clone, Copy)]
enum CertificateKind<'a> {
    V0(&'a RosterCertificate),
    V1(&'a CertificateV1),
}

impl<'a> CertificateRef<'a> {
    pub(super) fn kind_v0(&self) -> Option<&'a RosterCertificate> {
        match self.0 {
            CertificateKind::V0(certificate) => Some(certificate),
            CertificateKind::V1(_) => None,
        }
    }

    pub(super) fn kind_v1(&self) -> Option<&'a CertificateV1> {
        match self.0 {
            CertificateKind::V0(_) => None,
            CertificateKind::V1(v1) => Some(v1),
        }
    }
}

impl<'a> From<&'a RosterCertificate> for CertificateRef<'a> {
    fn from(certificate: &'a RosterCertificate) -> Self {
        Self(CertificateKind::V0(certificate))
    }
}

impl<'a> From<&'a CertificateV1> for CertificateRef<'a> {
    fn from(v1: &'a CertificateV1) -> Self {
        Self(CertificateKind::V1(v1))
    }
}

impl<'a> From<&'a VersionedCertificate> for CertificateRef<'a> {
    fn from(certificate: &'a VersionedCertificate) -> Self {
        match certificate {
            VersionedCertificate::V0(certificate) => certificate.into(),
            VersionedCertificate::V1(v1) => v1.into(),
        }
    }
}

impl CertificateV1 {
    fn to_bytes(&self) -> Result<Vec<u8>, WireError> {
        if self.proofs.len() > MAX_CERTIFICATE_PROOFS {
            return Err(WireError::Malformed);
        }
        let base = self
            .certificate
            .to_bytes()
            .map_err(|_: Error| WireError::Malformed)?;
        let mut previous: Option<&[u8; 32]> = None;
        for proof in &self.proofs {
            let in_scope =
                proof.group == self.certificate.group && proof.parent == self.certificate.parent;
            let ordered = previous.is_none_or(|p| *p < proof.signer);
            if !in_scope || !ordered || proof.first.0 >= proof.second.0 {
                return Err(WireError::Malformed);
            }
            previous = Some(&proof.signer);
        }
        let mut bytes = Vec::with_capacity(
            1 + base.len() + DIGEST_LEN + 1 + self.proofs.len() * PROOF_WIRE_LEN,
        );
        bytes.push(1);
        bytes.extend_from_slice(&base[..HEADER_LEN]);
        bytes.extend_from_slice(&self.chain_digest);
        bytes.push(self.proofs.len() as u8);
        for proof in &self.proofs {
            bytes.extend_from_slice(&proof.signer);
            bytes.extend_from_slice(&proof.round.to_be_bytes());
            bytes.push(proof.phase);
            bytes.extend_from_slice(&proof.first.0);
            bytes.extend_from_slice(&proof.first.1);
            bytes.extend_from_slice(&proof.second.0);
            bytes.extend_from_slice(&proof.second.1);
        }
        bytes.extend_from_slice(&base[HEADER_LEN..]);
        Ok(bytes)
    }

    fn from_body(body: &[u8]) -> Result<Self, WireError> {
        if body.len() < HEADER_LEN + DIGEST_LEN + 1 {
            return Err(WireError::Malformed);
        }
        let (header, rest) = body.split_at(HEADER_LEN);
        let (digest, rest) = rest.split_at(DIGEST_LEN);
        let count = rest[0] as usize;
        let rest = &rest[1..];
        if count > MAX_CERTIFICATE_PROOFS || rest.len() < count * PROOF_WIRE_LEN {
            return Err(WireError::Malformed);
        }
        let (proof_bytes, votes) = rest.split_at(count * PROOF_WIRE_LEN);
        let group = u64::from_be_bytes(header[..8].try_into().unwrap());
        let parent: [u8; 32] = header[8..40].try_into().unwrap();
        let mut proofs = Vec::with_capacity(count);
        for chunk in proof_bytes.chunks_exact(PROOF_WIRE_LEN) {
            let signer: [u8; 32] = chunk[..32].try_into().unwrap();
            let round = u32::from_be_bytes(chunk[32..36].try_into().unwrap());
            let phase = chunk[36];
            let first: ([u8; 32], [u8; 64]) = (
                chunk[37..69].try_into().unwrap(),
                chunk[69..133].try_into().unwrap(),
            );
            let second: ([u8; 32], [u8; 64]) = (
                chunk[133..165].try_into().unwrap(),
                chunk[165..229].try_into().unwrap(),
            );
            if first.0 >= second.0
                || proofs
                    .last()
                    .is_some_and(|p: &EquivocationProof| p.signer >= signer)
            {
                return Err(WireError::Malformed);
            }
            proofs.push(EquivocationProof {
                signer,
                group,
                parent,
                round,
                phase,
                first,
                second,
            });
        }
        let mut base = Vec::with_capacity(HEADER_LEN + votes.len());
        base.extend_from_slice(header);
        base.extend_from_slice(votes);
        let certificate = RosterCertificate::from_bytes(&base).map_err(|_| WireError::Malformed)?;
        Ok(Self {
            certificate,
            chain_digest: digest.try_into().unwrap(),
            proofs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::evidence::RosterVote;

    fn vote(seed: u8) -> RosterVote {
        RosterVote {
            signer: [seed; 32],
            signature: [seed ^ 0x5a; 64],
        }
    }

    fn certificate(signers: usize) -> RosterCertificate {
        RosterCertificate {
            group: 7,
            parent: [3; 32],
            child: [4; 32],
            round: 2,
            prepares: (0..signers).map(|i| vote(i as u8 + 1)).collect(),
            commits: (0..signers).map(|i| vote(i as u8 + 101)).collect(),
        }
    }

    fn proof(cert: &RosterCertificate, seed: u8) -> EquivocationProof {
        EquivocationProof {
            signer: [seed; 32],
            group: cert.group,
            parent: cert.parent,
            round: 1,
            phase: 2,
            first: ([10; 32], [seed ^ 1; 64]),
            second: ([20; 32], [seed ^ 2; 64]),
        }
    }

    fn v1(signers: usize, proofs: usize) -> VersionedCertificate {
        let certificate = certificate(signers);
        let proofs = (0..proofs)
            .map(|i| proof(&certificate, i as u8 + 1))
            .collect();
        VersionedCertificate::V1(CertificateV1 {
            certificate,
            chain_digest: [9; 32],
            proofs,
        })
    }

    fn same(a: &VersionedCertificate, b: &VersionedCertificate) -> bool {
        a.to_bytes().unwrap() == b.to_bytes().unwrap()
    }

    #[test]
    fn version_one_round_trips_at_the_bounds() {
        for (signers, proofs) in [
            (1, 0),
            (1, 1),
            (4, 3),
            (128, 0),
            (128, MAX_CERTIFICATE_PROOFS),
        ] {
            let original = v1(signers, proofs);
            let bytes = original.to_bytes().unwrap();
            assert_eq!(bytes[0], 1);
            assert_eq!(
                bytes.len(),
                1 + HEADER_LEN + DIGEST_LEN + 1 + proofs * PROOF_WIRE_LEN + signers * 192
            );
            let decoded = VersionedCertificate::from_bytes(&bytes).unwrap();
            assert!(
                same(&original, &decoded),
                "signers {signers} proofs {proofs}"
            );
        }
    }

    #[test]
    fn version_zero_is_the_current_encoding_behind_a_tag() {
        let base = certificate(4);
        let bytes = VersionedCertificate::V0(certificate(4)).to_bytes().unwrap();
        assert_eq!(bytes[0], 0);
        assert_eq!(&bytes[1..], &base.to_bytes().unwrap()[..]);
        let decoded = VersionedCertificate::from_bytes(&bytes).unwrap();
        assert!(matches!(decoded, VersionedCertificate::V0(_)));
        // The untagged decoder is untouched.
        assert!(RosterCertificate::from_bytes(&base.to_bytes().unwrap()).is_ok());
    }

    #[test]
    fn unknown_tags_and_empty_input_fail_closed() {
        let bytes = v1(2, 1).to_bytes().unwrap();
        for tag in (2u8..=255).chain([]) {
            let mut altered = bytes.clone();
            altered[0] = tag;
            assert_eq!(
                VersionedCertificate::from_bytes(&altered).err(),
                Some(WireError::UnsupportedVersion(tag))
            );
        }
        assert_eq!(
            VersionedCertificate::from_bytes(&[]).err(),
            Some(WireError::Malformed)
        );
    }

    #[test]
    fn every_truncation_and_extension_is_rejected() {
        for (signers, proofs) in [(1, 0), (2, 2), (3, 1)] {
            let bytes = v1(signers, proofs).to_bytes().unwrap();
            for cut in 0..bytes.len() {
                // Dropping a whole signer pair leaves a well-formed certificate with fewer
                // signers (its signatures will not verify); every other cut must fail.
                if (bytes.len() - cut).is_multiple_of(192)
                    && cut >= 1 + HEADER_LEN + DIGEST_LEN + 1 + proofs * PROOF_WIRE_LEN + 192
                {
                    continue;
                }
                assert!(
                    VersionedCertificate::from_bytes(&bytes[..cut]).is_err(),
                    "cut {cut} of {}",
                    bytes.len()
                );
            }
            for extra in 1..=200 {
                let mut longer = bytes.clone();
                longer.extend(std::iter::repeat_n(0xAB, extra));
                // A whole extra signer pair would be a different valid certificate; every
                // other length must fail.
                if extra % 192 != 0 {
                    assert!(
                        VersionedCertificate::from_bytes(&longer).is_err(),
                        "extra {extra}"
                    );
                }
            }
        }
    }

    #[test]
    fn proofs_must_be_unique_ascending_and_in_scope() {
        let cert = certificate(2);
        let make = |proofs: Vec<EquivocationProof>| {
            VersionedCertificate::V1(CertificateV1 {
                certificate: certificate(2),
                chain_digest: [0; 32],
                proofs,
            })
            .to_bytes()
        };
        assert!(make(vec![proof(&cert, 1), proof(&cert, 2)]).is_ok());
        assert!(make(vec![proof(&cert, 2), proof(&cert, 1)]).is_err());
        assert!(make(vec![proof(&cert, 1), proof(&cert, 1)]).is_err());
        let mut other_group = proof(&cert, 1);
        other_group.group += 1;
        assert!(make(vec![other_group]).is_err());
        let mut other_parent = proof(&cert, 1);
        other_parent.parent = [0; 32];
        assert!(make(vec![other_parent]).is_err());
        let mut unordered_children = proof(&cert, 1);
        std::mem::swap(
            &mut unordered_children.first,
            &mut unordered_children.second,
        );
        assert!(make(vec![unordered_children]).is_err());
        let mut equal_children = proof(&cert, 1);
        equal_children.second.0 = equal_children.first.0;
        assert!(make(vec![equal_children]).is_err());
        let too_many: Vec<_> = (0..=MAX_CERTIFICATE_PROOFS)
            .map(|i| proof(&cert, i as u8 + 1))
            .collect();
        assert!(make(too_many).is_err());
    }

    #[test]
    fn the_decoder_rejects_non_canonical_proofs_and_bad_counts() {
        let bytes = v1(2, 2).to_bytes().unwrap();
        let proofs_at = 1 + HEADER_LEN + DIGEST_LEN + 1;
        // Swap the two proofs' signers' order by editing the first signer upward.
        let mut unsorted = bytes.clone();
        unsorted[proofs_at..proofs_at + 32].fill(0xFF);
        assert!(VersionedCertificate::from_bytes(&unsorted).is_err());
        // Children out of order inside the first proof.
        let mut swapped = bytes.clone();
        swapped[proofs_at + 37..proofs_at + 69].fill(0xFF);
        assert!(VersionedCertificate::from_bytes(&swapped).is_err());
        // A proof count that claims more than is present, and one over the cap.
        for count in [3u8, 64, 65, 255] {
            let mut altered = bytes.clone();
            altered[1 + HEADER_LEN + DIGEST_LEN] = count;
            assert!(
                VersionedCertificate::from_bytes(&altered).is_err(),
                "count {count}"
            );
        }
        // A proof count that is too small leaves proof bytes in the vote section.
        let mut fewer = bytes.clone();
        fewer[1 + HEADER_LEN + DIGEST_LEN] = 1;
        assert!(VersionedCertificate::from_bytes(&fewer).is_err());
    }

    /// Every byte of valid encodings, flipped in several ways: decoding never panics, and
    /// whatever decodes re-encodes to exactly the mutated input (one encoding per certificate).
    #[test]
    fn mutation_never_panics_and_decodes_are_canonical() {
        let mut decoded = 0u32;
        for original in [v1(1, 0), v1(2, 2), v1(3, 1)] {
            let bytes = original.to_bytes().unwrap();
            for position in 0..bytes.len() {
                for mask in [0x01u8, 0x80, 0xFF] {
                    let mut mutated = bytes.clone();
                    mutated[position] ^= mask;
                    if let Ok(value) = VersionedCertificate::from_bytes(&mutated) {
                        assert_eq!(value.to_bytes().unwrap(), mutated, "byte {position}");
                        decoded += 1;
                    }
                }
            }
        }
        assert!(decoded > 100);
    }
}
