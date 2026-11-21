//! Canonical deterministic CBOR array framing for Encounter v0.1 (`cbor_det`).
//! RFC 8949 §4.2.1 Core Deterministic Encoding using `cbor2`.

use cbor2::Value;

pub fn cbor_det_bytes(items: Vec<Value>) -> Vec<u8> {
    let val = Value::Array(items);
    cbor2::to_vec(&val).expect("cbor serialization cannot fail")
}

pub mod byte_seq {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_bytes::{ByteBuf, Bytes};

    pub mod array32 {
        use super::*;
        pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
            Bytes::new(bytes).serialize(s)
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
            let buf = ByteBuf::deserialize(d)?;
            buf.as_slice().try_into().map_err(serde::de::Error::custom)
        }
    }

    pub mod array16 {
        use super::*;
        pub fn serialize<S: Serializer>(bytes: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
            Bytes::new(bytes).serialize(s)
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
            let buf = ByteBuf::deserialize(d)?;
            buf.as_slice().try_into().map_err(serde::de::Error::custom)
        }
    }

    pub mod opt_array32 {
        use super::*;
        pub fn serialize<S: Serializer>(opt: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
            match opt {
                Some(b) => s.serialize_some(Bytes::new(b)),
                None => s.serialize_none(),
            }
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
            let opt: Option<ByteBuf> = Deserialize::deserialize(d)?;
            match opt {
                Some(buf) => {
                    let arr = buf
                        .as_slice()
                        .try_into()
                        .map_err(serde::de::Error::custom)?;
                    Ok(Some(arr))
                }
                None => Ok(None),
            }
        }
    }

    pub mod vec_array32 {
        use super::*;
        use serde::ser::SerializeSeq;
        pub fn serialize<S: Serializer>(vec: &[[u8; 32]], s: S) -> Result<S::Ok, S::Error> {
            let mut seq = s.serialize_seq(Some(vec.len()))?;
            for item in vec {
                seq.serialize_element(Bytes::new(item))?;
            }
            seq.end()
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 32]>, D::Error> {
            let bufs: Vec<ByteBuf> = Deserialize::deserialize(d)?;
            bufs.into_iter()
                .map(|b| b.as_slice().try_into().map_err(serde::de::Error::custom))
                .collect()
        }
    }

    pub mod btreeset_array32 {
        use super::*;
        use serde::ser::SerializeSeq;
        use std::collections::BTreeSet;

        pub fn serialize<S: Serializer>(set: &BTreeSet<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
            let mut seq = s.serialize_seq(Some(set.len()))?;
            for item in set {
                seq.serialize_element(Bytes::new(item))?;
            }
            seq.end()
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(
            d: D,
        ) -> Result<BTreeSet<[u8; 32]>, D::Error> {
            let bufs: Vec<ByteBuf> = Deserialize::deserialize(d)?;
            bufs.into_iter()
                .map(|b| b.as_slice().try_into().map_err(serde::de::Error::custom))
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct ByteStruct {
        #[serde(with = "byte_seq::array32")]
        key32: [u8; 32],
        #[serde(with = "byte_seq::array16")]
        key16: [u8; 16],
        #[serde(with = "byte_seq::opt_array32")]
        opt_key: Option<[u8; 32]>,
        #[serde(with = "byte_seq::vec_array32")]
        vec_keys: Vec<[u8; 32]>,
        #[serde(with = "serde_bytes")]
        bytes_vec: Vec<u8>,
    }

    #[test]
    fn test_byte_seq_cbor_encoding() {
        let val = ByteStruct {
            key32: [0xaa; 32],
            key16: [0xbb; 16],
            opt_key: Some([0xcc; 32]),
            vec_keys: vec![[0x11; 32], [0x22; 32]],
            bytes_vec: vec![0x33; 64],
        };

        let encoded = cbor2::to_vec(&val).unwrap();
        // 32-byte key is 1 header byte + 1 length byte (0x58 0x20) + 32 bytes = 34 bytes (not ~65 bytes)
        // Check that key32 starts with byte string header 0x58 0x20
        assert!(
            encoded
                .windows(34)
                .any(|w| w[0] == 0x58 && w[1] == 32 && w[2..].iter().all(|b| *b == 0xaa))
        );

        let decoded: ByteStruct = cbor2::from_reader(encoded.as_slice()).unwrap();
        assert_eq!(val, decoded);
    }
}
