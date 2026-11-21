//! Multi-transport abstraction for Encounter v0.1:
//! Supports QR (optical), BLE (stream / GATT pipe), and Hybrid (QR bootstrap + BLE negotiation).

use crate::protocol::MAX_FRAME_BYTES;
use std::collections::VecDeque;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TransportError {
    ChannelClosed,
    Timeout,
    ReceiveQueueFull,
    FramingError(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for TransportError {}

pub trait Transport {
    fn send(&mut self, payload: &[u8]) -> Result<(), TransportError>;
    fn receive(&mut self) -> Result<Vec<u8>, TransportError>;
}

// ----------------- 1. Optical QR Transport -----------------

pub struct QrTransport {
    pub display_screen: Option<String>,
    pub camera_inbox: VecDeque<String>,
}

impl QrTransport {
    pub fn new() -> Self {
        Self {
            display_screen: None,
            camera_inbox: VecDeque::new(),
        }
    }

    /// Simulates optical screen-to-camera scanning from another QR device
    pub fn scan_from_peer(&mut self, peer_screen: &str) {
        self.camera_inbox.push_back(peer_screen.to_string());
    }

    /// Renders an ASCII border representing a QR code displayed on screen
    pub fn render_ascii_qr(payload: &str) -> String {
        format!(
            "┌────────────────────────────────────────────────────────┐\n\
             │ [QR CODE DISPLAY]                                      │\n\
             │ payload: {:<45} │\n\
             └────────────────────────────────────────────────────────┘",
            payload.chars().take(45).collect::<String>()
        )
    }
}

impl Default for QrTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for QrTransport {
    fn send(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        if payload.len() > MAX_FRAME_BYTES {
            return Err(TransportError::FramingError(
                "Payload exceeds MAX_FRAME_BYTES".into(),
            ));
        }
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
        self.display_screen = Some(format!("mesh:encounter:{}", b64));
        Ok(())
    }

    fn receive(&mut self) -> Result<Vec<u8>, TransportError> {
        let scanned = self
            .camera_inbox
            .pop_front()
            .ok_or(TransportError::ChannelClosed)?;
        use base64::Engine;
        let prefix = "mesh:encounter:";
        if let Some(b64) = scanned.strip_prefix(prefix) {
            let max_b64_len = MAX_FRAME_BYTES.div_ceil(3) * 4 + 4;
            if b64.len() > max_b64_len {
                return Err(TransportError::FramingError("Oversized QR payload".into()));
            }
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| TransportError::FramingError(format!("Corrupt QR Base64: {}", e)))?;
            if decoded.len() > MAX_FRAME_BYTES {
                return Err(TransportError::FramingError("Oversized QR payload".into()));
            }
            Ok(decoded)
        } else {
            Err(TransportError::FramingError(
                "Invalid QR URI scheme".to_string(),
            ))
        }
    }
}

// ----------------- 2. Bluetooth Low Energy (BLE) Transport -----------------

/// Standard BLE ATT MTU default is 23 bytes (3 bytes ATT header overhead = 20 bytes data).
pub const DEFAULT_BLE_ATT_PAYLOAD_MTU: usize = 20;

pub struct BleTransport {
    mtu: usize, // 0 means unfragmented pipe; > 0 enforces GATT characteristic chunking
    tx_queue: VecDeque<Vec<u8>>,
    rx_queue: VecDeque<Vec<u8>>,
}

impl BleTransport {
    pub fn create_pair() -> (Self, Self) {
        Self::create_pair_with_mtu(0)
    }

    pub fn create_pair_with_mtu(mtu: usize) -> (Self, Self) {
        let a = BleTransport {
            mtu,
            tx_queue: VecDeque::new(),
            rx_queue: VecDeque::new(),
        };
        let b = BleTransport {
            mtu,
            tx_queue: VecDeque::new(),
            rx_queue: VecDeque::new(),
        };
        (a, b)
    }

    /// Queue one incoming packet. The queue holds at most one maximum-sized
    /// frame's worth of packets, with backpressure when the consumer falls behind.
    pub fn enqueue_rx(&mut self, packet: &[u8]) -> Result<(), TransportError> {
        let capacity = match self.mtu {
            0 => {
                if packet.len() > MAX_FRAME_BYTES {
                    return Err(TransportError::FramingError(
                        "BLE payload exceeds frame limit".into(),
                    ));
                }
                1
            }
            1 | 2 => {
                return Err(TransportError::FramingError(
                    "BLE MTU too small for framing".into(),
                ));
            }
            mtu => {
                if !(2..=mtu.min(MAX_FRAME_BYTES + 2)).contains(&packet.len()) {
                    return Err(TransportError::FramingError(
                        "Invalid BLE packet size".into(),
                    ));
                }
                MAX_FRAME_BYTES.div_ceil(mtu - 2).min(250)
            }
        };
        if self.rx_queue.len() >= capacity {
            return Err(TransportError::ReceiveQueueFull);
        }
        self.rx_queue.push_back(packet.to_vec());
        Ok(())
    }

    /// Pump packets between paired handles, preserving unsent packets on backpressure.
    pub fn pump(a: &mut BleTransport, b: &mut BleTransport) -> Result<(), TransportError> {
        fn transfer(
            sender: &mut BleTransport,
            receiver: &mut BleTransport,
        ) -> Result<(), TransportError> {
            while let Some(packet) = sender.tx_queue.front() {
                receiver.enqueue_rx(packet)?;
                sender.tx_queue.pop_front();
            }
            Ok(())
        }

        transfer(a, b)?;
        transfer(b, a)
    }

    /// Discards any buffered packets in the RX queue.
    /// Call when a connection times out, disconnects, or resets.
    pub fn reset_rx(&mut self) {
        self.rx_queue.clear();
    }
}

impl Transport for BleTransport {
    /// `mtu == 0` is a raw pipe (no framing). With an MTU, EVERY message is framed as
    /// `[index, total, data...]`, even a one-packet message, so the receiver never has to guess
    /// whether a packet is a chunk or a bare payload.
    fn send(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        if payload.len() > MAX_FRAME_BYTES {
            return Err(TransportError::FramingError(
                "BLE payload exceeds frame limit".into(),
            ));
        }
        if self.mtu == 0 {
            self.tx_queue.push_back(payload.to_vec());
            return Ok(());
        }
        if self.mtu < 3 {
            return Err(TransportError::FramingError(
                "MTU too small for a chunk header".into(),
            ));
        }
        let chunk_data_len = self.mtu - 2;
        let total_chunks = payload.len().div_ceil(chunk_data_len).max(1);
        if total_chunks > 250 {
            return Err(TransportError::FramingError(
                "Payload too large for 1-byte chunking".into(),
            ));
        }
        if payload.is_empty() {
            self.tx_queue.push_back(vec![0, 1]);
            return Ok(());
        }
        for (i, chunk) in payload.chunks(chunk_data_len).enumerate() {
            let mut packet = Vec::with_capacity(2 + chunk.len());
            packet.push(i as u8);
            packet.push(total_chunks as u8);
            packet.extend_from_slice(chunk);
            self.tx_queue.push_back(packet);
        }
        Ok(())
    }

    fn receive(&mut self) -> Result<Vec<u8>, TransportError> {
        if self.mtu == 0 {
            return self
                .rx_queue
                .pop_front()
                .ok_or(TransportError::ChannelClosed);
        }

        let first = self.rx_queue.front().ok_or(TransportError::ChannelClosed)?;
        let valid_length = |packet: &[u8]| (2..=self.mtu).contains(&packet.len());
        if !valid_length(first) || first[0] != 0 || !(1..=250).contains(&first[1]) {
            self.rx_queue.pop_front();
            return Err(TransportError::FramingError(
                "Invalid BLE frame start".into(),
            ));
        }
        let total = first[1] as usize;
        // Bound buffering before the protocol layer's frame cap applies: no valid message needs
        // more chunks than ceil(MAX_FRAME_BYTES / payload-per-chunk).
        if self.mtu < 3 {
            return Err(TransportError::FramingError(
                "BLE MTU too small for framing".into(),
            ));
        }
        let max_chunks = MAX_FRAME_BYTES.div_ceil(self.mtu - 2);
        if total > max_chunks {
            self.rx_queue.pop_front();
            return Err(TransportError::FramingError(
                "BLE frame exceeds the maximum message size".into(),
            ));
        }
        let mut payload_len = 0;
        for index in 0..total {
            let Some(packet) = self.rx_queue.get(index) else {
                // Keep the prefix until additional chunks arrive.
                return Err(TransportError::Timeout);
            };
            let matches_frame = valid_length(packet)
                && packet[0] as usize == index
                && packet[1] as usize == total
                && (index + 1 == total || packet.len() == self.mtu)
                && (total == 1 || packet.len() > 2);
            if !matches_frame {
                // Preserve the start of a following frame when a chunk was lost.
                let next_start = index > 0
                    && valid_length(packet)
                    && packet[0] == 0
                    && (1..=250).contains(&packet[1]);
                self.rx_queue.drain(..index + usize::from(!next_start));
                return Err(TransportError::FramingError(
                    "Invalid BLE chunk sequence or size".into(),
                ));
            }
            payload_len += packet.len() - 2;
            if payload_len > MAX_FRAME_BYTES {
                self.rx_queue.drain(..=index);
                return Err(TransportError::FramingError(
                    "BLE payload exceeds frame limit".into(),
                ));
            }
        }

        Ok(self
            .rx_queue
            .drain(..total)
            .flat_map(|packet| packet.into_iter().skip(2))
            .collect())
    }
}

// ----------------- 3. Hybrid Transport (QR Bootstrap + BLE Stream) -----------------

pub struct HybridBootstrapQr {
    pub ble_service_uuid: [u8; 16],
    pub offer_payload_b64: String,
}

impl HybridBootstrapQr {
    pub fn encode(&self) -> String {
        use base64::Engine;
        let uuid_b64 = base64::engine::general_purpose::STANDARD.encode(self.ble_service_uuid);
        format!("mesh:hybrid:{}:{}", uuid_b64, self.offer_payload_b64)
    }

    pub fn decode(uri: &str) -> Result<Self, TransportError> {
        use base64::Engine;
        let prefix = "mesh:hybrid:";
        let rest = uri
            .strip_prefix(prefix)
            .ok_or_else(|| TransportError::FramingError("Missing hybrid URI prefix".into()))?;
        let parts: Vec<&str> = rest.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(TransportError::FramingError(
                "Invalid hybrid URI parts".into(),
            ));
        }
        let uuid_bytes = base64::engine::general_purpose::STANDARD
            .decode(parts[0])
            .map_err(|e| TransportError::FramingError(format!("Bad UUID base64: {}", e)))?;
        let mut uuid = [0u8; 16];
        if uuid_bytes.len() != 16 {
            return Err(TransportError::FramingError("UUID must be 16 bytes".into()));
        }
        uuid.copy_from_slice(&uuid_bytes);
        Ok(HybridBootstrapQr {
            ble_service_uuid: uuid,
            offer_payload_b64: parts[1].to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ble_mtu_fragmentation_and_reassembly() {
        // Standard BLE ATT MTU default: 20 bytes data payload
        let (mut a, mut b) = BleTransport::create_pair_with_mtu(DEFAULT_BLE_ATT_PAYLOAD_MTU);

        // A 281-byte payload (matching EncounterResponseV1 wire frame)
        let sample_payload: Vec<u8> = (0..281).map(|i| (i * 17 % 256) as u8).collect();
        a.send(&sample_payload).unwrap();

        // Must be chunked into ceil(281 / 18) = 16 packets of size <= 20
        assert_eq!(a.tx_queue.len(), 16);
        for packet in &a.tx_queue {
            assert!(packet.len() <= DEFAULT_BLE_ATT_PAYLOAD_MTU);
        }

        // Pump packets across simulated BLE connection
        BleTransport::pump(&mut a, &mut b).unwrap();
        assert_eq!(b.rx_queue.len(), 16);

        // Reassembly on receiver
        let reassembled = b.receive().unwrap();
        assert_eq!(reassembled, sample_payload);
    }

    #[test]
    fn test_ble_chunk_tamper_rejected() {
        let (mut a, mut b) = BleTransport::create_pair_with_mtu(20);
        let sample_payload = vec![42u8; 100];
        a.send(&sample_payload).unwrap();

        BleTransport::pump(&mut a, &mut b).unwrap();

        // Corrupt chunk order in rx_queue
        b.rx_queue.swap(1, 2);
        assert!(matches!(b.receive(), Err(TransportError::FramingError(_))));
    }

    #[test]
    fn frame_byte_limit_applies_after_reassembly_and_in_raw_mode() {
        let (mut a, mut b) = BleTransport::create_pair_with_mtu(20);
        let frame = vec![42; MAX_FRAME_BYTES];
        a.send(&frame).unwrap();
        BleTransport::pump(&mut a, &mut b).unwrap();
        assert_eq!(b.receive(), Ok(frame));

        let total = MAX_FRAME_BYTES.div_ceil(18) as u8;
        for index in 0..total {
            let mut packet = [42; 20];
            packet[..2].copy_from_slice(&[index, total]);
            b.enqueue_rx(&packet).unwrap();
        }
        assert!(matches!(b.receive(), Err(TransportError::FramingError(_))));
        assert!(b.rx_queue.is_empty());

        let (mut raw, _) = BleTransport::create_pair();
        let oversized = vec![0; MAX_FRAME_BYTES + 1];
        assert!(raw.enqueue_rx(&oversized).is_err());
        assert!(raw.send(&oversized).is_err());
        assert!(a.send(&oversized).is_err());
    }

    #[test]
    fn receive_queue_backpressure_preserves_unsent_packets() {
        let (mut a, mut b) = BleTransport::create_pair();
        a.send(b"first").unwrap();
        a.send(b"second").unwrap();
        assert_eq!(
            BleTransport::pump(&mut a, &mut b),
            Err(TransportError::ReceiveQueueFull)
        );
        assert_eq!(b.receive().unwrap(), b"first");
        BleTransport::pump(&mut a, &mut b).unwrap();
        assert_eq!(b.receive().unwrap(), b"second");
    }

    #[test]
    fn oversized_declared_frame_is_rejected_without_buffering() {
        let (mut a, mut b) = BleTransport::create_pair_with_mtu(20);
        a.rx_queue.push_back(vec![0, 250, 1, 2, 3]);
        assert!(matches!(a.receive(), Err(TransportError::FramingError(_))));
        assert!(a.rx_queue.is_empty());
        let _ = &mut b;
    }

    #[test]
    fn short_and_header_lookalike_payloads_roundtrip() {
        // Regression: [0, 1, ...] used to be mistaken for a one-chunk header and stripped.
        let (mut a, mut b) = BleTransport::create_pair_with_mtu(20);
        let msgs: Vec<Vec<u8>> = vec![
            vec![0, 1, 9, 9],
            vec![7, 5, 9, 9],
            vec![1, 2, 3],
            vec![],
            vec![42; 18],
            vec![42; 19],
        ];
        for m in &msgs {
            a.send(m).unwrap();
        }
        BleTransport::pump(&mut a, &mut b).unwrap();
        for m in &msgs {
            assert_eq!(&b.receive().unwrap(), m);
        }
        assert_eq!(b.receive(), Err(TransportError::ChannelClosed));
    }

    #[test]
    fn partial_delivery_can_resume() {
        let (mut a, mut b) = BleTransport::create_pair_with_mtu(20);
        let payload = vec![42; 30];
        a.send(&payload).unwrap();
        b.rx_queue.push_back(a.tx_queue.pop_front().unwrap());
        assert_eq!(b.receive(), Err(TransportError::Timeout));
        BleTransport::pump(&mut a, &mut b).unwrap();
        assert_eq!(b.receive(), Ok(payload));
    }

    #[test]
    fn stalled_partial_frame_can_be_reset() {
        let (mut a, mut b) = BleTransport::create_pair_with_mtu(20);
        a.send(&[42; 30]).unwrap();
        // Only deliver first chunk:
        b.rx_queue.push_back(a.tx_queue.pop_front().unwrap());
        assert_eq!(b.receive(), Err(TransportError::Timeout));
        b.reset_rx();
        assert_eq!(b.receive(), Err(TransportError::ChannelClosed));
    }

    #[test]
    fn lost_chunk_does_not_consume_following_frame() {
        let (mut a, mut b) = BleTransport::create_pair_with_mtu(20);
        a.send(&[42; 30]).unwrap();
        a.tx_queue.pop_back();
        a.send(&[7; 21]).unwrap();
        BleTransport::pump(&mut a, &mut b).unwrap();
        assert!(matches!(b.receive(), Err(TransportError::FramingError(_))));
        assert_eq!(b.receive(), Ok(vec![7; 21]));
    }

    #[test]
    fn oversized_chunk_is_rejected() {
        let (_, mut b) = BleTransport::create_pair_with_mtu(20);
        b.rx_queue
            .push_back(vec![0, 2].into_iter().chain([42; 18]).collect());
        b.rx_queue
            .push_back(vec![1, 2].into_iter().chain([42; 19]).collect());
        assert!(matches!(b.receive(), Err(TransportError::FramingError(_))));
        assert!(b.rx_queue.is_empty());
    }

    #[test]
    fn test_hybrid_qr_bootstrap_roundtrip() {
        let uuid = [0x55; 16];
        let original = HybridBootstrapQr {
            ble_service_uuid: uuid,
            offer_payload_b64: "c29tZV9vZmZlcl9kYXRh".to_string(),
        };
        let uri = original.encode();
        assert!(uri.starts_with("mesh:hybrid:"));
        let decoded = HybridBootstrapQr::decode(&uri).unwrap();
        assert_eq!(decoded.ble_service_uuid, uuid);
        assert_eq!(decoded.offer_payload_b64, "c29tZV9vZmZlcl9kYXRh");
    }

    #[test]
    fn test_qr_transport_render_and_error_display() {
        let qr_ascii = QrTransport::render_ascii_qr("test payload");
        assert!(qr_ascii.contains("test payload"));

        let mut qr = QrTransport::new();
        qr.scan_from_peer("invalid_scheme");
        assert!(matches!(qr.receive(), Err(TransportError::FramingError(_))));

        let err = TransportError::FramingError("test".into());
        assert_eq!(format!("{}", err), "FramingError(\"test\")");
    }
}
