//! Passive WebSocket-over-HTTP/1.1 decoder. I/O-free: bytes are handed in by
//! `proxy.rs`, timestamps + file writes are done by `dump.rs`. Obeys
//! parse-or-skip — on any unparseable input the connection becomes
//! `Undecodable` and no further messages are emitted.

pub mod frame;
pub mod handshake;
pub mod tap;

pub use tap::WsTap;

/// The two WebSocket data message types we emit (RFC 6455 opcodes 0x1 / 0x2).
/// Control frames (ping/pong/close) are handled internally, never emitted here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    Text,
    Binary,
}

/// One fully-reassembled, decompressed application message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsMessage {
    pub from_client: bool,
    pub opcode: Opcode,
    /// Decoded (post-inflate) payload. Always raw bytes; text vs base64 encoding
    /// is decided at dump time.
    pub payload: Vec<u8>,
}

/// Terminal per-connection WebSocket status; maps 1:1 to the index.jsonl fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsKind {
    None,
    Decoded,
    Undecodable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsStatus {
    pub kind: WsKind,
    pub permessage_deflate: bool,
    pub message_count: u64,
    pub close_code: Option<u16>,
    pub close_reason: Option<String>,
    pub undecodable_reason: Option<&'static str>,
}

impl WsStatus {
    /// Status for a connection that is not a WebSocket (or decoding disabled).
    pub fn none() -> WsStatus {
        WsStatus {
            kind: WsKind::None,
            permessage_deflate: false,
            message_count: 0,
            close_code: None,
            close_reason: None,
            undecodable_reason: None,
        }
    }

    /// Lowercase string for the index `ws` field.
    pub fn kind_str(&self) -> &'static str {
        match self.kind {
            WsKind::None => "none",
            WsKind::Decoded => "decoded",
            WsKind::Undecodable => "undecodable",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_status_none_maps_to_none_string() {
        let s = WsStatus::none();
        assert_eq!(s.kind_str(), "none");
        assert_eq!(s.message_count, 0);
        assert!(!s.permessage_deflate);
    }

    #[test]
    fn ws_message_holds_raw_bytes() {
        let m = WsMessage { from_client: true, opcode: Opcode::Binary, payload: vec![0, 159, 146, 150] };
        assert_eq!(m.opcode, Opcode::Binary);
        assert_eq!(m.payload.len(), 4);
    }
}
