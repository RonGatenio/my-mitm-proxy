//! Per-connection WebSocket decode state machine. I/O-free: `proxy.rs` feeds
//! observed bytes via `on_client_bytes` / `on_server_bytes` and drains completed
//! `WsMessage`s from `out`; `finalize` returns the terminal `WsStatus`. Parse-or-
//! skip: on any unparseable input the tap becomes `Undecodable` and stops.

use flate2::{Decompress, FlushDecompress, Status};

use super::{Opcode, WsKind, WsMessage, WsStatus};
use crate::ws::frame::{parse_frame, Frame, FrameError};
use crate::ws::handshake::{scan_request, scan_response, Negotiation, RequestScan, ResponseScan};

/// Cap on accumulated, not-yet-transitioned-to-framing handshake bytes per
/// direction. v1 limitation: this counts raw header bytes PLUS any framing
/// bytes an optimistic peer bundles into the same read(s) — e.g. a client that
/// pipelines a large first WS frame before waiting for the server's 101. Such
/// pipelining can trip this cap before the handshake itself completes, which
/// is (fail-safe) reported as `handshake-too-large` rather than decoded.
const MAX_HANDSHAKE: usize = 64 * 1024;
const MAX_MESSAGE: usize = 64 * 1024 * 1024;

enum State {
    Handshake,
    Framing,
    Closed,
    NotWebSocket,
    Undecodable(&'static str),
}

/// Per-direction framing state.
struct DirState {
    buf: Vec<u8>,
    frag_opcode: Option<u8>, // 0x1 or 0x2 while a fragmented message is open
    frag_payload: Vec<u8>,
    frag_compressed: bool,
    inflater: Option<Decompress>, // lazily created; persists for context takeover
}

impl DirState {
    fn new() -> DirState {
        DirState {
            buf: Vec::new(),
            frag_opcode: None,
            frag_payload: Vec::new(),
            frag_compressed: false,
            inflater: None,
        }
    }
}

pub struct WsTap {
    state: State,
    // handshake accumulation
    c2s_hs: Vec<u8>,
    s2c_hs: Vec<u8>,
    req_consumed: Option<usize>,
    resp_consumed: Option<usize>,
    req_ok: bool,
    // framing
    neg: Negotiation,
    c2s: DirState,
    s2c: DirState,
    message_count: u64,
    close_code: Option<u16>,
    close_reason: Option<String>,
}

impl WsTap {
    pub fn new() -> WsTap {
        WsTap {
            state: State::Handshake,
            c2s_hs: Vec::new(),
            s2c_hs: Vec::new(),
            req_consumed: None,
            resp_consumed: None,
            req_ok: false,
            neg: Negotiation::default(),
            c2s: DirState::new(),
            s2c: DirState::new(),
            message_count: 0,
            close_code: None,
            close_reason: None,
        }
    }

    pub fn on_client_bytes(&mut self, data: &[u8], out: &mut Vec<WsMessage>) {
        self.feed(true, data, out);
    }

    pub fn on_server_bytes(&mut self, data: &[u8], out: &mut Vec<WsMessage>) {
        self.feed(false, data, out);
    }

    fn bail(&mut self, reason: &'static str) {
        self.state = State::Undecodable(reason);
    }

    fn feed(&mut self, from_client: bool, data: &[u8], out: &mut Vec<WsMessage>) {
        match self.state {
            State::Handshake => {
                self.feed_handshake(from_client, data, out);
            }
            State::Framing => {
                self.feed_framing(from_client, data, out);
            }
            // Terminal states ignore further bytes.
            State::Closed | State::NotWebSocket | State::Undecodable(_) => {}
        }
    }

    fn feed_handshake(&mut self, from_client: bool, data: &[u8], out: &mut Vec<WsMessage>) {
        {
            let hs = if from_client { &mut self.c2s_hs } else { &mut self.s2c_hs };
            hs.extend_from_slice(data);
            if hs.len() > MAX_HANDSHAKE {
                return self.bail("handshake-too-large");
            }
        }

        if from_client && self.req_consumed.is_none() {
            match scan_request(&self.c2s_hs) {
                RequestScan::NeedMore => {}
                RequestScan::NotWebSocket => {
                    self.state = State::NotWebSocket;
                    return;
                }
                RequestScan::Upgrade { consumed } => {
                    self.req_consumed = Some(consumed);
                    self.req_ok = true;
                }
            }
        } else if !from_client && self.resp_consumed.is_none() {
            match scan_response(&self.s2c_hs) {
                ResponseScan::NeedMore => {}
                ResponseScan::NotWebSocket => {
                    self.state = State::NotWebSocket;
                    return;
                }
                ResponseScan::Accepted { consumed, neg } => {
                    self.resp_consumed = Some(consumed);
                    self.neg = neg;
                }
            }
        }

        // Transition once both sides confirmed the upgrade.
        if self.req_ok {
            if let (Some(rc), Some(sc)) = (self.req_consumed, self.resp_consumed) {
                if self.neg.unsupported_extension {
                    return self.bail("unsupported-extension");
                }
                // Move post-handshake tails into the framing buffers, then parse.
                self.c2s.buf = self.c2s_hs.split_off(rc);
                self.s2c.buf = self.s2c_hs.split_off(sc);
                self.state = State::Framing;
                self.parse_dir(true, out);
                if matches!(self.state, State::Framing) {
                    self.parse_dir(false, out);
                }
            }
        }
    }

    fn feed_framing(&mut self, from_client: bool, data: &[u8], out: &mut Vec<WsMessage>) {
        let dir = if from_client { &mut self.c2s } else { &mut self.s2c };
        dir.buf.extend_from_slice(data);
        self.parse_dir(from_client, out);
    }

    fn parse_dir(&mut self, from_client: bool, out: &mut Vec<WsMessage>) {
        // Bound the accumulated unparsed buffer (a single huge frame can't grow past the cap).
        {
            let dir = if from_client { &self.c2s } else { &self.s2c };
            if dir.buf.len() > MAX_MESSAGE {
                return self.bail("oversize");
            }
        }
        // Parse every whole frame currently buffered, advancing a cursor instead of
        // draining per frame (per-frame prefix drains are O(n^2) over a multi-frame buffer).
        let mut cursor = 0usize;
        loop {
            let parsed = {
                let dir = if from_client { &self.c2s } else { &self.s2c };
                parse_frame(&dir.buf[cursor..])
            };
            match parsed {
                Ok(None) => break,
                Err(e) => {
                    return self.bail(match e {
                        FrameError::ReservedOpcode => "reserved-opcode",
                        FrameError::ReservedBits => "reserved-bits",
                        FrameError::BadControlFrame => "bad-control-frame",
                    });
                }
                Ok(Some((frame, consumed))) => {
                    cursor += consumed;
                    self.handle_frame(from_client, frame, out);
                    if !matches!(self.state, State::Framing) {
                        return; // terminal (bail/close): remaining buffer is irrelevant
                    }
                }
            }
        }
        // Drop the fully-parsed frames once; keep any partial remainder for the next feed.
        let dir = if from_client { &mut self.c2s } else { &mut self.s2c };
        dir.buf.drain(0..cursor);
    }

    fn handle_frame(&mut self, from_client: bool, frame: Frame, out: &mut Vec<WsMessage>) {
        // Control frames (0x8-0xA).
        if frame.opcode & 0x08 != 0 {
            match frame.opcode {
                // v1 limitation: decoding stops at the FIRST Close frame seen in
                // EITHER direction — `state` becomes `Closed` here and no further
                // frames from either side are parsed/emitted. The raw `.c2s`/`.s2c`
                // dumps are independent of tap state and remain complete regardless.
                0x8 => {
                    if frame.payload.len() >= 2 {
                        self.close_code = Some(u16::from_be_bytes([frame.payload[0], frame.payload[1]]));
                        if frame.payload.len() > 2 {
                            self.close_reason =
                                Some(String::from_utf8_lossy(&frame.payload[2..]).into_owned());
                        }
                    }
                    self.state = State::Closed;
                }
                _ => {} // ping / pong: parsed to advance the stream, not emitted
            }
            return;
        }

        // Data frames (0x0 continuation, 0x1 text, 0x2 binary).
        let dir = if from_client { &mut self.c2s } else { &mut self.s2c };
        let is_start = frame.opcode == 0x1 || frame.opcode == 0x2;
        if is_start {
            if dir.frag_opcode.is_some() {
                return self.bail("bad-frame"); // new data frame mid-fragmentation
            }
            if frame.rsv1 {
                if !self.neg.permessage_deflate {
                    return self.bail("rsv1-without-deflate");
                }
                dir.frag_compressed = true;
            } else {
                dir.frag_compressed = false;
            }
            dir.frag_opcode = Some(frame.opcode);
            dir.frag_payload = frame.payload;
        } else {
            // continuation
            if dir.frag_opcode.is_none() {
                return self.bail("bad-frame"); // continuation without a start
            }
            if frame.rsv1 {
                return self.bail("bad-frame"); // RSV1 (RFC 7692 §7.2.3.1) is first-frame-only
            }
            dir.frag_payload.extend_from_slice(&frame.payload);
        }

        if dir.frag_payload.len() > MAX_MESSAGE {
            return self.bail("oversize");
        }

        if frame.fin {
            self.complete_message(from_client, out);
        }
    }

    /// Finish the in-progress message for a direction, inflating it first if it
    /// was sent with permessage-deflate (RSV1 on the first frame).
    fn complete_message(&mut self, from_client: bool, out: &mut Vec<WsMessage>) {
        let no_ctx = if from_client {
            self.neg.client_no_context_takeover
        } else {
            self.neg.server_no_context_takeover
        };
        let dir = if from_client { &mut self.c2s } else { &mut self.s2c };
        let opcode_raw = dir.frag_opcode.take().unwrap();
        let compressed = dir.frag_compressed;
        let raw = std::mem::take(&mut dir.frag_payload);
        dir.frag_compressed = false;

        let payload = if compressed {
            if dir.inflater.is_none() {
                dir.inflater = Some(Decompress::new(false)); // raw deflate
            }
            let dec = dir.inflater.as_mut().unwrap();
            match inflate_message(dec, &raw, MAX_MESSAGE) {
                Ok(p) => {
                    if no_ctx {
                        dec.reset(false);
                    }
                    p
                }
                Err(reason) => return self.bail(reason),
            }
        } else {
            raw
        };

        let opcode = if opcode_raw == 0x1 { Opcode::Text } else { Opcode::Binary };
        out.push(WsMessage { from_client, opcode, payload });
        self.message_count += 1;
    }

    pub fn finalize(self) -> WsStatus {
        let (kind, reason) = match self.state {
            State::Framing | State::Closed => (WsKind::Decoded, None),
            State::NotWebSocket | State::Handshake => (WsKind::None, None),
            State::Undecodable(r) => (WsKind::Undecodable, Some(r)),
        };
        WsStatus {
            kind,
            permessage_deflate: self.neg.permessage_deflate,
            message_count: self.message_count,
            close_code: self.close_code,
            close_reason: self.close_reason,
            undecodable_reason: reason,
        }
    }
}

/// Inflate one permessage-deflate message. `compressed` is the reassembled
/// payload WITHOUT the sync trailer, which we append here (RFC 7692 §7.2.2).
/// `dec` persists across calls so the LZ77 window carries over (context
/// takeover). Returns `Err("oversize")` / `Err("inflate-error")` per parse-or-skip.
fn inflate_message(
    dec: &mut Decompress,
    compressed: &[u8],
    cap: usize,
) -> Result<Vec<u8>, &'static str> {
    let mut input = Vec::with_capacity(compressed.len() + 4);
    input.extend_from_slice(compressed);
    input.extend_from_slice(&[0x00, 0x00, 0xFF, 0xFF]);

    let mut out = Vec::new();
    let mut in_off = 0usize;
    loop {
        let in_before = dec.total_in();
        let out_before = dec.total_out();
        out.reserve(8192); // decompress_vec fills spare capacity; it never grows the Vec
        let status = dec
            .decompress_vec(&input[in_off..], &mut out, FlushDecompress::Sync)
            .map_err(|_| "inflate-error")?;
        let consumed = (dec.total_in() - in_before) as usize;
        let produced = (dec.total_out() - out_before) as usize;
        in_off += consumed;

        if out.len() > cap {
            return Err("oversize");
        }
        if status == Status::StreamEnd { break; }
        if produced == 0 && consumed == 0 { break; }   // no progress: done, or stuck — either way stop
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ws::Opcode;
    use flate2::{Compress, Compression, FlushCompress, Status as CStatus};

    /// Compress `data` as one permessage-deflate message, stripping the trailing
    /// 0x00 0x00 0xFF 0xFF sync marker (as a WS sender does). `comp` persists for
    /// context takeover.
    fn deflate_message(comp: &mut Compress, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut in_off = 0usize;
        loop {
            let in_before = comp.total_in();
            let out_before = comp.total_out();
            out.reserve(8192);
            let status = comp
                .compress_vec(&data[in_off..], &mut out, FlushCompress::Sync)
                .unwrap();
            in_off += (comp.total_in() - in_before) as usize;
            let produced = (comp.total_out() - out_before) as usize;
            // NOTE: deviates from the brief's literal `in_off >= data.len() && produced == 0`.
            // Empirically (flate2 1.1.9 / miniz_oxide 0.8.9), once all input is consumed, a
            // Sync-flush `compress_vec` call with an empty remaining slice keeps returning
            // `Status::Ok` with a fresh nonzero `produced` (a new empty sync block) forever —
            // `produced` never reaches 0, so the brief's condition never fires and the loop
            // never terminates. All three test messages here fully flush (all input consumed
            // AND the complete compressed output, including the trailing sync marker, written)
            // within the single call that first reaches `in_off >= data.len()`, so breaking
            // there — without waiting for `produced == 0` — is correct and terminates.
            if in_off >= data.len() {
                break;
            }
            if produced == 0 && status == CStatus::Ok {
                break;
            }
        }
        if out.ends_with(&[0x00, 0x00, 0xFF, 0xFF]) {
            out.truncate(out.len() - 4);
        }
        out
    }

    const RESP_DEFLATE: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
        Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n";

    fn handshaken_deflate() -> WsTap {
        let mut t = WsTap::new();
        let mut out = Vec::new();
        t.on_client_bytes(REQ, &mut out);
        t.on_server_bytes(RESP_DEFLATE, &mut out);
        t
    }

    #[test]
    fn inflates_server_text_with_context_takeover() {
        let mut t = handshaken_deflate();
        let mut comp = Compress::new(Compression::default(), false); // raw deflate
        let mut out = Vec::new();

        let c1 = deflate_message(&mut comp, b"first message");
        t.on_server_bytes(&frame(true, 0x1, true, None, &c1), &mut out);
        assert_eq!(out[0].payload, b"first message");

        // second message relies on the retained LZ77 window (context takeover)
        let c2 = deflate_message(&mut comp, b"first message again");
        t.on_server_bytes(&frame(true, 0x1, true, None, &c2), &mut out);
        assert_eq!(out[1].payload, b"first message again");
    }

    #[test]
    fn inflates_client_binary() {
        let mut t = handshaken_deflate();
        let mut comp = Compress::new(Compression::default(), false);
        let mut out = Vec::new();
        let data = vec![7u8; 5000];
        let c = deflate_message(&mut comp, &data);
        t.on_client_bytes(&frame(true, 0x2, true, Some([4, 3, 2, 1]), &c), &mut out);
        assert_eq!(out[0].opcode, Opcode::Binary);
        assert_eq!(out[0].payload, data);
    }

    #[test]
    fn uncompressed_frame_still_works_when_deflate_negotiated() {
        let mut t = handshaken_deflate();
        let mut out = Vec::new();
        // rsv1=false -> not compressed even though deflate negotiated
        t.on_server_bytes(&frame(true, 0x1, false, None, b"plain"), &mut out);
        assert_eq!(out[0].payload, b"plain");
    }

    #[test]
    fn inflate_message_oversize_is_err() {
        // A payload that easily inflates past a tiny cap must be rejected, not
        // truncated or allowed to grow the output Vec without bound.
        let mut comp = Compress::new(Compression::default(), false);
        let mut dec = Decompress::new(false);
        let data = vec![b'z'; 5000];
        let compressed = deflate_message(&mut comp, &data);
        assert_eq!(inflate_message(&mut dec, &compressed, 16), Err("oversize"));
    }

    #[test]
    fn inflate_message_invalid_deflate_is_err() {
        // Clearly-invalid raw-deflate bytes (first block header has the reserved
        // BTYPE=3) must surface as "inflate-error", not panic or hang. If the
        // no-progress guard in `inflate_message` regressed, this would hang
        // instead of returning.
        let mut dec = Decompress::new(false);
        let garbage = vec![0xFFu8; 32];
        assert_eq!(inflate_message(&mut dec, &garbage, MAX_MESSAGE), Err("inflate-error"));
    }

    #[test]
    fn rsv1_on_continuation_is_undecodable() {
        // RFC 7692 §7.2.3.1: RSV1 is set only on the first frame of a message; a
        // continuation frame with RSV1 set is malformed fragmentation.
        let mut t = handshaken_deflate();
        let mut out = Vec::new();
        t.on_server_bytes(&frame(false, 0x1, true, None, b"AAAA"), &mut out);
        assert!(out.is_empty(), "message not complete until FIN");
        t.on_server_bytes(&frame(true, 0x0, true, None, b"BBBB"), &mut out);
        let s = t.finalize();
        assert_eq!(s.kind, WsKind::Undecodable);
        assert_eq!(s.undecodable_reason, Some("bad-frame"));
    }

    fn frame(fin: bool, opcode: u8, rsv1: bool, mask: Option<[u8; 4]>, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        let b0 = (if fin { 0x80 } else { 0 }) | (if rsv1 { 0x40 } else { 0 }) | (opcode & 0x0F);
        v.push(b0);
        let mask_bit = if mask.is_some() { 0x80 } else { 0 };
        let len = payload.len();
        if len < 126 {
            v.push(mask_bit | len as u8);
        } else if len <= 0xFFFF {
            v.push(mask_bit | 126);
            v.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            v.push(mask_bit | 127);
            v.extend_from_slice(&(len as u64).to_be_bytes());
        }
        match mask {
            Some(key) => {
                v.extend_from_slice(&key);
                for (i, b) in payload.iter().enumerate() {
                    v.push(b ^ key[i % 4]);
                }
            }
            None => v.extend_from_slice(payload),
        }
        v
    }

    const REQ: &[u8] = b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
    const RESP: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";

    /// Drive a full handshake, returns a tap in Framing state.
    fn handshaken() -> WsTap {
        let mut t = WsTap::new();
        let mut out = Vec::new();
        t.on_client_bytes(REQ, &mut out);
        t.on_server_bytes(RESP, &mut out);
        assert!(out.is_empty());
        t
    }

    #[test]
    fn plain_http_response_is_none() {
        let mut t = WsTap::new();
        let mut out = Vec::new();
        t.on_client_bytes(b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n", &mut out);
        t.on_server_bytes(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi", &mut out);
        let s = t.finalize();
        assert_eq!(s.kind, WsKind::None);
        assert!(out.is_empty());
    }

    #[test]
    fn decodes_masked_client_text() {
        let mut t = handshaken();
        let mut out = Vec::new();
        t.on_client_bytes(&frame(true, 0x1, false, Some([1, 2, 3, 4]), b"hi client"), &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].from_client, true);
        assert_eq!(out[0].opcode, Opcode::Text);
        assert_eq!(out[0].payload, b"hi client");
    }

    #[test]
    fn decodes_server_binary_and_reassembles_fragments() {
        let mut t = handshaken();
        let mut out = Vec::new();
        // fragmented binary: first (fin=0, binary) + continuation (fin=1)
        t.on_server_bytes(&frame(false, 0x2, false, None, b"AAAA"), &mut out);
        assert!(out.is_empty(), "message not complete until FIN");
        t.on_server_bytes(&frame(true, 0x0, false, None, b"BBBB"), &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].opcode, Opcode::Binary);
        assert_eq!(out[0].payload, b"AAAABBBB");
    }

    #[test]
    fn ping_between_fragments_is_ignored() {
        let mut t = handshaken();
        let mut out = Vec::new();
        t.on_server_bytes(&frame(false, 0x1, false, None, b"AA"), &mut out);
        t.on_server_bytes(&frame(true, 0x9, false, None, b"pingpayload"[..5].as_ref()), &mut out); // ping
        t.on_server_bytes(&frame(true, 0x0, false, None, b"BB"), &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].payload, b"AABB");
    }

    #[test]
    fn close_records_code_and_reason() {
        let mut t = handshaken();
        let mut out = Vec::new();
        let mut payload = vec![0x03, 0xE8]; // 1000
        payload.extend_from_slice(b"bye");
        t.on_client_bytes(&frame(true, 0x8, false, Some([9, 9, 9, 9]), &payload), &mut out);
        let s = t.finalize();
        assert_eq!(s.kind, WsKind::Decoded);
        assert_eq!(s.close_code, Some(1000));
        assert_eq!(s.close_reason.as_deref(), Some("bye"));
    }

    #[test]
    fn invalid_frame_is_undecodable() {
        let mut t = handshaken();
        let mut out = Vec::new();
        // reserved opcode 0x3
        t.on_client_bytes(&frame(true, 0x3, false, Some([1, 2, 3, 4]), b"x"), &mut out);
        let s = t.finalize();
        assert_eq!(s.kind, WsKind::Undecodable);
        assert_eq!(s.undecodable_reason, Some("reserved-opcode"));
    }

    #[test]
    fn rsv1_without_deflate_is_undecodable() {
        let mut t = handshaken(); // handshake did NOT negotiate deflate
        let mut out = Vec::new();
        t.on_server_bytes(&frame(true, 0x2, true, None, b"z"), &mut out);
        let s = t.finalize();
        assert_eq!(s.kind, WsKind::Undecodable);
        assert_eq!(s.undecodable_reason, Some("rsv1-without-deflate"));
    }

    #[test]
    fn handshake_header_cap_is_undecodable() {
        let mut t = WsTap::new();
        let mut out = Vec::new();
        let huge = vec![b'a'; 70 * 1024]; // > 64 KiB, no CRLFCRLF
        t.on_client_bytes(&huge, &mut out);
        let s = t.finalize();
        assert_eq!(s.kind, WsKind::Undecodable);
        assert_eq!(s.undecodable_reason, Some("handshake-too-large"));
    }

    #[test]
    fn message_count_and_ordering() {
        let mut t = handshaken();
        let mut out = Vec::new();
        t.on_client_bytes(&frame(true, 0x1, false, Some([1, 2, 3, 4]), b"c1"), &mut out);
        t.on_server_bytes(&frame(true, 0x1, false, None, b"s1"), &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].from_client, true);
        assert_eq!(out[1].from_client, false);
        let s = t.finalize();
        assert_eq!(s.message_count, 2);
    }

    #[test]
    fn many_frames_in_one_call_decode_in_order() {
        // Exercises the cursor path: 1000 frames delivered in a single call must all
        // decode, in order. This guards ordering/correctness of the cursor path
        // (not a performance regression — 1000 frames is too little data to detect
        // an O(n^2) drain).
        let mut t = handshaken();
        let mut out = Vec::new();
        let mut buf = Vec::new();
        for i in 0..1000u32 {
            buf.extend_from_slice(&frame(true, 0x2, false, None, &i.to_be_bytes()));
        }
        t.on_server_bytes(&buf, &mut out);
        assert_eq!(out.len(), 1000);
        for (i, m) in out.iter().enumerate() {
            assert_eq!(m.opcode, Opcode::Binary);
            assert_eq!(m.payload, (i as u32).to_be_bytes().to_vec());
        }
    }

    #[test]
    fn client_flood_after_request_hits_handshake_cap() {
        // Client completes its upgrade request, then floods bytes before the server
        // responds — must be capped (Fix B), not grow unbounded.
        let mut t = WsTap::new();
        let mut out = Vec::new();
        t.on_client_bytes(REQ, &mut out);
        t.on_client_bytes(&vec![b'x'; 70 * 1024], &mut out);
        let s = t.finalize();
        assert_eq!(s.kind, WsKind::Undecodable);
        assert_eq!(s.undecodable_reason, Some("handshake-too-large"));
    }
}
