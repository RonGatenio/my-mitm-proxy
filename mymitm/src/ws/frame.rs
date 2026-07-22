//! Pure, passive WebSocket frame parser (RFC 6455 §5.2). No I/O, no state.
//! Observes both directions, so it honors the MASK bit as-is (client frames are
//! masked, server frames are not) rather than enforcing an endpoint role.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub fin: bool,
    pub rsv1: bool,
    /// Raw 4-bit opcode: 0x0 continuation, 0x1 text, 0x2 binary, 0x8 close,
    /// 0x9 ping, 0xA pong.
    pub opcode: u8,
    /// Payload, already unmasked if the frame's MASK bit was set.
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    ReservedOpcode,
    ReservedBits,
    BadControlFrame,
}

/// Parse one frame from the front of `buf`.
/// - `Ok(None)`: `buf` does not yet hold a complete frame; caller must append more.
/// - `Ok(Some((frame, n)))`: a complete frame consuming `n` bytes.
/// - `Err(_)`: an unrecoverable protocol violation (caller marks undecodable).
pub fn parse_frame(buf: &[u8]) -> Result<Option<(Frame, usize)>, FrameError> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let b0 = buf[0];
    let fin = b0 & 0x80 != 0;
    let rsv1 = b0 & 0x40 != 0;
    let rsv2 = b0 & 0x20 != 0;
    let rsv3 = b0 & 0x10 != 0;
    let opcode = b0 & 0x0F;

    if rsv2 || rsv3 {
        return Err(FrameError::ReservedBits);
    }
    // Reserved opcodes: 0x3-0x7 (data), 0xB-0xF (control).
    let is_control = opcode & 0x08 != 0;
    match opcode {
        0x0 | 0x1 | 0x2 | 0x8 | 0x9 | 0xA => {}
        _ => return Err(FrameError::ReservedOpcode),
    }

    let b1 = buf[1];
    let masked = b1 & 0x80 != 0;
    let len7 = (b1 & 0x7F) as usize;

    // Extended-length header size.
    let mut header = 2usize;
    let payload_len: usize = if len7 < 126 {
        len7
    } else if len7 == 126 {
        if buf.len() < header + 2 {
            return Ok(None);
        }
        let n = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        header += 2;
        n
    } else {
        if buf.len() < header + 8 {
            return Ok(None);
        }
        let n = u64::from_be_bytes([
            buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
        ]);
        header += 8;
        n as usize
    };

    // Control-frame rules (RFC 6455 §5.5): never fragmented, payload <= 125.
    if is_control && (!fin || payload_len > 125) {
        return Err(FrameError::BadControlFrame);
    }

    let mask_key_len = if masked { 4 } else { 0 };
    let overhead = header + mask_key_len; // small (<= 14), cannot overflow
    if buf.len() < overhead || payload_len > buf.len() - overhead {
        return Ok(None); // not all bytes buffered yet (also handles absurd lengths safely)
    }
    let total = overhead + payload_len; // safe: payload_len <= buf.len() - overhead

    let mut payload = buf[overhead..total].to_vec();
    if masked {
        let key = &buf[header..header + 4];
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= key[i % 4];
        }
    }

    Ok(Some((Frame { fin, rsv1, opcode, payload }, total)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a raw WS frame for tests. `mask` = Some(key) masks the payload.
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

    #[test]
    fn parses_unmasked_text() {
        let raw = frame(true, 0x1, false, None, b"hello");
        let (f, consumed) = parse_frame(&raw).unwrap().unwrap();
        assert!(f.fin);
        assert_eq!(f.opcode, 0x1);
        assert_eq!(f.payload, b"hello");
        assert_eq!(consumed, raw.len());
    }

    #[test]
    fn unmasks_client_frame() {
        let raw = frame(true, 0x1, false, Some([0x37, 0xfa, 0x21, 0x3d]), b"hello");
        let (f, _) = parse_frame(&raw).unwrap().unwrap();
        assert_eq!(f.payload, b"hello");
    }

    #[test]
    fn handles_16bit_length() {
        let big = vec![b'x'; 300];
        let raw = frame(true, 0x2, false, None, &big);
        let (f, consumed) = parse_frame(&raw).unwrap().unwrap();
        assert_eq!(f.payload.len(), 300);
        assert_eq!(consumed, raw.len());
    }

    #[test]
    fn partial_frame_needs_more() {
        let raw = frame(true, 0x1, false, None, b"hello world");
        assert!(parse_frame(&raw[..3]).unwrap().is_none());
        // header present but payload short
        assert!(parse_frame(&raw[..4]).unwrap().is_none());
    }

    #[test]
    fn rsv1_is_reported_not_error() {
        let raw = frame(true, 0x2, true, None, b"z");
        let (f, _) = parse_frame(&raw).unwrap().unwrap();
        assert!(f.rsv1);
    }

    #[test]
    fn reserved_bits_error() {
        let mut raw = frame(true, 0x1, false, None, b"z");
        raw[0] |= 0x20; // set RSV2
        assert_eq!(parse_frame(&raw), Err(FrameError::ReservedBits));
    }

    #[test]
    fn reserved_opcode_error() {
        let raw = frame(true, 0x3, false, None, b"z");
        assert_eq!(parse_frame(&raw), Err(FrameError::ReservedOpcode));
    }

    #[test]
    fn fragmented_control_frame_error() {
        let raw = frame(false, 0x9, false, None, b"z"); // ping with FIN=0
        assert_eq!(parse_frame(&raw), Err(FrameError::BadControlFrame));
    }

    #[test]
    fn oversized_control_frame_error() {
        let raw = frame(true, 0x8, false, None, &vec![0u8; 126]); // close >125
        assert_eq!(parse_frame(&raw), Err(FrameError::BadControlFrame));
    }

    #[test]
    fn two_frames_consume_only_first() {
        let mut raw = frame(true, 0x1, false, None, b"aa");
        raw.extend_from_slice(&frame(true, 0x1, false, None, b"bb"));
        let (f, consumed) = parse_frame(&raw).unwrap().unwrap();
        assert_eq!(f.payload, b"aa");
        let (f2, _) = parse_frame(&raw[consumed..]).unwrap().unwrap();
        assert_eq!(f2.payload, b"bb");
    }

    #[test]
    fn huge_extended_length_does_not_panic() {
        // 10-byte header: FIN=1, binary(0x2), unmasked, len7=127, length=u64::MAX, no payload.
        let mut raw = vec![0x82u8, 0x7F];
        raw.extend_from_slice(&u64::MAX.to_be_bytes());
        // Must NOT panic; u64::MAX bytes aren't buffered, so this is "need more".
        assert_eq!(parse_frame(&raw), Ok(None));
    }
}
