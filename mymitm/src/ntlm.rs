//! Detection of the NTLM CHALLENGE_MESSAGE (NTLMSSP Type 2) inside a decrypted
//! byte stream — e.g. the plaintext this proxy dumps from a Microsoft Remote
//! Desktop Gateway's HTTP authentication (`WWW-Authenticate: NTLM|Negotiate …`).
//!
//! The gateway authentication rides the *outer* client↔gateway TLS that this
//! proxy terminates, so the server challenge (nonce) and the gateway's
//! computer/domain names are recoverable — even though the tunneled RDP stream
//! stays independently (doubly) encrypted and opaque to us.
//!
//! Wire forms handled: raw NTLMSSP bytes, base64 (`NTLM <b64>`), and
//! SPNEGO-wrapped (`Negotiate <b64>`, with the NTLMSSP token embedded inside).
//!
//! Message layout per [MS-NLMP] §2.2.1.2 (CHALLENGE_MESSAGE); the unit-test
//! vector uses the documented example values from [MS-NLMP] §4.2.
//!
//! NOTE: today this is exercised only by the unit tests below. Wiring the live
//! proxy dump path to log detections lands with the end-to-end (Hyper-V) RD
//! Gateway harness.
#![allow(dead_code)]

/// A parsed NTLM CHALLENGE_MESSAGE (NTLMSSP Type 2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NtlmChallenge {
    /// The 8-byte server challenge nonce.
    pub server_challenge: [u8; 8],
    /// The top-level TargetName field (server or domain name), if present.
    pub target_name: Option<String>,
    /// TargetInfo AV_PAIR MsvAvNbComputerName.
    pub nb_computer_name: Option<String>,
    /// TargetInfo AV_PAIR MsvAvNbDomainName.
    pub nb_domain_name: Option<String>,
    /// TargetInfo AV_PAIR MsvAvDnsComputerName.
    pub dns_computer_name: Option<String>,
    /// TargetInfo AV_PAIR MsvAvDnsDomainName.
    pub dns_domain_name: Option<String>,
}

const SIG: &[u8; 8] = b"NTLMSSP\0";

fn le_u16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn le_u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Decode a UTF-16LE byte slice (lossy; a trailing odd byte is ignored).
fn utf16le(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Read a `*_Fields` descriptor (Len `u16` @ `fields_off`, BufferOffset `u32`
/// @ `fields_off + 4`) and return the referenced payload as a UTF-16LE string,
/// if non-empty and in-bounds.
fn read_field_str(msg: &[u8], fields_off: usize) -> Option<String> {
    let len = le_u16(msg, fields_off) as usize;
    let off = le_u32(msg, fields_off + 4) as usize;
    if len == 0 {
        return None;
    }
    let end = off.checked_add(len)?;
    if end > msg.len() {
        return None;
    }
    Some(utf16le(&msg[off..end]))
}

/// Parse a CHALLENGE_MESSAGE from a slice that begins at the NTLMSSP signature.
/// Returns `None` if the slice is not a well-formed Type-2 message.
fn parse_challenge(msg: &[u8]) -> Option<NtlmChallenge> {
    // The fixed header runs through TargetInfoFields (0x28..0x30).
    if msg.len() < 48 || &msg[0..8] != SIG || le_u32(msg, 8) != 2 {
        return None;
    }

    let mut server_challenge = [0u8; 8];
    server_challenge.copy_from_slice(&msg[24..32]);

    let mut c = NtlmChallenge {
        server_challenge,
        target_name: read_field_str(msg, 12),
        ..Default::default()
    };

    // TargetInfo: Len `u16` @ 0x28, BufferOffset `u32` @ 0x2c.
    let ti_len = le_u16(msg, 40) as usize;
    let ti_off = le_u32(msg, 44) as usize;
    if ti_len > 0 {
        if let Some(end) = ti_off.checked_add(ti_len) {
            if end <= msg.len() {
                parse_av_pairs(&msg[ti_off..end], &mut c);
            }
        }
    }
    Some(c)
}

/// Walk the TargetInfo AV_PAIR list, filling in the name fields we care about.
fn parse_av_pairs(ti: &[u8], c: &mut NtlmChallenge) {
    let mut i = 0;
    while i + 4 <= ti.len() {
        let av_id = le_u16(ti, i);
        let av_len = le_u16(ti, i + 2) as usize;
        i += 4;
        if av_id == 0 {
            break; // MsvAvEOL
        }
        if i + av_len > ti.len() {
            break;
        }
        let val = &ti[i..i + av_len];
        match av_id {
            1 => c.nb_computer_name = Some(utf16le(val)),
            2 => c.nb_domain_name = Some(utf16le(val)),
            3 => c.dns_computer_name = Some(utf16le(val)),
            4 => c.dns_domain_name = Some(utf16le(val)),
            _ => {}
        }
        i += av_len;
    }
}

/// Find a CHALLENGE_MESSAGE at any offset where the raw NTLMSSP signature
/// appears in `buf` (also used to locate a signature embedded in a decoded
/// SPNEGO token).
fn scan_raw(buf: &[u8]) -> Option<NtlmChallenge> {
    if buf.len() < 8 {
        return None;
    }
    for i in 0..=buf.len() - 8 {
        if &buf[i..i + 8] == SIG {
            if let Some(c) = parse_challenge(&buf[i..]) {
                return Some(c);
            }
        }
    }
    None
}

fn is_b64(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'='
}

/// Case-insensitive ASCII substring search.
fn find_ci(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|&i| {
        hay[i..i + needle.len()]
            .iter()
            .zip(needle)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    })
}

/// Extract the base64 tokens that follow an `NTLM`/`Negotiate` auth-scheme
/// keyword (as seen in `Authorization:` / `WWW-Authenticate:` headers).
fn auth_base64_tokens(buf: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    for kw in [b"ntlm".as_slice(), b"negotiate".as_slice()] {
        let mut from = 0;
        while let Some(rel) = find_ci(&buf[from..], kw) {
            let mut i = from + rel + kw.len();
            while i < buf.len() && (buf[i] == b' ' || buf[i] == b'\t') {
                i += 1;
            }
            let start = i;
            while i < buf.len() && is_b64(buf[i]) {
                i += 1;
            }
            if i > start {
                out.push(&buf[start..i]);
            }
            from += rel + kw.len();
        }
    }
    out
}

/// Decode standard base64 (RFC 4648), skipping whitespace and stopping at
/// padding or the first non-alphabet byte.
fn base64_decode(s: &[u8]) -> Vec<u8> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in s {
        if c == b'=' {
            break;
        }
        if c.is_ascii_whitespace() {
            continue;
        }
        let Some(v) = val(c) else { break };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

/// Scan a decrypted byte stream for the first NTLM CHALLENGE_MESSAGE, looking
/// through raw bytes, base64 `NTLM` tokens, and SPNEGO `Negotiate` tokens.
pub fn detect_challenge(stream: &[u8]) -> Option<NtlmChallenge> {
    if let Some(c) = scan_raw(stream) {
        return Some(c);
    }
    for token in auth_base64_tokens(stream) {
        if let Some(c) = scan_raw(&base64_decode(token)) {
            return Some(c);
        }
    }
    None
}

/// The CHALLENGE_MESSAGE from [MS-NLMP] §4.2 example values, laid out per
/// §2.2.1.2. Server challenge `0123456789abcdef`, TargetName "Server",
/// TargetInfo NbDomainName "Domain" + NbComputerName "Server". At module scope
/// (behind `cfg(test)`) so the dump-path tests can reuse it via
/// `crate::ntlm::CHALLENGE_MESSAGE_EXAMPLE`.
#[cfg(test)]
#[rustfmt::skip]
pub(crate) const CHALLENGE_MESSAGE_EXAMPLE: [u8; 104] = [
    // 0x00  Signature "NTLMSSP\0"
    0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
    // 0x08  MessageType = 2 (CHALLENGE)
    0x02, 0x00, 0x00, 0x00,
    // 0x0c  TargetNameFields: Len=12, MaxLen=12, BufferOffset=56
    0x0c, 0x00, 0x0c, 0x00, 0x38, 0x00, 0x00, 0x00,
    // 0x14  NegotiateFlags = 0xe28a8233 (UNICODE|REQUEST_TARGET|NTLM|
    //       TARGET_TYPE_SERVER|TARGET_INFO|VERSION|128|KEY_EXCH|56)
    0x33, 0x82, 0x8a, 0xe2,
    // 0x18  ServerChallenge = 01 23 45 67 89 ab cd ef
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    // 0x20  Reserved
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x28  TargetInfoFields: Len=36, MaxLen=36, BufferOffset=68
    0x24, 0x00, 0x24, 0x00, 0x44, 0x00, 0x00, 0x00,
    // 0x30  Version: 6.0 build 6000, NTLMRevision=15
    0x06, 0x00, 0x70, 0x17, 0x00, 0x00, 0x00, 0x0f,
    // 0x38  TargetName payload: "Server" (UTF-16LE)
    0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00,
    // 0x44  TargetInfo payload:
    //   MsvAvNbDomainName (AvId=2, Len=12) "Domain"
    0x02, 0x00, 0x0c, 0x00,
    0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e, 0x00,
    //   MsvAvNbComputerName (AvId=1, Len=12) "Server"
    0x01, 0x00, 0x0c, 0x00,
    0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00,
    //   MsvAvEOL (AvId=0, Len=0)
    0x00, 0x00, 0x00, 0x00,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_challenge_in_raw_ntlmssp_bytes() {
        let c = detect_challenge(&CHALLENGE_MESSAGE_EXAMPLE).expect("challenge detected");
        assert_eq!(
            c.server_challenge,
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
        assert_eq!(c.nb_computer_name.as_deref(), Some("Server"));
        assert_eq!(c.nb_domain_name.as_deref(), Some("Domain"));
    }

    /// Standard base64 (RFC 4648) encoder — test-only, for building inputs.
    fn base64_encode(data: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for chunk in data.chunks(3) {
            let b0 = chunk[0];
            let b1 = *chunk.get(1).unwrap_or(&0);
            let b2 = *chunk.get(2).unwrap_or(&0);
            s.push(T[(b0 >> 2) as usize] as char);
            s.push(T[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
            s.push(if chunk.len() > 1 {
                T[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
            } else {
                '='
            });
            s.push(if chunk.len() > 2 {
                T[(b2 & 0x3f) as usize] as char
            } else {
                '='
            });
        }
        s
    }

    #[test]
    fn detects_challenge_in_base64_www_authenticate() {
        let b64 = base64_encode(&CHALLENGE_MESSAGE_EXAMPLE);
        let resp = format!(
            "HTTP/1.1 401 Unauthorized\r\n\
             WWW-Authenticate: NTLM {b64}\r\n\
             Content-Length: 0\r\n\r\n"
        );
        let c = detect_challenge(resp.as_bytes()).expect("challenge detected in header");
        assert_eq!(
            c.server_challenge,
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
        assert_eq!(c.nb_computer_name.as_deref(), Some("Server"));
    }

    #[test]
    fn detects_challenge_embedded_in_negotiate_spnego_token() {
        // A SPNEGO-like wrapper: the NTLMSSP CHALLENGE_MESSAGE is embedded
        // inside a larger token (not at offset 0), as it appears in a
        // `WWW-Authenticate: Negotiate` NegTokenResp.
        let prefix: &[u8] = &[
            0xa1, 0x81, 0x94, 0x30, 0x81, 0x91, 0xa0, 0x03, 0x0a, 0x01, 0x01, 0xa1, 0x0c, 0x06,
            0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, 0xa2, 0x7c, 0x04,
            0x7a,
        ];
        let mut token = prefix.to_vec();
        token.extend_from_slice(&CHALLENGE_MESSAGE_EXAMPLE);
        let b64 = base64_encode(&token);
        let resp =
            format!("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Negotiate {b64}\r\n\r\n");
        let c = detect_challenge(resp.as_bytes()).expect("challenge detected in SPNEGO token");
        assert_eq!(c.nb_computer_name.as_deref(), Some("Server"));
        assert_eq!(
            c.server_challenge,
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
    }

    #[test]
    fn ignores_type1_negotiate_message() {
        // A NEGOTIATE_MESSAGE (Type 1) shares the signature but is not a
        // challenge. Padded past the 48-byte header so it's the MessageType
        // check — not the length guard — that rejects it.
        let mut m = SIG.to_vec();
        m.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // MessageType = 1
        m.resize(56, 0);
        assert!(detect_challenge(&m).is_none());
    }

    #[test]
    fn base64_decode_matches_rfc_vectors() {
        assert_eq!(base64_decode(b"TWFu"), b"Man");
        assert_eq!(base64_decode(b"TWE="), b"Ma");
        assert_eq!(base64_decode(b"TQ=="), b"M");
        assert!(base64_decode(b"").is_empty());
    }
}
