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
    /// Auth scheme that carried the challenge — "NTLM" or "Negotiate" — when it
    /// was detected in a `WWW-Authenticate`/`Authorization` header (`None` for a
    /// raw-bytes hit).
    pub scheme: Option<String>,
    /// The verbatim base64 token as sent (the value after the scheme keyword) —
    /// the full wire Type-2 / SPNEGO message, preserving fields we don't decode
    /// (flags, timestamp, all AV pairs, MIC). `None` for a raw-bytes hit.
    pub token: Option<String>,
}

/// A parsed NTLM AUTHENTICATE_MESSAGE (NTLMSSP Type 3) — the client's response.
/// Together with the Type-2 `server_challenge` from the same connection, the
/// `nt_proof_str` + `blob` form a crackable net-NTLMv2 hash (hashcat `-m 5600`:
/// `username::domain:server_challenge:nt_proof_str:blob`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NtlmResponse {
    /// AUTHENTICATE_MESSAGE DomainName (the account's domain / NetBIOS name).
    pub domain: Option<String>,
    /// AUTHENTICATE_MESSAGE UserName.
    pub username: Option<String>,
    /// AUTHENTICATE_MESSAGE Workstation (the client machine name).
    pub workstation: Option<String>,
    /// NtChallengeResponse[0..16] — the NTProofStr (HMAC-MD5 over the challenge).
    pub nt_proof_str: Option<Vec<u8>>,
    /// NtChallengeResponse[16..] — the NTLMv2 "temp"/blob (response version,
    /// timestamp, client challenge, target AV pairs).
    pub blob: Option<Vec<u8>>,
    /// Auth scheme that carried the response — "NTLM" or "Negotiate" — when found
    /// in an `Authorization` header (`None` for a raw-bytes hit).
    pub scheme: Option<String>,
    /// The verbatim base64 token as sent — the full wire Type-3 / SPNEGO message.
    pub token: Option<String>,
}

const SIG: &[u8; 8] = b"NTLMSSP\0";

fn le_u16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn le_u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Decode a UTF-16LE byte slice (lossy; a trailing odd byte is ignored).
pub(crate) fn utf16le(b: &[u8]) -> String {
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

/// Read a `*_Fields` descriptor (Len `u16` @ `fields_off`, BufferOffset `u32`
/// @ `fields_off + 4`) and return the referenced raw payload bytes, if non-empty
/// and in-bounds. (Byte-slice sibling of `read_field_str`, for the Type-3
/// NtChallengeResponse.)
fn read_field_bytes(msg: &[u8], fields_off: usize) -> Option<&[u8]> {
    let len = le_u16(msg, fields_off) as usize;
    let off = le_u32(msg, fields_off + 4) as usize;
    if len == 0 {
        return None;
    }
    let end = off.checked_add(len)?;
    if end > msg.len() {
        return None;
    }
    Some(&msg[off..end])
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

/// Parse an AUTHENTICATE_MESSAGE from a slice that begins at the NTLMSSP
/// signature. Returns `None` if the slice is not a well-formed Type-3 message.
/// Layout per [MS-NLMP] §2.2.1.3: DomainName/UserName/Workstation via
/// `read_field_str`; NtChallengeResponse (NTProofStr ‖ blob) via
/// `read_field_bytes`. The fixed header runs through WorkstationFields (0x34).
fn parse_authenticate(msg: &[u8]) -> Option<NtlmResponse> {
    if msg.len() < 52 || &msg[0..8] != SIG || le_u32(msg, 8) != 3 {
        return None;
    }
    let mut r = NtlmResponse {
        domain: read_field_str(msg, 28),      // DomainNameFields  @ 0x1c
        username: read_field_str(msg, 36),    // UserNameFields    @ 0x24
        workstation: read_field_str(msg, 44), // WorkstationFields @ 0x2c
        ..Default::default()
    };
    // NtChallengeResponse @ 0x14 = NTProofStr (first 16 bytes) ‖ blob (rest).
    if let Some(nt) = read_field_bytes(msg, 20) {
        if nt.len() >= 16 {
            r.nt_proof_str = Some(nt[..16].to_vec());
            r.blob = Some(nt[16..].to_vec());
        }
    }
    Some(r)
}

/// Find an AUTHENTICATE_MESSAGE at any offset where the raw NTLMSSP signature
/// appears in `buf` (also used to locate a signature embedded in a decoded
/// SPNEGO token). Type-3 sibling of `scan_raw`.
fn scan_raw_auth(buf: &[u8]) -> Option<NtlmResponse> {
    if buf.len() < 8 {
        return None;
    }
    for i in 0..=buf.len() - 8 {
        if &buf[i..i + 8] == SIG {
            if let Some(r) = parse_authenticate(&buf[i..]) {
                return Some(r);
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

/// Extract the `(scheme, base64-token)` pairs that follow an `NTLM`/`Negotiate`
/// auth-scheme keyword (as seen in `WWW-Authenticate:` / `Authorization:`
/// headers). `scheme` is the canonical label; `token` is the verbatim base64.
fn auth_tokens(buf: &[u8]) -> Vec<(&'static str, &[u8])> {
    let mut out = Vec::new();
    for (kw, label) in [(b"ntlm".as_slice(), "NTLM"), (b"negotiate".as_slice(), "Negotiate")] {
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
                out.push((label, &buf[start..i]));
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
    for (scheme, token) in auth_tokens(stream) {
        if let Some(mut c) = scan_raw(&base64_decode(token)) {
            // Preserve the raw wire carrier alongside the decoded fields.
            c.scheme = Some(scheme.to_string());
            c.token = Some(String::from_utf8_lossy(token).into_owned());
            return Some(c);
        }
    }
    None
}

/// Scan a decrypted byte stream (client→server) for the first NTLM
/// AUTHENTICATE_MESSAGE (Type 3), through raw bytes, base64 `NTLM` tokens, and
/// SPNEGO `Negotiate` tokens. The Type-3 carries the account identity and the
/// NTLMv2 response needed (with the Type-2 challenge) to assemble a net-NTLMv2
/// hash.
pub fn detect_authenticate(stream: &[u8]) -> Option<NtlmResponse> {
    if let Some(r) = scan_raw_auth(stream) {
        return Some(r);
    }
    for (scheme, token) in auth_tokens(stream) {
        if let Some(mut r) = scan_raw_auth(&base64_decode(token)) {
            // Preserve the raw wire carrier alongside the decoded fields.
            r.scheme = Some(scheme.to_string());
            r.token = Some(String::from_utf8_lossy(token).into_owned());
            return Some(r);
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

/// A hand-laid-out AUTHENTICATE_MESSAGE (NTLMSSP Type 3) per [MS-NLMP] §2.2.1.3,
/// for the Type-3 parser tests (and reused by the dump-path tests via
/// `crate::ntlm::AUTHENTICATE_MESSAGE_EXAMPLE`). No Version/MIC block: the payload
/// starts right after NegotiateFlags at 0x40. Values: Domain "CORP", User "alice",
/// Workstation "WS01", NtChallengeResponse = NTProofStr(01..10) ‖ blob(01 01 00…).
#[cfg(test)]
#[rustfmt::skip]
pub(crate) const AUTHENTICATE_MESSAGE_EXAMPLE: [u8; 114] = [
    // 0x00  Signature "NTLMSSP\0"
    0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
    // 0x08  MessageType = 3 (AUTHENTICATE)
    0x03, 0x00, 0x00, 0x00,
    // 0x0c  LmChallengeResponseFields: Len=0, MaxLen=0, BufferOffset=64
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
    // 0x14  NtChallengeResponseFields: Len=24, MaxLen=24, BufferOffset=64
    0x18, 0x00, 0x18, 0x00, 0x40, 0x00, 0x00, 0x00,
    // 0x1c  DomainNameFields: Len=8, MaxLen=8, BufferOffset=88
    0x08, 0x00, 0x08, 0x00, 0x58, 0x00, 0x00, 0x00,
    // 0x24  UserNameFields: Len=10, MaxLen=10, BufferOffset=96
    0x0a, 0x00, 0x0a, 0x00, 0x60, 0x00, 0x00, 0x00,
    // 0x2c  WorkstationFields: Len=8, MaxLen=8, BufferOffset=106
    0x08, 0x00, 0x08, 0x00, 0x6a, 0x00, 0x00, 0x00,
    // 0x34  EncryptedRandomSessionKeyFields: Len=0, MaxLen=0, BufferOffset=0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x3c  NegotiateFlags = NTLMSSP_NEGOTIATE_UNICODE
    0x01, 0x00, 0x00, 0x00,
    // 0x40  NtChallengeResponse (24): NTProofStr(16) ‖ blob(8)
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x58  DomainName "CORP" (UTF-16LE)
    0x43, 0x00, 0x4f, 0x00, 0x52, 0x00, 0x50, 0x00,
    // 0x60  UserName "alice" (UTF-16LE)
    0x61, 0x00, 0x6c, 0x00, 0x69, 0x00, 0x63, 0x00, 0x65, 0x00,
    // 0x6a  Workstation "WS01" (UTF-16LE)
    0x57, 0x00, 0x53, 0x00, 0x30, 0x00, 0x31, 0x00,
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
        // Found as raw bytes (no auth header) -> no carrier scheme/token.
        assert_eq!(c.scheme, None);
        assert_eq!(c.token, None);
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
        // The raw WWW-Authenticate carrier is surfaced: scheme + verbatim token.
        assert_eq!(c.scheme.as_deref(), Some("NTLM"));
        assert_eq!(c.token.as_deref(), Some(b64.as_str()));
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
        assert_eq!(c.scheme.as_deref(), Some("Negotiate"));
        assert_eq!(c.token.as_deref(), Some(b64.as_str()));
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

    #[test]
    fn detects_authenticate_in_raw_bytes() {
        let r = detect_authenticate(&AUTHENTICATE_MESSAGE_EXAMPLE).expect("authenticate detected");
        assert_eq!(r.username.as_deref(), Some("alice"));
        assert_eq!(r.domain.as_deref(), Some("CORP"));
        assert_eq!(r.workstation.as_deref(), Some("WS01"));
        assert_eq!(
            r.nt_proof_str.as_deref(),
            Some(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16][..])
        );
        assert_eq!(r.blob.as_deref(), Some(&[1, 1, 0, 0, 0, 0, 0, 0][..]));
        // Found as raw bytes (no auth header) -> no carrier scheme/token.
        assert_eq!(r.scheme, None);
        assert_eq!(r.token, None);
    }

    #[test]
    fn detects_authenticate_in_base64_authorization() {
        let b64 = base64_encode(&AUTHENTICATE_MESSAGE_EXAMPLE);
        let req = format!(
            "RDG_OUT_DATA /remoteDesktopGateway/ HTTP/1.1\r\n\
             Authorization: NTLM {b64}\r\n\r\n"
        );
        let r = detect_authenticate(req.as_bytes()).expect("authenticate detected in header");
        assert_eq!(r.username.as_deref(), Some("alice"));
        assert_eq!(r.domain.as_deref(), Some("CORP"));
        // The raw Authorization carrier is surfaced: scheme + verbatim token.
        assert_eq!(r.scheme.as_deref(), Some("NTLM"));
        assert_eq!(r.token.as_deref(), Some(b64.as_str()));
    }

    #[test]
    fn detects_authenticate_embedded_in_negotiate_spnego_token() {
        // The NTLMSSP AUTHENTICATE_MESSAGE embedded inside a larger SPNEGO
        // NegTokenResp, as it appears in an `Authorization: Negotiate` header.
        let prefix: &[u8] = &[0xa1, 0x82, 0x01, 0x00, 0x30, 0x82, 0x00, 0xfc, 0xa2, 0x03];
        let mut token = prefix.to_vec();
        token.extend_from_slice(&AUTHENTICATE_MESSAGE_EXAMPLE);
        let b64 = base64_encode(&token);
        let req = format!("POST /rpc/rpcproxy.dll HTTP/1.1\r\nAuthorization: Negotiate {b64}\r\n\r\n");
        let r = detect_authenticate(req.as_bytes()).expect("authenticate detected in SPNEGO token");
        assert_eq!(r.username.as_deref(), Some("alice"));
        assert_eq!(r.workstation.as_deref(), Some("WS01"));
        assert_eq!(r.scheme.as_deref(), Some("Negotiate"));
        assert_eq!(r.token.as_deref(), Some(b64.as_str()));
    }

    #[test]
    fn detect_authenticate_ignores_challenge_and_type1() {
        // A CHALLENGE_MESSAGE (Type 2) is not an AUTHENTICATE.
        assert!(detect_authenticate(&CHALLENGE_MESSAGE_EXAMPLE).is_none());
        // A NEGOTIATE_MESSAGE (Type 1) is not an AUTHENTICATE.
        let mut m = SIG.to_vec();
        m.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // MessageType = 1
        m.resize(64, 0);
        assert!(detect_authenticate(&m).is_none());
    }

    #[test]
    fn detect_challenge_ignores_authenticate() {
        // Symmetric guard: the Type-2 detector must not match a Type-3 message.
        assert!(detect_challenge(&AUTHENTICATE_MESSAGE_EXAMPLE).is_none());
    }
}
