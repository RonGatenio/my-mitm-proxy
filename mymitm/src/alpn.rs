//! Pure ALPN helpers for the upstream-first mirror. No I/O and no rustls types
//! so the negotiation logic is trivially unit-testable.

/// Convert human protocol names (e.g. "h2", "http/1.1") to ALPN wire form (the
/// raw bytes rustls expects in `alpn_protocols`). Whitespace is trimmed and
/// empty entries are dropped.
pub fn to_wire(names: &[String]) -> Vec<Vec<u8>> {
    names
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.as_bytes().to_vec())
        .collect()
}

/// Compute the ALPN list to offer UPSTREAM: the client's offered protocols
/// filtered to those in `allowlist`, preserving the client's preference order.
/// If the client offered none, or nothing survives the filter, the result is
/// empty (offer no ALPN upstream).
pub fn offer(client_offered: &[Vec<u8>], allowlist: &[Vec<u8>]) -> Vec<Vec<u8>> {
    client_offered
        .iter()
        .filter(|p| allowlist.iter().any(|a| a == *p))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn w(s: &str) -> Vec<u8> { s.as_bytes().to_vec() }

    #[test]
    fn to_wire_maps_and_trims() {
        assert_eq!(to_wire(&["h2".into(), "http/1.1".into()]), vec![w("h2"), w("http/1.1")]);
        assert_eq!(to_wire(&[" h2 ".into(), "".into(), "  ".into()]), vec![w("h2")]);
    }

    #[test]
    fn offer_intersects_preserving_client_order() {
        let client = vec![w("h2"), w("http/1.1")];
        let allow = vec![w("http/1.1"), w("h2")]; // allowlist order differs
        // client order is preserved, not allowlist order
        assert_eq!(offer(&client, &allow), vec![w("h2"), w("http/1.1")]);
    }

    #[test]
    fn offer_filters_to_allowlist() {
        let client = vec![w("h2"), w("http/1.1")];
        let allow = vec![w("http/1.1")]; // force downgrade
        assert_eq!(offer(&client, &allow), vec![w("http/1.1")]);
    }

    #[test]
    fn offer_empty_when_no_overlap_or_empty_inputs() {
        assert!(offer(&[w("h2")], &[w("http/1.1")]).is_empty()); // no overlap
        assert!(offer(&[], &[w("h2")]).is_empty());               // client offered none
        assert!(offer(&[w("h2")], &[]).is_empty());               // allowlist empty (ALPN off)
    }
}
