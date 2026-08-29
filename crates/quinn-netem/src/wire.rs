//! On-wire byte accounting.
//!
//! A rate limit is a claim about what a link carries, and a link carries IP and
//! UDP headers as well as payload. So every byte quantity in this crate — what
//! the token bucket charges, what the queue holds, what the MTU black hole
//! compares against, what the decision log records — is the **on-wire** size of
//! a datagram, computed here and nowhere else. Two models that sized the same
//! packet differently would be two rate limits wearing one name.

use std::net::{IpAddr, SocketAddr};

/// IPv4 header (20) plus UDP header (8).
const IPV4_UDP_OVERHEAD: u32 = 28;

/// IPv6 header (40) plus UDP header (8). No extension headers: this crate
/// emits none and the shim sees none, so counting them would be inventing
/// bytes the wire does not carry.
const IPV6_UDP_OVERHEAD: u32 = 48;

/// ON-WIRE bytes for a datagram of `payload_len` sent to or received from
/// `addr`: the payload plus 28 bytes for IPv4 or 48 for IPv6.
///
/// A rate configured in this crate therefore means the same thing it means to
/// an external traffic shaper, which counts the headers whether or not we do.
///
/// # An IPv4-mapped address costs an IPv4 header
///
/// `SocketAddr::is_ipv6` is `true` for `::ffff:a.b.c.d`, and a datagram to such
/// a peer goes out as IPv4. Charging on `is_ipv6` alone over-charges every IPv4
/// peer of a dual-stack listener by 20 bytes: 1.4% at a 1400-byte datagram, but
/// 42% on a 48-byte ACK-only packet, where it materially lowers the configured
/// rate for exactly the traffic most sensitive to it.
///
/// The test is `to_ipv4_mapped`, not `to_ipv4`: the latter also converts the
/// deprecated IPv4-compatible form `::a.b.c.d`, which is a genuine IPv6 address
/// on the wire and carries a 40-byte header.
///
/// # Why `u32`, and why saturating
///
/// The engine takes `wire_bytes: u32`, so the `usize` narrows here, once. A UDP
/// datagram cannot exceed 65 535 bytes of payload, so no caller reaches the
/// saturating arm. It saturates anyway because `payload_len as u32` truncates
/// `2^32 + 100` to `100` without failing — silently reporting a huge datagram
/// as a small one, which the black hole passes and the bucket under-charges.
/// Saturating to `u32::MAX` is loud in the log and drops at any configured MTU.
pub fn wire_bytes(payload_len: usize, addr: SocketAddr) -> u32 {
    let overhead = match addr.ip() {
        IpAddr::V4(_) => IPV4_UDP_OVERHEAD,
        IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some() => IPV4_UDP_OVERHEAD,
        IpAddr::V6(_) => IPV6_UDP_OVERHEAD,
    };
    u32::try_from(payload_len).unwrap_or(u32::MAX).saturating_add(overhead)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three address forms, at a full-size datagram and at an ACK-sized
    /// one, as exact integers.
    ///
    /// The mapped row is the whole point of the table. The other two rows are
    /// satisfied by any implementation that branches on `is_ipv6`, including
    /// the wrong one.
    #[test]
    fn on_wire_bytes_charge_the_right_header() {
        let v4: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:4433".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:4433".parse().unwrap();

        assert!(mapped.is_ipv6(), "the mapped row is only interesting while this holds");

        assert_eq!(wire_bytes(1200, v4), 1228, "v4 1200");
        assert_eq!(wire_bytes(1200, v6), 1248, "v6 1200");
        assert_eq!(wire_bytes(1200, mapped), 1228, "mapped 1200");

        assert_eq!(wire_bytes(20, v4), 48, "v4 20");
        assert_eq!(wire_bytes(20, v6), 68, "v6 20");
        assert_eq!(wire_bytes(20, mapped), 48, "mapped 20");

        // The overheads themselves, stated as differences so the table cannot
        // pass by having both rows wrong by the same amount.
        assert_eq!(wire_bytes(1200, v4) - 1200, 28, "IPv4 + UDP");
        assert_eq!(wire_bytes(1200, v6) - 1200, 48, "IPv6 + UDP");
        assert_eq!(wire_bytes(0, v6) - wire_bytes(0, v4), 20, "the IPv6 header is 20 larger");
    }

    /// The IPv4-*compatible* form `::a.b.c.d` is a real IPv6 address and costs
    /// 48, even though `to_ipv4` would happily convert it.
    #[test]
    fn an_ipv4_compatible_address_is_not_an_ipv4_address() {
        let compat: SocketAddr = "[::127.0.0.1]:4433".parse().unwrap();
        assert_eq!(wire_bytes(1200, compat), 1248);
    }

    /// The MTU black hole drops a datagram whose ON-WIRE size exceeds the
    /// limit, so the boundary is: at the limit passes, one byte over drops,
    /// one byte under passes — and the payload that fits over IPv4 does not
    /// fit over IPv6, because the header is 20 bytes larger.
    ///
    /// The comparison is spelled out here rather than taken from the engine
    /// because it is the *quantity* being compared that this test pins: an
    /// engine comparing the same limit against `payload_len` passes every
    /// hand-written case a reader would think to try at 1200 bytes and then
    /// under-drops by 28 or 48 bytes for every datagram in production.
    #[test]
    fn the_mtu_black_hole_compares_on_wire_bytes() {
        /// The engine's rule: strictly greater than the limit is a black hole.
        fn passes(mtu: u32, payload_len: usize, addr: SocketAddr) -> bool {
            wire_bytes(payload_len, addr) <= mtu
        }

        const MTU: u32 = 1252;
        let v4: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:4433".parse().unwrap();

        // Exactly at the limit, over IPv4: 1224 + 28 == 1252.
        assert_eq!(wire_bytes(1224, v4), MTU, "the threshold payload");
        assert!(passes(MTU, 1224, v4), "a datagram of exactly the limit passes");
        assert!(passes(MTU, 1223, v4), "one byte under passes");
        assert!(!passes(MTU, 1225, v4), "one byte over drops");

        // The same three payloads over IPv6 are 20 bytes larger, so all three
        // are past the limit.
        assert!(!passes(MTU, 1224, v6), "v6 at the v4 threshold");
        assert!(!passes(MTU, 1223, v6), "v6 one under the v4 threshold");
        assert_eq!(wire_bytes(1204, v6), MTU, "the v6 threshold payload is 20 smaller");
        assert!(passes(MTU, 1204, v6), "the v6 threshold payload passes");
        assert!(!passes(MTU, 1205, v6), "one byte over the v6 threshold drops");
    }

    /// A payload length that does not fit a `u32` saturates instead of
    /// truncating.
    ///
    /// Nothing in this crate can call it with such a length — a UDP datagram
    /// carries at most 65 535 bytes — but the function is public and takes a
    /// `usize`, and the two failure modes are not symmetric. Truncation is
    /// silent and under-charges: `2^32 + 100` becomes a 128-byte datagram that
    /// sails through a 1252-byte black hole and costs the bucket almost
    /// nothing. Saturation is a datagram that drops at every configured MTU
    /// and shows `4294967295` in the log.
    #[test]
    fn an_oversized_length_saturates_rather_than_truncating() {
        let v4: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        // Skipped on a 32-bit target, where the value is not representable and
        // `u32::try_from` can never fail in the first place.
        if let Ok(huge) = usize::try_from(u64::from(u32::MAX) + 101) {
            assert_eq!(wire_bytes(huge, v4), u32::MAX);
        }
        assert_eq!(wire_bytes(usize::MAX, v4), u32::MAX);
        // The last payload that does not saturate, and the first that does.
        assert_eq!(wire_bytes(u32::MAX as usize - 28, v4), u32::MAX);
        assert_eq!(wire_bytes(u32::MAX as usize - 29, v4), u32::MAX - 1);
    }
}
