//! A datagram carrying an Object Status may not also carry a payload.
//!
//! Drafts 17, 18 and 19 all say it twice. Section 10.2.1.1 / 11.2.1.1: "Any
//! object with a status code other than zero MUST have an empty payload."
//! Section 10.3.1 / 11.3.1, for the datagram carrier specifically: "The STATUS
//! bit (0x20) indicates whether the datagram contains an Object Status or Object
//! Payload. When set to 1, the Object Status field is present and there is no
//! Object Payload."
//!
//! This is the one place the blanket rule is not already satisfied by the
//! framing. On a subgroup stream the status and the payload share a wire
//! position, so no frame can state both. A datagram's payload is whatever
//! follows the header to the end of the transport datagram, which
//! `DatagramHeader::decode` never sees — it stops at the end of the header and
//! hands the tail back to the caller.
//!
//! `permits_payload` is what a caller holding that tail asks. The client's
//! `Connection::recv_datagram` is the caller, and it refuses a datagram whose
//! header forbids a payload and whose tail is non-empty.

#![cfg(all(feature = "draft17", feature = "draft18", feature = "draft19"))]

/// A status datagram reports that its trailing bytes may not exist; a Normal one
/// reports that they may.
///
/// The input for the first case is `20 01 00 00 80 03 de ad be ef`: type 0x20
/// (STATUS set), track alias 1, group 0, object 0, priority 0x80, status 0x03
/// (End of Group), then four bytes that the draft forbids. Decoding stops after
/// the status, so the header alone cannot see them — which is exactly why the
/// predicate exists rather than a decoder refusal.
///
/// # Observed with the fix reverted
///
/// Replacing draft-17's `permits_payload` body with `true`:
///
/// ```text
/// ---- a_status_datagram_permits_no_payload_and_a_normal_one_does stdout ----
///
/// thread 'a_status_datagram_permits_no_payload_and_a_normal_one_does' (8768) panicked at crates\moqtap-codec\tests\datagram_payload_rule.rs:55:9:
/// draft-17 says an End-of-Group datagram may carry a payload
/// ```
#[test]
fn a_status_datagram_permits_no_payload_and_a_normal_one_does() {
    // STATUS bit set, End of Group, four trailing bytes.
    let status_datagram = hex::decode("2001000080 03 deadbeef".replace(' ', "")).unwrap();
    // STATUS bit clear: an ordinary object whose tail is its payload.
    let normal_datagram = hex::decode("0001000080deadbeef").unwrap();

    {
        use moqtap_codec::draft17::data_stream::DatagramHeader;
        let mut cursor = &status_datagram[..];
        let h = DatagramHeader::decode(&mut cursor).expect("draft-17 status datagram");
        assert!(h.has_status(), "the STATUS bit was not read");
        assert!(!cursor.is_empty(), "the trailing bytes vanished into the header decode");
        assert!(!h.permits_payload(), "draft-17 says an End-of-Group datagram may carry a payload");

        let mut cursor = &normal_datagram[..];
        let h = DatagramHeader::decode(&mut cursor).expect("draft-17 normal datagram");
        assert!(h.permits_payload(), "draft-17 refused a payload on a Normal object");
    }

    {
        use moqtap_codec::draft18::data_stream::DatagramHeader;
        let mut cursor = &status_datagram[..];
        let h = DatagramHeader::decode(&mut cursor).expect("draft-18 status datagram");
        assert!(!h.permits_payload(), "draft-18 says an End-of-Group datagram may carry a payload");

        let mut cursor = &normal_datagram[..];
        let h = DatagramHeader::decode(&mut cursor).expect("draft-18 normal datagram");
        assert!(h.permits_payload(), "draft-18 refused a payload on a Normal object");
    }

    {
        use moqtap_codec::draft19::data_stream::DatagramHeader;
        let mut cursor = &status_datagram[..];
        let h = DatagramHeader::decode(&mut cursor).expect("draft-19 status datagram");
        assert!(!h.permits_payload(), "draft-19 says an End-of-Group datagram may carry a payload");

        let mut cursor = &normal_datagram[..];
        let h = DatagramHeader::decode(&mut cursor).expect("draft-19 normal datagram");
        assert!(h.permits_payload(), "draft-19 refused a payload on a Normal object");
    }
}
