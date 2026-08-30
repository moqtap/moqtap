//! A non-existent object carries no extension headers.
//!
//! Drafts 11 through 13 state it this way: "Any Object may have extension
//! headers except those with Object Status 'Object Does Not Exist'. If an
//! endpoint receives a non-existent Object containing extension headers it MUST
//! close the session with a Protocol Violation." Draft-14 states the same
//! sentence with the code spelled PROTOCOL_VIOLATION.
//!
//! The rule reaches all three carriers that can announce a status: an object on
//! a subgroup stream, an object on a fetch stream, and a status datagram. A
//! plain datagram has no status field and so is the only one that cannot break
//! it.
//!
//! The fetch stream is the carrier that gets forgotten. It is the third of
//! three, it is the only one whose extension block is unconditional rather than
//! gated on the stream type, and a first pass at this rule covered the other
//! two and left it. A relay that forwards such an object hands a conforming
//! subscriber a session-closing frame, and the fetch response is lost.
//!
//! Draft-15 is deliberately absent. It drops the sentence, and drafts 16 and
//! later drop the Object Does Not Exist status itself, so there is nothing left
//! for the rule to bind. Applying it to draft-15 would refuse objects that
//! draft permits, which is the same mistake in the other direction.
//!
//! Draft-14 is here too, and driven by a gate of its own rather than a row in
//! the list. It states the same sentence and enforces it in one shared place
//! that all three carriers reach, but the types those carriers are read through
//! are not the ones the macro drives: there is no `ObjectHeader` and no
//! `DatagramStatusHeader`, and the same three objects arrive through a
//! `SubgroupObjectReader`, a whole `FetchObject` and a whole `DatagramObject`.
//! The object bytes are the same, so the builders below are shared.
//!
//! The gates for drafts 11 to 13 call the header decoder directly rather than
//! framing a whole datagram. The type byte that selects a status datagram is
//! not the same number on every one of those drafts — that disagreement is its
//! own problem — and this rule is about the object, not about how the carrier
//! is addressed. Draft-14 has no header decoder to call, so its gate writes the
//! byte and says which one it is.

#[cfg(any(
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14"
))]
use moqtap_codec::error::CodecError;
#[cfg(any(
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14"
))]
use moqtap_codec::varint::VarInt;

#[cfg(any(feature = "draft11", feature = "draft12", feature = "draft13", feature = "draft14"))]
fn vi(v: u64) -> VarInt {
    VarInt::from_u64(v).expect("value fits a varint")
}

/// A subgroup-stream object: Object ID, extensions, payload length, status.
///
/// The status is written only because the payload length is zero, which is the
/// only shape in which these drafts carry one at all.
#[cfg(any(feature = "draft11", feature = "draft12", feature = "draft13", feature = "draft14"))]
fn subgroup_object(extension_bytes: usize, status: u64) -> Vec<u8> {
    let mut wire = Vec::new();
    vi(1).encode(&mut wire);
    VarInt::from_usize(extension_bytes).encode(&mut wire);
    wire.extend(std::iter::repeat_n(0xAA, extension_bytes));
    vi(0).encode(&mut wire); // Object Payload Length
    vi(status).encode(&mut wire);
    wire
}

/// A fetch-stream object: group, subgroup, object, priority, extensions,
/// payload length, status.
///
/// The extension block here is unconditional — a fetch object always carries an
/// Extension Headers Length, where a subgroup object carries one only when its
/// stream type says so.
#[cfg(any(feature = "draft11", feature = "draft12", feature = "draft13", feature = "draft14"))]
fn fetch_object(extension_bytes: usize, status: u64) -> Vec<u8> {
    let mut wire = Vec::new();
    vi(1).encode(&mut wire);
    vi(0).encode(&mut wire);
    vi(2).encode(&mut wire);
    wire.push(128); // Publisher Priority
    VarInt::from_usize(extension_bytes).encode(&mut wire);
    wire.extend(std::iter::repeat_n(0xAA, extension_bytes));
    vi(0).encode(&mut wire); // Object Payload Length
    vi(status).encode(&mut wire);
    wire
}

/// A status datagram whose type says it carries no extensions, so the
/// Extension Headers Length field is absent rather than zero.
#[cfg(any(feature = "draft11", feature = "draft12", feature = "draft13", feature = "draft14"))]
fn status_datagram_without_extensions(status: u64) -> Vec<u8> {
    let mut wire = Vec::new();
    vi(1).encode(&mut wire);
    vi(2).encode(&mut wire);
    vi(3).encode(&mut wire);
    wire.push(128); // Publisher Priority
    vi(status).encode(&mut wire);
    wire
}

/// A status datagram: alias, group, object, priority, extensions, status.
#[cfg(any(feature = "draft11", feature = "draft12", feature = "draft13", feature = "draft14"))]
fn status_datagram(extension_bytes: usize, status: u64) -> Vec<u8> {
    let mut wire = Vec::new();
    vi(1).encode(&mut wire);
    vi(2).encode(&mut wire);
    vi(3).encode(&mut wire);
    wire.push(128); // Publisher Priority
    VarInt::from_usize(extension_bytes).encode(&mut wire);
    wire.extend(std::iter::repeat_n(0xAA, extension_bytes));
    vi(status).encode(&mut wire);
    wire
}

/// Draft-14 reads the datagram type for itself, so its status datagrams are the
/// bodies above behind a leading type byte.
#[cfg(feature = "draft14")]
fn typed_status_datagram(datagram_type: u8, body: &[u8]) -> Vec<u8> {
    let mut wire = vec![datagram_type];
    wire.extend_from_slice(body);
    wire
}

/// Build the pair of gates for one draft.
///
/// # What this catches, observed by removing the check and running it
///
/// ```text
/// a non-existent object on a subgroup stream cannot carry extensions, got Ok(ObjectHeader { object_id: VarInt(1), extension_headers_length: VarInt(2), extensions: [170, 170], payload_length: VarInt(0), object_status: ObjectDoesNotExist })
/// ```
///
/// for the fetch stream:
///
/// ```text
/// a non-existent object on a fetch stream cannot carry extensions, got Ok(FetchObjectHeader { group_id: VarInt(1), subgroup_id: VarInt(0), object_id: VarInt(2), publisher_priority: 128, extension_headers_length: VarInt(2), extensions: [170, 170], payload_length: VarInt(0), object_status: ObjectDoesNotExist })
/// ```
///
/// and for the datagram:
///
/// ```text
/// a non-existent object in a status datagram cannot carry extensions, got Ok(DatagramStatusHeader { track_alias: VarInt(1), group_id: VarInt(2), object_id: VarInt(3), publisher_priority: 128, extension_headers_length: VarInt(2), extensions: [170, 170], object_status: ObjectDoesNotExist })
/// ```
macro_rules! non_existent_object_gate {
    ($fname:ident, $feat:literal, $draft:ident) => {
        #[cfg(feature = $feat)]
        #[test]
        fn $fname() {
            use moqtap_codec::$draft::data_stream::{
                DatagramStatusHeader, FetchObjectHeader, ObjectHeader,
            };

            // Object Status 0x1 is Object Does Not Exist on every draft here.
            let wire = subgroup_object(2, 0x1);
            let got = ObjectHeader::decode_with_extensions(true, &mut &wire[..]);
            assert!(
                matches!(got, Err(CodecError::ExtensionsOnNonExistentObject(2))),
                "a non-existent object on a subgroup stream cannot carry extensions, got {got:?}"
            );

            let wire = fetch_object(2, 0x1);
            let got = FetchObjectHeader::decode(&mut &wire[..]);
            assert!(
                matches!(got, Err(CodecError::ExtensionsOnNonExistentObject(2))),
                "a non-existent object on a fetch stream cannot carry extensions, got {got:?}"
            );

            let wire = status_datagram(2, 0x1);
            let got = DatagramStatusHeader::decode_with_extensions(true, &mut &wire[..]);
            assert!(
                matches!(got, Err(CodecError::ExtensionsOnNonExistentObject(2))),
                "a non-existent object in a status datagram cannot carry extensions, got {got:?}"
            );

            // The same object without extensions is lawful, so what the gates
            // above observe is the pairing and not the status on its own.
            let wire = subgroup_object(0, 0x1);
            ObjectHeader::decode_with_extensions(true, &mut &wire[..])
                .expect("a non-existent object with no extensions is lawful");
            let wire = fetch_object(0, 0x1);
            FetchObjectHeader::decode(&mut &wire[..])
                .expect("a non-existent fetch object with no extensions is lawful");
            // The datagram is read with extensions *absent* rather than with a
            // zero-length block: these drafts make a length of 0 on a datagram
            // whose type announces extensions a session-closing offence in its
            // own right, so a zero-length block would prove nothing about this
            // rule.
            let wire = status_datagram_without_extensions(0x1);
            DatagramStatusHeader::decode_with_extensions(false, &mut &wire[..])
                .expect("a non-existent status datagram with no extensions is lawful");

            // And extensions are lawful on a status that permits them, so the
            // gates do not simply refuse every extension block.
            let wire = status_datagram(2, 0x3);
            DatagramStatusHeader::decode_with_extensions(true, &mut &wire[..])
                .expect("End of Group may carry extensions");
        }
    };
}

non_existent_object_gate!(draft11_refuses_extensions_on_a_non_existent_object, "draft11", draft11);
non_existent_object_gate!(draft12_refuses_extensions_on_a_non_existent_object, "draft12", draft12);
non_existent_object_gate!(draft13_refuses_extensions_on_a_non_existent_object, "draft13", draft13);
/// The same three carriers on draft-14, through the types that draft has.
///
/// The status datagram is the one that needs a byte the others do not: drafts
/// 11 to 13 are told whether extensions are present, and draft-14 reads it off
/// the type byte, where `0x21` is the status datagram that announces them and
/// `0x20` the one that does not.
///
/// # What this catches, observed by removing the check and running it
///
/// All three carriers reach one shared check here, which makes this three
/// ablations rather than one: removing the check outright stops at the first
/// assertion and leaves the other two carriers unmeasured. Removed from the
/// subgroup object alone:
///
/// ```text
/// a non-existent object on a subgroup stream cannot carry extensions, got Ok(SubgroupObject { object_id: VarInt(1), extension_headers: [170, 170], status: Some(ObjectDoesNotExist), payload: [] })
/// ```
///
/// from the fetch object alone:
///
/// ```text
/// a non-existent object on a fetch stream cannot carry extensions, got Ok(FetchObject { group_id: VarInt(1), subgroup_id: VarInt(0), object_id: VarInt(2), publisher_priority: 128, extension_headers: [170, 170], status: Some(ObjectDoesNotExist), payload: [] })
/// ```
///
/// and from the datagram alone:
///
/// ```text
/// a non-existent object in a status datagram cannot carry extensions, got Ok(DatagramObject { datagram_type: DatagramType(33), track_alias: VarInt(1), group_id: VarInt(2), object_id: VarInt(3), publisher_priority: 128, extension_headers: [170, 170], status: Some(ObjectDoesNotExist), payload: [] })
/// ```
#[cfg(feature = "draft14")]
#[test]
fn draft14_refuses_extensions_on_a_non_existent_object() {
    use moqtap_codec::draft14::data_stream::{
        DatagramObject, FetchObject, SubgroupHeader, SubgroupObjectReader, SubgroupStreamType,
    };

    // Stream type 0x11: every object on the stream carries an extension block,
    // and there is no explicit Subgroup ID field.
    let header = SubgroupHeader {
        stream_type: SubgroupStreamType::from_u8(0x11).expect("0x11 is a defined stream type"),
        track_alias: vi(1),
        group_id: vi(2),
        subgroup_id: None,
        publisher_priority: 128,
    };

    let wire = subgroup_object(2, 0x1);
    let got = SubgroupObjectReader::new(&header).read_object(&mut &wire[..]);
    assert!(
        matches!(got, Err(CodecError::ExtensionsOnNonExistentObject(2))),
        "a non-existent object on a subgroup stream cannot carry extensions, got {got:?}"
    );

    let wire = fetch_object(2, 0x1);
    let got = FetchObject::decode(&mut &wire[..]);
    assert!(
        matches!(got, Err(CodecError::ExtensionsOnNonExistentObject(2))),
        "a non-existent object on a fetch stream cannot carry extensions, got {got:?}"
    );

    let wire = typed_status_datagram(0x21, &status_datagram(2, 0x1));
    let got = DatagramObject::decode(&mut &wire[..]);
    assert!(
        matches!(got, Err(CodecError::ExtensionsOnNonExistentObject(2))),
        "a non-existent object in a status datagram cannot carry extensions, got {got:?}"
    );

    // The same object without extensions is lawful, so what the gates above
    // observe is the pairing and not the status on its own.
    let wire = subgroup_object(0, 0x1);
    SubgroupObjectReader::new(&header)
        .read_object(&mut &wire[..])
        .expect("a non-existent object with no extensions is lawful");
    let wire = fetch_object(0, 0x1);
    FetchObject::decode(&mut &wire[..])
        .expect("a non-existent fetch object with no extensions is lawful");
    let wire = typed_status_datagram(0x20, &status_datagram_without_extensions(0x1));
    DatagramObject::decode(&mut &wire[..])
        .expect("a non-existent status datagram with no extensions is lawful");

    // And extensions are lawful on a status that permits them, so the gates do
    // not simply refuse every extension block.
    let wire = typed_status_datagram(0x21, &status_datagram(2, 0x3));
    DatagramObject::decode(&mut &wire[..]).expect("End of Group may carry extensions");
}
