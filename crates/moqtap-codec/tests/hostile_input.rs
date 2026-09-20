//! Inputs a hostile peer can send before anything is negotiated.
//!
//! A decoder's first job is to survive the bytes it is given. These gates are
//! not about producing the right value — they are about not dying, and about
//! not doing so on a message short enough to fit in a single datagram.
//!
//! The class of defect here is a length or count taken from the wire and used
//! to size an allocation before the items it counts have been read. MoQT
//! varints reach 2^62-1, so a declared count costs eleven bytes to send and
//! asks for an allocation no machine can satisfy. `Vec::with_capacity` answers
//! that by aborting the process, which is not an error a caller can catch or a
//! session can be closed over.
//!
//! Reading the count is fine and necessary. Trusting it is not. Every item in
//! these lists takes at least one byte on the wire, so the bytes still unread
//! bound how many can really follow, and that bound is what
//! `types::reserve_bounded` applies.

use moqtap_codec::kvp::KeyValuePair;

/// A count-prefixed key-value list must not size its allocation from the count.
///
/// Eleven bytes: a varint count of 2^62-1 and nothing after it. Before this was
/// bounded, `KeyValuePair::decode_list` reached `Vec::with_capacity` with that
/// count and the process aborted — no error returned, no session closed, no
/// stack to unwind.
///
/// *Ablation:* restore `Vec::with_capacity(count)` in `decode_list`, and the
/// test does not fail — it takes the whole process down with it:
///
/// ```text
/// thread 'a_hostile_parameter_count_does_not_abort_the_process' panicked at
/// library\alloc\src\raw_vec\mod.rs:
/// capacity overflow
/// ```
#[test]
fn a_hostile_parameter_count_does_not_abort_the_process() {
    // 0xff repeated is the largest eight-byte varint: 2^62-1.
    let wire = [0xffu8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    let mut cursor = &wire[..];
    let decoded = KeyValuePair::decode_list(&mut cursor);
    assert!(
        decoded.is_err(),
        "a count of 2^62-1 with no pairs behind it must be an error, got {decoded:?}"
    );
}

/// The same, reached the way a peer would actually reach it: the first message
/// of a session.
///
/// SETUP is the first thing either side sends, so this runs before version
/// negotiation, before any parameter is read, and before there is any notion of
/// who the peer is. That is what makes the allocation bound a property worth
/// gating rather than a tidiness fix.
///
/// *Ablation:* as above — the process aborts rather than the test failing.
#[cfg(feature = "draft14")]
#[test]
fn a_hostile_setup_does_not_abort_the_process() {
    use moqtap_codec::draft14::message::ControlMessage;

    // CLIENT_SETUP (0x20), declared length 8, then a parameter count of 2^62-1.
    let wire = [0x20u8, 0x00, 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    assert_eq!(wire.len(), 11, "the whole attack is eleven bytes");

    let mut cursor = &wire[..];
    let decoded = ControlMessage::decode(&mut cursor);
    assert!(decoded.is_err(), "a hostile SETUP must be an error, got {decoded:?}");
}

/// A count that is merely large rather than absurd must also not be trusted.
///
/// `2^62-1` aborts, but a count of a few million allocates successfully and
/// then fails on the first missing item — succeeding at the allocation is the
/// problem, because it is memory a peer can ask for repeatedly with a handful
/// of bytes each time. The bound makes the request proportional to what was
/// actually sent.
///
/// *Ablation:* restore the unbounded capacity and this still passes, because it
/// asserts the error rather than the allocation. It is here for the shape, and
/// the gate that bites is the one above.
#[test]
fn a_large_but_allocatable_count_still_fails_on_the_missing_items() {
    // 4 million, as a four-byte varint, with nothing behind it.
    let mut wire = Vec::new();
    moqtap_codec::varint::VarInt::from_u64(4_000_000).unwrap().encode(&mut wire);
    let mut cursor = &wire[..];
    let decoded = KeyValuePair::decode_list(&mut cursor);
    assert!(decoded.is_err(), "no pairs follow the count, got {decoded:?}");
}

/// Naming a field must not depend on the value being the shape the name implies.
///
/// The decoders refuse a parameter whose value is not one varint, but only for
/// the types the draft in question defines as an integer. Field extraction runs
/// on any `ControlMessage`, including one assembled in a program rather than
/// read off a wire, and it reads the same parameter as an integer from a table
/// of its own. Where the two disagree, an extractor that reaches an unchecked
/// `VarInt::decode(..).unwrap()` panics, and an empty value is enough to do it.
///
/// This builds the message rather than decoding one: draft-07 does define
/// MAX_SUBSCRIBE_ID as an integer, so its own encoder and decoder both refuse
/// this value, and it is exactly the case the extractor cannot assume it has
/// been spared.
///
/// *Ablation:* restore the `unwrap` and this does not fail — it panics inside
/// the function under test, which is the report.
#[cfg(feature = "draft07")]
#[test]
fn a_named_integer_parameter_with_no_varint_in_it_does_not_panic() {
    use moqtap_codec::draft07::message::{ClientSetup, ControlMessage};
    use moqtap_codec::fields::FieldValue;
    use moqtap_codec::kvp::KvpValue;
    use moqtap_codec::varint::VarInt;

    let msg = ControlMessage::ClientSetup(ClientSetup {
        supported_versions: vec![VarInt::from_u64(0xff07).unwrap()],
        // 0x02 is MAX_SUBSCRIBE_ID, and its value is nothing at all.
        parameters: vec![KeyValuePair {
            key: VarInt::from_u64(0x02).unwrap(),
            value: KvpValue::Bytes(Vec::new()),
        }],
    });

    let fields = moqtap_codec::draft07::fields::message_fields(&msg);
    let Some(FieldValue::Array(parameters)) = fields.get("parameters") else {
        panic!("no parameter list in {fields:?}");
    };
    let [FieldValue::Map(entry)] = &parameters[..] else {
        panic!("one parameter was sent: {parameters:?}");
    };
    assert_eq!(entry.get("name"), Some(&FieldValue::Text("max_subscribe_id".into())));
    assert_eq!(
        entry.get("raw_hex"),
        Some(&FieldValue::Bytes(Vec::new())),
        "the value a message carried, not a judgement on it: {entry:?}"
    );
}

/// A parameter type a draft dropped is not named by the draft that had it.
///
/// ROLE is parameter type 0x00 in draft-07 and occurs nowhere in the text of
/// 08, 09 or 10, which give 0x00 to nothing else. Those drafts' decoders say so
/// — each excludes 0x00 from the setup types whose value it checks is an
/// integer — and field extraction has to agree, or it reads an unchecked value
/// as an integer under a name the sender cannot have meant.
///
/// The message is built with this crate's encoder and read back with its
/// decoder, because that is what says the bytes are reachable: a peer can send
/// this before a session exists, and until the tables agreed it took the
/// process down.
///
/// *Ablation:* point draft-08 back at draft-07's setup table and this panics
/// rather than fails, on the `unwrap` above or on the name below.
#[cfg(feature = "draft08")]
#[test]
fn a_setup_parameter_type_draft_08_dropped_is_not_named_role() {
    use moqtap_codec::draft08::message::{ClientSetup, ControlMessage};
    use moqtap_codec::fields::FieldValue;
    use moqtap_codec::kvp::KvpValue;
    use moqtap_codec::varint::VarInt;

    let msg = ControlMessage::ClientSetup(ClientSetup {
        supported_versions: vec![VarInt::from_u64(0xff08).unwrap()],
        parameters: vec![KeyValuePair {
            key: VarInt::from_u64(0x00).unwrap(),
            value: KvpValue::Bytes(Vec::new()),
        }],
    });
    let mut wire = Vec::new();
    msg.encode(&mut wire).expect("this draft does not check type 0x00");
    let decoded = ControlMessage::decode(&mut &wire[..]).expect("nor on the way back");

    let fields = moqtap_codec::draft08::fields::message_fields(&decoded);
    let Some(FieldValue::Array(parameters)) = fields.get("parameters") else {
        panic!("no parameter list in {fields:?}");
    };
    let [FieldValue::Map(entry)] = &parameters[..] else {
        panic!("one parameter was sent: {parameters:?}");
    };
    // An entry with no `name` is how the rendering says the draft assigns the
    // type nothing. There is no second container to look in: the type is on
    // the entry, beside the bytes that arrived under it.
    assert_eq!(entry.get("type"), Some(&FieldValue::Text("0x0".into())));
    assert_eq!(entry.get("name"), None, "draft-08 has no ROLE: {entry:?}");
}
