//! A fetch stream this client writes is one that comes back off the wire.
//!
//! The four data-stream writers on `FramedSendStream` are async and want a
//! transport, so nothing in the suite drove them until a loopback pair was
//! available. The subgroup pair got one; the fetch pair did not, and what that
//! hid was not a subtle framing bug but an absence: on drafts 15 through 19
//! there was no `write_fetch_object` at all. A caller could open a fetch stream
//! through this type and had no way to put an object on it.
//!
//! Draft-14's was there and went out through the unchecked encoder, so an
//! object carrying a payload beside a status that forbids one, or a status the
//! draft leaves unassigned, was written rather than refused. Every other draft's
//! fetch writer had used the checked encoder since it was written.
//!
//! # What each half covers
//!
//! Drafts 07 through 14 have a reader for the fetch object as well, so those go
//! out through `FramedSendStream` and come back through `FramedRecvStream` -
//! the two halves of this crate meeting on a real QUIC stream.
//!
//! Drafts 15 through 19 now have one too, and it took five shapes because the
//! drafts do. Draft-15 and draft-18 resolve an Object against the Object before
//! it, so their readers carry state and the stream has to hold it; drafts 16, 17
//! and 19 decode each Object's framing on its own and hand back the elisions
//! unresolved.
//!
//! Draft-18 is the one that cannot be started from the stream. Section 11.4.4.1
//! makes a Group ID Delta count upward under Ascending and downward under
//! Descending, and the Group Order arrives on the FETCH_OK — a control message
//! a data stream never sees. So draft-18 alone has `begin_fetch_objects`, and
//! the last gate here is the one that shows the argument is load-bearing:
//! the same bytes read in the other order do not decode at all.

mod common;

use moqtap_codec::varint::VarInt;

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap()
}

/// Payload bytes chosen so a misframed read produces something visible.
const PAYLOAD: [u8; 3] = [0xDE, 0xAD, 0xBE];

/// The fetch round trip for a draft whose client has both halves.
///
/// Two objects, not one: a writer that kept no stream state would pass with a
/// single object and lose the second, and the reader's own delta state only
/// starts mattering on the object after the first.
macro_rules! fetch_round_trip {
    (
        $mod_name:ident,
        $feat:literal,
        $draft:ident,
        $variant:ident,
        $version:ident,
        $id_field:ident,
        { $($extension_fields:tt)* }
    ) => {
        #[cfg(feature = $feat)]
        mod $mod_name {
            use super::{common, varint, PAYLOAD};
            use moqtap_client::$draft::connection::{FramedRecvStream, FramedSendStream};
            use moqtap_client::$draft::event::FetchObject;
            use moqtap_client::transport::{RecvStream, SendStream};
            use moqtap_codec::$draft::data_stream::{FetchHeader, FetchObjectHeader};
            use moqtap_codec::$draft::types::ObjectStatus;
            use moqtap_codec::dispatch::AnyFetchHeader;
            use moqtap_codec::version::DraftVersion;

            fn header() -> AnyFetchHeader {
                AnyFetchHeader::$variant(FetchHeader { $id_field: varint(1) })
            }

            fn object(id: u64) -> FetchObject {
                FetchObject {
                    header: FetchObjectHeader {
                        group_id: varint(0),
                        subgroup_id: varint(0),
                        object_id: varint(id),
                        publisher_priority: 128,
                        $($extension_fields)*
                        object_status: ObjectStatus::Normal,
                        payload_length: varint(PAYLOAD.len() as u64),
                    },
                    payload: PAYLOAD.to_vec(),
                }
            }

            /// What the writer puts on a fetch stream is what the reader gets.
            #[tokio::test]
            async fn a_fetch_stream_this_client_wrote_is_one_it_can_read() {
                common::init_crypto();
                let alpn = DraftVersion::$version.quic_alpn();
                let (server, addr) = common::spawn_server(&[alpn]);

                let reader = tokio::spawn(async move {
                    let conn = server.accept().await.expect("accept").await.expect("handshake");
                    let recv = conn.accept_uni().await.expect("accept_uni");
                    let mut framed = FramedRecvStream::new(RecvStream::Quic(recv));
                    let header = framed.read_fetch_header().await;
                    let first = framed.read_fetch_object().await;
                    let second = framed.read_fetch_object().await;
                    (header, first, second)
                });

                let client = common::client_endpoint(&[alpn]);
                let conn =
                    client.connect(addr, "localhost").expect("connect").await.expect("handshake");
                let send = conn.open_uni().await.expect("open_uni");
                let mut framed = FramedSendStream::new(SendStream::Quic(send));
                framed.write_fetch_header(&header()).await.expect("write fetch header");
                framed.write_fetch_object(&object(0)).await.expect("write first object");
                framed.write_fetch_object(&object(1)).await.expect("write second object");
                framed.finish().await.expect("finish");

                let (read_header, first, second) = reader.await.expect("reader task");
                read_header.expect("the reader must accept the header the writer wrote");

                let first = first.unwrap_or_else(|e| {
                    panic!("the client must be able to read the fetch stream it wrote: {e:?}")
                });
                assert_eq!(first.header.object_id.into_inner(), 0);
                assert_eq!(first.payload, PAYLOAD, "the payload must survive the stream");

                let second = second.unwrap_or_else(|e| {
                    panic!("the framing must hold for every object, not just the first: {e:?}")
                });
                assert_eq!(second.header.object_id.into_inner(), 1);
                assert_eq!(second.payload, PAYLOAD);
            }
        }
    };
}

// The Fetch Header's one field is a Subscribe ID through draft-10 and a Request
// ID from draft-11; the object header gains an extension block at draft-08 and
// renames its length field at draft-09.
fetch_round_trip!(draft07, "draft07", draft07, Draft07, Draft07, subscribe_id, {});
fetch_round_trip!(draft08, "draft08", draft08, Draft08, Draft08, subscribe_id, {
    extension_count: varint(0),
    extensions: Vec::new(),
});
fetch_round_trip!(draft09, "draft09", draft09, Draft09, Draft09, subscribe_id, {
    extension_headers_length: varint(0),
    extensions: Vec::new(),
});
fetch_round_trip!(draft10, "draft10", draft10, Draft10, Draft10, subscribe_id, {
    extension_headers_length: varint(0),
    extensions: Vec::new(),
});
fetch_round_trip!(draft11, "draft11", draft11, Draft11, Draft11, request_id, {
    extension_headers_length: varint(0),
    extensions: Vec::new(),
});
fetch_round_trip!(draft12, "draft12", draft12, Draft12, Draft12, request_id, {
    extension_headers_length: varint(0),
    extensions: Vec::new(),
});
fetch_round_trip!(draft13, "draft13", draft13, Draft13, Draft13, request_id, {
    extension_headers_length: varint(0),
    extensions: Vec::new(),
});

// -- draft-14, whose writer had a different problem --------------------------

/// The one draft whose fetch object writer used the unchecked encoder.
///
/// Draft-14 also gives `FramedSendStream::new` a draft argument and hands the
/// codec's own `FetchObject` to the writer rather than a client-side event type,
/// so it does not fit the macro above.
#[cfg(feature = "draft14")]
mod draft14 {
    use super::{common, varint, PAYLOAD};
    use moqtap_client::draft14::connection::{FramedRecvStream, FramedSendStream};
    use moqtap_client::transport::{RecvStream, SendStream};
    use moqtap_codec::dispatch::AnyFetchHeader;
    use moqtap_codec::draft14::data_stream::{FetchHeader, FetchObject};
    use moqtap_codec::draft14::types::ObjectStatus;
    use moqtap_codec::version::DraftVersion;

    fn header() -> AnyFetchHeader {
        AnyFetchHeader::Draft14(FetchHeader { request_id: varint(1) })
    }

    fn object(id: u64, status: Option<ObjectStatus>, payload: Vec<u8>) -> FetchObject {
        FetchObject {
            group_id: varint(0),
            subgroup_id: varint(0),
            object_id: varint(id),
            publisher_priority: 128,
            extension_headers: Vec::new(),
            status,
            payload,
        }
    }

    #[tokio::test]
    async fn a_fetch_stream_this_client_wrote_is_one_it_can_read() {
        common::init_crypto();
        let alpn = DraftVersion::Draft14.quic_alpn();
        let (server, addr) = common::spawn_server(&[alpn]);

        let reader = tokio::spawn(async move {
            let conn = server.accept().await.expect("accept").await.expect("handshake");
            let recv = conn.accept_uni().await.expect("accept_uni");
            let mut framed = FramedRecvStream::new(RecvStream::Quic(recv), DraftVersion::Draft14);
            let header = framed.read_fetch_header().await;
            let first = framed.read_fetch_object().await;
            let second = framed.read_fetch_object().await;
            (header, first, second)
        });

        let client = common::client_endpoint(&[alpn]);
        let conn = client.connect(addr, "localhost").expect("connect").await.expect("handshake");
        let send = conn.open_uni().await.expect("open_uni");
        let mut framed = FramedSendStream::new(SendStream::Quic(send), DraftVersion::Draft14);
        framed.write_fetch_header(&header()).await.expect("write fetch header");
        framed
            .write_fetch_object(&object(0, None, PAYLOAD.to_vec()))
            .await
            .expect("write first object");
        framed
            .write_fetch_object(&object(1, None, PAYLOAD.to_vec()))
            .await
            .expect("write second object");
        framed.finish().await.expect("finish");

        let (read_header, first, second) = reader.await.expect("reader task");
        read_header.expect("the reader must accept the header the writer wrote");

        let first = first.unwrap_or_else(|e| {
            panic!("the client must be able to read the fetch stream it wrote: {e:?}")
        });
        assert_eq!(first.object_id.into_inner(), 0);
        assert_eq!(first.payload, PAYLOAD);

        let second = second.unwrap_or_else(|e| {
            panic!("the framing must hold for every object, not just the first: {e:?}")
        });
        assert_eq!(second.object_id.into_inner(), 1);
        assert_eq!(second.payload, PAYLOAD);
    }

    /// An object the draft forbids does not reach the wire.
    ///
    /// Section 10.2.1.1: "Any object with a status code other than zero MUST
    /// have an empty payload." This writer used the unchecked encoder, so the
    /// object went out; the peer that receives it is required to close the
    /// session, and the sender's first sign of trouble is the session going.
    ///
    /// Ablation: putting `object.encode(&mut buf)` back in place of
    /// `encode_checked` fails with
    ///
    /// ```text
    /// an object whose status forbids a payload must be refused rather than
    /// written: Ok(())
    /// ```
    #[tokio::test]
    async fn a_payload_beside_a_status_that_forbids_one_is_refused() {
        common::init_crypto();
        let alpn = DraftVersion::Draft14.quic_alpn();
        let (server, addr) = common::spawn_server(&[alpn]);

        let reader = tokio::spawn(async move {
            let conn = server.accept().await.expect("accept").await.expect("handshake");
            let _ = conn.accept_uni().await;
        });

        let client = common::client_endpoint(&[alpn]);
        let conn = client.connect(addr, "localhost").expect("connect").await.expect("handshake");
        let send = conn.open_uni().await.expect("open_uni");
        let mut framed = FramedSendStream::new(SendStream::Quic(send), DraftVersion::Draft14);
        framed.write_fetch_header(&header()).await.expect("write fetch header");

        let result = framed
            .write_fetch_object(&object(0, Some(ObjectStatus::EndOfGroup), PAYLOAD.to_vec()))
            .await;
        assert!(
            result.is_err(),
            "an object whose status forbids a payload must be refused rather than written: \
             {result:?}",
        );

        // The same status with no payload still goes, so the refusal is about
        // the rule and not about the writer having given up on the stream.
        framed
            .write_fetch_object(&object(0, Some(ObjectStatus::EndOfGroup), Vec::new()))
            .await
            .expect("the same status with no payload is what the draft asks for");
        framed.finish().await.expect("finish");
        reader.await.expect("reader task");
    }
}

// -- drafts 15 through 19, whose writer is new -------------------------------
//
// Their Serialization Flags share a layout: the low two bits carry the Subgroup
// ID mode and `0b11` puts it on the wire, 0x04 the Object ID, 0x08 the Group ID,
// 0x10 the Publisher Priority and 0x20 a properties block. `0x1F` is therefore
// the object that inherits nothing from a previous one, which is the only shape
// the first object on a stream may take.

/// Every field explicit, no properties block.
#[allow(dead_code)]
const EVERYTHING_EXPLICIT: u64 = 0x1F;

#[cfg(feature = "draft15")]
mod draft15 {
    use super::{common, varint, EVERYTHING_EXPLICIT, PAYLOAD};
    use moqtap_client::draft15::connection::{FramedRecvStream, FramedSendStream};
    use moqtap_client::transport::{RecvStream, SendStream};
    use moqtap_codec::dispatch::AnyFetchHeader;
    use moqtap_codec::draft15::data_stream::{FetchHeader, FetchObjectHeader};
    use moqtap_codec::version::DraftVersion;

    fn object(id: u64) -> FetchObjectHeader {
        FetchObjectHeader {
            serialization_flags: EVERYTHING_EXPLICIT as u8,
            group_id: varint(0),
            subgroup_id: varint(0),
            object_id: varint(id),
            publisher_priority: 128,
            extension_headers: Vec::new(),
            payload_length: varint(PAYLOAD.len() as u64),
            object_status: None,
        }
    }

    /// A fetch stream this client wrote is one it can read.
    ///
    /// Two objects rather than one, because draft-15's reader carries the prior
    /// Object and a reader that kept no state passes on the first and loses the
    /// second. The payloads are checked as well as the headers: the header
    /// declares a length and a reader that takes the wrong number of bytes leaves
    /// every later object misaligned, which is the failure this method exists to
    /// keep out of callers.
    ///
    /// # What it catches
    ///
    /// Ablation: renaming `FramedRecvStream::read_fetch_object` out of the way,
    /// which is the state the five drafts were in:
    ///
    /// ```text
    /// error[E0599]: no method named `read_fetch_object` found for struct
    /// `FramedRecvStream` in the current scope
    ///    --> crates/moqtap-client/tests/fetch_stream_round_trip.rs:355:32
    /// ```
    ///
    /// A compile error rather than a failing assertion, which is the only shape
    /// an absent method can be caught in.
    ///
    /// Ablation: leaving the payload on the buffer after handing it back, so the
    /// next read starts inside the last object's bytes:
    ///
    /// ```text
    /// the second object: Codec(InvalidField)
    /// ```
    ///
    /// The payload of the fixture happens to begin 0xDE, which is not a
    /// Serialization Flags value draft-15 assigns. A payload whose first byte
    /// were a legal flag word would decode into an object that never existed,
    /// which is why this method takes the count rather than trusting a caller
    /// to.
    #[tokio::test]
    async fn a_fetch_stream_this_client_wrote_is_one_it_can_read() {
        common::init_crypto();
        let alpn = DraftVersion::Draft15.quic_alpn();
        let (server, addr) = common::spawn_server(&[alpn]);

        let reader = tokio::spawn(async move {
            let conn = server.accept().await.expect("accept").await.expect("handshake");
            let recv = conn.accept_uni().await.expect("accept_uni");
            let mut framed = FramedRecvStream::new(RecvStream::Quic(recv), DraftVersion::Draft15);
            framed.read_fetch_header().await.expect("the fetch header");
            let first = framed.read_fetch_object().await.expect("the first object");
            let second = framed.read_fetch_object().await.expect("the second object");
            (first, second)
        });

        let client = common::client_endpoint(&[alpn]);
        let conn = client.connect(addr, "localhost").expect("connect").await.expect("handshake");
        let send = conn.open_uni().await.expect("open_uni");
        let mut framed = FramedSendStream::new(SendStream::Quic(send), DraftVersion::Draft15);
        framed
            .write_fetch_header(&AnyFetchHeader::Draft15(FetchHeader { request_id: varint(1) }))
            .await
            .expect("write fetch header");
        framed.write_fetch_object(&object(0), &PAYLOAD).await.expect("write first object");
        framed.write_fetch_object(&object(1), &PAYLOAD).await.expect("write second object");
        framed.finish().await.expect("finish");

        let ((first, first_payload), (second, second_payload)) = reader.await.expect("reader task");
        assert_eq!(first.object_id.into_inner(), 0);
        assert_eq!(second.object_id.into_inner(), 1, "the second object is not the first again");
        assert_eq!(first_payload, PAYLOAD, "the payload comes back with the header it followed");
        assert_eq!(second_payload, PAYLOAD);
    }
}

#[cfg(feature = "draft16")]
mod draft16 {
    use super::{common, varint, EVERYTHING_EXPLICIT, PAYLOAD};
    use moqtap_client::draft16::connection::{FramedRecvStream, FramedSendStream};
    use moqtap_client::transport::{RecvStream, SendStream};
    use moqtap_codec::dispatch::AnyFetchHeader;
    use moqtap_codec::draft16::data_stream::{FetchHeader, FetchObjectHeader};
    use moqtap_codec::version::DraftVersion;

    fn object(id: u64) -> FetchObjectHeader {
        FetchObjectHeader {
            serialization_flags: varint(EVERYTHING_EXPLICIT),
            group_id: Some(varint(0)),
            subgroup_id: Some(varint(0)),
            object_id: Some(varint(id)),
            publisher_priority: Some(128),
            extensions: None,
            payload_length: varint(PAYLOAD.len() as u64),
        }
    }

    /// A fetch stream this client wrote is one it can read.
    #[tokio::test]
    async fn a_fetch_stream_this_client_wrote_is_one_it_can_read() {
        common::init_crypto();
        let alpn = DraftVersion::Draft16.quic_alpn();
        let (server, addr) = common::spawn_server(&[alpn]);

        let reader = tokio::spawn(async move {
            let conn = server.accept().await.expect("accept").await.expect("handshake");
            let recv = conn.accept_uni().await.expect("accept_uni");
            let mut framed = FramedRecvStream::new(RecvStream::Quic(recv), DraftVersion::Draft16);
            framed.read_fetch_header().await.expect("the fetch header");
            let first = framed.read_fetch_object().await.expect("the first object");
            let second = framed.read_fetch_object().await.expect("the second object");
            (first, second)
        });

        let client = common::client_endpoint(&[alpn]);
        let conn = client.connect(addr, "localhost").expect("connect").await.expect("handshake");
        let send = conn.open_uni().await.expect("open_uni");
        let mut framed = FramedSendStream::new(SendStream::Quic(send), DraftVersion::Draft16);
        framed
            .write_fetch_header(&AnyFetchHeader::Draft16(FetchHeader { request_id: varint(1) }))
            .await
            .expect("write fetch header");
        framed.write_fetch_object(&object(0), &PAYLOAD).await.expect("write first object");
        framed.write_fetch_object(&object(1), &PAYLOAD).await.expect("write second object");
        framed.finish().await.expect("finish");

        let ((first, first_payload), (second, second_payload)) = reader.await.expect("reader task");
        assert_eq!(first.object_id, Some(varint(0)));
        assert_eq!(second.object_id, Some(varint(1)), "the second object is not the first again");
        assert_eq!(first_payload, PAYLOAD, "the payload comes back with the header it followed");
        assert_eq!(second_payload, PAYLOAD);
    }
}

#[cfg(feature = "draft17")]
mod draft17 {
    use super::{common, varint, EVERYTHING_EXPLICIT, PAYLOAD};
    use moqtap_client::draft17::connection::{FramedRecvStream, FramedSendStream};
    use moqtap_client::transport::{RecvStream, SendStream};
    use moqtap_codec::dispatch::AnyFetchHeader;
    use moqtap_codec::draft17::data_stream::{FetchHeader, FetchObjectHeader};
    use moqtap_codec::version::DraftVersion;

    fn object(id: u64) -> FetchObjectHeader {
        FetchObjectHeader {
            serialization_flags: varint(EVERYTHING_EXPLICIT),
            group_id: Some(varint(0)),
            subgroup_id: Some(varint(0)),
            object_id: Some(varint(id)),
            publisher_priority: Some(128),
            properties: Vec::new(),
            payload_length: varint(PAYLOAD.len() as u64),
        }
    }

    /// An Object that states nothing but its Subgroup ID and payload length.
    ///
    /// Flags 0x03: Subgroup ID mode `0b11` puts the Subgroup ID on the wire and
    /// every other bit is clear, so the Group ID, Object ID and Priority are all
    /// the prior Object's — the Object ID stepped by one, the other two
    /// repeated. It is the shape a resolver exists for, and the shape a reader
    /// that hands the header back cannot say anything about.
    fn inheriting_object() -> FetchObjectHeader {
        FetchObjectHeader {
            serialization_flags: varint(0x03),
            group_id: None,
            subgroup_id: Some(varint(0)),
            object_id: None,
            publisher_priority: None,
            properties: Vec::new(),
            payload_length: varint(PAYLOAD.len() as u64),
        }
    }

    /// A fetch stream this client wrote is one it can read.
    ///
    /// The resolved Location is what comes back, not the flags: both Objects
    /// state every field here, so the interesting half is the gate below.
    ///
    /// Ablation: dropping the line in `read_fetch_header` that seeds the reader,
    /// so nothing starts it — `the first object:
    /// DataStreamState("fetch header not read yet")`. Draft-17 has no
    /// `begin_fetch_objects` and the header is the only thing that can start it,
    /// so the seeding is what makes this method reachable at all.
    #[tokio::test]
    async fn a_fetch_stream_this_client_wrote_is_one_it_can_read() {
        common::init_crypto();
        let alpn = DraftVersion::Draft17.quic_alpn();
        let (server, addr) = common::spawn_server(&[alpn]);

        let reader = tokio::spawn(async move {
            let conn = server.accept().await.expect("accept").await.expect("handshake");
            let recv = conn.accept_uni().await.expect("accept_uni");
            let mut framed = FramedRecvStream::new(RecvStream::Quic(recv), DraftVersion::Draft17);
            framed.read_fetch_header().await.expect("the fetch header");
            let first = framed.read_fetch_object().await.expect("the first object");
            let second = framed.read_fetch_object().await.expect("the second object");
            (first, second)
        });

        let client = common::client_endpoint(&[alpn]);
        let conn = client.connect(addr, "localhost").expect("connect").await.expect("handshake");
        let send = conn.open_uni().await.expect("open_uni");
        let mut framed = FramedSendStream::new(SendStream::Quic(send), DraftVersion::Draft17);
        framed
            .write_fetch_header(&AnyFetchHeader::Draft17(FetchHeader { request_id: varint(1) }))
            .await
            .expect("write fetch header");
        framed.write_fetch_object(&object(0), &PAYLOAD).await.expect("write first object");
        framed.write_fetch_object(&object(1), &PAYLOAD).await.expect("write second object");
        framed.finish().await.expect("finish");

        let ((first, first_payload), (second, second_payload)) = reader.await.expect("reader task");
        assert_eq!(first.group_id, 0);
        assert_eq!(first.object_id, 0);
        assert_eq!(second.group_id, 0);
        assert_eq!(second.object_id, 1, "the second object is not the first again");
        assert_eq!(first_payload, PAYLOAD, "the payload comes back with the object it followed");
        assert_eq!(second_payload, PAYLOAD);
    }

    /// An Object that states nothing comes back with the Location it inherited.
    ///
    /// Draft-17 Section 10.4.4.1, Table 8: an absent Group ID is the prior
    /// Object's, an absent Object ID is the prior Object's plus one, and an
    /// absent Priority is the prior Object's. The second Object here writes
    /// none of the three, so every field this asserts on is one the wire never
    /// carried — which is what separates a reader that resolves from one that
    /// hands the header back.
    ///
    /// Ablation: an absent Object ID takes the prior Object's without stepping
    /// it:
    ///
    /// ```text
    /// assertion `left == right` failed: an absent Object ID is the prior Object's plus one
    ///   left: 4
    ///  right: 5
    /// ```
    ///
    /// Repeating rather than stepping is the mistake the wording invites, and it
    /// hands two Objects the same Location rather than failing to decode.
    #[tokio::test]
    async fn an_object_that_states_nothing_comes_back_with_what_it_inherited() {
        common::init_crypto();
        let alpn = DraftVersion::Draft17.quic_alpn();
        let (server, addr) = common::spawn_server(&[alpn]);

        let reader = tokio::spawn(async move {
            let conn = server.accept().await.expect("accept").await.expect("handshake");
            let recv = conn.accept_uni().await.expect("accept_uni");
            let mut framed = FramedRecvStream::new(RecvStream::Quic(recv), DraftVersion::Draft17);
            framed.read_fetch_header().await.expect("the fetch header");
            let first = framed.read_fetch_object().await.expect("the first object");
            let second = framed.read_fetch_object().await.expect("the second object");
            (first, second)
        });

        let client = common::client_endpoint(&[alpn]);
        let conn = client.connect(addr, "localhost").expect("connect").await.expect("handshake");
        let send = conn.open_uni().await.expect("open_uni");
        let mut framed = FramedSendStream::new(SendStream::Quic(send), DraftVersion::Draft17);
        framed
            .write_fetch_header(&AnyFetchHeader::Draft17(FetchHeader { request_id: varint(7) }))
            .await
            .expect("write fetch header");
        framed.write_fetch_object(&object(4), &PAYLOAD).await.expect("write first object");
        framed
            .write_fetch_object(&inheriting_object(), &PAYLOAD)
            .await
            .expect("write second object");
        framed.finish().await.expect("finish");

        let ((_, _), (second, second_payload)) = reader.await.expect("reader task");
        assert!(second.header.group_id.is_none(), "the wire carried no Group ID");
        assert!(second.header.object_id.is_none(), "the wire carried no Object ID");
        assert!(second.header.publisher_priority.is_none(), "the wire carried no Priority");
        assert_eq!(second.group_id, 0, "an absent Group ID is the prior Object's");
        assert_eq!(second.object_id, 5, "an absent Object ID is the prior Object's plus one");
        assert_eq!(second.publisher_priority, Some(128), "an absent Priority is the prior one");
        assert_eq!(second_payload, PAYLOAD);
    }

    /// A first Object that inherits exactly one field, for each of the four it
    /// could inherit.
    ///
    /// Section 10.4.4.1: "If the first Object in the FETCH response uses a flag
    /// that references fields in the prior Object, the Subscriber MUST close the
    /// session with a PROTOCOL_VIOLATION." Four flags reference the prior Object
    /// and each is a separate refusal, so each is written on its own here. A
    /// frame that leaves all four off would be refused by whichever guard runs
    /// first, and would pass while three of the four were missing.
    ///
    /// Flag bits, from Table 8: the low two are the Subgroup ID mode, `0b11`
    /// putting it on the wire and `0b01` taking the prior Object's; 0x04 is the
    /// Object ID, 0x08 the Group ID, 0x10 the Priority.
    ///
    /// Ablation: the absent-Group-ID branch answers 0 instead of refusing when
    /// there is no prior Object — `a first Object has no prior Object to take a
    /// Group ID from`.
    ///
    /// The same ablation **passed** against the single-frame form of this gate,
    /// which wrote one Object inheriting all four fields: the Object ID and
    /// Priority guards still refused it, so three guards stood in for one and a
    /// missing guard was invisible. Four frames, four refusals, one each.
    #[tokio::test]
    async fn each_field_a_first_object_could_inherit_is_refused_on_its_own() {
        let inherits_group_id = FetchObjectHeader {
            serialization_flags: varint(0x03 | 0x04 | 0x10),
            group_id: None,
            subgroup_id: Some(varint(0)),
            object_id: Some(varint(0)),
            publisher_priority: Some(128),
            properties: Vec::new(),
            payload_length: varint(PAYLOAD.len() as u64),
        };
        let inherits_object_id = FetchObjectHeader {
            serialization_flags: varint(0x03 | 0x08 | 0x10),
            group_id: Some(varint(0)),
            subgroup_id: Some(varint(0)),
            object_id: None,
            publisher_priority: Some(128),
            properties: Vec::new(),
            payload_length: varint(PAYLOAD.len() as u64),
        };
        let inherits_priority = FetchObjectHeader {
            serialization_flags: varint(0x03 | 0x04 | 0x08),
            group_id: Some(varint(0)),
            subgroup_id: Some(varint(0)),
            object_id: Some(varint(0)),
            publisher_priority: None,
            properties: Vec::new(),
            payload_length: varint(PAYLOAD.len() as u64),
        };
        let inherits_subgroup_id = FetchObjectHeader {
            serialization_flags: varint(0x01 | 0x04 | 0x08 | 0x10),
            group_id: Some(varint(0)),
            subgroup_id: None,
            object_id: Some(varint(0)),
            publisher_priority: Some(128),
            properties: Vec::new(),
            payload_length: varint(PAYLOAD.len() as u64),
        };

        for (what, first) in [
            ("Group ID", inherits_group_id),
            ("Object ID", inherits_object_id),
            ("Priority", inherits_priority),
            ("Subgroup ID", inherits_subgroup_id),
        ] {
            common::init_crypto();
            let alpn = DraftVersion::Draft17.quic_alpn();
            let (server, addr) = common::spawn_server(&[alpn]);

            let reader = tokio::spawn(async move {
                let conn = server.accept().await.expect("accept").await.expect("handshake");
                let recv = conn.accept_uni().await.expect("accept_uni");
                let mut framed =
                    FramedRecvStream::new(RecvStream::Quic(recv), DraftVersion::Draft17);
                framed.read_fetch_header().await.expect("the fetch header");
                framed.read_fetch_object().await.is_err()
            });

            let client = common::client_endpoint(&[alpn]);
            let conn =
                client.connect(addr, "localhost").expect("connect").await.expect("handshake");
            let send = conn.open_uni().await.expect("open_uni");
            let mut framed = FramedSendStream::new(SendStream::Quic(send), DraftVersion::Draft17);
            framed
                .write_fetch_header(&AnyFetchHeader::Draft17(FetchHeader { request_id: varint(7) }))
                .await
                .expect("write fetch header");
            framed.write_fetch_object(&first, &PAYLOAD).await.expect("write the first object");
            framed.finish().await.expect("finish");

            assert!(
                reader.await.expect("reader task"),
                "a first Object has no prior Object to take a {what} from",
            );
        }
    }
}

#[cfg(feature = "draft18")]
mod draft18 {
    use super::{common, varint, EVERYTHING_EXPLICIT, PAYLOAD};
    use moqtap_client::draft18::connection::{FramedRecvStream, FramedSendStream};
    use moqtap_client::transport::{RecvStream, SendStream};
    use moqtap_codec::dispatch::AnyFetchHeader;
    use moqtap_codec::draft18::data_stream::{FetchHeader, FetchObjectHeader, GroupOrder};
    use moqtap_codec::version::DraftVersion;

    /// Both fields explicit. On the first Object of a stream the two deltas are
    /// the absolute Group ID and Object ID; on the ones after it a Group ID
    /// Delta is counted from the prior Group in the stream's Group Order, which
    /// is what the second gate below turns on.
    fn object(group_delta: u64, object_delta: u64) -> FetchObjectHeader {
        FetchObjectHeader {
            serialization_flags: EVERYTHING_EXPLICIT,
            group_id_delta: Some(varint(group_delta)),
            subgroup_id: Some(varint(0)),
            object_id_delta: Some(varint(object_delta)),
            publisher_priority: Some(128),
            properties: Vec::new(),
            payload_length: varint(PAYLOAD.len() as u64),
        }
    }

    /// A fetch stream this client wrote is one it can read.
    ///
    /// The resolved Location is what comes back, not the deltas: the second
    /// Object's Group ID Delta of 0 resolves to Group 1 under Ascending, because
    /// Section 11.4.4.1 counts a new Group as the prior one plus the delta plus
    /// one.
    #[tokio::test]
    async fn a_fetch_stream_this_client_wrote_is_one_it_can_read() {
        common::init_crypto();
        let alpn = DraftVersion::Draft18.quic_alpn();
        let (server, addr) = common::spawn_server(&[alpn]);

        let reader = tokio::spawn(async move {
            let conn = server.accept().await.expect("accept").await.expect("handshake");
            let recv = conn.accept_uni().await.expect("accept_uni");
            let mut framed = FramedRecvStream::new(RecvStream::Quic(recv), DraftVersion::Draft18);
            framed.read_fetch_header().await.expect("the fetch header");
            framed.begin_fetch_objects(GroupOrder::Ascending);
            let first = framed.read_fetch_object().await.expect("the first object");
            let second = framed.read_fetch_object().await.expect("the second object");
            (first, second)
        });

        let client = common::client_endpoint(&[alpn]);
        let conn = client.connect(addr, "localhost").expect("connect").await.expect("handshake");
        let send = conn.open_uni().await.expect("open_uni");
        let mut framed = FramedSendStream::new(SendStream::Quic(send), DraftVersion::Draft18);
        framed
            .write_fetch_header(&AnyFetchHeader::Draft18(FetchHeader { request_id: varint(1) }))
            .await
            .expect("write fetch header");
        framed.write_fetch_object(&object(0, 0), &PAYLOAD).await.expect("write first object");
        framed.write_fetch_object(&object(0, 1), &PAYLOAD).await.expect("write second object");
        framed.finish().await.expect("finish");

        let ((first, first_payload), (second, second_payload)) = reader.await.expect("reader task");
        assert_eq!(first.group_id, 0);
        assert_eq!(first.object_id, 0);
        assert_eq!(second.group_id, 1, "a Group ID Delta of 0 is the next Group, not this one");
        assert_eq!(second.object_id, 1);
        assert_eq!(first_payload, PAYLOAD, "the payload comes back with the object it followed");
        assert_eq!(second_payload, PAYLOAD);
    }

    /// The Group Order the reader was started in is the one it reads in.
    ///
    /// The same bytes, read as Descending, ask for the Group before Group 0.
    /// There is none, so the second Object does not decode — which is the
    /// consequence that says `begin_fetch_objects` carries its argument through
    /// rather than taking it and defaulting.
    ///
    /// It is also why draft-18 has this method at all: nothing on a fetch stream
    /// says which order its Groups are in, and an endpoint that guessed would
    /// mis-locate every Object after the first.
    #[tokio::test]
    async fn the_group_order_the_reader_was_started_in_is_the_one_it_reads_in() {
        common::init_crypto();
        let alpn = DraftVersion::Draft18.quic_alpn();
        let (server, addr) = common::spawn_server(&[alpn]);

        let reader = tokio::spawn(async move {
            let conn = server.accept().await.expect("accept").await.expect("handshake");
            let recv = conn.accept_uni().await.expect("accept_uni");
            let mut framed = FramedRecvStream::new(RecvStream::Quic(recv), DraftVersion::Draft18);
            framed.read_fetch_header().await.expect("the fetch header");
            framed.begin_fetch_objects(GroupOrder::Descending);
            let first = framed.read_fetch_object().await;
            let second = framed.read_fetch_object().await;
            (first.is_ok(), second.is_err())
        });

        let client = common::client_endpoint(&[alpn]);
        let conn = client.connect(addr, "localhost").expect("connect").await.expect("handshake");
        let send = conn.open_uni().await.expect("open_uni");
        let mut framed = FramedSendStream::new(SendStream::Quic(send), DraftVersion::Draft18);
        framed
            .write_fetch_header(&AnyFetchHeader::Draft18(FetchHeader { request_id: varint(1) }))
            .await
            .expect("write fetch header");
        framed.write_fetch_object(&object(0, 0), &PAYLOAD).await.expect("write first object");
        framed.write_fetch_object(&object(0, 1), &PAYLOAD).await.expect("write second object");
        framed.finish().await.expect("finish");

        let (first_read, second_refused) = reader.await.expect("reader task");
        assert!(first_read, "the first Object states its Location outright and reads either way");
        assert!(second_refused, "counting down from Group 0 reaches no Group at all");
    }
}

#[cfg(feature = "draft19")]
mod draft19 {
    use super::{common, varint, EVERYTHING_EXPLICIT, PAYLOAD};
    use moqtap_client::draft19::connection::{FramedRecvStream, FramedSendStream};
    use moqtap_client::transport::{RecvStream, SendStream};
    use moqtap_codec::dispatch::AnyFetchHeader;
    use moqtap_codec::draft19::data_stream::{FetchHeader, FetchObjectHeader, GroupOrder};
    use moqtap_codec::version::DraftVersion;

    /// Both fields explicit. On the first Object of a stream the two deltas are
    /// the absolute Group ID and Object ID; on the ones after it a Group ID
    /// Delta is counted from the prior Group in the stream's Group Order, which
    /// is what the second gate below turns on.
    fn object(object_delta: u64) -> FetchObjectHeader {
        FetchObjectHeader {
            serialization_flags: varint(EVERYTHING_EXPLICIT),
            group_id_delta: Some(varint(0)),
            subgroup_id: Some(varint(0)),
            object_id_delta: Some(varint(object_delta)),
            publisher_priority: Some(128),
            properties: None,
            payload_length: varint(PAYLOAD.len() as u64),
        }
    }

    /// A fetch stream this client wrote is one it can read.
    ///
    /// The resolved Location is what comes back, not the deltas: the second
    /// Object's Group ID Delta of 0 resolves to Group 1 under Ascending, because
    /// Section 11.4.4.1 counts a new Group as the prior one plus the delta plus
    /// one.
    #[tokio::test]
    async fn a_fetch_stream_this_client_wrote_is_one_it_can_read() {
        common::init_crypto();
        let alpn = DraftVersion::Draft19.quic_alpn();
        let (server, addr) = common::spawn_server(&[alpn]);

        let reader = tokio::spawn(async move {
            let conn = server.accept().await.expect("accept").await.expect("handshake");
            let recv = conn.accept_uni().await.expect("accept_uni");
            let mut framed = FramedRecvStream::new(RecvStream::Quic(recv), DraftVersion::Draft19);
            framed.read_fetch_header().await.expect("the fetch header");
            framed.begin_fetch_objects(GroupOrder::Ascending);
            let first = framed.read_fetch_object().await.expect("the first object");
            let second = framed.read_fetch_object().await.expect("the second object");
            (first, second)
        });

        let client = common::client_endpoint(&[alpn]);
        let conn = client.connect(addr, "localhost").expect("connect").await.expect("handshake");
        let send = conn.open_uni().await.expect("open_uni");
        let mut framed = FramedSendStream::new(SendStream::Quic(send), DraftVersion::Draft19);
        framed
            .write_fetch_header(&AnyFetchHeader::Draft19(FetchHeader { request_id: varint(1) }))
            .await
            .expect("write fetch header");
        framed.write_fetch_object(&object(0), &PAYLOAD).await.expect("write first object");
        framed.write_fetch_object(&object(1), &PAYLOAD).await.expect("write second object");
        framed.finish().await.expect("finish");

        let ((first, first_payload), (second, second_payload)) = reader.await.expect("reader task");
        assert_eq!(first.group_id, 0);
        assert_eq!(first.object_id, 0);
        assert_eq!(second.group_id, 1, "a Group ID Delta of 0 is the next Group, not this one");
        assert_eq!(second.object_id, 1);
        assert_eq!(first_payload, PAYLOAD, "the payload comes back with the object it followed");
        assert_eq!(second_payload, PAYLOAD);
    }

    /// The Group Order the reader was started in is the one it reads in.
    ///
    /// The same bytes, read as Descending, ask for the Group before Group 0.
    /// There is none, so the second Object does not decode — which is the
    /// consequence that says `begin_fetch_objects` carries its argument through
    /// rather than taking it and defaulting.
    ///
    /// It is also why draft-19 has this method at all, as draft-18 does: nothing
    /// on a fetch stream says which order its Groups are in, and an endpoint
    /// that guessed would mis-locate every Object after the first.
    ///
    /// Ablation: `FetchObjectReader::new` takes the order and stores Ascending
    /// regardless — `counting down from Group 0 reaches no Group at all`.
    #[tokio::test]
    async fn the_group_order_the_reader_was_started_in_is_the_one_it_reads_in() {
        common::init_crypto();
        let alpn = DraftVersion::Draft19.quic_alpn();
        let (server, addr) = common::spawn_server(&[alpn]);

        let reader = tokio::spawn(async move {
            let conn = server.accept().await.expect("accept").await.expect("handshake");
            let recv = conn.accept_uni().await.expect("accept_uni");
            let mut framed = FramedRecvStream::new(RecvStream::Quic(recv), DraftVersion::Draft19);
            framed.read_fetch_header().await.expect("the fetch header");
            framed.begin_fetch_objects(GroupOrder::Descending);
            let first = framed.read_fetch_object().await;
            let second = framed.read_fetch_object().await;
            (first.is_ok(), second.is_err())
        });

        let client = common::client_endpoint(&[alpn]);
        let conn = client.connect(addr, "localhost").expect("connect").await.expect("handshake");
        let send = conn.open_uni().await.expect("open_uni");
        let mut framed = FramedSendStream::new(SendStream::Quic(send), DraftVersion::Draft19);
        framed
            .write_fetch_header(&AnyFetchHeader::Draft19(FetchHeader { request_id: varint(1) }))
            .await
            .expect("write fetch header");
        framed.write_fetch_object(&object(0), &PAYLOAD).await.expect("write first object");
        framed.write_fetch_object(&object(1), &PAYLOAD).await.expect("write second object");
        framed.finish().await.expect("finish");

        let (first_read, second_refused) = reader.await.expect("reader task");
        assert!(first_read, "the first Object states its Location outright and reads either way");
        assert!(second_refused, "counting down from Group 0 reaches no Group at all");
    }

    /// Reading fetch objects without starting the reader is refused.
    ///
    /// Draft-19's reader cannot be seeded from the fetch header, because the
    /// header does not carry the Group Order. Defaulting to Ascending would
    /// decode a Descending stream into Locations that walk the wrong way and
    /// report success, so the absence is an error rather than an assumption.
    ///
    /// Ablation: an unstarted reader is started as Ascending instead of refused
    /// — `the reader was never given a Group Order`.
    #[tokio::test]
    async fn reading_before_the_reader_is_started_is_refused() {
        common::init_crypto();
        let alpn = DraftVersion::Draft19.quic_alpn();
        let (server, addr) = common::spawn_server(&[alpn]);

        let reader = tokio::spawn(async move {
            let conn = server.accept().await.expect("accept").await.expect("handshake");
            let recv = conn.accept_uni().await.expect("accept_uni");
            let mut framed = FramedRecvStream::new(RecvStream::Quic(recv), DraftVersion::Draft19);
            framed.read_fetch_header().await.expect("the fetch header");
            framed.read_fetch_object().await.is_err()
        });

        let client = common::client_endpoint(&[alpn]);
        let conn = client.connect(addr, "localhost").expect("connect").await.expect("handshake");
        let send = conn.open_uni().await.expect("open_uni");
        let mut framed = FramedSendStream::new(SendStream::Quic(send), DraftVersion::Draft19);
        framed
            .write_fetch_header(&AnyFetchHeader::Draft19(FetchHeader { request_id: varint(1) }))
            .await
            .expect("write fetch header");
        framed.write_fetch_object(&object(0), &PAYLOAD).await.expect("write first object");
        framed.finish().await.expect("finish");

        assert!(reader.await.expect("reader task"), "the reader was never given a Group Order");
    }
}
