#![cfg(any(feature = "draft15", feature = "draft17"))]

//! Both ways of reading a fetch header leave the stream able to read objects.
//!
//! `FramedRecvStream` has two: `read_fetch_header`, which returns an
//! `AnyFetchHeader`, and `read_fetch_stream_header`, which returns the draft's
//! own `FetchHeader` for a caller that already knows the draft. They consume
//! the same bytes off the same stream.
//!
//! Only the first used to seed `fetch_io`. `read_fetch_object` opens with
//!
//! ```text
//! if self.fetch_io.is_none() {
//!     return Err(ConnectionError::DataStreamState("fetch header not read yet"));
//! }
//! ```
//!
//! so a caller that reached for the typed accessor got that refusal about a
//! header it had just successfully read — and could not recover from it, because
//! the header's bytes were already consumed and a second read would decode the
//! first object's bytes as a header. A public method whose only effect is to
//! make the next call impossible is worth a gate.
//!
//! # Why only drafts 15 and 17
//!
//! `read_fetch_stream_header` exists on drafts 15 through 20, but the defect
//! needs `read_fetch_header` to seed where the typed one does not, and that is
//! true on exactly two of them:
//!
//! * **Draft-16** carries no reader state at all — its objects decode their
//!   framing individually, `read_fetch_object` has no `fetch_io` gate, and
//!   neither header method seeds anything.
//! * **Drafts 18 through 20** seed from `begin_fetch_objects(group_order)` and from
//!   nothing else, deliberately: their Group ID is a difference whose direction
//!   comes off the FETCH_OK, which a data stream never sees. Neither header
//!   method seeds there, so the two are equally unable to start a read and the
//!   typed one is not the odd sibling.
//!
//! Naming the reason rather than the count, because *two drafts* is what was
//! observed and *the drafts where one header reader seeds and the other does
//! not* is what the gate is about. Quote marks are reserved here for a draft's
//! own words, which neither of those is.
//!
//! # The second half: the method could not reach its own refill
//!
//! The seeding is not all that was wrong. The loop had no `ensure(1)` and its
//! short-read arm matched `CodecError::UnexpectedEnd` alone, but the
//! draft-specific `FetchHeader::decode` reports a varint that ran out of buffer
//! as `CodecError::VarInt(VarIntError::UnexpectedEnd)` — a different variant,
//! which fell through to the arm that returns. `read_fetch_header` never showed
//! it because `AnyFetchHeader::decode` reports the bare variant and because it
//! calls `ensure(1)` first.
//!
//! Since `buf` starts empty, that made the first call on a fresh stream fail
//! outright, which is the only way this method is ever reached. It is public on
//! five drafts and no caller in this workspace or its consumers has one, which
//! is the only reason nothing had noticed.
//!
//! # Ablations, measured
//!
//! Removing the `fetch_io` seeding from draft-15's `read_fetch_stream_header`,
//! under `--features draft15`:
//!
//! ```text
//! the typed header read must leave the stream able to read objects, and it did not: DataStreamState("fetch header not read yet")
//! ```
//!
//! Reverting the refill half — dropping the `ensure(1)` and the `VarInt`
//! arm — which is the state both drafts shipped in:
//!
//! ```text
//! the typed accessor must read the header the writer wrote: Codec(VarInt(UnexpectedEnd))
//! ```
//!
//! Two cuts because they fail in different places: the first gets a header and
//! cannot read an object, the second never gets a header at all. A gate that
//! only asserted the object read would report the same failure for both.

mod common;

/// Serialization Flags with every field stated explicitly, so the object the
/// writer builds does not depend on a prior one — this gate is about whether a
/// read can start at all, not about resolution.
const EVERYTHING_EXPLICIT: u64 = 0x1F;

const PAYLOAD: &[u8] = b"typed-read";
const REQUEST_ID: u64 = 9;

// One module per affected draft rather than a macro: the two `FetchObjectHeader`
// types are not one shape behind two names, and a macro would have to be read
// against both definitions to be checked.

#[cfg(feature = "draft15")]
mod draft15 {
    use super::{common, EVERYTHING_EXPLICIT, PAYLOAD, REQUEST_ID};
    use moqtap_client::draft15::connection::{FramedRecvStream, FramedSendStream};
    use moqtap_client::transport::{RecvStream, SendStream};
    use moqtap_codec::dispatch::AnyFetchHeader;
    use moqtap_codec::draft15::data_stream::{FetchHeader, FetchObjectHeader};
    use moqtap_codec::varint::VarInt;
    use moqtap_codec::version::DraftVersion;

    fn varint(v: u64) -> VarInt {
        VarInt::from_u64(v).unwrap()
    }

    #[tokio::test]
    async fn the_typed_header_read_leaves_the_stream_able_to_read_objects() {
        common::init_crypto();
        let alpn = DraftVersion::Draft15.quic_alpn();
        let (server, addr) = common::spawn_server(&[alpn]);

        let reader = tokio::spawn(async move {
            let conn = server.accept().await.expect("accept").await.expect("handshake");
            let recv = conn.accept_uni().await.expect("accept_uni");
            let mut framed = FramedRecvStream::new(RecvStream::Quic(recv), DraftVersion::Draft15);
            // The typed accessor, not `read_fetch_header`: that is the path
            // under test, and the two are interchangeable only if this works.
            let header = framed.read_fetch_stream_header().await;
            let object = framed.read_fetch_object().await;
            (header, object)
        });

        let client = common::client_endpoint(&[alpn]);
        let conn = client.connect(addr, "localhost").expect("connect").await.expect("handshake");
        let send = conn.open_uni().await.expect("open_uni");
        let mut framed = FramedSendStream::new(SendStream::Quic(send), DraftVersion::Draft15);
        framed
            .write_fetch_header(&AnyFetchHeader::Draft15(FetchHeader {
                request_id: varint(REQUEST_ID),
            }))
            .await
            .expect("write fetch header");
        let object = FetchObjectHeader {
            serialization_flags: EVERYTHING_EXPLICIT as u8,
            group_id: varint(0),
            subgroup_id: varint(0),
            object_id: varint(0),
            publisher_priority: 128,
            extension_headers: Vec::new(),
            payload_length: varint(PAYLOAD.len() as u64),
            object_status: None,
        };
        framed.write_fetch_object(&object, PAYLOAD).await.expect("write fetch object");
        framed.finish().await.expect("finish");

        let (header, object) = reader.await.expect("reader task");
        let header = header.expect("the typed accessor must read the header the writer wrote");
        assert_eq!(header.request_id.into_inner(), REQUEST_ID);

        let (_object_header, payload) = object.unwrap_or_else(|e| {
            panic!(
                "the typed header read must leave the stream able to read objects, and it did \
                 not: {e:?}"
            )
        });
        assert_eq!(payload, PAYLOAD, "the object read after a typed header read must be intact");
    }
}

#[cfg(feature = "draft17")]
mod draft17 {
    use super::{common, EVERYTHING_EXPLICIT, PAYLOAD, REQUEST_ID};
    use moqtap_client::draft17::connection::{FramedRecvStream, FramedSendStream};
    use moqtap_client::transport::{RecvStream, SendStream};
    use moqtap_codec::dispatch::AnyFetchHeader;
    use moqtap_codec::draft17::data_stream::{FetchHeader, FetchObjectHeader};
    use moqtap_codec::varint::VarInt;
    use moqtap_codec::version::DraftVersion;

    fn varint(v: u64) -> VarInt {
        VarInt::from_u64(v).unwrap()
    }

    #[tokio::test]
    async fn the_typed_header_read_leaves_the_stream_able_to_read_objects() {
        common::init_crypto();
        let alpn = DraftVersion::Draft17.quic_alpn();
        let (server, addr) = common::spawn_server(&[alpn]);

        let reader = tokio::spawn(async move {
            let conn = server.accept().await.expect("accept").await.expect("handshake");
            let recv = conn.accept_uni().await.expect("accept_uni");
            let mut framed = FramedRecvStream::new(RecvStream::Quic(recv), DraftVersion::Draft17);
            let header = framed.read_fetch_stream_header().await;
            let object = framed.read_fetch_object().await;
            (header, object)
        });

        let client = common::client_endpoint(&[alpn]);
        let conn = client.connect(addr, "localhost").expect("connect").await.expect("handshake");
        let send = conn.open_uni().await.expect("open_uni");
        let mut framed = FramedSendStream::new(SendStream::Quic(send), DraftVersion::Draft17);
        framed
            .write_fetch_header(&AnyFetchHeader::Draft17(FetchHeader {
                request_id: varint(REQUEST_ID),
            }))
            .await
            .expect("write fetch header");
        let object = FetchObjectHeader {
            serialization_flags: varint(EVERYTHING_EXPLICIT),
            group_id: Some(varint(0)),
            subgroup_id: Some(varint(0)),
            object_id: Some(varint(0)),
            publisher_priority: Some(128),
            properties: Vec::new(),
            payload_length: varint(PAYLOAD.len() as u64),
        };
        framed.write_fetch_object(&object, PAYLOAD).await.expect("write fetch object");
        framed.finish().await.expect("finish");

        let (header, object) = reader.await.expect("reader task");
        let header = header.expect("the typed accessor must read the header the writer wrote");
        assert_eq!(header.request_id.into_inner(), REQUEST_ID);

        let (_object_header, payload) = object.unwrap_or_else(|e| {
            panic!(
                "the typed header read must leave the stream able to read objects, and it did \
                 not: {e:?}"
            )
        });
        assert_eq!(payload, PAYLOAD, "the object read after a typed header read must be intact");
    }
}
