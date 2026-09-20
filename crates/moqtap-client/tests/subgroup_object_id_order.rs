//! A subgroup stream's Object IDs must advance, and the client's write path is
//! where that is settled.
//!
//! Drafts 07 through 13 each state it once, of the subgroup stream: "A publisher
//! MUST NOT send an Object on a stream if its Object ID is less than a
//! previously sent Object ID within a given group in that stream." Drafts 14 and
//! later encode the ID as a delta from the object before it, so a repeat or a
//! decrease underflows the subtraction and the per-draft writer already refuses
//! it - those seven need nothing and have nothing here.
//!
//! # Why this is not an `encode_checked` test
//!
//! `encode_checked` is handed one header. The rule compares that header against
//! the object before it on the same stream, and a per-header check has no memory
//! to compare against. So the state belongs to the stream, and the gate drives
//! the object at the thing that owns the stream: `FramedSendStream`, over a real
//! loopback QUIC connection. A test against a helper beside the write path would
//! pass just as well if the write path never called it.
//!
//! # What each draft asserts
//!
//! * Ascending IDs are written.
//! * An ID equal to the last one written is refused.
//! * An ID below the last one written is refused.
//! * A refused object does not advance the state, so the stream stays usable and
//!   the next legal ID is still measured against the last one *kept*.
//! * An object written before any subgroup header is refused, because there is
//!   no stream state for it to be measured against and the bytes would land
//!   in front of the header that frames them.
//!
//! # Recorded failures
//!
//! Each was produced by making the change and running the tests, on draft-07.
//!
//! Dropping the comparison - keeping the state but never reading it:
//!
//! ```text
//! an object may not repeat the id of the one before it: Ok(())
//! ```
//!
//! Refusing only an id equal to the last one, letting a smaller one through:
//!
//! ```text
//! an object may not go backwards: Ok(())
//! ```
//!
//! Moving the mark to the id of a refused object instead of leaving it on the
//! last one written:
//!
//! ```text
//! the mark stays on the last object written, not the last one refused: Ok(())
//! ```
//!
//! Seeding the state in `FramedSendStream::new` instead of in
//! `write_subgroup_header`:
//!
//! ```text
//! an object cannot precede the header that frames it: Ok(())
//! ```

mod common;

use moqtap_codec::varint::VarInt;

/// Unread in a build that enables only drafts whose gates do not use it.
#[allow(dead_code)]
fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap()
}

/// A live loopback QUIC connection and one unidirectional stream on it.
///
/// The server end accepts and then does nothing: what is under test is what the
/// writer agrees to write, and a reader on the far side would not change any of
/// it. The endpoint is returned so it outlives the stream.
/// Unread in a build that enables only drafts whose gates do not use it.
#[allow(dead_code)]
async fn loopback_uni(alpn: &[u8]) -> (quinn::Endpoint, quinn::Connection, quinn::SendStream) {
    common::init_crypto();
    let (server, addr) = common::spawn_server(&[alpn]);
    tokio::spawn(async move {
        if let Some(incoming) = server.accept().await {
            let _ = incoming.await;
            // Hold the connection open for the life of the test.
            std::future::pending::<()>().await;
        }
    });
    let client = common::client_endpoint(&[alpn]);
    let conn = client.connect(addr, "localhost").expect("connect").await.expect("tls handshake");
    let send = conn.open_uni().await.expect("open_uni");
    (client, conn, send)
}

#[cfg(feature = "draft07")]
mod draft07 {
    use super::{loopback_uni, varint};
    use moqtap_client::draft07::connection::FramedSendStream;
    use moqtap_client::draft07::event::SubgroupObject;
    use moqtap_client::transport::SendStream;
    use moqtap_codec::dispatch::AnySubgroupHeader;
    use moqtap_codec::draft07::data_stream::*;
    use moqtap_codec::draft07::types::ObjectStatus;
    use moqtap_codec::version::DraftVersion;

    fn header() -> AnySubgroupHeader {
        AnySubgroupHeader::Draft07(SubgroupHeader {
            track_alias: varint(1),
            group_id: varint(0),
            subgroup_id: varint(0),
            publisher_priority: 128,
        })
    }

    fn object(id: u64) -> SubgroupObject {
        SubgroupObject {
            header: ObjectHeader {
                object_id: varint(id),
                payload_length: varint(0),
                object_status: ObjectStatus::Normal,
            },
            payload: Vec::new(),
        }
    }

    /// A stream with its header written and nothing on it yet.
    async fn opened() -> (quinn::Endpoint, quinn::Connection, FramedSendStream) {
        let (endpoint, conn, send) = loopback_uni(DraftVersion::Draft07.quic_alpn()).await;
        let mut framed = FramedSendStream::new(SendStream::Quic(send));
        framed.write_subgroup_header(&header()).await.expect("write subgroup header");
        (endpoint, conn, framed)
    }

    /// Section 7.3.1: an Object ID may not be less than one already sent on the
    /// stream. Nor equal to it - see `write_subgroup_object` for why the line is
    /// drawn there.
    #[tokio::test]
    async fn object_ids_must_advance_on_a_subgroup_stream() {
        let (_endpoint, _conn, mut framed) = opened().await;

        framed.write_subgroup_object(&object(0)).await.expect("the first object sets the mark");
        framed.write_subgroup_object(&object(5)).await.expect("5 is past 0");

        let repeat = framed.write_subgroup_object(&object(5)).await;
        assert!(
            repeat.is_err(),
            "an object may not repeat the id of the one before it: {repeat:?}"
        );

        let backwards = framed.write_subgroup_object(&object(1)).await;
        assert!(backwards.is_err(), "an object may not go backwards: {backwards:?}");
    }

    /// A refused object leaves the mark on the last object actually written.
    ///
    /// Both halves of that are asserted, because each alone is satisfied by a
    /// mistake the other catches. An id chosen above the refused one would still
    /// be accepted if the mark had moved down to it, so the id tried next here is
    /// one that sits **between** the refused object and the last one kept: with
    /// the mark where it belongs it is behind and refused, and with the mark on
    /// the refused id it is ahead and would go out. Then a genuinely later id
    /// shows the stream is still usable rather than poisoned by the refusal.
    #[tokio::test]
    async fn a_refused_object_does_not_move_the_mark() {
        let (_endpoint, _conn, mut framed) = opened().await;

        framed.write_subgroup_object(&object(4)).await.expect("the first object sets the mark");
        assert!(framed.write_subgroup_object(&object(2)).await.is_err(), "2 is behind 4");

        let between = framed.write_subgroup_object(&object(3)).await;
        assert!(
            between.is_err(),
            "the mark stays on the last object written, not the last one refused: {between:?}",
        );

        let ahead = framed.write_subgroup_object(&object(5)).await;
        assert!(ahead.is_ok(), "and a refusal does not poison the stream: {ahead:?}");
    }

    /// An object written before the subgroup header would land in front of the
    /// framing that describes it, and there is no previous id to measure it
    /// against either.
    #[tokio::test]
    async fn an_object_needs_its_header_first() {
        let (_endpoint, _conn, send) = loopback_uni(DraftVersion::Draft07.quic_alpn()).await;
        let mut framed = FramedSendStream::new(SendStream::Quic(send));

        let early = framed.write_subgroup_object(&object(0)).await;
        assert!(early.is_err(), "an object cannot precede the header that frames it: {early:?}");

        framed.write_subgroup_header(&header()).await.expect("write subgroup header");
        framed.write_subgroup_object(&object(0)).await.expect("and after the header it is fine");
    }
}

#[cfg(feature = "draft08")]
mod draft08 {
    use super::{loopback_uni, varint};
    use moqtap_client::draft08::connection::FramedSendStream;
    use moqtap_client::draft08::event::SubgroupObject;
    use moqtap_client::transport::SendStream;
    use moqtap_codec::dispatch::AnySubgroupHeader;
    use moqtap_codec::draft08::data_stream::*;
    use moqtap_codec::draft08::types::ObjectStatus;
    use moqtap_codec::version::DraftVersion;

    fn header() -> AnySubgroupHeader {
        AnySubgroupHeader::Draft08(SubgroupHeader {
            track_alias: varint(1),
            group_id: varint(0),
            subgroup_id: varint(0),
            publisher_priority: 128,
        })
    }

    fn object(id: u64) -> SubgroupObject {
        SubgroupObject {
            header: ObjectHeader {
                object_id: varint(id),
                extension_count: varint(0),
                extensions: Vec::new(),
                payload_length: varint(0),
                object_status: ObjectStatus::Normal,
            },
            payload: Vec::new(),
        }
    }

    /// A stream with its header written and nothing on it yet.
    async fn opened() -> (quinn::Endpoint, quinn::Connection, FramedSendStream) {
        let (endpoint, conn, send) = loopback_uni(DraftVersion::Draft08.quic_alpn()).await;
        let mut framed = FramedSendStream::new(SendStream::Quic(send));
        framed.write_subgroup_header(&header()).await.expect("write subgroup header");
        (endpoint, conn, framed)
    }

    /// Section 8.4.1: an Object ID may not be less than one already sent on the
    /// stream. Nor equal to it - see `write_subgroup_object` for why the line is
    /// drawn there.
    #[tokio::test]
    async fn object_ids_must_advance_on_a_subgroup_stream() {
        let (_endpoint, _conn, mut framed) = opened().await;

        framed.write_subgroup_object(&object(0)).await.expect("the first object sets the mark");
        framed.write_subgroup_object(&object(5)).await.expect("5 is past 0");

        let repeat = framed.write_subgroup_object(&object(5)).await;
        assert!(
            repeat.is_err(),
            "an object may not repeat the id of the one before it: {repeat:?}"
        );

        let backwards = framed.write_subgroup_object(&object(1)).await;
        assert!(backwards.is_err(), "an object may not go backwards: {backwards:?}");
    }

    /// A refused object leaves the mark on the last object actually written.
    ///
    /// Both halves of that are asserted, because each alone is satisfied by a
    /// mistake the other catches. An id chosen above the refused one would still
    /// be accepted if the mark had moved down to it, so the id tried next here is
    /// one that sits **between** the refused object and the last one kept: with
    /// the mark where it belongs it is behind and refused, and with the mark on
    /// the refused id it is ahead and would go out. Then a genuinely later id
    /// shows the stream is still usable rather than poisoned by the refusal.
    #[tokio::test]
    async fn a_refused_object_does_not_move_the_mark() {
        let (_endpoint, _conn, mut framed) = opened().await;

        framed.write_subgroup_object(&object(4)).await.expect("the first object sets the mark");
        assert!(framed.write_subgroup_object(&object(2)).await.is_err(), "2 is behind 4");

        let between = framed.write_subgroup_object(&object(3)).await;
        assert!(
            between.is_err(),
            "the mark stays on the last object written, not the last one refused: {between:?}",
        );

        let ahead = framed.write_subgroup_object(&object(5)).await;
        assert!(ahead.is_ok(), "and a refusal does not poison the stream: {ahead:?}");
    }

    /// An object written before the subgroup header would land in front of the
    /// framing that describes it, and there is no previous id to measure it
    /// against either.
    #[tokio::test]
    async fn an_object_needs_its_header_first() {
        let (_endpoint, _conn, send) = loopback_uni(DraftVersion::Draft08.quic_alpn()).await;
        let mut framed = FramedSendStream::new(SendStream::Quic(send));

        let early = framed.write_subgroup_object(&object(0)).await;
        assert!(early.is_err(), "an object cannot precede the header that frames it: {early:?}");

        framed.write_subgroup_header(&header()).await.expect("write subgroup header");
        framed.write_subgroup_object(&object(0)).await.expect("and after the header it is fine");
    }
}

#[cfg(feature = "draft09")]
mod draft09 {
    use super::{loopback_uni, varint};
    use moqtap_client::draft09::connection::FramedSendStream;
    use moqtap_client::draft09::event::SubgroupObject;
    use moqtap_client::transport::SendStream;
    use moqtap_codec::dispatch::AnySubgroupHeader;
    use moqtap_codec::draft09::data_stream::*;
    use moqtap_codec::draft09::types::ObjectStatus;
    use moqtap_codec::version::DraftVersion;

    fn header() -> AnySubgroupHeader {
        AnySubgroupHeader::Draft09(SubgroupHeader {
            track_alias: varint(1),
            group_id: varint(0),
            subgroup_id: varint(0),
            publisher_priority: 128,
        })
    }

    fn object(id: u64) -> SubgroupObject {
        SubgroupObject {
            header: ObjectHeader {
                object_id: varint(id),
                extension_headers_length: varint(0),
                extensions: Vec::new(),
                payload_length: varint(0),
                object_status: ObjectStatus::Normal,
            },
            payload: Vec::new(),
        }
    }

    /// A stream with its header written and nothing on it yet.
    async fn opened() -> (quinn::Endpoint, quinn::Connection, FramedSendStream) {
        let (endpoint, conn, send) = loopback_uni(DraftVersion::Draft09.quic_alpn()).await;
        let mut framed = FramedSendStream::new(SendStream::Quic(send));
        framed.write_subgroup_header(&header()).await.expect("write subgroup header");
        (endpoint, conn, framed)
    }

    /// Section 8.4.1: an Object ID may not be less than one already sent on the
    /// stream. Nor equal to it - see `write_subgroup_object` for why the line is
    /// drawn there.
    #[tokio::test]
    async fn object_ids_must_advance_on_a_subgroup_stream() {
        let (_endpoint, _conn, mut framed) = opened().await;

        framed.write_subgroup_object(&object(0)).await.expect("the first object sets the mark");
        framed.write_subgroup_object(&object(5)).await.expect("5 is past 0");

        let repeat = framed.write_subgroup_object(&object(5)).await;
        assert!(
            repeat.is_err(),
            "an object may not repeat the id of the one before it: {repeat:?}"
        );

        let backwards = framed.write_subgroup_object(&object(1)).await;
        assert!(backwards.is_err(), "an object may not go backwards: {backwards:?}");
    }

    /// A refused object leaves the mark on the last object actually written.
    ///
    /// Both halves of that are asserted, because each alone is satisfied by a
    /// mistake the other catches. An id chosen above the refused one would still
    /// be accepted if the mark had moved down to it, so the id tried next here is
    /// one that sits **between** the refused object and the last one kept: with
    /// the mark where it belongs it is behind and refused, and with the mark on
    /// the refused id it is ahead and would go out. Then a genuinely later id
    /// shows the stream is still usable rather than poisoned by the refusal.
    #[tokio::test]
    async fn a_refused_object_does_not_move_the_mark() {
        let (_endpoint, _conn, mut framed) = opened().await;

        framed.write_subgroup_object(&object(4)).await.expect("the first object sets the mark");
        assert!(framed.write_subgroup_object(&object(2)).await.is_err(), "2 is behind 4");

        let between = framed.write_subgroup_object(&object(3)).await;
        assert!(
            between.is_err(),
            "the mark stays on the last object written, not the last one refused: {between:?}",
        );

        let ahead = framed.write_subgroup_object(&object(5)).await;
        assert!(ahead.is_ok(), "and a refusal does not poison the stream: {ahead:?}");
    }

    /// An object written before the subgroup header would land in front of the
    /// framing that describes it, and there is no previous id to measure it
    /// against either.
    #[tokio::test]
    async fn an_object_needs_its_header_first() {
        let (_endpoint, _conn, send) = loopback_uni(DraftVersion::Draft09.quic_alpn()).await;
        let mut framed = FramedSendStream::new(SendStream::Quic(send));

        let early = framed.write_subgroup_object(&object(0)).await;
        assert!(early.is_err(), "an object cannot precede the header that frames it: {early:?}");

        framed.write_subgroup_header(&header()).await.expect("write subgroup header");
        framed.write_subgroup_object(&object(0)).await.expect("and after the header it is fine");
    }
}

#[cfg(feature = "draft10")]
mod draft10 {
    use super::{loopback_uni, varint};
    use moqtap_client::draft10::connection::FramedSendStream;
    use moqtap_client::draft10::event::SubgroupObject;
    use moqtap_client::transport::SendStream;
    use moqtap_codec::dispatch::AnySubgroupHeader;
    use moqtap_codec::draft10::data_stream::*;
    use moqtap_codec::draft10::types::ObjectStatus;
    use moqtap_codec::version::DraftVersion;

    fn header() -> AnySubgroupHeader {
        AnySubgroupHeader::Draft10(SubgroupHeader {
            track_alias: varint(1),
            group_id: varint(0),
            subgroup_id: varint(0),
            publisher_priority: 128,
        })
    }

    fn object(id: u64) -> SubgroupObject {
        SubgroupObject {
            header: ObjectHeader {
                object_id: varint(id),
                extension_headers_length: varint(0),
                extensions: Vec::new(),
                payload_length: varint(0),
                object_status: ObjectStatus::Normal,
            },
            payload: Vec::new(),
        }
    }

    /// A stream with its header written and nothing on it yet.
    async fn opened() -> (quinn::Endpoint, quinn::Connection, FramedSendStream) {
        let (endpoint, conn, send) = loopback_uni(DraftVersion::Draft10.quic_alpn()).await;
        let mut framed = FramedSendStream::new(SendStream::Quic(send));
        framed.write_subgroup_header(&header()).await.expect("write subgroup header");
        (endpoint, conn, framed)
    }

    /// Section 9.4.2: an Object ID may not be less than one already sent on the
    /// stream. Nor equal to it - see `write_subgroup_object` for why the line is
    /// drawn there.
    #[tokio::test]
    async fn object_ids_must_advance_on_a_subgroup_stream() {
        let (_endpoint, _conn, mut framed) = opened().await;

        framed.write_subgroup_object(&object(0)).await.expect("the first object sets the mark");
        framed.write_subgroup_object(&object(5)).await.expect("5 is past 0");

        let repeat = framed.write_subgroup_object(&object(5)).await;
        assert!(
            repeat.is_err(),
            "an object may not repeat the id of the one before it: {repeat:?}"
        );

        let backwards = framed.write_subgroup_object(&object(1)).await;
        assert!(backwards.is_err(), "an object may not go backwards: {backwards:?}");
    }

    /// A refused object leaves the mark on the last object actually written.
    ///
    /// Both halves of that are asserted, because each alone is satisfied by a
    /// mistake the other catches. An id chosen above the refused one would still
    /// be accepted if the mark had moved down to it, so the id tried next here is
    /// one that sits **between** the refused object and the last one kept: with
    /// the mark where it belongs it is behind and refused, and with the mark on
    /// the refused id it is ahead and would go out. Then a genuinely later id
    /// shows the stream is still usable rather than poisoned by the refusal.
    #[tokio::test]
    async fn a_refused_object_does_not_move_the_mark() {
        let (_endpoint, _conn, mut framed) = opened().await;

        framed.write_subgroup_object(&object(4)).await.expect("the first object sets the mark");
        assert!(framed.write_subgroup_object(&object(2)).await.is_err(), "2 is behind 4");

        let between = framed.write_subgroup_object(&object(3)).await;
        assert!(
            between.is_err(),
            "the mark stays on the last object written, not the last one refused: {between:?}",
        );

        let ahead = framed.write_subgroup_object(&object(5)).await;
        assert!(ahead.is_ok(), "and a refusal does not poison the stream: {ahead:?}");
    }

    /// An object written before the subgroup header would land in front of the
    /// framing that describes it, and there is no previous id to measure it
    /// against either.
    #[tokio::test]
    async fn an_object_needs_its_header_first() {
        let (_endpoint, _conn, send) = loopback_uni(DraftVersion::Draft10.quic_alpn()).await;
        let mut framed = FramedSendStream::new(SendStream::Quic(send));

        let early = framed.write_subgroup_object(&object(0)).await;
        assert!(early.is_err(), "an object cannot precede the header that frames it: {early:?}");

        framed.write_subgroup_header(&header()).await.expect("write subgroup header");
        framed.write_subgroup_object(&object(0)).await.expect("and after the header it is fine");
    }
}

#[cfg(feature = "draft11")]
mod draft11 {
    use super::{loopback_uni, varint};
    use moqtap_client::draft11::connection::FramedSendStream;
    use moqtap_client::draft11::event::SubgroupObject;
    use moqtap_client::transport::SendStream;
    use moqtap_codec::dispatch::AnySubgroupHeader;
    use moqtap_codec::draft11::data_stream::*;
    use moqtap_codec::draft11::types::ObjectStatus;
    use moqtap_codec::version::DraftVersion;

    fn header() -> AnySubgroupHeader {
        AnySubgroupHeader::Draft11(SubgroupHeader {
            stream_type: StreamType::SubgroupExplicit,
            track_alias: varint(1),
            group_id: varint(0),
            subgroup_id: varint(0),
            publisher_priority: 128,
        })
    }

    fn object(id: u64) -> SubgroupObject {
        SubgroupObject {
            header: ObjectHeader {
                object_id: varint(id),
                extension_headers_length: varint(0),
                extensions: Vec::new(),
                payload_length: varint(0),
                object_status: ObjectStatus::Normal,
            },
            payload: Vec::new(),
        }
    }

    /// A stream with its header written and nothing on it yet.
    async fn opened() -> (quinn::Endpoint, quinn::Connection, FramedSendStream) {
        let (endpoint, conn, send) = loopback_uni(DraftVersion::Draft11.quic_alpn()).await;
        let mut framed = FramedSendStream::new(SendStream::Quic(send));
        framed.write_subgroup_header(&header()).await.expect("write subgroup header");
        (endpoint, conn, framed)
    }

    /// Section 9.4.2: an Object ID may not be less than one already sent on the
    /// stream. Nor equal to it - see `write_subgroup_object` for why the line is
    /// drawn there.
    #[tokio::test]
    async fn object_ids_must_advance_on_a_subgroup_stream() {
        let (_endpoint, _conn, mut framed) = opened().await;

        framed.write_subgroup_object(&object(0)).await.expect("the first object sets the mark");
        framed.write_subgroup_object(&object(5)).await.expect("5 is past 0");

        let repeat = framed.write_subgroup_object(&object(5)).await;
        assert!(
            repeat.is_err(),
            "an object may not repeat the id of the one before it: {repeat:?}"
        );

        let backwards = framed.write_subgroup_object(&object(1)).await;
        assert!(backwards.is_err(), "an object may not go backwards: {backwards:?}");
    }

    /// A refused object leaves the mark on the last object actually written.
    ///
    /// Both halves of that are asserted, because each alone is satisfied by a
    /// mistake the other catches. An id chosen above the refused one would still
    /// be accepted if the mark had moved down to it, so the id tried next here is
    /// one that sits **between** the refused object and the last one kept: with
    /// the mark where it belongs it is behind and refused, and with the mark on
    /// the refused id it is ahead and would go out. Then a genuinely later id
    /// shows the stream is still usable rather than poisoned by the refusal.
    #[tokio::test]
    async fn a_refused_object_does_not_move_the_mark() {
        let (_endpoint, _conn, mut framed) = opened().await;

        framed.write_subgroup_object(&object(4)).await.expect("the first object sets the mark");
        assert!(framed.write_subgroup_object(&object(2)).await.is_err(), "2 is behind 4");

        let between = framed.write_subgroup_object(&object(3)).await;
        assert!(
            between.is_err(),
            "the mark stays on the last object written, not the last one refused: {between:?}",
        );

        let ahead = framed.write_subgroup_object(&object(5)).await;
        assert!(ahead.is_ok(), "and a refusal does not poison the stream: {ahead:?}");
    }

    /// An object written before the subgroup header would land in front of the
    /// framing that describes it, and there is no previous id to measure it
    /// against either.
    #[tokio::test]
    async fn an_object_needs_its_header_first() {
        let (_endpoint, _conn, send) = loopback_uni(DraftVersion::Draft11.quic_alpn()).await;
        let mut framed = FramedSendStream::new(SendStream::Quic(send));

        let early = framed.write_subgroup_object(&object(0)).await;
        assert!(early.is_err(), "an object cannot precede the header that frames it: {early:?}");

        framed.write_subgroup_header(&header()).await.expect("write subgroup header");
        framed.write_subgroup_object(&object(0)).await.expect("and after the header it is fine");
    }
}

#[cfg(feature = "draft12")]
mod draft12 {
    use super::{loopback_uni, varint};
    use moqtap_client::draft12::connection::FramedSendStream;
    use moqtap_client::draft12::event::SubgroupObject;
    use moqtap_client::transport::SendStream;
    use moqtap_codec::dispatch::AnySubgroupHeader;
    use moqtap_codec::draft12::data_stream::*;
    use moqtap_codec::draft12::types::ObjectStatus;
    use moqtap_codec::version::DraftVersion;

    fn header() -> AnySubgroupHeader {
        AnySubgroupHeader::Draft12(SubgroupHeader {
            stream_type: StreamType::SubgroupExplicit,
            track_alias: varint(1),
            group_id: varint(0),
            subgroup_id: varint(0),
            publisher_priority: 128,
        })
    }

    fn object(id: u64) -> SubgroupObject {
        SubgroupObject {
            header: ObjectHeader {
                object_id: varint(id),
                extension_headers_length: varint(0),
                extensions: Vec::new(),
                payload_length: varint(0),
                object_status: ObjectStatus::Normal,
            },
            payload: Vec::new(),
        }
    }

    /// A stream with its header written and nothing on it yet.
    async fn opened() -> (quinn::Endpoint, quinn::Connection, FramedSendStream) {
        let (endpoint, conn, send) = loopback_uni(DraftVersion::Draft12.quic_alpn()).await;
        let mut framed = FramedSendStream::new(SendStream::Quic(send));
        framed.write_subgroup_header(&header()).await.expect("write subgroup header");
        (endpoint, conn, framed)
    }

    /// Section 9.4.2: an Object ID may not be less than one already sent on the
    /// stream. Nor equal to it - see `write_subgroup_object` for why the line is
    /// drawn there.
    #[tokio::test]
    async fn object_ids_must_advance_on_a_subgroup_stream() {
        let (_endpoint, _conn, mut framed) = opened().await;

        framed.write_subgroup_object(&object(0)).await.expect("the first object sets the mark");
        framed.write_subgroup_object(&object(5)).await.expect("5 is past 0");

        let repeat = framed.write_subgroup_object(&object(5)).await;
        assert!(
            repeat.is_err(),
            "an object may not repeat the id of the one before it: {repeat:?}"
        );

        let backwards = framed.write_subgroup_object(&object(1)).await;
        assert!(backwards.is_err(), "an object may not go backwards: {backwards:?}");
    }

    /// A refused object leaves the mark on the last object actually written.
    ///
    /// Both halves of that are asserted, because each alone is satisfied by a
    /// mistake the other catches. An id chosen above the refused one would still
    /// be accepted if the mark had moved down to it, so the id tried next here is
    /// one that sits **between** the refused object and the last one kept: with
    /// the mark where it belongs it is behind and refused, and with the mark on
    /// the refused id it is ahead and would go out. Then a genuinely later id
    /// shows the stream is still usable rather than poisoned by the refusal.
    #[tokio::test]
    async fn a_refused_object_does_not_move_the_mark() {
        let (_endpoint, _conn, mut framed) = opened().await;

        framed.write_subgroup_object(&object(4)).await.expect("the first object sets the mark");
        assert!(framed.write_subgroup_object(&object(2)).await.is_err(), "2 is behind 4");

        let between = framed.write_subgroup_object(&object(3)).await;
        assert!(
            between.is_err(),
            "the mark stays on the last object written, not the last one refused: {between:?}",
        );

        let ahead = framed.write_subgroup_object(&object(5)).await;
        assert!(ahead.is_ok(), "and a refusal does not poison the stream: {ahead:?}");
    }

    /// An object written before the subgroup header would land in front of the
    /// framing that describes it, and there is no previous id to measure it
    /// against either.
    #[tokio::test]
    async fn an_object_needs_its_header_first() {
        let (_endpoint, _conn, send) = loopback_uni(DraftVersion::Draft12.quic_alpn()).await;
        let mut framed = FramedSendStream::new(SendStream::Quic(send));

        let early = framed.write_subgroup_object(&object(0)).await;
        assert!(early.is_err(), "an object cannot precede the header that frames it: {early:?}");

        framed.write_subgroup_header(&header()).await.expect("write subgroup header");
        framed.write_subgroup_object(&object(0)).await.expect("and after the header it is fine");
    }
}

#[cfg(feature = "draft13")]
mod draft13 {
    use super::{loopback_uni, varint};
    use moqtap_client::draft13::connection::FramedSendStream;
    use moqtap_client::draft13::event::SubgroupObject;
    use moqtap_client::transport::SendStream;
    use moqtap_codec::dispatch::AnySubgroupHeader;
    use moqtap_codec::draft13::data_stream::*;
    use moqtap_codec::draft13::types::ObjectStatus;
    use moqtap_codec::version::DraftVersion;

    fn header() -> AnySubgroupHeader {
        AnySubgroupHeader::Draft13(SubgroupHeader {
            stream_type: StreamType::SubgroupExplicit,
            track_alias: varint(1),
            group_id: varint(0),
            subgroup_id: varint(0),
            publisher_priority: 128,
        })
    }

    fn object(id: u64) -> SubgroupObject {
        SubgroupObject {
            header: ObjectHeader {
                object_id: varint(id),
                extension_headers_length: varint(0),
                extensions: Vec::new(),
                payload_length: varint(0),
                object_status: ObjectStatus::Normal,
            },
            payload: Vec::new(),
        }
    }

    /// A stream with its header written and nothing on it yet.
    async fn opened() -> (quinn::Endpoint, quinn::Connection, FramedSendStream) {
        let (endpoint, conn, send) = loopback_uni(DraftVersion::Draft13.quic_alpn()).await;
        let mut framed = FramedSendStream::new(SendStream::Quic(send));
        framed.write_subgroup_header(&header()).await.expect("write subgroup header");
        (endpoint, conn, framed)
    }

    /// Section 9.4.2: an Object ID may not be less than one already sent on the
    /// stream. Nor equal to it - see `write_subgroup_object` for why the line is
    /// drawn there.
    #[tokio::test]
    async fn object_ids_must_advance_on_a_subgroup_stream() {
        let (_endpoint, _conn, mut framed) = opened().await;

        framed.write_subgroup_object(&object(0)).await.expect("the first object sets the mark");
        framed.write_subgroup_object(&object(5)).await.expect("5 is past 0");

        let repeat = framed.write_subgroup_object(&object(5)).await;
        assert!(
            repeat.is_err(),
            "an object may not repeat the id of the one before it: {repeat:?}"
        );

        let backwards = framed.write_subgroup_object(&object(1)).await;
        assert!(backwards.is_err(), "an object may not go backwards: {backwards:?}");
    }

    /// A refused object leaves the mark on the last object actually written.
    ///
    /// Both halves of that are asserted, because each alone is satisfied by a
    /// mistake the other catches. An id chosen above the refused one would still
    /// be accepted if the mark had moved down to it, so the id tried next here is
    /// one that sits **between** the refused object and the last one kept: with
    /// the mark where it belongs it is behind and refused, and with the mark on
    /// the refused id it is ahead and would go out. Then a genuinely later id
    /// shows the stream is still usable rather than poisoned by the refusal.
    #[tokio::test]
    async fn a_refused_object_does_not_move_the_mark() {
        let (_endpoint, _conn, mut framed) = opened().await;

        framed.write_subgroup_object(&object(4)).await.expect("the first object sets the mark");
        assert!(framed.write_subgroup_object(&object(2)).await.is_err(), "2 is behind 4");

        let between = framed.write_subgroup_object(&object(3)).await;
        assert!(
            between.is_err(),
            "the mark stays on the last object written, not the last one refused: {between:?}",
        );

        let ahead = framed.write_subgroup_object(&object(5)).await;
        assert!(ahead.is_ok(), "and a refusal does not poison the stream: {ahead:?}");
    }

    /// An object written before the subgroup header would land in front of the
    /// framing that describes it, and there is no previous id to measure it
    /// against either.
    #[tokio::test]
    async fn an_object_needs_its_header_first() {
        let (_endpoint, _conn, send) = loopback_uni(DraftVersion::Draft13.quic_alpn()).await;
        let mut framed = FramedSendStream::new(SendStream::Quic(send));

        let early = framed.write_subgroup_object(&object(0)).await;
        assert!(early.is_err(), "an object cannot precede the header that frames it: {early:?}");

        framed.write_subgroup_header(&header()).await.expect("write subgroup header");
        framed.write_subgroup_object(&object(0)).await.expect("and after the header it is fine");
    }
}
