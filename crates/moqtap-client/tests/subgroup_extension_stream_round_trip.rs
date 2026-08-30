//! A subgroup stream this client writes is one this client can read.
//!
//! Drafts 11, 12 and 13 put an Extensions Present column on the SUBGROUP_HEADER
//! type table, so whether each object carries an Extension Headers Length field
//! is fixed once, by the header, for the whole stream. The read side of
//! `FramedRecvStream` has always kept that answer and handed it to every
//! object decode. The write side did not keep it: it encoded each object header
//! on its own, and an object header encoded on its own writes the framing that
//! has no extension block.
//!
//! On a stream opened with an extension-bearing type the two halves therefore
//! disagreed, and the interesting part is what that looked like. The reader
//! goes looking for an Extension Headers Length, finds the Object Payload
//! Length in its place, and reads that many bytes of payload as the extension
//! block. With nothing after the object it runs out and reports a short read.
//! With another object behind it - which is the ordinary case on a stream -
//! there are bytes to take, so it does not fail at all: it returns an object
//! whose extension headers are the previous object's payload, and carries on
//! misframing everything after. The write returned `Ok` each time.
//!
//! # Why the assertion is a read and not an encoder check
//!
//! Because the framing belongs to the stream, and only something that owns the
//! stream can hold it. A check on the object encoder can say the object is
//! self-consistent and still be handed the wrong framing. Driving the real
//! `FramedSendStream` at a real `FramedRecvStream` over loopback QUIC is what
//! makes the two agree about something rather than each about itself.
//!
//! Drafts 07 through 10 have no such disagreement to test: draft-07 has no
//! extension block and drafts 08 through 10 give every object one
//! unconditionally. Drafts 14 and later thread the framing through a reader
//! object on the write path, so they were never guessing.
//!
//! # Recorded failures
//!
//! Restoring the old write - `header.encode_checked(&mut buf)?` in place of
//! `encode_checked_with_extensions` - while the codec keeps its guard, on
//! draft-11. The object no longer reaches the wire at all:
//!
//! ```text
//! write first object: Codec(InvalidField)
//! ```
//!
//! Restoring the old write *and* dropping the codec's guard, which is what
//! shipped. Nothing fails at the writer, nothing fails at the reader, and the
//! object comes back with the payload sitting in its extension headers:
//!
//! ```text
//! assertion `left == right` failed: the extension bytes must survive the
//! stream
//!   left: [222, 173]
//!  right: [170, 187, 204]
//! ```
//!
//! and, from the same run, the stream that carries no block accepting an
//! object that has one:
//!
//! ```text
//! a stream with no extension block has nowhere to put these bytes, so the
//! object must be refused rather than written without them: Ok(())
//! ```

mod common;

use moqtap_codec::varint::VarInt;

/// Unread in a build that enables only drafts whose gates do not use it.
#[allow(dead_code)]
fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap()
}

/// Extension bytes chosen so a decoder that lands on them by mistake produces
/// something visible rather than a coincidentally legal frame.
/// Unread in a build that enables only drafts whose gates do not use it.
#[allow(dead_code)]
const EXTENSIONS: [u8; 3] = [0xAA, 0xBB, 0xCC];

/// Generates the round trip for one of the three drafts that gate the block on
/// the stream type.
///
/// The three differ only in where the extensions bit sits in the header type
/// byte — drafts 12 and 13 double the table with an End of Group column — so
/// each names its own `SubgroupExplicitExt` rather than sharing a constant.
macro_rules! extension_stream_round_trip {
    ($mod_name:ident, $feat:literal, $draft:ident, $variant:ident, $version:ident) => {
        #[cfg(feature = $feat)]
        mod $mod_name {
            use super::{common, varint, EXTENSIONS};
            use moqtap_client::$draft::connection::{FramedRecvStream, FramedSendStream};
            use moqtap_client::$draft::event::SubgroupObject;
            use moqtap_client::transport::{RecvStream, SendStream};
            use moqtap_codec::$draft::data_stream::{ObjectHeader, StreamType, SubgroupHeader};
            use moqtap_codec::$draft::types::ObjectStatus;
            use moqtap_codec::dispatch::AnySubgroupHeader;
            use moqtap_codec::version::DraftVersion;

            /// A stream whose type says every object carries an extension
            /// block.
            fn header() -> AnySubgroupHeader {
                AnySubgroupHeader::$variant(SubgroupHeader {
                    stream_type: StreamType::SubgroupExplicitExt,
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
                        extension_headers_length: varint(EXTENSIONS.len() as u64),
                        extensions: EXTENSIONS.to_vec(),
                        payload_length: varint(2),
                        object_status: ObjectStatus::Normal,
                    },
                    payload: vec![0xDE, 0xAD],
                }
            }

            /// What the writer puts on an extension-bearing stream is what the
            /// reader on the far side gets back.
            ///
            /// Two objects, not one. A writer that dropped the block would fail
            /// on the first object here, but a writer that wrote the block only
            /// for the first object — seeding the framing and then losing it —
            /// would pass a one-object test.
            #[tokio::test]
            async fn extensions_survive_the_stream_this_client_wrote() {
                common::init_crypto();
                let alpn = DraftVersion::$version.quic_alpn();
                let (server, addr) = common::spawn_server(&[alpn]);

                let reader = tokio::spawn(async move {
                    let conn = server.accept().await.expect("accept").await.expect("handshake");
                    let recv = conn.accept_uni().await.expect("accept_uni");
                    let mut framed = FramedRecvStream::new(RecvStream::Quic(recv));
                    let header = framed.read_subgroup_header().await;
                    let first = framed.read_subgroup_object().await;
                    let second = framed.read_subgroup_object().await;
                    (header, first, second)
                });

                let client = common::client_endpoint(&[alpn]);
                let conn = client
                    .connect(addr, "localhost")
                    .expect("connect")
                    .await
                    .expect("tls handshake");
                let send = conn.open_uni().await.expect("open_uni");
                let mut framed = FramedSendStream::new(SendStream::Quic(send));
                framed.write_subgroup_header(&header()).await.expect("write subgroup header");
                framed.write_subgroup_object(&object(0)).await.expect("write first object");
                framed.write_subgroup_object(&object(1)).await.expect("write second object");
                framed.finish().await.expect("finish");

                let (read_header, first, second) = reader.await.expect("reader task");
                read_header.expect("the reader must accept the header the writer wrote");

                let first = first.unwrap_or_else(|e| {
                    panic!("the client must be able to read the subgroup stream it just wrote: {e:?}")
                });
                assert_eq!(
                    first.header.extensions, EXTENSIONS,
                    "the extension bytes must survive the stream"
                );
                assert_eq!(first.payload, vec![0xDE, 0xAD], "the payload must survive with them");

                let second = second.unwrap_or_else(|e| {
                    panic!("the framing must hold for every object, not just the first: {e:?}")
                });
                assert_eq!(second.header.object_id.into_inner(), 1);
                assert_eq!(second.header.extensions, EXTENSIONS);
                assert_eq!(second.payload, vec![0xDE, 0xAD]);
            }

            /// A stream that carries no block still refuses an object holding
            /// extensions, rather than writing bytes with the block missing.
            ///
            /// The other half of the same fact. Without it the writer could pass
            /// the test above by always writing the block, which would break
            /// every stream opened without the bit.
            #[tokio::test]
            async fn a_stream_without_a_block_refuses_an_object_that_has_one() {
                common::init_crypto();
                let alpn = DraftVersion::$version.quic_alpn();
                let (server, addr) = common::spawn_server(&[alpn]);
                tokio::spawn(async move {
                    if let Some(incoming) = server.accept().await {
                        let _ = incoming.await;
                        std::future::pending::<()>().await;
                    }
                });

                let client = common::client_endpoint(&[alpn]);
                let conn = client
                    .connect(addr, "localhost")
                    .expect("connect")
                    .await
                    .expect("tls handshake");
                let send = conn.open_uni().await.expect("open_uni");
                let mut framed = FramedSendStream::new(SendStream::Quic(send));

                let plain = AnySubgroupHeader::$variant(SubgroupHeader {
                    stream_type: StreamType::SubgroupExplicit,
                    track_alias: varint(1),
                    group_id: varint(0),
                    subgroup_id: varint(0),
                    publisher_priority: 128,
                });
                framed.write_subgroup_header(&plain).await.expect("write subgroup header");

                let refused = framed.write_subgroup_object(&object(0)).await;
                assert!(
                    refused.is_err(),
                    "a stream with no extension block has nowhere to put these bytes, so \
                     the object must be refused rather than written without them: {refused:?}"
                );
            }
        }
    };
}

extension_stream_round_trip!(draft11, "draft11", draft11, Draft11, Draft11);
extension_stream_round_trip!(draft12, "draft12", draft12, Draft12, Draft12);
extension_stream_round_trip!(draft13, "draft13", draft13, Draft13, Draft13);

/// The header itself is refused when its fields disagree with its own type.
///
/// The stream type is what every object after it is framed against, so a header
/// that goes out saying the wrong thing cannot be taken back: there is no later
/// point at which the mistake becomes visible to either end. Draft-14 is the
/// case with the sharpest consequence — its Subgroup ID is an `Option` and a
/// `None` under a type that carries the field is written as zero, which names
/// subgroup 0 rather than no subgroup — so that is what is driven here, through
/// the same `write_subgroup_header` every draft uses.
///
/// # Recorded failure
///
/// Produced by putting `header.encode_stream(&mut buf);` back in
/// `write_subgroup_header`:
///
/// ```text
/// a header whose Subgroup ID disagrees with its own type must not open a
/// stream: Ok(())
/// ```
#[cfg(feature = "draft14")]
#[tokio::test]
async fn a_header_that_disagrees_with_its_type_does_not_open_a_stream() {
    use moqtap_client::draft14::connection::FramedSendStream;
    use moqtap_client::transport::SendStream;
    use moqtap_codec::dispatch::AnySubgroupHeader;
    use moqtap_codec::draft14::data_stream::{SubgroupHeader, SubgroupStreamType};
    use moqtap_codec::version::DraftVersion;

    common::init_crypto();
    let alpn = DraftVersion::Draft14.quic_alpn();
    let (server, addr) = common::spawn_server(&[alpn]);
    tokio::spawn(async move {
        if let Some(incoming) = server.accept().await {
            let _ = incoming.await;
            std::future::pending::<()>().await;
        }
    });

    let client = common::client_endpoint(&[alpn]);
    let conn = client.connect(addr, "localhost").expect("connect").await.expect("tls handshake");
    let send = conn.open_uni().await.expect("open_uni");
    let mut framed = FramedSendStream::new(SendStream::Quic(send), DraftVersion::Draft14);

    let explicit = SubgroupStreamType::from_flags(true, false, false, false);
    assert!(explicit.has_subgroup_id_field(), "fixture: this type must carry the field");
    let mismatched = AnySubgroupHeader::Draft14(SubgroupHeader {
        stream_type: explicit,
        track_alias: varint(1),
        group_id: varint(0),
        // The type says a Subgroup ID follows. There is none.
        subgroup_id: None,
        publisher_priority: 128,
    });

    let refused = framed.write_subgroup_header(&mismatched).await;
    assert!(
        refused.is_err(),
        "a header whose Subgroup ID disagrees with its own type must not open a \
         stream: {refused:?}"
    );

    // And the agreeing header still opens one, so the check is about the
    // disagreement rather than about the type.
    let agreeing = AnySubgroupHeader::Draft14(SubgroupHeader {
        stream_type: explicit,
        track_alias: varint(1),
        group_id: varint(0),
        subgroup_id: Some(varint(3)),
        publisher_priority: 128,
    });
    framed.write_subgroup_header(&agreeing).await.expect("an agreeing header opens the stream");
}
