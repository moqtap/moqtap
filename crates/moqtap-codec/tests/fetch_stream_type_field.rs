//! A fetch stream opens with its stream type, and the codec can write one.
//!
//! `data_stream_type_field.rs` covers datagrams and subgroup streams. Fetch is
//! the third carrier that opens a unidirectional stream, and it needs a case of
//! its own: a `FetchHeader` whose `decode_stream` has nothing on the other side
//! of it is a defect no other test sees. The read side pins the type; the write
//! side writes the body alone; and nothing puts the two together.
//!
//! So the gate is the round trip, driven on every draft: what
//! `encode_stream` writes, `decode_stream` reads. The second half is the one
//! that matters — on the drafts where the type is a separate leading field,
//! the body-only `encode` must **not** satisfy `decode_stream`, or the round
//! trip proves nothing.

// Both are re-exported into every per-draft module the macro below generates,
// and every one of those is behind a `#[cfg(feature = "draftNN")]`. The
// zero-draft row - `--no-default-features --all-targets` - expands the macro
// nowhere, so nothing imports these. That row is there to prove the crate still
// builds with no draft at all, which is the whole reach of this `allow`.
#[allow(unused_imports)]
use moqtap_codec::dispatch::AnyFetchHeader;
#[allow(unused_imports)]
use moqtap_codec::version::DraftVersion;

macro_rules! fetch_stream_suite {
    ($feature:literal, $draft:ident, $variant:ident, $version:expr, $field:ident,
     $type_is_separate:literal) => {
        #[cfg(feature = $feature)]
        mod $draft {
            use super::{AnyFetchHeader, DraftVersion};
            use moqtap_codec::varint::VarInt;

            fn header() -> AnyFetchHeader {
                // 5 is FETCH_HEADER's own stream type on the drafts that have
                // one, so an id read as a type - or a type read as an id -
                // still looks plausible and has to be caught by the round
                // trip rather than by a range check.
                AnyFetchHeader::$variant(moqtap_codec::$draft::data_stream::FetchHeader {
                    $field: VarInt::from_u64(5).unwrap(),
                })
            }

            /// What `encode_stream` writes, `decode_stream` reads back.
            ///
            /// Writing the body alone instead fails with:
            ///
            /// ```text
            /// a fetch stream this codec opened must be readable by this codec: Err(VarInt(UnexpectedEnd))
            /// ```
            ///
            /// The error is the *body* running out rather than a bad type,
            /// because the id chosen here is 5 and so reads as the fetch type
            /// itself. That is the adversarial case on purpose: a value that
            /// did not collide would be caught by the type check alone and
            /// would say nothing about whether the field was written.
            #[test]
            fn a_fetch_stream_opening_round_trips() {
                let mut buf = Vec::new();
                header().encode_stream(&mut buf);

                let decoded = AnyFetchHeader::decode_stream($version, &mut &buf[..]);
                assert!(
                    decoded.is_ok(),
                    "a fetch stream this codec opened must be readable by this codec: {decoded:?}",
                );
            }

            /// The body-only encoder is not the inverse of `decode_stream` on
            /// the drafts that carry the type as a separate leading field, and
            /// this says so out loud: if it were, the gate above would pass
            /// whether or not the type was ever written.
            #[test]
            fn the_body_only_encoder_is_not_a_stream_opening() {
                let mut body = Vec::new();
                header().encode(&mut body);

                let decoded = AnyFetchHeader::decode_stream($version, &mut &body[..]);
                if $type_is_separate {
                    assert!(
                        decoded.is_err(),
                        "the body alone must not read as a stream opening: {decoded:?}",
                    );
                } else {
                    assert!(
                        decoded.is_ok(),
                        "this draft folds the type into the header, so the two coincide: \
                         {decoded:?}",
                    );
                }
            }
        }
    };
}

fetch_stream_suite!("draft07", draft07, Draft07, DraftVersion::Draft07, subscribe_id, true);
fetch_stream_suite!("draft08", draft08, Draft08, DraftVersion::Draft08, subscribe_id, true);
fetch_stream_suite!("draft09", draft09, Draft09, DraftVersion::Draft09, subscribe_id, true);
fetch_stream_suite!("draft10", draft10, Draft10, DraftVersion::Draft10, subscribe_id, true);
fetch_stream_suite!("draft11", draft11, Draft11, DraftVersion::Draft11, request_id, true);
fetch_stream_suite!("draft12", draft12, Draft12, DraftVersion::Draft12, request_id, true);
fetch_stream_suite!("draft13", draft13, Draft13, DraftVersion::Draft13, request_id, true);
fetch_stream_suite!("draft14", draft14, Draft14, DraftVersion::Draft14, request_id, false);
fetch_stream_suite!("draft15", draft15, Draft15, DraftVersion::Draft15, request_id, false);
fetch_stream_suite!("draft16", draft16, Draft16, DraftVersion::Draft16, request_id, false);
fetch_stream_suite!("draft17", draft17, Draft17, DraftVersion::Draft17, request_id, false);
fetch_stream_suite!("draft18", draft18, Draft18, DraftVersion::Draft18, request_id, false);
fetch_stream_suite!("draft19", draft19, Draft19, DraftVersion::Draft19, request_id, false);
fetch_stream_suite!("draft20", draft20, Draft20, DraftVersion::Draft20, request_id, false);
