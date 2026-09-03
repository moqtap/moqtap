//! Object-site actions, asserted against bytes an independent encoder wrote.
//!
//! Every fixture on this file is assembled by [`Wire`], a deliberately
//! separate encoder written from each draft's documented layout. It shares no code with `moqtap-codec`: it never names
//! `AnySubgroupObjectWriter`, `AnySubgroupObject` or any per-draft type,
//! and the only codec item it imports is [`DraftVersion`], which is a
//! label rather than a layout.
//!
//! That separation is the whole point. Three wire bugs once shipped green
//! — drafts 17-19 read the property block as count-prefixed KVPs when the
//! wire is byte-length-prefixed, drafts 15/16 dropped the `+1` from the
//! Object ID delta, and `write_object` omitted the property block's length
//! prefix — underneath tests that built a
//! stream with the writer and read it back with the reader. A reader and a
//! writer that share a misunderstanding round-trip perfectly. **No
//! assertion in this file may compare the proxy's output to
//! `AnySubgroupObjectWriter`'s output.**
//!
//! # What is asserted, and how
//!
//! The proxy is driven end to end — a real client, a real
//! [`ProxySession`](moqtap_proxy::session::ProxySession), a real upstream —
//! and the *destination bytes* are compared to a stream [`Wire`] built from
//! the draft's layout. For an elide the expectation is an independently
//! encoded stream **of just the survivors**, which is one assertion that
//! catches both "successors renumbered to `[0,1]`" and "successors
//! re-encoded non-identically".
//!
//! # Reading the fixtures
//!
//! Object IDs are absolute on drafts 07-13 and written as `id - prev - 1`
//! from draft-14 on, where the first object's field is its absolute ID.
//! [`Wire::delta_encoded`] is the only place that fact lives here.
//!
//! # The oversized-object tests, and why their fixtures are 5 MiB
//!
//! The obvious way to reach the oversized path would be a deliberately
//! small `FramerConfig::max_buffered_object_bytes`.
//! **There is no way to set one on a live session**: `session.rs` builds
//! every framer with `FramerConfig::default()`, and the only framing-side
//! knob `ProxySessionConfig` exposes is `egress`. The cap is therefore its 4 MiB
//! default, and the only way to reach the oversized path end to end is an
//! object larger than that. The fixtures are sized accordingly — see
//! [`OVERSIZED_PAYLOAD`], whose margin over the cap is itself load-bearing.
//! Doing it at the framer's own API instead would have made
//! `Impairment { ObjectNotAddressable }`, which `session.rs` emits and the
//! framer does not, unassertable.
//!
//! # Ablations
//!
//! Every test here names an ablation under `*Ablation (measured)*`, and
//! every one of those was applied to a private copy of the workspace,
//! compiled and run. Seventeen ablations, seventeen genuine failures; the
//! doc comments quote the observed bytes or counter values rather than
//! predicting them, and say which *other* tests the same ablation takes
//! down. Two of them passed on the first attempt and the fixtures were the
//! thing at fault, not the implementation — see [`OVERSIZED_PAYLOAD`].

mod common;

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use moqtap_codec::version::{DraftVersion, VarIntEncoding};

use moqtap_proxy::action::{Action, DropMode, Interest};
use moqtap_proxy::capability::{ActionKind, Refusal, Site};
use moqtap_proxy::event::{Effect, ImpairmentKind};
use moqtap_proxy::framer::BypassReason;
use moqtap_proxy::hook::{ObjectCtx, ProxyHook};
use moqtap_proxy::instrument::Counters;
use moqtap_proxy::observer::ProxyObserver;
use moqtap_proxy::parser::data::DataStreamType;

use common::{Ending, FakeRelay, Recorded, RecordingObserver};

/// Every draft this crate speaks.
const DRAFTS: &[DraftVersion] = &[
    #[cfg(feature = "draft07")]
    DraftVersion::Draft07,
    #[cfg(feature = "draft08")]
    DraftVersion::Draft08,
    #[cfg(feature = "draft09")]
    DraftVersion::Draft09,
    #[cfg(feature = "draft10")]
    DraftVersion::Draft10,
    #[cfg(feature = "draft11")]
    DraftVersion::Draft11,
    #[cfg(feature = "draft12")]
    DraftVersion::Draft12,
    #[cfg(feature = "draft13")]
    DraftVersion::Draft13,
    #[cfg(feature = "draft14")]
    DraftVersion::Draft14,
    #[cfg(feature = "draft15")]
    DraftVersion::Draft15,
    #[cfg(feature = "draft16")]
    DraftVersion::Draft16,
    #[cfg(feature = "draft17")]
    DraftVersion::Draft17,
    #[cfg(feature = "draft18")]
    DraftVersion::Draft18,
    #[cfg(feature = "draft19")]
    DraftVersion::Draft19,
    #[cfg(feature = "draft20")]
    DraftVersion::Draft20,
];

/// The drafts that write an Object ID as `id - prev - 1` on a subgroup
/// stream, and so are the only ones where eliding one renumbers its
/// successor.
const DELTA_DRAFTS: &[DraftVersion] = &[
    #[cfg(feature = "draft14")]
    DraftVersion::Draft14,
    #[cfg(feature = "draft15")]
    DraftVersion::Draft15,
    #[cfg(feature = "draft16")]
    DraftVersion::Draft16,
    #[cfg(feature = "draft17")]
    DraftVersion::Draft17,
    #[cfg(feature = "draft18")]
    DraftVersion::Draft18,
    #[cfg(feature = "draft19")]
    DraftVersion::Draft19,
    #[cfg(feature = "draft20")]
    DraftVersion::Draft20,
];

/// The ten drafts with a stream type whose Subgroup ID is the Object ID
/// of the first object on the stream rather than a field of the header.
/// Drafts 07-10 always carry the ID explicitly; every draft from 11 on has
/// the mode, in one of two wordings. Drafts 11-15 say the Subgroup ID "is
/// either 0 ... or the Object ID of the first object transmitted in this
/// subgroup", enumerating the types that mean each; drafts 16-20 name a
/// SUBGROUP_ID_MODE field and say "The Subgroup ID field is absent and the
/// Subgroup ID is the Object ID of the first Object transmitted in this
/// Subgroup". Both spell the same stream `0x12`.
const IMPLICIT_SUBGROUP_DRAFTS: &[DraftVersion] = &[
    #[cfg(feature = "draft11")]
    DraftVersion::Draft11,
    #[cfg(feature = "draft12")]
    DraftVersion::Draft12,
    #[cfg(feature = "draft13")]
    DraftVersion::Draft13,
    #[cfg(feature = "draft14")]
    DraftVersion::Draft14,
    #[cfg(feature = "draft15")]
    DraftVersion::Draft15,
    #[cfg(feature = "draft16")]
    DraftVersion::Draft16,
    #[cfg(feature = "draft17")]
    DraftVersion::Draft17,
    #[cfg(feature = "draft18")]
    DraftVersion::Draft18,
    #[cfg(feature = "draft19")]
    DraftVersion::Draft19,
    #[cfg(feature = "draft20")]
    DraftVersion::Draft20,
];

/// The drafts whose subgroup header-type octet carries a subgroup-ID
/// **mode** field with a reserved value (mode 3).
const MODE_FIELD_DRAFTS: &[DraftVersion] = &[
    #[cfg(feature = "draft16")]
    DraftVersion::Draft16,
    #[cfg(feature = "draft17")]
    DraftVersion::Draft17,
    #[cfg(feature = "draft18")]
    DraftVersion::Draft18,
    #[cfg(feature = "draft19")]
    DraftVersion::Draft19,
    #[cfg(feature = "draft20")]
    DraftVersion::Draft20,
];

/// The drafts with a fetch **object** layout this codec decodes.
const FETCH_OBJECT_DRAFTS: &[DraftVersion] = &[
    #[cfg(feature = "draft07")]
    DraftVersion::Draft07,
    #[cfg(feature = "draft08")]
    DraftVersion::Draft08,
    #[cfg(feature = "draft09")]
    DraftVersion::Draft09,
    #[cfg(feature = "draft10")]
    DraftVersion::Draft10,
    #[cfg(feature = "draft11")]
    DraftVersion::Draft11,
    #[cfg(feature = "draft12")]
    DraftVersion::Draft12,
    #[cfg(feature = "draft13")]
    DraftVersion::Draft13,
    #[cfg(feature = "draft14")]
    DraftVersion::Draft14,
];

/// The drafts whose fetch objects the framer does not address.
///
/// Drafts 18, 19 and 20 write a fetch object's Group ID as a difference from
/// the previous object's, and the fetch's Group Order decides whether it is
/// added or subtracted (draft-19 Section 11.4.4.1). That order is settled by
/// the control exchange and never reaches the data stream, so a framer given
/// only the stream cannot resolve a Group ID at all — and reading the stream
/// under the wrong order decodes rather than fails.
const FETCH_BYPASS_DRAFTS: &[DraftVersion] = &[
    #[cfg(feature = "draft18")]
    DraftVersion::Draft18,
    #[cfg(feature = "draft19")]
    DraftVersion::Draft19,
    #[cfg(feature = "draft20")]
    DraftVersion::Draft20,
];

/// The drafts whose fetch objects the framer addresses and pays to elide.
///
/// Drafts 15, 16 and 17 let a fetch object leave a field off and take the
/// previous object's (draft-17 Section 10.4.4.1), which the reader resolves
/// without needing anything the stream does not carry — so these streams are
/// framed and every object on them reaches the hook. Deleting one object's
/// bytes is not enough, though: the object after it would resolve against a
/// predecessor no longer on the wire, so its framing is re-encoded against
/// the one that is.
#[cfg(any(feature = "draft15", feature = "draft16", feature = "draft17"))]
const FETCH_REENCODE_ELIDE_DRAFTS: &[DraftVersion] = &[
    #[cfg(feature = "draft15")]
    DraftVersion::Draft15,
    #[cfg(feature = "draft16")]
    DraftVersion::Draft16,
    #[cfg(feature = "draft17")]
    DraftVersion::Draft17,
];

/// The drafts that write a subgroup object's leading field as the object's
/// **absolute** ID *and* carry an extension block for it to be copied
/// alongside.
///
/// Complement of [`DELTA_DRAFTS`] less draft-07, whose subgroup objects
/// have no extension block at all — so a survivor copied on draft-07 would
/// have nothing in it that a re-serializing implementation could get
/// wrong.
const ABSOLUTE_ID_EXT_DRAFTS: &[DraftVersion] = &[
    #[cfg(feature = "draft08")]
    DraftVersion::Draft08,
    #[cfg(feature = "draft09")]
    DraftVersion::Draft09,
    #[cfg(feature = "draft10")]
    DraftVersion::Draft10,
    #[cfg(feature = "draft11")]
    DraftVersion::Draft11,
    #[cfg(feature = "draft12")]
    DraftVersion::Draft12,
    #[cfg(feature = "draft13")]
    DraftVersion::Draft13,
];

/// The newest draft this build compiled, for the one claim below that is
/// about the forwarder rather than about a draft.
///
/// A session configured for a draft this build holds no codec for is
/// refused by `ProxyError::DraftNotCompiled` before it dials, so naming a
/// draft outright decides whether such a test runs on the feature set
/// rather than on the code. The newest rather than the first, so a build
/// with every draft still runs it on draft-19, which is the draft it named
/// before this was derived. `DRAFTS` is cfg-built and the file-level gate
/// guarantees it is not empty.
fn a_compiled_draft() -> DraftVersion {
    DRAFTS[DRAFTS.len() - 1]
}

/// The two-byte spelling of `0` under `draft`'s variable-length integer.
///
/// `0x40 0x00` under RFC 9000's, which drafts 07-16 use; `0x80 0x00` under
/// MoQT's own, which 17-20 use. Both are legal and neither is minimal,
/// which is the whole point of the fixture that carries one.
fn widened_zero(draft: DraftVersion) -> [u8; 2] {
    match draft.varint_encoding() {
        VarIntEncoding::Rfc9000 => [0x40, 0x00],
        _ => [0x80, 0x00],
    }
}

/// A zero-length object's status code. `EndOfGroup` is `0x03` on every
/// draft that validates the code (07-14) and passes through unvalidated on
/// 15-19.
const STATUS_END_OF_GROUP: u64 = 3;

/// One even-typed Key-Value-Pair: type `0x3c`, varint value `0x02`. Two
/// bytes, so the same blob serves as a byte-length of 2 and as a count of
/// 1.
const EXT: &[u8] = &[0x3c, 0x02];

/// The same pair with its **value** written as a legal two-byte varint
/// rather than the one-byte minimum. Draft-08's reader re-encodes each KVP
/// minimally, so an object carrying this survives byte deletion and does
/// **not** survive a `read_object` / `write_object` round-trip. Three
/// bytes, one pair.
const EXT_NON_MINIMAL: &[u8] = &[0x3c, 0x40, 0x02];

/// Payload size that puts an object past the framer's 4 MiB default cap
/// **by more than one read**.
///
/// The session hard-codes `FramerConfig::default()`, so payload size is
/// the only lever an end-to-end test has over the oversized path (see the
/// module note). The margin is the load-bearing part, and it was measured
/// rather than guessed:
///
/// * The framer buffers until the cap and then asks whether the object it
///   holds is complete. If it is, `poll_object` emits it whole as one
///   `Passthrough`; if it is not, `poll_oversized` measures it against
///   padding, fixes up the **first chunk** and streams the remainder.
/// * `pipe_data_framed` reads 8 KiB at a time, so with a payload of
///   `cap + 64` the buffer almost always jumps straight past the object's
///   end and the chunked path is never entered. The first version of these
///   tests used exactly that size — and the two ablations aimed at
///   `poll_oversized` both passed, which is how the gap was found.
/// * A payload a whole megabyte past the cap makes the crossing
///   unavoidable: at the poll where the buffer first reaches the cap the
///   object still owes ~1 MiB, so `poll_oversized` runs every time.
const OVERSIZED_PAYLOAD: usize = 5 * 1024 * 1024;

/// How many bytes the client writes per `write_all`.
const WRITE_CHUNK: usize = 64;

// ============================================================
// An encoder that shares no code with the crate under test
// ============================================================

/// QUIC variable-length integer, RFC 9000 §16.
fn put_varint(draft: DraftVersion, out: &mut Vec<u8>, value: u64) {
    if draft.uses_moqt_varint() {
        let width = (1..=8).find(|w| value < 1u64 << (7 * w)).unwrap_or(9);
        put_varint_wide(draft, out, value, width);
    } else if value < 1 << 6 {
        out.push(value as u8);
    } else if value < 1 << 14 {
        out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else if value < 1 << 30 {
        out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(value | 0xC000_0000_0000_0000).to_be_bytes());
    }
}

/// The same value written in exactly `width` bytes.
///
/// QUIC permits a varint wider than the minimum, and a publisher that
/// writes one is emitting a legal stream. Two tests turn on that: a
/// non-minimal field must be forwarded untouched, and a field the proxy
/// *does* rewrite must come back minimal.
fn put_varint_wide(draft: DraftVersion, out: &mut Vec<u8>, value: u64, width: usize) {
    if draft.uses_moqt_varint() {
        // MoQT (Section 1.4.1): `width - 1` leading 1 bits then a 0, in the
        // top `width` bits of the first byte. 0xFF is the nine-byte form and
        // is prefix only.
        if width == 9 {
            out.push(0xFF);
            out.extend_from_slice(&value.to_be_bytes());
            return;
        }
        assert!((1..=8).contains(&width), "a MoQT varint is 1..=9 bytes, not {width}");
        assert!(value < 1u64 << (7 * width), "{value} does not fit a {width}-byte varint");
        let prefix = (((1u16 << (width - 1)) - 1) << (9 - width)) as u8;
        let combined = ((prefix as u64) << (8 * (width - 1))) | value;
        for i in (0..width).rev() {
            out.push((combined >> (8 * i)) as u8);
        }
        return;
    }
    match width {
        1 => {
            assert!(value < 1 << 6, "{value} does not fit a one-byte varint");
            out.push(value as u8);
        }
        2 => {
            assert!(value < 1 << 14, "{value} does not fit a two-byte varint");
            out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
        }
        4 => {
            assert!(value < 1 << 30, "{value} does not fit a four-byte varint");
            out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
        }
        8 => out.extend_from_slice(&(value | 0xC000_0000_0000_0000).to_be_bytes()),
        other => panic!("a varint is 1, 2, 4 or 8 bytes, not {other}"),
    }
}

/// How a draft prefixes an object's extension/property block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExtBlock {
    /// No block on the wire at all.
    Absent,
    /// Draft-08: a count of Key-Value-Pairs, then the pairs.
    Count,
    /// Drafts 09+: a byte length, then that many bytes.
    Length,
}

/// What the stream header says about the subgroup ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubgroupIdMode {
    /// An explicit Subgroup ID varint follows the Group ID.
    Explicit,
    /// The subgroup ID is the first object's Object ID, so index 0 may not
    /// be removed.
    FirstObject,
    /// Drafts 17-20 mode 3, a value those drafts reserve.
    Reserved,
}

/// One subgroup object, described the way the wire describes it.
#[derive(Debug, Clone)]
struct Obj {
    /// Absolute Object ID.
    id: u64,
    /// Force the leading ID field to this many bytes. `None` writes the
    /// minimal encoding.
    id_width: Option<usize>,
    /// The extension/property block's contents, verbatim.
    ext: Vec<u8>,
    /// Key-Value-Pairs in `ext`. Only draft-08 puts this on the wire.
    ext_count: u64,
    /// Object Status wire code. `Some` writes a zero payload length
    /// followed by the code.
    status: Option<u64>,
    /// Payload bytes.
    payload: Vec<u8>,
}

impl Obj {
    /// A plain object with a four-byte payload derived from its ID.
    fn new(id: u64) -> Self {
        Self {
            id,
            id_width: None,
            ext: Vec::new(),
            ext_count: 0,
            status: None,
            payload: vec![0xA0 ^ (id as u8), 0xB1, 0xC2, id as u8],
        }
    }

    fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }

    fn with_status(mut self, code: u64) -> Self {
        self.status = Some(code);
        self.payload = Vec::new();
        self
    }

    fn with_id_width(mut self, width: usize) -> Self {
        self.id_width = Some(width);
        self
    }

    fn with_ext(mut self, ext: &[u8], count: u64) -> Self {
        self.ext = ext.to_vec();
        self.ext_count = count;
        self
    }
}

/// One fetch object. Fetch objects carry their own group, subgroup and
/// object IDs, absolutely, on every draft that defines the layout.
#[derive(Debug, Clone)]
struct FetchObj {
    group_id: u64,
    subgroup_id: u64,
    object_id: u64,
    publisher_priority: u8,
    ext: Vec<u8>,
    ext_count: u64,
    status: Option<u64>,
    payload: Vec<u8>,
}

impl FetchObj {
    fn new(group_id: u64, object_id: u64) -> Self {
        Self {
            group_id,
            subgroup_id: 0,
            object_id,
            publisher_priority: 128,
            ext: Vec::new(),
            ext_count: 0,
            status: None,
            payload: vec![0xA0 ^ (object_id as u8), 0xD3, 0xE4, object_id as u8],
        }
    }
}

/// Builds subgroup and fetch streams for one draft straight from its
/// documented wire layout.
#[derive(Debug, Clone, Copy)]
struct Wire {
    draft: DraftVersion,
    /// Whether the stream's objects carry an extension/property block. On
    /// drafts 11+ this selects the stream type; on 08-10 the block is
    /// unconditional and this only decides whether it is non-empty;
    /// draft-07 has no block.
    extensions: bool,
    mode: SubgroupIdMode,
}

impl Wire {
    /// A stream whose header carries an explicit Subgroup ID.
    fn new(draft: DraftVersion) -> Self {
        Self { draft, extensions: false, mode: SubgroupIdMode::Explicit }
    }

    fn with_extensions(mut self) -> Self {
        self.extensions = true;
        self
    }

    fn with_mode(mut self, mode: SubgroupIdMode) -> Self {
        self.mode = mode;
        self
    }

    /// Object IDs are absolute on drafts 07-13 and delta-encoded from
    /// draft-14 on, where the first object's field is its absolute ID and
    /// every later field is the gap to its predecessor biased by one.
    fn delta_encoded(&self) -> bool {
        DELTA_DRAFTS.contains(&self.draft)
    }

    fn subgroup_ext_block(&self) -> ExtBlock {
        match self.draft {
            DraftVersion::Draft07 => ExtBlock::Absent,
            DraftVersion::Draft08 => ExtBlock::Count,
            DraftVersion::Draft09 | DraftVersion::Draft10 => ExtBlock::Length,
            // Drafts 11+ gate the block on the stream type.
            _ if self.extensions => ExtBlock::Length,
            _ => ExtBlock::Absent,
        }
    }

    /// The fetch object extension block is unconditional from draft-09 on,
    /// even on drafts 11-13 where the *subgroup* block is gated on the
    /// stream type.
    fn fetch_ext_block(&self) -> ExtBlock {
        match self.draft {
            DraftVersion::Draft07 => ExtBlock::Absent,
            DraftVersion::Draft08 => ExtBlock::Count,
            _ => ExtBlock::Length,
        }
    }

    /// The stream type field that opens this subgroup stream.
    ///
    /// Drafts 07-10 define a single subgroup type with an explicit
    /// Subgroup ID. Draft-11 numbered them from `0x08` — `0x0A` takes the
    /// Subgroup ID from the first object, `0x0C` states it — and drafts 12+
    /// moved the same two to `0x12` and `0x14`. Drafts 17-20 reinterpret
    /// bits 1-2 as a two-bit mode field, where `3` (`0x16`) is reserved.
    fn subgroup_stream_type(&self) -> u8 {
        let ext = u8::from(self.extensions);
        match (self.draft, self.mode) {
            (
                DraftVersion::Draft07
                | DraftVersion::Draft08
                | DraftVersion::Draft09
                | DraftVersion::Draft10,
                SubgroupIdMode::Explicit,
            ) => 0x04,
            (DraftVersion::Draft11, SubgroupIdMode::Explicit) => 0x0C | ext,
            (DraftVersion::Draft11, SubgroupIdMode::FirstObject) => 0x0A | ext,
            (_, SubgroupIdMode::Explicit) => 0x14 | ext,
            (draft, SubgroupIdMode::FirstObject) => {
                assert!(
                    IMPLICIT_SUBGROUP_DRAFTS.contains(&draft),
                    "[{draft}] defines no first-object subgroup mode"
                );
                0x12 | ext
            }
            (draft, SubgroupIdMode::Reserved) => {
                assert!(
                    MODE_FIELD_DRAFTS.contains(&draft),
                    "[{draft}] has no reserved subgroup-ID mode"
                );
                0x16 | ext
            }
        }
    }

    /// Track alias 1, group 0, subgroup 0, publisher priority 128 —
    /// including the leading stream type field. The Subgroup ID varint is
    /// on the wire only in [`SubgroupIdMode::Explicit`].
    fn subgroup_header(&self) -> Vec<u8> {
        let mut out = vec![self.subgroup_stream_type(), 0x01, 0x00];
        if self.mode == SubgroupIdMode::Explicit {
            out.push(0x00);
        }
        out.push(0x80);
        out
    }

    fn put_ext_block(&self, out: &mut Vec<u8>, block: ExtBlock, ext: &[u8], count: u64) {
        match block {
            ExtBlock::Absent => {}
            ExtBlock::Count => {
                put_varint(self.draft, out, count);
                out.extend_from_slice(ext);
            }
            ExtBlock::Length => {
                put_varint(self.draft, out, ext.len() as u64);
                out.extend_from_slice(ext);
            }
        }
    }

    /// One subgroup object. `prev` is the previous object's absolute ID on
    /// this stream, or `None` for the first object.
    fn subgroup_object(&self, prev: Option<u64>, object: &Obj) -> Vec<u8> {
        let mut out = Vec::new();

        let id_field = match (self.delta_encoded(), prev) {
            (true, Some(prev)) => object
                .id
                .checked_sub(prev)
                .and_then(|d| d.checked_sub(1))
                .expect("object IDs must strictly increase"),
            _ => object.id,
        };
        match object.id_width {
            Some(width) => put_varint_wide(self.draft, &mut out, id_field, width),
            None => put_varint(self.draft, &mut out, id_field),
        }

        self.put_ext_block(&mut out, self.subgroup_ext_block(), &object.ext, object.ext_count);

        match object.status {
            Some(code) => {
                put_varint(self.draft, &mut out, 0);
                put_varint(self.draft, &mut out, code);
            }
            None => {
                put_varint(self.draft, &mut out, object.payload.len() as u64);
                out.extend_from_slice(&object.payload);
            }
        }
        out
    }

    /// The object region of a subgroup stream — everything after the
    /// header — with the delta chain restarted from the first object given.
    fn subgroup_objects(&self, objects: &[Obj]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut prev = None;
        for object in objects {
            out.extend_from_slice(&self.subgroup_object(prev, object));
            prev = Some(object.id);
        }
        out
    }

    /// A complete subgroup stream: header, then objects.
    fn subgroup_stream(&self, objects: &[Obj]) -> Vec<u8> {
        let mut out = self.subgroup_header();
        out.extend_from_slice(&self.subgroup_objects(objects));
        out
    }

    /// The stream the destination must receive when `elided` are removed:
    /// the same header, then the survivors encoded as if they had been the
    /// only objects on the stream.
    ///
    /// One assertion that catches both "successors renumbered" and
    /// "successors re-encoded non-identically" — and it is
    /// *not* a slice of the source: on a delta draft the survivor after an
    /// elided run has a different leading varint, and on draft-08 the
    /// survivors' extension blocks must come through byte-for-byte.
    fn survivor_stream(&self, objects: &[Obj], elided: &[usize]) -> Vec<u8> {
        let kept: Vec<Obj> = objects
            .iter()
            .enumerate()
            .filter(|(i, _)| !elided.contains(i))
            .map(|(_, o)| o.clone())
            .collect();
        self.subgroup_stream(&kept)
    }

    /// Objects with the given IDs, each carrying this stream's extension
    /// blob.
    fn objects(&self, ids: &[u64]) -> Vec<Obj> {
        let (ext, count) = if self.extensions { (EXT, 1) } else { (&[][..], 0) };
        ids.iter().map(|&id| Obj::new(id).with_ext(ext, count)).collect()
    }

    /// Fetch stream header: type `0x05` and request ID 9.
    fn fetch_header(&self) -> Vec<u8> {
        vec![0x05, 0x09]
    }

    fn fetch_object(&self, object: &FetchObj) -> Vec<u8> {
        let mut out = Vec::new();
        put_varint(self.draft, &mut out, object.group_id);
        put_varint(self.draft, &mut out, object.subgroup_id);
        put_varint(self.draft, &mut out, object.object_id);
        out.push(object.publisher_priority);
        self.put_ext_block(&mut out, self.fetch_ext_block(), &object.ext, object.ext_count);
        match object.status {
            Some(code) => {
                put_varint(self.draft, &mut out, 0);
                put_varint(self.draft, &mut out, code);
            }
            None => {
                put_varint(self.draft, &mut out, object.payload.len() as u64);
                out.extend_from_slice(&object.payload);
            }
        }
        out
    }

    fn fetch_stream(&self, objects: &[FetchObj]) -> Vec<u8> {
        let mut out = self.fetch_header();
        for object in objects {
            out.extend_from_slice(&self.fetch_object(object));
        }
        out
    }

    /// A drafts 15-17 fetch stream whose objects inherit fields from the
    /// object before them, resolving to `(7, 0)`, `(7, 1)`, `(7, 2)`.
    ///
    /// Deliberately *not* an all-fields-stated stream. Deleting an object
    /// from one of those would in fact be safe, and a test built on one
    /// would leave "the engine refused something it could have done"
    /// indistinguishable from "the engine refused something that would
    /// have corrupted the stream".
    ///
    /// Here the third object states **nothing at all** — its flags say its
    /// Subgroup ID, Group ID and Priority are the previous object's and its
    /// Object ID is the previous object's plus one. Remove the middle object
    /// and that "plus one" counts from the first instead, so the survivor
    /// arrives as object 1: the Location of the object that was deleted. The
    /// stream still decodes and its length is still self-consistent, which
    /// is the whole difficulty.
    ///
    /// One byte sequence serves all three drafts: the low two flag bits
    /// pick the Subgroup ID's meaning, `0x04` puts the Object ID on the
    /// wire, `0x08` the Group ID and `0x10` the Priority, and every value
    /// below is one byte under either draft's integer encoding.
    #[cfg(any(feature = "draft15", feature = "draft16", feature = "draft17"))]
    fn inheriting_fetch_stream(&self) -> Vec<u8> {
        let mut out = self.fetch_header();
        for frame in self.inheriting_fetch_frames() {
            out.extend_from_slice(&frame);
        }
        out
    }

    /// The three frames of [`Self::inheriting_fetch_stream`], apart, so a
    /// test that expects only some of them on the wire can name which.
    #[cfg(any(feature = "draft15", feature = "draft16", feature = "draft17"))]
    fn inheriting_fetch_frames(&self) -> Vec<Vec<u8>> {
        vec![
            // Group, subgroup, object and priority all stated.
            self.fetch_frame(0x03 | 0x04 | 0x08 | 0x10, &[7, 0, 0]),
            // Object ID stated; subgroup, group and priority inherited.
            self.fetch_frame(0x01 | 0x04, &[1]),
            // Nothing stated: this object's Location is entirely the previous
            // object's, stepped by one.
            self.fetch_frame(0x01, &[]),
        ]
    }

    /// One flags-encoded fetch frame with a four-byte payload.
    #[cfg(any(feature = "draft15", feature = "draft16", feature = "draft17"))]
    fn fetch_frame(&self, flags: u64, fields: &[u64]) -> Vec<u8> {
        let mut out = Vec::new();
        put_varint(self.draft, &mut out, flags);
        for &f in fields {
            put_varint(self.draft, &mut out, f);
        }
        if flags & 0x10 != 0 {
            out.push(128);
        }
        put_varint(self.draft, &mut out, 4);
        out.extend_from_slice(b"oooo");
        out
    }

    /// The stream the destination must receive when the middle object of
    /// [`Self::inheriting_fetch_stream`] is elided.
    ///
    /// Written out rather than derived, so that what the survivor has to say
    /// is chosen here and not taken from whatever the engine produced. The
    /// first object is untouched. The third stated **nothing at all**, and
    /// against its new predecessor it has to state its Object ID: "the
    /// previous object's plus one" now counts from object 0, so leaving the
    /// field off would put it on the wire as object 1 — the Location of the
    /// object that was deleted. Its Group ID, Subgroup ID and Priority are
    /// still the predecessor's and stay off the wire, so exactly one flag
    /// bit and one field appear.
    #[cfg(any(feature = "draft15", feature = "draft16", feature = "draft17"))]
    fn inheriting_fetch_survivor_stream(&self) -> Vec<u8> {
        let mut out = self.fetch_header();
        out.extend_from_slice(&self.fetch_frame(0x03 | 0x04 | 0x08 | 0x10, &[7, 0, 0]));
        out.extend_from_slice(&self.fetch_frame(0x01 | 0x04, &[2]));
        out
    }

    /// The fetch stream that survives eliding `elided`.
    ///
    /// Fetch object IDs are absolute on every draft that has the layout,
    /// so this is pure byte deletion — which is the property under test,
    /// stated by construction.
    fn fetch_survivor_stream(&self, objects: &[FetchObj], elided: &[usize]) -> Vec<u8> {
        let kept: Vec<FetchObj> = objects
            .iter()
            .enumerate()
            .filter(|(i, _)| !elided.contains(i))
            .map(|(_, o)| o.clone())
            .collect();
        self.fetch_stream(&kept)
    }
}

// ============================================================
// Hooks
// ============================================================

/// Decides one object at a time, from a closure the test supplies.
struct ObjectHook {
    interest: Interest,
    rule: Box<dyn Fn(&ObjectCtx<'_>) -> Action + Send + Sync>,
}

impl ProxyHook for ObjectHook {
    fn interest(&self) -> Interest {
        self.interest
    }

    fn on_object(&self, cx: &ObjectCtx<'_>, _raw: &[u8]) -> Action {
        (self.rule)(cx)
    }
}

/// An `Interest::OBJECTS` hook driven by `rule`.
fn hook(rule: impl Fn(&ObjectCtx<'_>) -> Action + Send + Sync + 'static) -> Arc<dyn ProxyHook> {
    Arc::new(ObjectHook { interest: Interest::OBJECTS, rule: Box::new(rule) })
}

/// A hook that declares object interest and passes everything.
///
/// Not a `NoOpHook`: that one declares `Interest::NONE`, which takes the
/// byte pump and would prove nothing about the shaped path.
fn pass_hook() -> Arc<dyn ProxyHook> {
    hook(|_| Action::Pass)
}

/// A hook that elides the objects at these indices in the stream.
fn elide_hook(indices: &'static [u64]) -> Arc<dyn ProxyHook> {
    hook(move |cx| {
        if indices.contains(&cx.meta.index_in_stream) {
            Action::Drop(DropMode::Elide)
        } else {
            Action::Pass
        }
    })
}

// ============================================================
// Driving one stream through a live proxy session
// ============================================================

/// What one forwarded stream produced.
struct Run {
    /// Every byte the far end received, in order.
    bytes: Vec<u8>,
    /// How the far end's stream ended.
    ending: Ending,
    /// Everything the session reported.
    events: Recorded,
    /// The session's slow-path counters, read before it was shut down.
    counters: Counters,
}

impl Run {
    /// `ActionApplied`, as `(site, action, effect)`.
    fn applied(&self) -> &[(Site, ActionKind, Effect)] {
        &self.events.applied
    }

    /// `ActionRefused`, as `(site, action, refusal)`.
    fn refused(&self) -> &[(Site, ActionKind, Refusal)] {
        &self.events.refused
    }

    /// Every `Impairment` kind, in order.
    fn impairments(&self) -> &[ImpairmentKind] {
        &self.events.impairments
    }

    /// Object IDs the session reported through `ProxyEvent::Object` — the
    /// objects it could address, in order.
    fn framed_ids(&self) -> Vec<u64> {
        self.events.objects.iter().map(|m| m.object_id).collect()
    }
}

/// Forward `parts` on one unidirectional stream through a live proxy
/// session on `draft`, and report what the far end saw.
///
/// `gap` is slept between parts, which is what lets a test put bytes on
/// the wire *before* the decision that tears the stream down.
async fn forward_parts(
    draft: DraftVersion,
    parts: &[&[u8]],
    gap: Duration,
    chunk: usize,
    hook: Arc<dyn ProxyHook>,
) -> Run {
    common::init_crypto();

    // The ALPN is load-bearing: `draft_is_fixed` is derived from it, and
    // `moq-00` does not resolve on drafts 15-20.
    let alpn = draft.quic_alpn();
    let relay = Arc::new(FakeRelay::bind(alpn));
    let observer = Arc::new(RecordingObserver::new());
    let proxy = common::spawn_proxy_with(
        common::session_config(draft, relay.addr),
        alpn,
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        hook,
    );

    let relay_for_task = Arc::clone(&relay);
    let uni = tokio::spawn(async move { relay_for_task.timed_uni().await });

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, alpn).await;
    let mut send = client_conn.open_uni().await.expect("open_uni");

    for (i, part) in parts.iter().enumerate() {
        if i > 0 && !gap.is_zero() {
            tokio::time::sleep(gap).await;
        }
        for piece in part.chunks(chunk.max(1)) {
            match send.write_all(piece).await {
                Ok(()) => {}
                // A `Truncate` or a stranded fix-up stops the source: the
                // remaining writes are expected to fail and are not the
                // property under test.
                Err(quinn::WriteError::Stopped(_)) | Err(quinn::WriteError::ClosedStream) => break,
                Err(e) => panic!("[{draft}] client write: {e:?}"),
            }
        }
    }
    let _ = send.finish();

    let rx = tokio::time::timeout(common::TIMEOUT, uni)
        .await
        .unwrap_or_else(|_| panic!("[{draft}] the relay never saw the forwarded stream"))
        .expect("join");
    let ending = rx.wait_for_ending().await;
    let bytes = rx.bytes();

    let counters = proxy.counters();
    let events = observer.recorded();

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;

    Run { bytes, ending, events, counters }
}

/// Forward one buffer through a live proxy session, 64 bytes at a time.
async fn forward(draft: DraftVersion, source: &[u8], hook: Arc<dyn ProxyHook>) -> Run {
    forward_parts(draft, &[source], Duration::ZERO, WRITE_CHUNK, hook).await
}

/// Assert `got` starts with `want`'s first `got.len()` bytes and is no
/// longer than `want`.
///
/// RFC 9000 §3.2 lets a receiver discard buffered data when a
/// `RESET_STREAM` is processed, and quinn does exactly that, so the only
/// honest claim about a truncated stream is an upper bound and a prefix.
fn assert_prefix_of(draft: DraftVersion, got: &[u8], want: &[u8], what: &str) {
    assert!(
        got.len() <= want.len(),
        "[{draft}] {what}: {} bytes arrived but at most {} could be correct",
        got.len(),
        want.len()
    );
    assert_eq!(got, &want[..got.len()], "[{draft}] {what}: the delivered bytes are not a prefix");
}

// ============================================================
// 1. Pass — the framing acceptance criterion, through the action path
// ============================================================

/// A hook with `Interest::OBJECTS` that returns `Action::Pass` for
/// everything forwards every draft's stream byte-identically.
///
/// This is byte-identical forwarding re-asserted under the *shaped* path:
/// the framer is
/// armed, `on_object` fires for every object, and `exec` runs — and the
/// destination bytes still equal the source.
///
/// The fixture set deliberately includes a draft-19 stream whose object 1
/// carries a **non-minimally encoded leading Object ID varint**. That is
/// the only field an elide fix-up can change, so it is the only fixture on
/// which an unconditional fix-up is visible.
///
/// *Ablation (measured):* drop the `self.fixup_pending` guard from
/// `ObjectFramer::apply_elide_fixup` — treat a fix-up as always owed.
/// Verified to fail this test, and the *way* it fails is the evidence:
///
/// * on the minimal fixtures the ablated build still forwards
///   byte-identical output — re-encoding an already-minimal varint
///   minimally changes nothing — so the bytes cannot catch it and the
///   `object_ids_rewritten == 0` assertion is what does (4 rewrites on
///   draft-14 where 0 are owed);
/// * on the draft-19 widened fixture the **bytes** differ, because
///   `0x40 0x00` is re-encoded to `0x00`.
///
/// The same ablation also fails
/// [`reemit_rewrites_the_leading_varint_when_it_must`],
/// [`elide_of_a_middle_object_is_byte_equal_to_the_encoded_survivors`] and
/// the two oversized tests through their counter assertions — and leaves
/// the other twelve green.
#[tokio::test]
async fn no_action_forwarding_is_byte_identical_on_every_draft() {
    for &draft in DRAFTS {
        for wire in fixtures_for(draft) {
            let objects = wire.objects(&[0, 1, 2, 3]);
            let stream = wire.subgroup_stream(&objects);

            let run = forward(draft, &stream, pass_hook()).await;

            assert_eq!(run.ending, Ending::Fin, "[{draft}] a passed stream ends with a FIN");
            assert_eq!(
                run.bytes, stream,
                "[{draft}] ext={} mode={:?}: Action::Pass must forward the framer's own bytes",
                wire.extensions, wire.mode
            );
            assert_eq!(run.framed_ids(), vec![0, 1, 2, 3], "[{draft}] every object was addressed");
            assert!(
                run.applied().iter().all(|(site, kind, effect)| *site == Site::Object
                    && *kind == ActionKind::Pass
                    && *effect == Effect::ForwardedVerbatim),
                "[{draft}] every applied action must be a verbatim forward: {:?}",
                run.applied()
            );
            assert!(run.refused().is_empty(), "[{draft}] nothing refused: {:?}", run.refused());
            assert_eq!(run.counters.objects_elided, 0, "[{draft}] nothing was elided");
            assert_eq!(
                run.counters.object_ids_rewritten, 0,
                "[{draft}] a stream with no elide must not have a single ID field rewritten"
            );
        }
    }

    // The fixture the ablation above needs: object 1's leading field is
    // the two-byte spelling of 0. Minimal is `0x00`, so a fix-up applied
    // here changes bytes and this assertion catches it. One draft rather
    // than a sweep, because the claim is about the fix-up guard and not
    // about any draft's layout.
    let draft = a_compiled_draft();
    let wire = Wire::new(draft);
    let mut objects = wire.objects(&[0, 1, 2]);
    objects[1] = objects[1].clone().with_id_width(2);
    let stream = wire.subgroup_stream(&objects);

    let run = forward(draft, &stream, pass_hook()).await;
    assert_eq!(run.ending, Ending::Fin);
    assert_eq!(
        run.bytes, stream,
        "[{draft}] a non-minimal leading Object ID varint must be forwarded untouched"
    );
    assert_eq!(run.counters.object_ids_rewritten, 0, "[{draft}] no fix-up was owed");
}

/// Every stream shape a draft can carry: explicit subgroup ID, with and
/// without an extension block.
fn fixtures_for(draft: DraftVersion) -> Vec<Wire> {
    let base = Wire::new(draft);
    if draft == DraftVersion::Draft07 {
        // Draft-07 objects have no extension block to carry.
        vec![base]
    } else {
        vec![base, base.with_extensions()]
    }
}

// ============================================================
// 2. Drop(Elide) — byte equality against the encoded survivors
// ============================================================

/// Eliding the middle of `[0,1,2]` leaves bytes equal to an independently
/// encoded stream of `[0,2]`.
///
/// One assertion catches both failure modes: successors renumbered to
/// `[0,1]` (the delta was left stale) and successors re-encoded
/// non-identically (the survivor went through a writer rather than being
/// copied).
///
/// *Ablation (measured):* make `ObjectFramer::note_elided` a no-op on the
/// delta drafts — never reach `self.fixup_pending = true`. Verified: the
/// loop runs 07 upwards and the first failure is **draft-14**
/// (`…, 0x00, 4, …` where `…, 0x01, 4, …` is owed), so drafts 07-13 passed
/// under the same ablated build. That is the proof the absolute/delta
/// split is real rather than asserted.
#[tokio::test]
async fn elide_of_a_middle_object_is_byte_equal_to_the_encoded_survivors() {
    for &draft in DRAFTS {
        for wire in fixtures_for(draft) {
            let objects = wire.objects(&[0, 1, 2]);
            let stream = wire.subgroup_stream(&objects);
            let expected = wire.survivor_stream(&objects, &[1]);
            let renumbered = DELTA_DRAFTS.contains(&draft);

            let run = forward(draft, &stream, elide_hook(&[1])).await;

            assert_eq!(run.ending, Ending::Fin, "[{draft}] the stream still FINs");
            assert_eq!(
                run.bytes, expected,
                "[{draft}] ext={}: the survivors must be the independently encoded [0, 2]",
                wire.extensions
            );
            assert_eq!(
                run.applied(),
                &[
                    (Site::Object, ActionKind::Pass, Effect::ForwardedVerbatim),
                    (
                        Site::Object,
                        ActionKind::DropElide,
                        Effect::Elided { renumbered_successor: renumbered }
                    ),
                    (Site::Object, ActionKind::Pass, Effect::ForwardedVerbatim),
                ],
                "[{draft}] one elide, reported once, between two verbatim forwards"
            );
            assert_eq!(run.counters.objects_elided, 1, "[{draft}]");
            assert_eq!(
                run.counters.object_ids_rewritten,
                u64::from(renumbered),
                "[{draft}] one fix-up, and only where IDs are deltas"
            );
        }
    }
}

/// Eliding index 0 leaves bytes equal to an independently encoded stream
/// of `[1,2]` — on **all fourteen drafts**.
///
/// Index 0 is elidable on every draft whenever the header carries an
/// explicit Subgroup ID, and that case is exactly where the
/// absolute-versus-delta seeding differs: object 1's field stops being a
/// delta and becomes an absolute ID, because `prev_forwarded` is still
/// `None`.
///
/// *Ablation (measured):* seed the fix-up with `Some(0)` instead of
/// `None` —
/// `reemit_subgroup_object(self.draft, self.last_forwarded_id.or(Some(0)), …)`
/// in `apply_elide_fixup`. Verified twice, because the shared loop stops
/// at the first failing draft and draft-15 had to be shown to fail on its
/// own account: once
/// as written, where it fails at draft-14, and once with this test's loop
/// narrowed to `[Draft15]` in the ablation sandbox, where it fails there
/// too — `[…, 0x00, 4, 161, …]` for the `[…, 0x01, 4, 161, …]` that is
/// owed, i.e. `1 - 0 - 1 = 0` written where the absolute `1` belongs.
/// Drafts 07-13 stay green, since they never reach the fix-up at all.
#[tokio::test]
async fn elide_of_index_zero_is_byte_equal_to_the_encoded_survivors() {
    for &draft in DRAFTS {
        for wire in fixtures_for(draft) {
            let objects = wire.objects(&[0, 1, 2]);
            let stream = wire.subgroup_stream(&objects);
            let expected = wire.survivor_stream(&objects, &[0]);

            let run = forward(draft, &stream, elide_hook(&[0])).await;

            assert_eq!(run.ending, Ending::Fin, "[{draft}]");
            assert_eq!(
                run.bytes, expected,
                "[{draft}] ext={}: object 1's field must become absolute, not stay a delta",
                wire.extensions
            );
            assert!(
                run.refused().is_empty(),
                "[{draft}] an explicit Subgroup ID makes index 0 elidable: {:?}",
                run.refused()
            );
            assert_eq!(run.counters.objects_elided, 1, "[{draft}]");
        }
    }
}

/// Eliding a *run* accumulates both gaps into one survivor rather than
/// applying a single correction.
///
/// `[0,1,2,3,4]` minus indices 1 and 2 must be the independently encoded
/// `[0,3,4]`: on a delta draft object 3's field goes from `0x00` to
/// `0x02`, and object 4's stays `0x00` because the cursor re-converged.
///
/// *Ablation (measured):* commit the object that carried a fix-up as
/// forwarded inside `apply_elide_fixup` — add
/// `self.last_forwarded_id = Some(object_id);` next to
/// `self.fixup_pending = false;`. A plausible mistake, since that object
/// usually *is* forwarded. It is wrong exactly when the object carrying
/// the fix-up is itself elided, which only a run can produce. Verified to
/// fail **this test and no other** in the file: object 3 goes out with the
/// delta measured from the elided object 2 instead of from object 0.
#[tokio::test]
async fn elide_of_a_run_is_byte_equal_to_the_encoded_survivors() {
    for &draft in DRAFTS {
        let wire = Wire::new(draft);
        let objects = wire.objects(&[0, 1, 2, 3, 4]);
        let stream = wire.subgroup_stream(&objects);
        let expected = wire.survivor_stream(&objects, &[1, 2]);

        let run = forward(draft, &stream, elide_hook(&[1, 2])).await;

        assert_eq!(run.ending, Ending::Fin, "[{draft}]");
        assert_eq!(
            run.bytes, expected,
            "[{draft}] two adjacent elides must accumulate into object 3's field"
        );
        assert_eq!(run.counters.objects_elided, 2, "[{draft}]");
    }
}

/// On an absolute-ID draft an elide is pure byte deletion: the survivors
/// arrive exactly as they were encoded, including a legal **non-minimal
/// varint** inside an extension block.
///
/// Draft-08's block is count-prefixed and its reader rebuilds each
/// Key-Value-Pair through `VarInt::encode`, so a re-serialization
/// normalizes `0x40 0x02` to `0x02`. Byte equality here is therefore the
/// assertion that the proxy deleted bytes rather than round-tripping the
/// survivors through the codec.
///
/// *Ablation (measured):* in `ObjectFramer::poll_object`, replace a
/// draft-08 object's forwarded slice with
/// `AnySubgroupObjectReader::read_object` +
/// `AnySubgroupObjectWriter::write_object` — a full re-serialization.
/// Verified to fail this test: object 2's extension block comes back one
/// byte shorter, while every minimal-varint *subgroup* fixture in the file
/// stays green. (It also takes down
/// [`fetch_elide_needs_no_encoder_on_drafts_07_to_14`], but only because
/// the crude patch reaches for a subgroup reader on a fetch stream — that
/// is the ablation's scaffolding failing, not the property.)
///
/// (One ablation that looks apt here cannot fail: forcing
/// `Reemit::Reencoded` changes nothing on this test, because
/// `reemit_subgroup_object` never touches the extension block — only the
/// leading varint. `reemit_rewrites_the_leading_varint_when_it_must` is
/// where that ablation does bite.)
#[tokio::test]
async fn elide_on_absolute_id_drafts_copies_survivors_verbatim() {
    // The first absolute-ID draft this build compiled that also has an
    // extension block; naming one outright made the test report on the
    // feature set instead of on the copy.
    let Some(&draft) = ABSOLUTE_ID_EXT_DRAFTS.first() else {
        return;
    };
    let wire = Wire::new(draft).with_extensions();

    let mut objects = wire.objects(&[0, 1, 2]);
    objects[2] = objects[2].clone().with_ext(EXT_NON_MINIMAL, 1);
    let stream = wire.subgroup_stream(&objects);

    // Written out rather than taken from `survivor_stream` so the claim is
    // visible: on an absolute draft the survivors' bytes are the source's
    // bytes, spliced.
    let mut expected = wire.subgroup_header();
    expected.extend_from_slice(&wire.subgroup_object(None, &objects[0]));
    expected.extend_from_slice(&wire.subgroup_object(Some(1), &objects[2]));
    assert_eq!(
        expected,
        wire.survivor_stream(&objects, &[1]),
        "the two ways of stating the expectation must agree on an absolute draft"
    );

    let run = forward(draft, &stream, elide_hook(&[1])).await;

    assert_eq!(run.ending, Ending::Fin);
    assert_eq!(run.bytes, expected, "[{draft}] survivors must be copied, not re-serialized");
    assert_eq!(
        run.counters.object_ids_rewritten, 0,
        "[{draft}] an absolute draft rewrites no ID field"
    );
}

/// The leading Object ID varint is rewritten when — and only when — the
/// elide made the old one wrong, and the rewrite is minimal.
///
/// Fixture: a delta-ID stream whose object 1 carries a non-minimally
/// encoded leading delta — the two-byte spelling of 0, which is
/// `0x80 0x00` under MoQT's varint and `0x40 0x00` under RFC 9000's, so
/// the fixture's own self-check derives it from the draft rather than
/// writing one of them down. Forwarding with no action must reproduce it
/// exactly; eliding object 0 must replace that field with the minimal
/// encoding of object 1's new **absolute** ID, and change nothing after
/// it.
///
/// *Ablation (measured):* re-encode the leading field of every object,
/// untouched ones included — drop `apply_elide_fixup`'s `fixup_pending`
/// guard. Verified to fail **half one**, whose forwarded stream comes back
/// with object 1's two-byte field collapsed to `0x00`:
/// `[…, 0, 4, 160, 177, 194, 0, 0, 4, 161, …]` for the
/// `[…, 0, 4, 160, 177, 194, 0, 64, 0, 4, 161, …]` that was sent. This is
/// the ablation that was first aimed at
/// [`elide_on_absolute_id_drafts_copies_survivors_verbatim`], where it
/// could not fail — `reemit_subgroup_object` never touches the extension
/// block, only the leading varint. Half two additionally fails under the
/// `Some(0)` seeding ablation described on
/// [`elide_of_index_zero_is_byte_equal_to_the_encoded_survivors`].
#[tokio::test]
async fn reemit_rewrites_the_leading_varint_when_it_must() {
    // The newest delta-ID draft this build compiled — draft-19 wherever
    // every draft is in, which is the draft this named before it was
    // derived. Eliding only renumbers a successor where the ID is written
    // as a delta, and the widened spelling of zero differs between the two
    // varint encodings, so it is derived rather than written out.
    let Some(&draft) = DELTA_DRAFTS.last() else {
        return;
    };
    let wire = Wire::new(draft);

    let mut objects = wire.objects(&[0, 1, 2]);
    objects[1] = objects[1].clone().with_id_width(2);
    let stream = wire.subgroup_stream(&objects);

    // Half one: nothing asked for, nothing changed.
    let run = forward(draft, &stream, pass_hook()).await;
    assert_eq!(run.ending, Ending::Fin);
    assert_eq!(run.bytes, stream, "[{draft}] a widened field must survive an untouched forward");

    // Half two: object 0 elided, so object 1 leads the stream and its
    // field becomes the minimal absolute `0x01`. Object 2's field is
    // `0x00` before and after — the cursor re-converged.
    let mut survivors = objects[1..].to_vec();
    survivors[0].id_width = None;
    let mut expected = wire.subgroup_header();
    expected.extend_from_slice(&wire.subgroup_objects(&survivors));

    let run = forward(draft, &stream, elide_hook(&[0])).await;
    assert_eq!(run.ending, Ending::Fin);
    assert_eq!(run.bytes, expected, "[{draft}] the rewritten field must be minimal");

    // And the claim stated field by field: one byte of ID where two were,
    // every byte after it identical.
    let head = wire.subgroup_header().len();
    let source_object_1 = wire.subgroup_object(Some(0), &objects[1]);
    assert_eq!(&source_object_1[..2], &widened_zero(draft), "the fixture's widened field");
    assert_eq!(run.bytes[head], 0x01, "[{draft}] object 1's new field is the absolute ID");
    assert_eq!(
        &run.bytes[head + 1..head + source_object_1.len() - 1],
        &source_object_1[2..],
        "[{draft}] every byte after the ID field must be untouched"
    );
    assert_eq!(run.counters.object_ids_rewritten, 1, "[{draft}] exactly one field was rewritten");
}

// ============================================================
// 3. The elide cursor across an object the framer cannot address
// ============================================================

/// An elide survives an object too large to buffer.
///
/// Object at index 2 is past `FramerConfig::max_buffered_object_bytes`, so
/// the framer streams it through as `Passthrough` and `on_object` is never
/// called for it. The fix-up owed by eliding index 1 must still be applied
/// to that object's **first chunk**, or its stale delta shifts every later
/// object for the rest of the stream.
///
/// The IDs are chosen so `id_bytes_after == id_bytes_before`
/// (`2 - 1 - 1 = 0` becomes `2 - 0 - 1 = 1`, both one byte);
/// [`an_oversized_successor_whose_new_delta_needs_a_wider_varint`] covers
/// the case where the width changes.
///
/// *Ablation (measured):* revert to the earlier design — call the fix-up
/// only from `poll_object`'s addressable arm, i.e. discard
/// `apply_elide_fixup`'s rewritten bytes in `poll_oversized`. Verified to
/// fail on every one of drafts 14-20, the emitted chunk carrying
/// `…, 0, 0, 128, 80, …` where `…, 0, 1, 128, 80, …` is owed. It fails
/// nothing outside the two oversized tests, because the addressable path
/// still fixes up.
#[tokio::test]
async fn elide_followed_by_an_oversized_object_keeps_ids_correct() {
    for &draft in DELTA_DRAFTS {
        let wire = Wire::new(draft);
        let mut objects = wire.objects(&[0, 1, 2, 3, 4, 5]);
        objects[2] = objects[2].clone().with_payload(vec![0x5A; OVERSIZED_PAYLOAD]);

        let stream = wire.subgroup_stream(&objects);
        let expected = wire.survivor_stream(&objects, &[1]);

        let run = forward_parts(draft, &[&stream], Duration::ZERO, 8192, elide_hook(&[1])).await;

        assert_eq!(run.ending, Ending::Fin, "[{draft}]");
        assert_eq!(run.bytes.len(), expected.len(), "[{draft}] survivor stream length");
        assert_eq!(run.bytes, expected, "[{draft}] the oversized successor's delta must be fixed");
        assert_eq!(
            run.framed_ids(),
            vec![0, 1, 3, 4, 5],
            "[{draft}] object 2 was never addressable, and framing resumed on object 3"
        );
        assert_eq!(run.counters.objects_not_addressable, 1, "[{draft}] one unaddressable object");
        assert_eq!(
            run.impairments()
                .iter()
                .filter(|k| matches!(k, ImpairmentKind::ObjectNotAddressable { .. }))
                .count(),
            1,
            "[{draft}] said exactly once per stream: {:?}",
            run.impairments()
        );
        assert_eq!(run.counters.object_ids_rewritten, 1, "[{draft}]");
        assert_eq!(run.counters.objects_elided, 1, "[{draft}]");
    }
}

/// The case the test above cannot reach: the survivor's **new delta needs
/// a wider varint**.
///
/// IDs `[0, 1, 2, 190, 200, 201]`, with ID 200 (index 4) past the buffer cap
/// and ID 190 (index 3) elided. Before the elide, ID 200's wire delta is
/// `200 - 190 - 1 = 9`, one byte. After it, the delta is `200 - 2 - 1 = 197`
/// — **two** bytes. 197 is chosen because it widens under both encodings:
/// RFC 9000's one-byte range stops at 63 and MoQT's at 127. Byte equality
/// against the independently encoded `[0, 1, 2, 200, 201]` pins three things
/// at once: the prefix chunk was
/// fixed up, the object's remaining chunks were passed through counting
/// **source** bytes (so the framer resynchronised on ID 81's real first
/// byte, not one byte early), and ID 81 was forwarded verbatim because the
/// cursor re-converged.
///
/// *Ablation 1 (measured):* subtract the fix-up's width growth from
/// `passthrough_remaining` in `poll_oversized` — the plausible-looking
/// "fix" that counts the destination's bytes where the passthrough budget
/// is measured in the source's. Verified to fail **this test and no other**:
/// the framer resynchronises one byte early, so the last object's ID field
/// starts inside the previous object and the tail decodes to a garbage ID.
/// [`elide_followed_by_an_oversized_object_keeps_ids_correct`] stays green
/// because there the two widths are equal, which is precisely why this
/// fixture exists.
///
/// *Ablation 2 (measured):* the earlier-design ablation above — no fix-up
/// on the oversized path at all. Verified to fail here on the length
/// assertion (5242914 delivered where 5242915 is owed) before the byte
/// comparison is reached.
#[tokio::test]
async fn an_oversized_successor_whose_new_delta_needs_a_wider_varint() {
    for &draft in DELTA_DRAFTS {
        let wire = Wire::new(draft);
        let mut objects = wire.objects(&[0, 1, 2, 190, 200, 201]);
        objects[4] = objects[4].clone().with_payload(vec![0x6B; OVERSIZED_PAYLOAD]);

        let stream = wire.subgroup_stream(&objects);
        let expected = wire.survivor_stream(&objects, &[3]);

        // The arithmetic this fixture exists for, stated so a future edit
        // to the IDs cannot silently stop testing the widening.
        let before = wire.subgroup_object(Some(190), &objects[4]);
        let after = wire.subgroup_object(Some(2), &objects[4]);
        let widened: &[u8] = if draft.uses_moqt_varint() { &[0x80, 197] } else { &[0x40, 197] };
        assert_eq!(before[0], 9, "[{draft}] ID 200's original delta is one byte");
        assert_eq!(&after[..2], widened, "[{draft}] ID 200's new delta needs two bytes");

        let run = forward_parts(draft, &[&stream], Duration::ZERO, 8192, elide_hook(&[3])).await;

        assert_eq!(run.ending, Ending::Fin, "[{draft}]");
        assert_eq!(
            run.bytes.len(),
            expected.len(),
            "[{draft}] a desynchronised passthrough shows up as a length mismatch first"
        );
        assert_eq!(run.bytes, expected, "[{draft}] survivors [0, 1, 2, 200, 201]");
        assert_eq!(
            run.framed_ids(),
            vec![0, 1, 2, 190, 201],
            "[{draft}] framing resumed exactly on ID 201"
        );
        assert_eq!(run.counters.object_ids_rewritten, 1, "[{draft}] exactly one fix-up");
        assert_eq!(run.counters.objects_not_addressable, 1, "[{draft}]");
    }
}

/// A framer that stops parsing while a fix-up is still owed resets the
/// destination rather than forwarding a tail that renumbers itself.
///
/// Objects 0 and 1 are forwarded and elided respectively, then an all-ones
/// varint arrives — eight bytes under RFC 9000, nine from draft-17, each the
/// widest its encoding defines. Its delta resolves to an Object ID above the
/// ceiling, so the object reader returns `InvalidField` and the framer
/// abandons the stream with the fix-up unspent.
///
/// The elided object is the **last** one on the stream, deliberately. A
/// fix-up is spent on the next object the framer emits, so a fixture with
/// a survivor after the elide would have discharged it before the poison
/// arrived and the stream would FIN — which is the shape the first draft
/// of this test had, and it passed against every implementation.
///
/// *Ablation (measured):* forward the remainder instead of resetting —
/// disable the `if fixup_owed` arm in `pipe_data_framed`'s
/// `FramerOut::Bypassed` branch. Verified to fail **this test and no
/// other**: the stream ends with `Ending::Fin`.
#[tokio::test]
async fn a_bypass_while_a_fixup_is_owed_resets_the_stream() {
    for &draft in DELTA_DRAFTS {
        let wire = Wire::new(draft);
        let objects = wire.objects(&[0, 1]);
        let stream = wire.subgroup_stream(&objects);
        let expected = wire.survivor_stream(&objects, &[1]);
        let poison: &[u8] = if draft.uses_moqt_varint() { &[0xFFu8; 9] } else { &[0xFFu8; 8] };

        // The poison arrives after a real pause, so the survivor bytes are
        // on the wire before the decision that tears the stream down.
        let run = forward_parts(
            draft,
            &[&stream, poison],
            Duration::from_millis(200),
            WRITE_CHUNK,
            elide_hook(&[1]),
        )
        .await;

        assert_eq!(
            run.ending,
            Ending::Reset(0x0),
            "[{draft}] a stranded fix-up must reset the destination"
        );
        assert_prefix_of(draft, &run.bytes, &expected, "bytes before the reset");
        // A prefix on its own admits the empty prefix, which every
        // implementation satisfies. The deterministic half of the claim is
        // proxy-side: both objects were framed, and the survivor's bytes
        // were handed to the transport 200 ms before the reset, so
        // something must have arrived.
        assert_eq!(run.framed_ids(), vec![0, 1], "[{draft}] both objects were addressed");
        assert!(
            !run.bytes.is_empty(),
            "[{draft}] the survivor was written {:?} before the reset and must have arrived",
            Duration::from_millis(200)
        );
        let lost: Vec<_> = run
            .impairments()
            .iter()
            .filter(|k| matches!(k, ImpairmentKind::ElideFixupLost { .. }))
            .collect();
        assert_eq!(lost.len(), 1, "[{draft}] one report: {:?}", run.impairments());
        assert!(
            matches!(
                lost[0],
                ImpairmentKind::ElideFixupLost { reason: BypassReason::DecodeError, code: 0, .. }
            ),
            "[{draft}] {:?}",
            lost[0]
        );
    }
}

/// The same reset on a **fetch** stream, where the fix-up is a re-encode of
/// the survivor's framing rather than a rewrite of one varint.
///
/// A separate test and not a widened sweep, because the two owe the debt from
/// different drafts — a subgroup stream from 14, a fetch stream from 15 — and
/// because the poison has to be a fetch object rather than a subgroup one.
///
/// The elided object is the **last** on the stream, for the reason the
/// subgroup version gives: a fix-up is spent on the next frame the framer
/// emits, so a survivor behind the elide would discharge it before the poison
/// arrived and the stream would FIN.
///
/// The poison is a flags field of all-ones. Draft-15 reads one fixed byte and
/// refuses it for the two bits Section 10.4.4 leaves unassigned; drafts 16 and
/// 17 read a variable-length integer and refuse the value for not being a flag
/// set they define. Either way it is a decode failure and not a short read,
/// which is what makes the framer give up rather than wait.
///
/// *Ablation (measured):* have `ObjectFramer::elide_owes_a_fixup` answer
/// `false` for fetch streams, which is what the predicate it replaced did.
/// Fails **this test and no other**:
///
/// ```text
/// assertion `left == right` failed: [draft-15] a stranded fetch fix-up must reset the destination
///   left: Fin
///  right: Reset(0)
/// ```
///
/// A clean FIN on a stream whose tail was never written, which is the answer
/// a subscriber cannot tell from a complete response.
#[tokio::test]
#[cfg(any(feature = "draft15", feature = "draft16", feature = "draft17"))]
async fn a_bypass_while_a_fetch_fixup_is_owed_resets_the_stream() {
    for &draft in FETCH_REENCODE_ELIDE_DRAFTS {
        let wire = Wire::new(draft);
        let stream = wire.inheriting_fetch_stream();
        let poison: &[u8] = if draft.uses_moqt_varint() { &[0xFFu8; 9] } else { &[0xFFu8; 8] };

        let run = forward_parts(
            draft,
            &[&stream, poison],
            Duration::from_millis(200),
            WRITE_CHUNK,
            elide_hook(&[2]),
        )
        .await;

        assert_eq!(
            run.ending,
            Ending::Reset(0x0),
            "[{draft}] a stranded fetch fix-up must reset the destination"
        );
        assert_eq!(run.framed_ids(), vec![0, 1, 2], "[{draft}] all three objects were addressed");
        // The two survivors are the stream's own bytes: nothing was removed
        // in front of them, so neither is re-encoded.
        let mut forwarded = wire.fetch_header();
        for frame in &wire.inheriting_fetch_frames()[..2] {
            forwarded.extend_from_slice(frame);
        }
        assert_prefix_of(draft, &run.bytes, &forwarded, "bytes before the reset");
        assert!(
            !run.bytes.is_empty(),
            "[{draft}] the survivors were written {:?} before the reset and must have arrived",
            Duration::from_millis(200)
        );
        let lost: Vec<_> = run
            .impairments()
            .iter()
            .filter(|k| matches!(k, ImpairmentKind::ElideFixupLost { .. }))
            .collect();
        assert_eq!(lost.len(), 1, "[{draft}] one report: {:?}", run.impairments());
        assert!(
            matches!(
                lost[0],
                ImpairmentKind::ElideFixupLost { reason: BypassReason::DecodeError, code: 0, .. }
            ),
            "[{draft}] {:?}",
            lost[0]
        );
        assert_eq!(run.counters.object_ids_rewritten, 0, "[{draft}] the fix-up was never spent");
    }
}

// ============================================================
// 4. Refusals at the object site
// ============================================================

/// Eliding index 0 of a stream whose Subgroup ID *is* the first object's
/// ID is refused, and the stream is forwarded unchanged.
///
/// Nine drafts define that stream type. Removing index 0 there would
/// silently redefine the subgroup ID for the receiver, which is a
/// different stream, not a shorter one.
///
/// *Ablation (measured):* delete the `cx.subgroup_id_resolved == Some(false)`
/// arm from `capability::object_drop_elide`. Verified to fail **this test
/// and no other**: the elide is admitted, the stream comes back one object
/// shorter, and the refusal vector is empty.
#[tokio::test]
async fn elide_of_index_zero_on_an_implicit_subgroup_stream_is_refused() {
    for &draft in IMPLICIT_SUBGROUP_DRAFTS {
        let wire = Wire::new(draft).with_mode(SubgroupIdMode::FirstObject);
        let objects = wire.objects(&[0, 1, 2]);
        let stream = wire.subgroup_stream(&objects);

        let run = forward(draft, &stream, elide_hook(&[0])).await;

        assert_eq!(run.ending, Ending::Fin, "[{draft}]");
        assert_eq!(
            run.refused(),
            &[(Site::Object, ActionKind::DropElide, Refusal::WouldRedefineSubgroupId)],
            "[{draft}] one refusal, naming the subgroup ID"
        );
        assert_eq!(run.bytes, stream, "[{draft}] a refused unit is forwarded unchanged");
        assert_eq!(run.counters.objects_elided, 0, "[{draft}] nothing was removed");
        assert_eq!(run.counters.actions_refused, 1, "[{draft}]");
    }
}

/// A stream opened with a reserved subgroup-ID mode is carried whole, and
/// no hook is offered a say over it.
///
/// Draft-19 Section 11.4.2, and the same list in 18, 17 and 16, gives every
/// mode-3 type value — `0x16` among them — as invalid and tells the
/// endpoint receiving one to close the session with a PROTOCOL_VIOLATION.
/// A proxy is not that endpoint: it exists to put a broken publisher in
/// front of a real subscriber, so the violation has to arrive at the
/// subscriber for the subscriber to be the one that answers it. Dropping
/// it, or resetting the stream, would take the induced error off the wire
/// and leave the run looking clean.
///
/// So the header never decodes, the framer abandons the stream at it, and
/// the elide the hook asks for is never asked *of* it — no object was ever
/// addressed for the hook to name. The refusal path is not reached at all,
/// which is why the refusal vector is empty rather than carrying one.
///
/// *Ablation (measured):* drop the buffered bytes where the header decode
/// fails, so the framer keeps the stream it could not read instead of
/// releasing it uninterpreted:
///
/// ```text
/// assertion `left == right` failed: [draft-17] every byte of an unreadable stream still reaches the far side
///   left: [1, 0, 128, 0, 4, 160, 177, 194, 0, 0, 4, 161, 177, 194, 1, 0, 4, 162, 177, 194, 2]
///  right: [22, 1, 0, 128, 0, 4, 160, 177, 194, 0, 0, 4, 161, 177, 194, 1, 0, 4, 162, 177, 194, 2]
/// ```
///
/// *Ablation (measured), for draft-16's place in the sweep:* the draft was
/// missing from `MODE_FIELD_DRAFTS` on the reading that only 17-19 carry the
/// field, so this ran over three drafts where four define the mode. Letting
/// draft-16's `subgroup_type_is_valid` admit the reserved mode shows the
/// fourth is doing work rather than repeating the others:
///
/// ```text
/// [draft-16] nothing on the stream is addressable: [144115207968506369]
/// ```
#[tokio::test]
async fn a_reserved_mode_stream_is_forwarded_whole_and_reaches_no_object_site() {
    for &draft in MODE_FIELD_DRAFTS {
        let wire = Wire::new(draft).with_mode(SubgroupIdMode::Reserved);
        let objects = wire.objects(&[0, 1, 2]);
        let stream = wire.subgroup_stream(&objects);

        let run = forward(draft, &stream, elide_hook(&[0])).await;

        assert_eq!(run.ending, Ending::Fin, "[{draft}] the stream ends as it was ended");
        assert_eq!(
            run.bytes, stream,
            "[{draft}] every byte of an unreadable stream still reaches the far side"
        );
        assert!(
            run.framed_ids().is_empty(),
            "[{draft}] nothing on the stream is addressable: {:?}",
            run.framed_ids()
        );
        assert_eq!(
            run.refused(),
            &[],
            "[{draft}] the object site is never reached, so nothing is refused there"
        );
        assert_eq!(
            run.impairments()
                .iter()
                .filter(|k| matches!(
                    k,
                    ImpairmentKind::FramerBypass { reason: BypassReason::DecodeError, .. }
                ))
                .count(),
            1,
            "[{draft}] the gap is reported once per stream: {:?}",
            run.impairments()
        );
        assert_eq!(run.counters.objects_elided, 0, "[{draft}] nothing was removed");
        assert_eq!(run.counters.actions_refused, 0, "[{draft}]");
    }
}

/// Eliding an object that carries an Object Status is refused on every
/// draft: a status object is treated as a boundary marker.
///
/// The status object sits at index 1, so the index-0 guard cannot be what
/// produces the refusal.
///
/// *Ablation (measured):* answer `Support::Yes` for
/// `cx.is_status_object == Some(true)` in `capability::object_drop_elide`.
/// Verified to fail **this test and no other**: the status object is
/// removed and the refusal vector is empty.
#[tokio::test]
async fn elide_of_a_status_object_is_refused() {
    for &draft in DRAFTS {
        let wire = Wire::new(draft);
        let mut objects = wire.objects(&[0, 1, 2]);
        objects[1] = objects[1].clone().with_status(STATUS_END_OF_GROUP);
        let stream = wire.subgroup_stream(&objects);

        let run = forward(draft, &stream, elide_hook(&[1])).await;

        assert_eq!(run.ending, Ending::Fin, "[{draft}]");
        assert_eq!(
            run.refused(),
            &[(Site::Object, ActionKind::DropElide, Refusal::WouldDestroyStatusObject)],
            "[{draft}]"
        );
        assert_eq!(run.bytes, stream, "[{draft}] a refused elide forwards the object unchanged");
        assert_eq!(run.counters.objects_elided, 0, "[{draft}]");
    }
}

// ============================================================
// 5. ReplacePayload
// ============================================================

/// A same-length payload replacement changes exactly one object's payload
/// and nothing else on the stream.
///
/// The assertion is stated twice on purpose: byte equality against an
/// independently encoded stream carrying the replacement, and a per-object
/// re-framing that names *which* object changed and shows its neighbours
/// still decode.
///
/// *Ablation (measured):* move the splice one byte earlier —
/// `payload_offset(...) - 1` in `exec`'s `Action::ReplacePayload` arm, the
/// smallest version of "splice somewhere other than the payload offset".
/// Verified to fail **this test and no other**.
#[tokio::test]
async fn replace_payload_at_the_same_length_changes_only_that_object() {
    const REPLACEMENT: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];

    for &draft in DRAFTS {
        for wire in fixtures_for(draft) {
            let objects = wire.objects(&[0, 1, 2]);
            assert_eq!(objects[1].payload.len(), REPLACEMENT.len(), "the fixture must match");

            let stream = wire.subgroup_stream(&objects);
            let mut replaced = objects.clone();
            replaced[1] = replaced[1].clone().with_payload(REPLACEMENT.to_vec());
            let expected = wire.subgroup_stream(&replaced);

            let run = forward(
                draft,
                &stream,
                hook(|cx| {
                    if cx.meta.index_in_stream == 1 {
                        Action::ReplacePayload(Bytes::from_static(REPLACEMENT))
                    } else {
                        Action::Pass
                    }
                }),
            )
            .await;

            assert_eq!(run.ending, Ending::Fin, "[{draft}]");
            assert_eq!(
                run.bytes, expected,
                "[{draft}] ext={}: only object 1's payload may differ",
                wire.extensions
            );
            assert_eq!(
                run.applied()[1],
                (
                    Site::Object,
                    ActionKind::ReplacePayload,
                    Effect::Replaced { bytes: wire.subgroup_object(Some(0), &replaced[1]).len() }
                ),
                "[{draft}] the effect counts the whole rewritten object"
            );
            assert!(run.refused().is_empty(), "[{draft}] {:?}", run.refused());

            // The neighbours still decode, and only the middle one moved.
            let framed = reframe(draft, &run.bytes);
            assert_eq!(
                framed.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
                vec![0, 1, 2],
                "[{draft}] the rewritten stream must still frame into three objects"
            );
            assert_eq!(framed[1].1, REPLACEMENT, "[{draft}] object 1 carries the replacement");
            assert_eq!(framed[0].1, objects[0].payload, "[{draft}] object 0 is untouched");
            assert_eq!(framed[2].1, objects[2].payload, "[{draft}] object 2 is untouched");
        }
    }
}

/// A payload replacement of a different length is refused with the two
/// lengths in it, and the object is forwarded unchanged.
///
/// *Ablation (measured):* disable the `from != to` arm in
/// `capability::object_replace_payload`. Verified to fail **this test and
/// no other**: the splice happens anyway and no refusal is reported.
#[tokio::test]
async fn replace_payload_at_a_different_length_is_refused() {
    const TOO_LONG: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF, 0x00];

    for &draft in DRAFTS {
        let wire = Wire::new(draft);
        let objects = wire.objects(&[0, 1, 2]);
        let from = objects[1].payload.len() as u64;
        let stream = wire.subgroup_stream(&objects);

        let run = forward(
            draft,
            &stream,
            hook(|cx| {
                if cx.meta.index_in_stream == 1 {
                    Action::ReplacePayload(Bytes::from_static(TOO_LONG))
                } else {
                    Action::Pass
                }
            }),
        )
        .await;

        assert_eq!(run.ending, Ending::Fin, "[{draft}]");
        assert_eq!(
            run.refused(),
            &[(
                Site::Object,
                ActionKind::ReplacePayload,
                Refusal::LengthChanged { from, to: TOO_LONG.len() as u64 }
            )],
            "[{draft}] the refusal must carry both lengths"
        );
        assert_eq!(run.bytes, stream, "[{draft}] a refused replacement forwards the original");
    }
}

// ============================================================
// 6. Truncate
// ============================================================

/// `Truncate { bytes, code }` writes at most `bytes` of the object and
/// then resets the destination with `code`.
///
/// The peer's view is asserted as an **upper bound and a prefix**, never
/// an exact count: quinn clears the receive assembler when it processes a
/// `RESET_STREAM` (RFC 9000 §3.2 permits it), so only bytes the
/// application had already read out survive.
///
/// *Ablation (measured):* queue the whole object instead of
/// `raw.slice(..bytes.min(raw.len()))` in `exec`'s `Action::Truncate` arm.
/// Verified to fail **this test and no other**, on the upper bound: more
/// than `TRUNCATE_AT` bytes of object 1 reach the peer.
#[tokio::test]
async fn truncate_writes_a_bounded_prefix_and_then_resets_with_its_code() {
    const TRUNCATE_AT: usize = 3;
    const CODE: u64 = 0x2;

    for &draft in DRAFTS {
        let wire = Wire::new(draft);
        let objects = wire.objects(&[0, 1, 2]);
        let stream = wire.subgroup_stream(&objects);

        // Everything the peer could legitimately see: the header, object
        // 0, and the first `TRUNCATE_AT` bytes of object 1.
        let mut ceiling = wire.subgroup_header();
        ceiling.extend_from_slice(&wire.subgroup_object(None, &objects[0]));
        let object_1 = wire.subgroup_object(Some(0), &objects[1]);
        ceiling.extend_from_slice(&object_1[..TRUNCATE_AT]);

        let run = forward_parts(
            draft,
            &[&stream],
            Duration::ZERO,
            WRITE_CHUNK,
            hook(|cx| {
                if cx.meta.index_in_stream == 1 {
                    Action::Truncate { bytes: TRUNCATE_AT, code: CODE }
                } else {
                    Action::Pass
                }
            }),
        )
        .await;

        assert_eq!(run.ending, Ending::Reset(CODE), "[{draft}] the reset carries the stated code");
        assert_prefix_of(draft, &run.bytes, &ceiling, "truncated stream");
        assert_eq!(
            run.applied().last(),
            Some(&(
                Site::Object,
                ActionKind::Truncate,
                Effect::Truncated {
                    forwarded: TRUNCATE_AT,
                    code: CODE,
                    // Drafts 07-10 define no stream-reset code vocabulary,
                    // so `code` there is a choice rather than a claim.
                    code_defined: !matches!(
                        draft,
                        DraftVersion::Draft07
                            | DraftVersion::Draft08
                            | DraftVersion::Draft09
                            | DraftVersion::Draft10
                    ),
                }
            )),
            "[{draft}] the effect reports bytes handed to the transport"
        );
    }
}

// ============================================================
// 7. Fetch streams
// ============================================================

/// Eliding a fetch object needs no encoder at all: fetch object IDs are
/// absolute, so the survivors are the source's bytes with one object's
/// bytes deleted.
///
/// *Ablation (measured):* let `ObjectFramer::delta_encodes_object_ids`
/// answer `true` for fetch streams too. Verified to fail **this test and
/// no other**, on draft-14: the framer rewrites the survivor's leading
/// **Group ID** varint, which is not an Object ID at all.
#[tokio::test]
async fn fetch_elide_needs_no_encoder_on_drafts_07_to_14() {
    for &draft in FETCH_OBJECT_DRAFTS {
        let wire = Wire::new(draft);
        let objects = vec![FetchObj::new(7, 0), FetchObj::new(7, 1), FetchObj::new(8, 0)];
        let stream = wire.fetch_stream(&objects);
        let expected = wire.fetch_survivor_stream(&objects, &[1]);

        let run = forward(draft, &stream, elide_hook(&[1])).await;

        assert_eq!(run.ending, Ending::Fin, "[{draft}]");
        assert_eq!(run.bytes, expected, "[{draft}] fetch survivors are copied verbatim");
        assert_eq!(
            run.applied(),
            &[
                (Site::Object, ActionKind::Pass, Effect::ForwardedVerbatim),
                (
                    Site::Object,
                    ActionKind::DropElide,
                    Effect::Elided { renumbered_successor: false }
                ),
                (Site::Object, ActionKind::Pass, Effect::ForwardedVerbatim),
            ],
            "[{draft}] a fetch elide renumbers nothing"
        );
        assert_eq!(run.counters.objects_elided, 1, "[{draft}]");
        assert_eq!(run.counters.object_ids_rewritten, 0, "[{draft}]");
    }
}

/// A rule that would match every object on a draft-18 or draft-19 fetch
/// stream takes **no** action when the session was never told what the fetch
/// asked for, and the stream says why exactly once.
///
/// Those two drafts write a fetch object's Group ID as a difference whose
/// sign the fetch's Group Order settles. A session that carried the FETCH
/// knows it and frames the response like any other stream; this one carried
/// no control frames at all, so the framer latches bypass after the header
/// and the hook is never called. The required behaviour is zero action
/// events and exactly one per-stream
/// `Impairment { FramerBypass { FetchGroupOrderUnknown } }`.
///
/// The contrast is
/// [`a_fetch_elide_re_encodes_the_survivor_where_the_objects_inherit`] on
/// drafts 15-17, where the hook *is* called for every object and the elide
/// is carried out. A silent stream and a stream that acts are two different
/// answers, and the pair is what keeps "not addressed" from spreading back
/// over drafts that are.
///
/// The count is asserted, not the presence: the counter is read from
/// **this** session's recorder, which is what makes `== 0` meaningful
/// while five eliding tests share the binary.
///
/// *Ablation (measured):* revert `ObjectFramer::latch_bypass` to the
/// silent form — never set `pending_bypass`, so no `FramerOut::Bypassed`
/// is produced. Verified to fail this test with an impairment count of 0.
/// It also fails
/// [`a_bypass_while_a_fixup_is_owed_resets_the_stream`], which needs the
/// same item to learn a fix-up was stranded.
#[tokio::test]
async fn a_matching_rule_on_a_fetch_stream_without_a_group_order_reports_a_bypass() {
    for &draft in FETCH_BYPASS_DRAFTS {
        let wire = Wire::new(draft);
        // The bytes after the header are whatever the publisher was
        // sending; nothing on these drafts can interpret them.
        let mut stream = wire.fetch_header();
        stream.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]);

        let run = forward(draft, &stream, elide_hook(&[0, 1, 2, 3])).await;

        assert_eq!(run.ending, Ending::Fin, "[{draft}] a bypassed stream still forwards and FINs");
        assert_eq!(run.bytes, stream, "[{draft}] every byte is forwarded uninterpreted");
        assert_eq!(run.counters.objects_elided, 0, "[{draft}] no object was ever addressable");
        assert!(
            run.applied().is_empty() && run.refused().is_empty(),
            "[{draft}] zero action events on a bypassed fetch stream: {:?} / {:?}",
            run.applied(),
            run.refused()
        );
        assert_eq!(
            run.impairments()
                .iter()
                .filter(|k| matches!(
                    k,
                    ImpairmentKind::FramerBypass {
                        reason: BypassReason::FetchGroupOrderUnknown,
                        ..
                    }
                ))
                .count(),
            1,
            "[{draft}] exactly one per-stream bypass report: {:?}",
            run.impairments()
        );
        assert_eq!(run.counters.streams_not_shapeable, 1, "[{draft}]");
    }
}

/// On drafts 15, 16 and 17 the hook **is** shown every fetch object, and an
/// elide is refused per attempt with the reason.
///
/// The three assertions that matter are separate on purpose, because three
/// different mistakes each satisfy two of them:
///
/// * the stream is framed — a bypass would also forward every byte and
///   elide nothing, and would look identical on the wire;
/// * the survivor's framing is **re-encoded**, so it arrives as object 2
///   rather than as object 1 — the byte comparison is against a stream
///   written out by hand, not against a slice of the source;
/// * the two `Pass` objects around it are still applied;
/// * exactly one fix-up is counted, and the elide reports that a successor
///   was renumbered.
///
/// The byte comparison is the load-bearing one, and byte deletion is what it
/// is measured against: deleting object 1's seven bytes leaves a stream that
/// decodes, whose length is self-consistent, and whose second object is the
/// deleted object's Location.
///
/// *Ablation (measured), three cuts, three different wrong streams:*
///
/// 1. `AnyFetchObjectWriter::reemit_object` answers `Unchanged` for every
///    frame — byte deletion, the defect this replaced:
///
/// ```text
/// assertion `left == right` failed: [draft-15] the survivor keeps its own Location
///   left: [5, 9, 31, 7, 0, 0, 128, 4, 111, 111, 111, 111, 1, 4, 111, 111, 111, 111]
///  right: [5, 9, 31, 7, 0, 0, 128, 4, 111, 111, 111, 111, 5, 2, 4, 111, 111, 111, 111]
/// ```
///
///    The survivor's flags byte is `1`: nothing stated, so its Location is
///    the previous object's stepped by one. It arrives as object **1** — the
///    Location of the object that was deleted — and the stream decodes.
///
/// 2. `ObjectFramer::note_elided` does not put the fetch writer back. Byte
///    for byte the same wrong stream, for the opposite reason: the writer
///    advanced past the elided frame before the hook's verdict landed, so it
///    believed the survivor already followed its predecessor.
///
/// 3. `ObjectFramer::apply_elide_fixup` shows the writer only the frames a
///    fix-up was owed for:
///
/// ```text
///   left: [5, 9, 31, 7, 0, 0, 128, 4, 111, 111, 111, 111, 28, 7, 2, 128, 4, 111, 111, 111, 111]
/// ```
///
///    The survivor is written out absolutely — flags `28`, group 7, object 2,
///    priority 128 — because the writer had never been shown a frame and had
///    no predecessor to write against. Its Location is right and its bytes are
///    four longer than they need to be, which is the visible half of a stale
///    writer; the corrupting half needs a forwarded frame between one elide
///    and the next.
#[tokio::test]
#[cfg(any(feature = "draft15", feature = "draft16", feature = "draft17"))]
async fn a_fetch_elide_re_encodes_the_survivor_where_the_objects_inherit() {
    for &draft in FETCH_REENCODE_ELIDE_DRAFTS {
        let wire = Wire::new(draft);
        let stream = wire.inheriting_fetch_stream();
        let expected = wire.inheriting_fetch_survivor_stream();

        let run = forward(draft, &stream, elide_hook(&[1])).await;

        assert_eq!(run.ending, Ending::Fin, "[{draft}]");
        assert_eq!(
            run.framed_ids(),
            vec![0, 1, 2],
            "[{draft}] the stream is framed and every object reaches the hook"
        );
        assert_eq!(run.bytes, expected, "[{draft}] the survivor keeps its own Location");
        assert!(run.refused().is_empty(), "[{draft}] nothing is refused: {:?}", run.refused());
        assert_eq!(
            run.applied(),
            &[
                (Site::Object, ActionKind::Pass, Effect::ForwardedVerbatim),
                (
                    Site::Object,
                    ActionKind::DropElide,
                    Effect::Elided { renumbered_successor: true }
                ),
                (Site::Object, ActionKind::Pass, Effect::ForwardedVerbatim),
            ],
            "[{draft}] the elide is applied and says a successor owes a fix-up"
        );
        assert_eq!(run.counters.objects_elided, 1, "[{draft}]");
        assert_eq!(run.counters.object_ids_rewritten, 1, "[{draft}] one survivor, one re-encode");
        assert!(
            run.impairments().is_empty(),
            "[{draft}] a paid-for elide is not an impairment: {:?}",
            run.impairments()
        );
    }
}

// ============================================================
// Re-framing a captured stream, for the assertions that name an object
// ============================================================

/// Frame `bytes` as a subgroup stream and report `(object_id, payload)`
/// for each object.
///
/// Used only where an assertion has to name *which* object changed. The
/// byte-level assertions never go through it — they compare against
/// [`Wire`]'s output, which is the point of this file.
fn reframe(draft: DraftVersion, bytes: &[u8]) -> Vec<(u64, Vec<u8>)> {
    use moqtap_proxy::framer::{FramerConfig, FramerOut, ObjectFramer};

    let mut framer = ObjectFramer::new(DataStreamType::Subgroup, draft, FramerConfig::default());
    framer.feed(bytes);
    let mut out = Vec::new();
    loop {
        match framer.poll() {
            FramerOut::NeedMore => break,
            FramerOut::Header { .. } => {}
            FramerOut::Object { meta, raw } => {
                let start = raw.len() - meta.payload_len as usize;
                out.push((meta.object_id, raw[start..].to_vec()));
            }
            FramerOut::Passthrough(raw) => {
                panic!("[{draft}] re-framing fell back to passthrough after {} bytes", raw.len())
            }
            FramerOut::Bypassed { reason, .. } => {
                panic!("[{draft}] re-framing bypassed: {reason:?}")
            }
            FramerOut::Error(e) => panic!("[{draft}] re-framing failed: {e}"),
            other => panic!("[{draft}] unhandled FramerOut: {other:?}"),
        }
    }
    assert_eq!(framer.buffered(), 0, "[{draft}] re-framing left bytes buffered");
    out
}
