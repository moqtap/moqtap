//! The Alias Type decides which field the Token's *second* varint is, and the
//! renderers have to read it the same way the decoder does.
//!
//! `tests/authorization_token_structure.rs` is about the decoder: which Tokens
//! a peer may send and which close the session. This file is about what a
//! reader is then told the Token said, which is a separate claim: a renderer
//! can misreport a Token that the decoder beside it read correctly.
//!
//! The structure is one structure across drafts 11 through 20, and no draft
//! before 11 has an AUTHORIZATION TOKEN at all, which is where this file's
//! feature gate starts:
//!
//! ```text
//! Token {
//!   Alias Type (i),
//!   [Token Alias (i),]
//!   [Token Type (i),]
//!   [Token Value (..)]
//! }
//! ```
//!
//! and the Alias Type is "an integer defining both the serialization and the
//! processing behavior of the receiver". Three of its four code points put the
//! Token Alias in the second position and one puts the Token Type there:
//!
//! | Alias Type | second varint |
//! |---|---|
//! | DELETE (0x0) | Token Alias |
//! | REGISTER (0x1) | Token Alias |
//! | USE_ALIAS (0x2) | Token Alias |
//! | USE_VALUE (0x3) | Token Type |
//!
//! A renderer that reads two varints unconditionally and labels the second
//! `token_type` is right on USE_VALUE and wrong on the other three: the Alias
//! goes out under the Type's name, no `token_alias` key is emitted at all, and
//! on REGISTER the real Token Type is swallowed into `token_value` along with
//! the rest of the tail. That is the failure the assertions below pin.
//!
//! The reading is not in dispute anywhere else in the crate —
//! `auth_token.rs::TokenAliasType::has_alias` is the same table, every draft's
//! renderer branches on it, and each draft's own `check_authorization_tokens`
//! runs `AuthorizationToken::decode` over the very bytes these renderers are
//! then handed. So the gate below is deliberately cross-draft: it asks every
//! draft this build has the same question and requires one answer, because the
//! structure the drafts define is the same structure.

#![cfg(any(
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20"
))]

use moqtap_codec::fields::{FieldMap, FieldValue};

/// A REGISTER Token: Alias Type 0x1, Alias 0x07, Token Type 0x02, and a value.
///
/// REGISTER is the form that carries all four fields, which makes it the only
/// one where all three failures of an unconditional two-varint read show at
/// once — the Alias mislabelled, the Type missing, and the Type's byte left
/// inside `token_value`.
///
/// Token Type 0x02 rather than 0x00 on purpose: a zero would be
/// indistinguishable from an absent field rendered as a default, and the point
/// of the assertion is that the field is the one the wire carried.
///
/// # One spelling, on every draft
///
/// Draft-17 carries no length ahead of the Token Value, so it needs no spelling
/// of its own. Section 9.3.2's Figure 5 is byte-for-byte draft-18's Figure 5 —
/// `[Token Value (..)]` and no length — and what Section 9.3.2 does say, "The
/// AUTHORIZATION TOKEN parameter (Parameter Type 0x03) uses Length-prefixed
/// encoding", is about the Key-Value-Pair's own Length field (Section 9.3:
/// "Length-prefixed: A varint length followed by that many bytes"), which the
/// KVP decoder has already consumed before the Token begins. Draft-18 carries
/// that same sentence verbatim over the same figure.
///
/// So draft-17 reads the Token exactly as its neighbours do, and the fixtures
/// below are one spelling for every draft in the list.
///
/// # Why none of these is gated or allowed
///
/// One spelling per fixture is what keeps every constant here read by every
/// build that compiles this file: `every_draft!` hands it to all ten arms, and
/// the arm for a draft the build does not have expands to `None` without
/// reading it. So none of them is dead under a single-draft build and none
/// carries `#[allow(dead_code)]`. Should one ever go unread, the attribute to
/// reach for is `allow` and not a `cfg` naming the drafts that read it — the
/// reason `tests/hostile_parameter_values.rs` gives for its own helpers: such
/// a list is an invariant nothing checks, and it stops being right the next
/// time a draft is added.
const REGISTER: &[u8] = &[0x01, 0x07, 0x02, 0xab, 0xcd];

/// A USE_ALIAS Token: Alias Type 0x2 and an Alias, and nothing else.
///
/// The shortest form an unconditional read gets wrong, and the one where it is
/// least ambiguous: there is no Token Type on the wire at all, so a
/// `token_type` key here can only have come from misreading the Alias.
const USE_ALIAS: &[u8] = &[0x02, 0x07];

/// A USE_VALUE Token: Alias Type 0x3, Token Type 0x02, and a value.
///
/// The one form an unconditional two-varint read gets right, kept as the
/// control. A renderer that simply renames the second field rather than
/// branching on the Alias Type breaks this.
const USE_VALUE: &[u8] = &[0x03, 0x02, 0xab, 0xcd];

/// The rendered `authorization_token` value of a message carrying `token`,
/// under draft `draft`.
///
/// Each arm builds that draft's own ANNOUNCE-equivalent, runs it through the
/// draft's encoder and decoder, and renders the result — so the bytes reaching
/// the renderer are bytes that draft's `check_authorization_tokens` accepted,
/// and the rendering is the one `dispatch::AnyControlMessage::fields` would
/// produce. `None` for a draft this build did not compile.
///
/// The parameter number is the one difference the drafts have here and it is
/// not cosmetic: draft-11 numbers the token 0x01 among version-specific
/// parameters and drafts 12 and later number it 0x03. A single number would
/// test PATH on one of them.
///
/// The trailing field list is for draft-17 alone, which is the one draft in the
/// range that puts a Required Request ID Delta on this message. It is written
/// out rather than defaulted because nothing here derives `Default`, and a
/// draft that grows a field should fail to compile rather than be filled in.
macro_rules! rendered_token {
    ($draft:literal, $feature:literal, $module:ident, $key:literal, $token:expr, $message:ident
     $(, $extra:ident : $value:expr)* $(,)?) => {{
        #[cfg(feature = $feature)]
        {
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            use moqtap_codec::types::TrackNamespace;
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::$module::message::*;

            let msg = ControlMessage::$message($message {
                request_id: VarInt::from_u64(1).unwrap(),
                $($extra: $value,)*
                track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
                parameters: vec![KeyValuePair {
                    key: VarInt::from_u64($key).unwrap(),
                    value: KvpValue::Bytes($token.to_vec()),
                }],
            });

            let mut wire = Vec::new();
            msg.encode(&mut wire).expect(concat!(
                "draft-",
                $draft,
                " writes a Token its own reader accepts"
            ));
            let back = ControlMessage::decode(&mut &wire[..])
                .expect(concat!("draft-", $draft, " reads back what it wrote"));

            Some(token_field(&moqtap_codec::$module::fields::message_fields(&back)))
        }
        #[cfg(not(feature = $feature))]
        {
            None
        }
    }};
}

/// The `authorization_token` entry of a rendered message's parameter list.
fn token_field(fields: &FieldMap) -> FieldMap {
    let Some(FieldValue::Array(entries)) = fields.get("parameters") else {
        panic!("a parameter block renders as a list: {fields:?}");
    };
    for entry in entries {
        let FieldValue::Map(entry) = entry else {
            panic!("an entry renders as a map: {entry:?}");
        };
        if entry.get("name") != Some(&FieldValue::Text("authorization_token".into())) {
            continue;
        }
        let Some(FieldValue::Map(token)) = entry.get("value") else {
            panic!("a Token renders as fields, not as bytes: {entry:?}");
        };
        return token.clone();
    }
    panic!("no authorization_token in the rendered parameters: {entries:?}");
}

/// Every draft's rendering of the Token in `TOKEN`, paired with its number.
///
/// Every draft in this build must answer the same, so the list is what makes
/// that a single assertion rather than ten.
macro_rules! every_draft {
    ($token:expr) => {
        [
            (11u8, rendered_token!("11", "draft11", draft11, 0x01, $token, Announce)),
            (12, rendered_token!("12", "draft12", draft12, 0x03, $token, Announce)),
            (13, rendered_token!("13", "draft13", draft13, 0x03, $token, Announce)),
            (14, rendered_token!("14", "draft14", draft14, 0x03, $token, PublishNamespace)),
            (15, rendered_token!("15", "draft15", draft15, 0x03, $token, PublishNamespace)),
            (16, rendered_token!("16", "draft16", draft16, 0x03, $token, PublishNamespace)),
            (
                17,
                rendered_token!(
                    "17",
                    "draft17",
                    draft17,
                    0x03,
                    $token,
                    PublishNamespace,
                    required_request_id_delta: moqtap_codec::varint::VarInt::from_u64(0).unwrap(),
                ),
            ),
            (18, rendered_token!("18", "draft18", draft18, 0x03, $token, PublishNamespace)),
            (19, rendered_token!("19", "draft19", draft19, 0x03, $token, PublishNamespace)),
            (20, rendered_token!("20", "draft20", draft20, 0x03, $token, PublishNamespace)),
        ]
    };
}

/// REGISTER's second varint is the Token Alias, and its third is the Token Type.
///
/// The Alias Type says so — "There is an Alias, a Type and a Value" — and an
/// unconditional two-varint read disagrees on all three counts at once.
///
/// *Ablation:* make `draft11/fields.rs::auth_token_to_json` read two varints
/// without branching on the Alias Type and this fails with:
///
/// ```text
/// draft-11: REGISTER's second varint is the Token Alias
///   left: None
///  right: Some(Uint(7))
/// ```
#[test]
fn a_register_token_renders_its_alias_and_its_type_apart() {
    for (draft, rendered) in every_draft!(REGISTER) {
        let Some(token) = rendered else { continue };
        assert_eq!(
            token.get("alias_type"),
            Some(&FieldValue::Uint(1)),
            "draft-{draft}: the Alias Type is the first varint"
        );
        assert_eq!(
            token.get("token_alias"),
            Some(&FieldValue::Uint(7)),
            "draft-{draft}: REGISTER's second varint is the Token Alias"
        );
        assert_eq!(
            token.get("token_type"),
            Some(&FieldValue::Uint(2)),
            "draft-{draft}: REGISTER's third varint is the Token Type"
        );
        assert_eq!(
            token.get("token_value"),
            Some(&FieldValue::Bytes(vec![0xab, 0xcd])),
            "draft-{draft}: the Token Value is what is left, and the Token Type is not in it"
        );
    }
}

/// USE_ALIAS carries an Alias and nothing else, so nothing may be reported as a
/// Token Type.
///
/// The strongest form of the same claim: there is no Token Type on the wire, so
/// a `token_type` key can only be a misread Alias.
#[test]
fn a_use_alias_token_renders_an_alias_and_no_type() {
    for (draft, rendered) in every_draft!(USE_ALIAS) {
        let Some(token) = rendered else { continue };
        assert_eq!(
            token.get("alias_type"),
            Some(&FieldValue::Uint(2)),
            "draft-{draft}: the Alias Type is the first varint"
        );
        assert_eq!(
            token.get("token_alias"),
            Some(&FieldValue::Uint(7)),
            "draft-{draft}: USE_ALIAS's second varint is the Token Alias"
        );
        assert_eq!(
            token.get("token_type"),
            None,
            "draft-{draft}: USE_ALIAS has no Token Type on the wire: {token:?}"
        );
        assert_eq!(
            token.get("token_value"),
            None,
            "draft-{draft}: USE_ALIAS has no Token Value either: {token:?}"
        );
    }
}

/// USE_VALUE's second varint really is the Token Type, and it must stay that
/// way.
///
/// The control. This is the one form an unconditional read is right about, so
/// a renderer that moved the label rather than branching on the Alias Type
/// would break it.
#[test]
fn a_use_value_token_still_renders_a_type_and_no_alias() {
    for (draft, rendered) in every_draft!(USE_VALUE) {
        let Some(token) = rendered else { continue };
        assert_eq!(
            token.get("alias_type"),
            Some(&FieldValue::Uint(3)),
            "draft-{draft}: the Alias Type is the first varint"
        );
        assert_eq!(
            token.get("token_alias"),
            None,
            "draft-{draft}: USE_VALUE carries no Alias: {token:?}"
        );
        assert_eq!(
            token.get("token_type"),
            Some(&FieldValue::Uint(2)),
            "draft-{draft}: USE_VALUE's second varint is the Token Type"
        );
        assert_eq!(
            token.get("token_value"),
            Some(&FieldValue::Bytes(vec![0xab, 0xcd])),
            "draft-{draft}: the Token Value is what is left"
        );
    }
}
