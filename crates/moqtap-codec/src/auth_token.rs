use crate::error::CodecError;
use crate::varint::{MoqtProfile, VarInt, VarIntError};
use bytes::{Buf, BufMut};

/// The parameter type carrying an Authorization Token on drafts 12 and later.
///
/// Drafts 12 through 19 all number it 0x03, in both the message parameter and
/// the setup namespace. Draft-11 numbers the message parameter 0x01 and has no
/// setup parameter of this kind at all, so a draft-11 setup 0x01 is a PATH and
/// is not a token; [`AUTH_TOKEN_PARAMETER_D11`] is the one it does have.
pub const AUTH_TOKEN_PARAMETER: u64 = 0x03;

/// The parameter type carrying an Authorization Token on draft-11.
///
/// Draft-11 Section 8.2.1.1 gives the AUTHORIZATION TOKEN parameter type 0x01
/// among the version-specific parameters. Draft-12 renumbered it to
/// [`AUTH_TOKEN_PARAMETER`] and added it to the setup namespace beside it.
pub const AUTH_TOKEN_PARAMETER_D11: u64 = 0x01;

/// What a Token's Alias Type says about the fields that follow it.
///
/// Drafts 11 through 19 all define the same four code points and describe them
/// as deciding the serialization, not merely the behaviour: "Alias Type - an
/// integer defining both the serialization and the processing behavior of the
/// receiver." A reader that does not recognise the value therefore cannot know
/// which of the three optional fields are present, which is why an unassigned
/// Alias Type is a formatting error rather than something to skip past.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenAliasType {
    /// DELETE (0x0). Carries an Alias and retires it: "This Alias and the Token
    /// Value it was previously associated with MUST be retired."
    Delete,
    /// REGISTER (0x1). Carries an Alias, a Token Type and a Token Value, and
    /// binds the Alias to that value for the rest of the session.
    Register,
    /// USE_ALIAS (0x2). Carries an Alias alone, standing for the Token Type and
    /// Token Value registered under it earlier.
    UseAlias,
    /// USE_VALUE (0x3). Carries a Token Type and Token Value and no Alias: "Use
    /// the Token Value as provided. The Token Value may be discarded after
    /// processing."
    UseValue,
}

impl TokenAliasType {
    /// The Alias Type this code point names, or `None` if no draft in the range
    /// assigns it.
    pub const fn from_id(id: u64) -> Option<Self> {
        match id {
            0x0 => Some(Self::Delete),
            0x1 => Some(Self::Register),
            0x2 => Some(Self::UseAlias),
            0x3 => Some(Self::UseValue),
            _ => None,
        }
    }

    /// The code point for this Alias Type.
    pub const fn id(self) -> u64 {
        match self {
            Self::Delete => 0x0,
            Self::Register => 0x1,
            Self::UseAlias => 0x2,
            Self::UseValue => 0x3,
        }
    }

    /// Whether a Token Alias field follows the Alias Type.
    ///
    /// Three of the four carry one. USE_VALUE is the exception — "There is no
    /// Alias and there is a Type and Value" — and it is the only form a sender
    /// can use before it has registered anything.
    pub const fn has_alias(self) -> bool {
        !matches!(self, Self::UseValue)
    }

    /// Whether a Token Type and a Token Value follow.
    ///
    /// The two travel together in every form: REGISTER and USE_VALUE carry
    /// both, DELETE and USE_ALIAS carry neither, and no form carries one
    /// without the other.
    pub const fn has_type_and_value(self) -> bool {
        matches!(self, Self::Register | Self::UseValue)
    }
}

/// The Token structure an AUTHORIZATION TOKEN parameter carries as its value.
///
/// Drafts 11 through 19 serialize it as
///
/// ```text
/// Token {
///   Alias Type (i),
///   [Token Alias (i),]
///   [Token Type (i),]
///   [Token Value (..)]
/// }
/// ```
///
/// with the Alias Type deciding which of the bracketed fields are present. The
/// Token Value has no length of its own and runs to the end of the parameter
/// value, which is what bounds it — draft-19 Section 1.4.3 says so outright:
/// "Key-Value-Pairs are always parsed with a known byte length, which bounds the
/// sequence."
///
/// The structure has not moved across the nine drafts that define it. Only the
/// integer encoding has: drafts 11 through 16 write the three integers as QUIC
/// variable-length integers and drafts 17 and later as MoQT ones, which is the
/// only difference between [`decode`](Self::decode) and
/// [`decode_moqt`](Self::decode_moqt).
///
/// The contents of the Token Value are deliberately opaque here. "The contents
/// and serialization of this payload are defined by the Token Type", and that
/// registry is not this codec's to interpret — Token Type 0 is reserved for a
/// meaning "negotiated out-of-band between client and receiver", so no reader
/// can hold the value to a shape without knowing what the two peers agreed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationToken {
    /// Which of the fields below are present, and what the receiver does with
    /// them.
    pub alias_type: TokenAliasType,
    /// The Session-specific Alias, present on every form but USE_VALUE.
    pub alias: Option<u64>,
    /// The Token Type, present on REGISTER and USE_VALUE.
    pub token_type: Option<u64>,
    /// The Token Value, present on REGISTER and USE_VALUE and running to the
    /// end of the parameter value. Empty on DELETE and USE_ALIAS.
    pub value: Vec<u8>,
}

/// Report a Token that cannot be decoded under the rule its draft states.
///
/// Drafts 15 through 19 give this rule its own sentence — "If the Token
/// structure cannot be decoded, the receiver MUST close the Session with
/// KEY_VALUE_FORMATTING_ERROR". Drafts 12, 13 and 14 state it in those same
/// words and name the code in prose instead, as Key-Value Formatting error —
/// draft-14 doing so even though its own registry and its general
/// Key-Value-Pair rule already spell KEY_VALUE_FORMATTING_ERROR. Draft-11 has
/// no sentence of its own and reaches the same answer through the general one
/// in Section 1.3.2, which covers any Type whose value does not match the
/// serialization that Type defines.
fn malformed(key: u64, detail: &'static str) -> CodecError {
    CodecError::KeyValueFormatting { key, detail }
}

impl AuthorizationToken {
    /// Decode a Token from a parameter value written with QUIC variable-length
    /// integers, as drafts 11 through 16 write them.
    ///
    /// `key` is the parameter type the value arrived under. It is carried into
    /// the error rather than used for the parse: the caller knows which
    /// namespace it read, and a report naming 0x03 when the frame said 0x01
    /// sends the reader to the wrong table.
    pub fn decode(key: u64, bytes: &[u8]) -> Result<Self, CodecError> {
        Self::decode_with(key, bytes, |buf: &mut &[u8]| VarInt::decode(buf))
    }

    /// Decode a Token from a parameter value written with MoQT variable-length
    /// integers, as drafts 17 and later write them.
    pub fn decode_moqt<P: MoqtProfile>(key: u64, bytes: &[u8]) -> Result<Self, CodecError> {
        Self::decode_with(key, bytes, |buf: &mut &[u8]| VarInt::decode_moqt::<P>(buf))
    }

    /// The body both readers share, taking the integer encoding as a parameter.
    ///
    /// Every refusal here is one rule seen from a different side, so they answer
    /// with one variant and differ only in `detail`. A Token that stops early
    /// and one that runs long are both structures the draft's own serialization
    /// does not describe, and neither leaves a receiver anything to act on.
    fn decode_with<F>(key: u64, bytes: &[u8], mut read: F) -> Result<Self, CodecError>
    where
        F: FnMut(&mut &[u8]) -> Result<VarInt, VarIntError>,
    {
        const NO_ALIAS_TYPE: &str = "it carries no Alias Type";
        const UNASSIGNED: &str = "its Alias Type is not one this draft assigns";
        const NO_ALIAS: &str = "its Alias Type promises a Token Alias and the value ends first";
        const NO_TYPE: &str = "its Alias Type promises a Token Type and the value ends first";
        const TRAILING: &str =
            "its Alias Type promises no Token Value and bytes follow the Token Alias";

        let mut buf = bytes;
        let raw = read(&mut buf).map_err(|_| malformed(key, NO_ALIAS_TYPE))?;
        let alias_type =
            TokenAliasType::from_id(raw.into_inner()).ok_or_else(|| malformed(key, UNASSIGNED))?;

        let alias = if alias_type.has_alias() {
            Some(read(&mut buf).map_err(|_| malformed(key, NO_ALIAS))?.into_inner())
        } else {
            None
        };

        let (token_type, value) = if alias_type.has_type_and_value() {
            let token_type = read(&mut buf).map_err(|_| malformed(key, NO_TYPE))?.into_inner();
            (Some(token_type), buf.to_vec())
        } else {
            if buf.has_remaining() {
                return Err(malformed(key, TRAILING));
            }
            (None, Vec::new())
        };

        Ok(AuthorizationToken { alias_type, alias, token_type, value })
    }

    /// Write this Token as a parameter value, using QUIC variable-length
    /// integers (drafts 11 through 16).
    ///
    /// Fallible where [`encode_moqt`](Self::encode_moqt) is not, for the reason
    /// the two integer encodings differ: the QUIC one stops at 2^62 - 1, so an
    /// Alias or Token Type above that has no representation and would otherwise
    /// be written as an unrelated number with the length bits folded into it.
    ///
    /// The fields written are the ones the Alias Type promises, not the ones
    /// that happen to be populated. A caller that sets a Token Alias on a
    /// USE_VALUE has described a structure no draft defines, and writing it
    /// would produce bytes this codec's own reader refuses; the Alias Type is
    /// the field a receiver parses by, so it is the field that decides.
    pub fn encode(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        let mut out = Vec::with_capacity(24 + self.value.len());
        VarInt::from_u64(self.alias_type.id())?.encode(&mut out);
        if self.alias_type.has_alias() {
            VarInt::from_u64(self.alias.unwrap_or(0))?.encode(&mut out);
        }
        if self.alias_type.has_type_and_value() {
            VarInt::from_u64(self.token_type.unwrap_or(0))?.encode(&mut out);
            out.extend_from_slice(&self.value);
        }
        buf.put_slice(&out);
        Ok(())
    }

    /// Write this Token as a parameter value, using MoQT variable-length
    /// integers (drafts 17 and later).
    ///
    /// Infallible: that encoding reaches the whole 64-bit range, so every value
    /// these fields can hold has a representation.
    pub fn encode_moqt<P: MoqtProfile>(&self, buf: &mut impl BufMut) {
        VarInt::from_u64_moqt(self.alias_type.id()).encode_moqt::<P>(buf);
        if self.alias_type.has_alias() {
            VarInt::from_u64_moqt(self.alias.unwrap_or(0)).encode_moqt::<P>(buf);
        }
        if self.alias_type.has_type_and_value() {
            VarInt::from_u64_moqt(self.token_type.unwrap_or(0)).encode_moqt::<P>(buf);
            buf.put_slice(&self.value);
        }
    }
}
