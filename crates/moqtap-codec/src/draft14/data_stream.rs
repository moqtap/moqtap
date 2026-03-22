use crate::error::CodecError;
use crate::kvp::KeyValuePair;
use crate::types::*;
use crate::varint::VarInt;
use bytes::{Buf, BufMut};

/// Subgroup stream header (unidirectional stream for subscription objects).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubgroupHeader {
    /// Track alias identifying the subscription.
    pub track_alias: VarInt,
    /// Group identifier.
    pub group: VarInt,
    /// Subgroup identifier within the group.
    pub subgroup: VarInt,
    /// Publisher priority for delivery ordering.
    pub publisher_priority: u8,
}

/// Datagram header (for datagram forwarding preference).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramHeader {
    /// Track alias identifying the subscription.
    pub track_alias: VarInt,
    /// Group identifier.
    pub group: VarInt,
    /// Object identifier within the group.
    pub object: VarInt,
    /// Publisher priority for delivery ordering.
    pub publisher_priority: u8,
}

/// Object header within a subgroup stream or fetch response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectHeader {
    /// Status of this object.
    pub object_status: ObjectStatus,
    /// Payload length in bytes; present unless status is `DoesNotExist`.
    pub payload_length: Option<VarInt>,
    /// Forwarding preference override; present when different from track default.
    pub forwarding_preference: Option<ForwardingPreference>,
    /// Number of dependencies; present for `Normal` status when dependencies exist.
    pub dependencies: Option<VarInt>,
    /// Object extension key-value pairs.
    pub extensions: Vec<KeyValuePair>,
}

/// Fetch response stream header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchHeader {
    /// Track alias identifying the fetch request.
    pub track_alias: VarInt,
    /// Group identifier.
    pub group: VarInt,
    /// Subgroup identifier within the group.
    pub subgroup: VarInt,
    /// Publisher priority for delivery ordering.
    pub publisher_priority: u8,
}

impl SubgroupHeader {
    /// Encode the subgroup header into the buffer.
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.track_alias.encode(buf);
        self.group.encode(buf);
        self.subgroup.encode(buf);
        buf.put_u8(self.publisher_priority);
    }

    /// Decode a subgroup header from the buffer.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let track_alias = VarInt::decode(buf)?;
        let group = VarInt::decode(buf)?;
        let subgroup = VarInt::decode(buf)?;
        if buf.remaining() < 1 {
            return Err(CodecError::UnexpectedEnd);
        }
        let publisher_priority = buf.get_u8();
        Ok(Self { track_alias, group, subgroup, publisher_priority })
    }
}

impl DatagramHeader {
    /// Encode the datagram header into the buffer.
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.track_alias.encode(buf);
        self.group.encode(buf);
        self.object.encode(buf);
        buf.put_u8(self.publisher_priority);
    }

    /// Decode a datagram header from the buffer.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let track_alias = VarInt::decode(buf)?;
        let group = VarInt::decode(buf)?;
        let object = VarInt::decode(buf)?;
        if buf.remaining() < 1 {
            return Err(CodecError::UnexpectedEnd);
        }
        let publisher_priority = buf.get_u8();
        Ok(Self { track_alias, group, object, publisher_priority })
    }
}

impl ObjectHeader {
    /// Encode the object header into the buffer.
    pub fn encode(&self, buf: &mut impl BufMut) {
        // Encode object status as VarInt
        VarInt::from_u64(self.object_status as u64).unwrap().encode(buf);

        // Encode flags: bit 0 = has forwarding_preference, bit 1 = has dependencies
        let mut flags: u64 = 0;
        if self.forwarding_preference.is_some() {
            flags |= 0x01;
        }
        if self.dependencies.is_some() {
            flags |= 0x02;
        }
        VarInt::from_u64(flags).unwrap().encode(buf);

        // Payload length (present unless DoesNotExist)
        if self.object_status != ObjectStatus::DoesNotExist {
            if let Some(pl) = &self.payload_length {
                pl.encode(buf);
            }
        }

        // Optional forwarding preference
        if let Some(fp) = &self.forwarding_preference {
            VarInt::from_u64(*fp as u64).unwrap().encode(buf);
        }

        // Optional dependencies
        if let Some(deps) = &self.dependencies {
            deps.encode(buf);
        }

        // Extensions as KVP list
        KeyValuePair::encode_list(&self.extensions, buf);
    }

    /// Decode an object header from the buffer.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let status_val = VarInt::decode(buf)?.into_inner();
        let object_status =
            ObjectStatus::from_u8(status_val as u8).ok_or(CodecError::InvalidField)?;

        let flags = VarInt::decode(buf)?.into_inner();
        let has_forwarding_preference = flags & 0x01 != 0;
        let has_dependencies = flags & 0x02 != 0;

        let payload_length = if object_status != ObjectStatus::DoesNotExist {
            Some(VarInt::decode(buf)?)
        } else {
            None
        };

        let forwarding_preference = if has_forwarding_preference {
            let fp_val = VarInt::decode(buf)?.into_inner();
            Some(ForwardingPreference::from_u8(fp_val as u8).ok_or(CodecError::InvalidField)?)
        } else {
            None
        };

        let dependencies = if has_dependencies { Some(VarInt::decode(buf)?) } else { None };

        let extensions = KeyValuePair::decode_list(buf)?;

        Ok(Self { object_status, payload_length, forwarding_preference, dependencies, extensions })
    }
}

impl FetchHeader {
    /// Encode the fetch header into the buffer.
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.track_alias.encode(buf);
        self.group.encode(buf);
        self.subgroup.encode(buf);
        buf.put_u8(self.publisher_priority);
    }

    /// Decode a fetch header from the buffer.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let track_alias = VarInt::decode(buf)?;
        let group = VarInt::decode(buf)?;
        let subgroup = VarInt::decode(buf)?;
        if buf.remaining() < 1 {
            return Err(CodecError::UnexpectedEnd);
        }
        let publisher_priority = buf.get_u8();
        Ok(Self { track_alias, group, subgroup, publisher_priority })
    }
}
