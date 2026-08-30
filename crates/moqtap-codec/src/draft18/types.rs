//! Draft-18 object status values (unchanged from draft-17).
//!
//! - 0x0 = Normal
//! - 0x3 = End of Group
//! - 0x4 = End of Track

/// Object status values, from MoQ Transport draft-18 Section 11.2.1.1
/// "Object Status".
///
/// The draft assigns 0x0, 0x3 and 0x4. Of every other value the section says:
/// "Any other value SHOULD be treated as a protocol error and the session
/// SHOULD be closed with a PROTOCOL_VIOLATION". [`ObjectStatus::from_u64`]
/// answers `None` for everything the draft leaves unassigned, 0x1 and 0x2
/// included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ObjectStatus {
    /// Normal object. Implicit for any non-zero length object; zero-length
    /// objects encode it explicitly.
    Normal = 0x0,
    /// End of Group. No object with the given Group ID and an Object ID greater
    /// than or equal to the one specified exists in that group.
    EndOfGroup = 0x3,
    /// End of Track. No object at a location equal to or greater than the one
    /// specified exists.
    EndOfTrack = 0x4,
}

impl ObjectStatus {
    /// Every status draft-18 assigns, in ascending wire order.
    ///
    /// This is exactly the set [`ObjectStatus::from_u64`] accepts. Any other
    /// value is one the draft does not assign.
    pub const ALL: &[ObjectStatus] =
        &[ObjectStatus::Normal, ObjectStatus::EndOfGroup, ObjectStatus::EndOfTrack];

    /// Convert a raw u64 to an `ObjectStatus`, or `None` if draft-18 does not
    /// assign that value.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(ObjectStatus::Normal),
            0x3 => Some(ObjectStatus::EndOfGroup),
            0x4 => Some(ObjectStatus::EndOfTrack),
            _ => None,
        }
    }

    /// Return the wire value.
    pub fn as_u64(self) -> u64 {
        self as u64
    }

    /// Return the wire value as a single byte.
    ///
    /// A draft-18 status datagram carries its status as one bare byte rather
    /// than a varint, so the datagram encoder needs the code in that width;
    /// every assigned code is well under 0xff, so this is the same number
    /// [`ObjectStatus::as_u64`] returns.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}
