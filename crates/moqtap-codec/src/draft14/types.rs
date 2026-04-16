//! Draft-14 specific types.
//!
//! Types in this module are specific to draft-14 wire values and are kept
//! separate from the shared [`crate::types`] module so that other drafts
//! can continue to use their own enums without collision.

/// Draft-14 Object Status values (§10.2.1.1).
///
/// Status is a varint on the wire. Any other value is a protocol error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ObjectStatus {
    /// Normal object. Implicit for non-zero length; zero-length objects must
    /// encode this explicitly.
    Normal = 0x0,
    /// This Object does not exist at any publisher.
    ObjectDoesNotExist = 0x1,
    /// End of Group. Object ID is one greater than the largest in the group
    /// (or 0 if the group is empty).
    EndOfGroup = 0x3,
    /// End of Track.
    EndOfTrack = 0x4,
}

impl ObjectStatus {
    /// Convert a raw wire value to [`ObjectStatus`].
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(ObjectStatus::Normal),
            0x1 => Some(ObjectStatus::ObjectDoesNotExist),
            0x3 => Some(ObjectStatus::EndOfGroup),
            0x4 => Some(ObjectStatus::EndOfTrack),
            _ => None,
        }
    }

    /// Return the wire value.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}
