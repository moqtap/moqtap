//! Draft-15 specific types.

/// Object status values, from MoQ Transport draft-15 Section 10.2.1.1
/// "Object Status".
///
/// Draft-15 assigns 0x0, 0x1, 0x3 and 0x4. Of every other value the section
/// says: "Any other value SHOULD be treated as a protocol error and the session
/// SHOULD be terminated with a PROTOCOL_VIOLATION". [`ObjectStatus::from_u64`]
/// answers `None` for 0x2 and for everything else the draft leaves unassigned.
///
/// Draft-15 is the last draft to assign 0x1; draft-16 drops Object Does Not
/// Exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum ObjectStatus {
    /// Normal object. Implicit for any non-zero length object; zero-length
    /// objects encode it explicitly.
    Normal = 0x00,
    /// The object does not exist at any publisher and will not be published in
    /// the future.
    ObjectDoesNotExist = 0x01,
    /// End of Group. Object ID is one greater than the largest object produced
    /// in the group identified by the Group ID; 0 means the group is empty.
    EndOfGroup = 0x03,
    /// End of Track. Either Group ID is the largest group produced in the track
    /// and Object ID is one greater than the largest object in that group, or
    /// Group ID is one greater than the largest group produced and Object ID is
    /// zero.
    EndOfTrack = 0x04,
}

impl ObjectStatus {
    /// Every status draft-15 assigns, in ascending wire order.
    ///
    /// This is exactly the set [`ObjectStatus::from_u64`] accepts. Any other
    /// value is one the draft does not assign.
    pub const ALL: &[ObjectStatus] = &[
        ObjectStatus::Normal,
        ObjectStatus::ObjectDoesNotExist,
        ObjectStatus::EndOfGroup,
        ObjectStatus::EndOfTrack,
    ];

    /// Convert a raw u64 to an `ObjectStatus`, or `None` if draft-15 does not
    /// assign that value.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x00 => Some(ObjectStatus::Normal),
            0x01 => Some(ObjectStatus::ObjectDoesNotExist),
            0x03 => Some(ObjectStatus::EndOfGroup),
            0x04 => Some(ObjectStatus::EndOfTrack),
            _ => None,
        }
    }

    /// Return the wire value.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}
