//! Draft-09 specific types.

/// Object status values, from MoQ Transport draft-09 Section 8.1.1.1
/// "Object Status".
///
/// The draft assigns 0x0, 0x1, 0x3, 0x4 and 0x5, and says of everything else
/// that it "SHOULD be treated as a protocol error and terminate the session
/// with a Protocol Violation". 0x2 is not assigned; [`ObjectStatus::from_u64`]
/// answers `None` for it, and for every other unassigned value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ObjectStatus {
    /// Object payload follows normally.
    Normal = 0,
    /// The referenced object does not exist.
    ObjectDoesNotExist = 1,
    /// Last object in the group.
    EndOfGroup = 3,
    /// Last object in the group AND the final group in the track.
    EndOfTrackAndGroup = 4,
    /// Last object in the track (group is not ending here).
    EndOfTrack = 5,
}

impl ObjectStatus {
    /// Every status draft-09 assigns, in ascending wire order.
    ///
    /// This is exactly the set [`ObjectStatus::from_u64`] accepts. Any other
    /// value is one the draft does not assign.
    pub const ALL: &[ObjectStatus] = &[
        ObjectStatus::Normal,
        ObjectStatus::ObjectDoesNotExist,
        ObjectStatus::EndOfGroup,
        ObjectStatus::EndOfTrackAndGroup,
        ObjectStatus::EndOfTrack,
    ];

    /// Convert a raw u64 to an `ObjectStatus`, or `None` if draft-09 does not
    /// assign that value.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0 => Some(ObjectStatus::Normal),
            1 => Some(ObjectStatus::ObjectDoesNotExist),
            3 => Some(ObjectStatus::EndOfGroup),
            4 => Some(ObjectStatus::EndOfTrackAndGroup),
            5 => Some(ObjectStatus::EndOfTrack),
            _ => None,
        }
    }

    /// Return the wire value.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}
