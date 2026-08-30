/// SETUP ROLE parameter values (draft-07, key 0x00).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    /// Publisher only.
    Publisher = 1,
    /// Subscriber only.
    Subscriber = 2,
    /// Both publisher and subscriber.
    PubSub = 3,
}

impl Role {
    /// Convert a raw byte to a `Role`, if valid.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Role::Publisher),
            2 => Some(Role::Subscriber),
            3 => Some(Role::PubSub),
            _ => None,
        }
    }
}

/// Object status values, from MoQ Transport draft-07 Section 7.1.1.1
/// "Object Status".
///
/// The draft assigns 0x0, 0x1, 0x3, 0x4 and 0x5, and says of everything else
/// that it "SHOULD be treated as a protocol error and terminate the session
/// with a Protocol Violation". 0x2 is not assigned; [`ObjectStatus::from_u64`]
/// answers `None` for it, and for every other unassigned value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ObjectStatus {
    /// Normal object. The payload is an array of bytes and can be empty.
    Normal = 0,
    /// The object does not exist at any publisher and will not be published in
    /// the future.
    ObjectDoesNotExist = 1,
    /// End of Group. Object ID is one greater than the largest object produced
    /// in the group identified by the Group ID; 0 means the group is empty.
    EndOfGroup = 3,
    /// End of Track and Group, which is the name draft-07 gives 0x4: Group ID
    /// is one greater than the largest group produced in the track and Object
    /// ID is one greater than the largest object produced in that group.
    ///
    /// Named as the draft names it, and as drafts 08-10 name the same code
    /// point. Draft-08 keeps 0x4 here and adds a separate "end of Track" at
    /// 0x5, so a variant called `EndOfTrack` at 0x4 would read as that later
    /// status one code point off.
    EndOfTrackAndGroup = 4,
    /// End of Subgroup. Object ID is one greater than the largest normal
    /// object ID in the subgroup.
    EndOfSubgroup = 5,
}

impl ObjectStatus {
    /// Every status draft-07 assigns, in ascending wire order.
    ///
    /// This is exactly the set [`ObjectStatus::from_u64`] accepts. Any other
    /// value is one the draft does not assign.
    pub const ALL: &[ObjectStatus] = &[
        ObjectStatus::Normal,
        ObjectStatus::ObjectDoesNotExist,
        ObjectStatus::EndOfGroup,
        ObjectStatus::EndOfTrackAndGroup,
        ObjectStatus::EndOfSubgroup,
    ];

    /// Convert a raw u64 to an `ObjectStatus`, or `None` if draft-07 does not
    /// assign that value.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0 => Some(ObjectStatus::Normal),
            1 => Some(ObjectStatus::ObjectDoesNotExist),
            3 => Some(ObjectStatus::EndOfGroup),
            4 => Some(ObjectStatus::EndOfTrackAndGroup),
            5 => Some(ObjectStatus::EndOfSubgroup),
            _ => None,
        }
    }

    /// Return the wire value.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}
