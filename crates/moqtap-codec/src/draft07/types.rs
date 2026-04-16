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

/// Object status values (draft-07).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ObjectStatus {
    /// Object payload follows normally.
    Normal = 0,
    /// The referenced object does not exist.
    ObjectDoesNotExist = 1,
    /// The referenced group does not exist.
    GroupDoesNotExist = 2,
    /// Last object in the group.
    EndOfGroup = 3,
    /// Last object in the track.
    EndOfTrack = 4,
    /// Last object in the subgroup.
    EndOfSubgroup = 5,
}

impl ObjectStatus {
    /// Convert a raw u64 to an `ObjectStatus`, if valid.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0 => Some(ObjectStatus::Normal),
            1 => Some(ObjectStatus::ObjectDoesNotExist),
            2 => Some(ObjectStatus::GroupDoesNotExist),
            3 => Some(ObjectStatus::EndOfGroup),
            4 => Some(ObjectStatus::EndOfTrack),
            5 => Some(ObjectStatus::EndOfSubgroup),
            _ => None,
        }
    }
}
