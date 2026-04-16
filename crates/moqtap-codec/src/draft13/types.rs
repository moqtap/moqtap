//! Draft-13 specific types.

/// Object status values for draft-13 data streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum ObjectStatus {
    Normal = 0x00,
    ObjectDoesNotExist = 0x01,
    GroupDoesNotExist = 0x02,
    EndOfGroup = 0x03,
    EndOfTrack = 0x04,
}

impl ObjectStatus {
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x00 => Some(ObjectStatus::Normal),
            0x01 => Some(ObjectStatus::ObjectDoesNotExist),
            0x02 => Some(ObjectStatus::GroupDoesNotExist),
            0x03 => Some(ObjectStatus::EndOfGroup),
            0x04 => Some(ObjectStatus::EndOfTrack),
            _ => None,
        }
    }
}
