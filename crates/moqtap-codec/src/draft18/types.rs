//! Draft-18 object status values (unchanged from draft-17).
//!
//! - 0x0 = Normal
//! - 0x3 = End of Group
//! - 0x4 = End of Track

/// Object status values (draft-18).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ObjectStatus {
    Normal = 0x0,
    EndOfGroup = 0x3,
    EndOfTrack = 0x4,
}

impl ObjectStatus {
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(ObjectStatus::Normal),
            0x3 => Some(ObjectStatus::EndOfGroup),
            0x4 => Some(ObjectStatus::EndOfTrack),
            _ => None,
        }
    }
}
