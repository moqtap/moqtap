//! Draft-17 object status values.
//!
//! Draft-17 changes status codes from draft-16:
//! - 0x0 = Normal
//! - 0x3 = End of Group (was 0x1)
//! - 0x4 = End of Track (was 0x2)
//! - DoesNotExist removed

/// Object status values (draft-17).
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
