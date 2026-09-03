//! Draft-20 object status values.
//!
//! - 0x0 = Normal, may carry a payload
//! - 0x3 = End of Group, may not
//! - 0x4 = End of Track, may not
//!
//! Unchanged from draft-19 in both the code points and the rule behind them.
//! Draft-18 and earlier stated flatly that an Object with a status other than
//! Normal has an empty payload, so the payload rule could be read off the
//! status number; draft-19 gave the Object Status registry a "Payload" column
//! and made the rule registry data, and draft-20 Section 15.9 keeps it that
//! way. It is carried here as a `PayloadPermission` on the status itself.
//!
//! Object Status is present only on subscription-delivered Objects. Draft-20
//! Section 11.2.1.1 is unchanged on this: a fetch stream's objects carry no
//! status field at all.

/// Whether an Object carrying a given status is permitted a non-empty payload:
/// the "Payload" column of the Object Status registry, MoQ Transport draft-20
/// Section 15.9, Table 16.
///
/// Draft-20 Section 11.2.1.1 phrases the rule as "An Object MUST have an empty
/// payload unless its Object Status value is registered as permitting a
/// payload", and Section 15.9 adds that each new registration "MUST indicate
/// whether the status permits a payload". Modelling the column as a value keeps
/// that obligation visible: a status cannot be added to [`ObjectStatus`]
/// without [`ObjectStatus::payload_permission`] refusing to compile until its
/// column is filled in.
///
/// Drafts up to 18 had no such column — they derived the same answer
/// arithmetically, from the status being non-zero — so this type belongs to
/// draft-19 and later rather than being shared across the range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadPermission {
    /// Registry column "Yes". The status permits a payload but does not
    /// require one: a zero-length Object with such a status is well formed.
    Permitted,
    /// Registry column "No". An Object with such a status has an empty
    /// payload, and one carrying bytes is malformed.
    Forbidden,
}

impl PayloadPermission {
    /// `true` for [`PayloadPermission::Permitted`].
    ///
    /// The permission answers on its own, without a payload length in hand,
    /// which is the point of moving the rule onto the status.
    pub fn permits(self) -> bool {
        matches!(self, PayloadPermission::Permitted)
    }
}

/// Object status values, from MoQ Transport draft-20 Section 11.2.1.1
/// "Object Status", with the same three code points listed in the IANA Object
/// Status registry at Section 15.9, Table 16.
///
/// The draft assigns 0x0, 0x3 and 0x4. Of every other value the section says:
/// "Any other value SHOULD be treated as a protocol error and the session
/// SHOULD be closed with a PROTOCOL_VIOLATION". [`ObjectStatus::from_u64`]
/// answers `None` for everything the draft leaves unassigned, 0x1 and 0x2
/// included. The section also states plainly that there is no status meaning
/// end of Subgroup: a subgroup ends when its stream is closed with a FIN.
///
/// Each status carries the registry's payload rule with it, as
/// [`ObjectStatus::payload_permission`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ObjectStatus {
    /// Normal object. The one status Table 16 marks "Payload: Yes", and the
    /// status of every Object that carries bytes — the encodings elide it and
    /// spell it out only when the payload is empty.
    Normal = 0x0,
    /// End of Group. No object with the given Group ID and an Object ID greater
    /// than or equal to the one specified exists in that group. Table 16 marks
    /// it "Payload: No".
    EndOfGroup = 0x3,
    /// End of Track. No object at a location equal to or greater than the one
    /// specified exists. Table 16 marks it "Payload: No".
    EndOfTrack = 0x4,
}

impl ObjectStatus {
    /// Every status draft-20 assigns, in ascending wire order.
    ///
    /// This is exactly the set [`ObjectStatus::from_u64`] accepts, and exactly
    /// the three rows of the draft's Object Status registry. Any other value is
    /// one the draft does not assign.
    pub const ALL: &[ObjectStatus] =
        &[ObjectStatus::Normal, ObjectStatus::EndOfGroup, ObjectStatus::EndOfTrack];

    /// Convert a raw u64 to an `ObjectStatus`, or `None` if draft-20 does not
    /// assign that value.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x0 => Some(ObjectStatus::Normal),
            0x3 => Some(ObjectStatus::EndOfGroup),
            0x4 => Some(ObjectStatus::EndOfTrack),
            _ => None,
        }
    }

    /// The registry's "Payload" column for this status, from draft-20
    /// Section 15.9, Table 16: Normal is "Yes", End of Group and End of Track
    /// are "No".
    ///
    /// This is the whole of the rule draft-20 Section 11.2.1.1 states — an
    /// Object has an empty payload unless its status is registered as
    /// permitting one — so no caller has to restate it, and none has to reach
    /// for a payload length to guess at it. The three rows currently agree with
    /// the blanket *any status other than Normal means an empty payload* that
    /// drafts up to 18 used; they agree by coincidence of the current
    /// assignments, not by construction, and a status registered later with
    /// "Payload: Yes" would part them.
    pub fn payload_permission(self) -> PayloadPermission {
        match self {
            ObjectStatus::Normal => PayloadPermission::Permitted,
            ObjectStatus::EndOfGroup => PayloadPermission::Forbidden,
            ObjectStatus::EndOfTrack => PayloadPermission::Forbidden,
        }
    }

    /// `true` when the registry permits an Object with this status to carry a
    /// non-empty payload. Shorthand for
    /// `self.payload_permission().permits()`.
    ///
    /// Permitting is not requiring: a Normal Object with no payload is well
    /// formed, and draft-20's encodings have a way to spell it.
    pub fn permits_payload(self) -> bool {
        self.payload_permission().permits()
    }

    /// Return the wire value.
    pub fn as_u64(self) -> u64 {
        self as u64
    }

    /// Return the wire value as a single byte.
    ///
    /// A draft-20 status datagram carries its status as one bare byte rather
    /// than a varint, so the datagram encoder needs the code in that width;
    /// every assigned code is well under 0xff, so this is the same number
    /// [`ObjectStatus::as_u64`] returns.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}
