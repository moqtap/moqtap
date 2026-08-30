//! How far each track's objects have reached, for the drafts that make an
//! end-of-track object's placement a protocol error.
//!
//! Six drafts state it. Draft-11 Section 9.1.1.1 gives the form that drafts 12
//! and 13 repeat word for word: Object Status 0x4 "Indicates end of Track.
//! GroupID is either the largest group produced in this track and the ObjectID
//! is one greater than the largest object produced in that group, or GroupID is
//! one greater than the largest group produced in this track and the ObjectID is
//! zero. This status also indicates the last group has ended. An object with
//! this status that has a Group ID less than any other GroupID, or an ObjectID
//! less than or equal to the largest in the specified group, is a protocol
//! error, and the receiver MUST terminate the session."
//!
//! Drafts 08, 09 and 10 spell the same prohibition against a status 0x4 that
//! means "end of Track and Group", and carry a second status beside it — 0x5,
//! "end of Track" — whose condition is one notch stricter: "An object with this
//! status that has a Group ID less than or equal to any other Group ID, or an
//! Object ID other than zero, is a protocol error, and the receiver MUST
//! terminate the session." Draft-11 merged the two statuses and kept the looser
//! condition, which is why one record answers both.
//!
//! This module holds only the observation. What each draft does about it is its
//! own close table's business, as it is for every other rule broken on a data
//! stream.
//!
//! # Two numbers per track, and that is not a shortcut
//!
//! "The largest object produced in that group" reads like a record of every
//! group a track has carried, which for a live track is unbounded. It is not
//! needed, and the reason is the other half of the same sentence.
//!
//! The Group ID condition says an end-of-track object may not name a group
//! behind any the track has carried. So by the time the Object ID condition is
//! read, "the specified group" is either the largest group the track has
//! carried or one beyond it — and a group beyond it has carried no objects, so
//! there is no largest in it to be at or behind. Every group below the largest
//! is unreachable by the question. Two numbers answer it: the largest Group ID
//! seen, and the largest Object ID seen *in that group*, which resets whenever
//! a larger group arrives.
//!
//! # Only Normal objects are produced objects
//!
//! An object with a status is a statement about objects rather than one of
//! them, and two of the statuses name an ID one past the end on purpose. Status
//! 0x3, End of Group, has an "ObjectId ... one greater that the largest object
//! produced in the group"; status 0x4 has an Object ID one greater again. So a
//! record that counted an End of Group object as produced would raise the
//! largest by one and then refuse the very End of Track object the draft
//! defines — the rule would fire on a conforming track. Only status Normal is
//! written down.
//!
//! # Why the key is the track and not the alias
//!
//! The same reason [`crate::forwarding_preference`] gives: an alias is free
//! again the moment its subscription ends and may then name a different track,
//! so a record kept against the alias would measure the second track's
//! end-of-track object against the first track's groups. The alias is resolved
//! through the endpoint's binding table before anything is written down.
//!
//! # Which objects reach this
//!
//! Objects a subscriber *receives*, on subgroup streams and in datagrams. The
//! sentence names the receiver — "the receiver MUST terminate the session" —
//! which is what separates this from the forwarding-preference rule beside it:
//! that one names the Original Publisher, so its writers are gated too, and
//! this one does not.
//!
//! # A second rule, and a third number
//!
//! Drafts 12 through 19 carry a Malformed Track condition this record is the
//! right place for as well. Draft-12 Section 2.5: "An Object is received on a
//! Track whose Group and Object ID are larger than the final Object in the
//! Track. The final Object in a Track is the Object with Status END_OF_TRACK or
//! the last Object sent in a FETCH whose response indicated End of Track."
//! Drafts 13 through 17 carry it word for word; drafts 18 and 19 drop the two
//! words "on a Track" and change nothing else.
//!
//! **It is the mirror of the rule above rather than a widening of it.** That
//! one asks whether an end-of-track object is behind what the track has
//! carried, and ends the session over it. This one asks whether an ordinary
//! object is past where the track ended, and withdraws from the track. Two
//! rules, two answers, and the two numbers above answer neither of them for the
//! other: a third is kept, the location the end-of-track object named, written
//! down once that object has been judged.
//!
//! **Larger is the drafts' own comparison and not a reading of the words.**
//! Every draft that carries the condition carries a Location Structure section
//! with it, and that section settles the ordering outright — draft-12 Section
//! 1.3.1 and draft-19 Section 1.4.2 give one Location as below another in the
//! same words: "A.Group < B.Group || (A.Group == B.Group && A.Object <
//! B.Object)". Lexicographic, and worth naming because the field-by-field
//! reading the sentence also admits would let an object in a later group with a
//! smaller Object ID escape, which is the plainest case of the fault there is.
//!
//! **The FETCH half of the definition is out of reach on this path**, and is
//! not quietly folded into the other half. A fetch's objects arrive on a stream
//! that opens by naming a Request ID and never a Track Alias, so nothing
//! measuring objects here knows which track they belong to. What is written
//! down is the END_OF_TRACK half, and a track whose end was only ever announced
//! by a fetch response has no final object recorded to be past.

use std::sync::{Arc, Mutex};

use moqtap_codec::types::TrackNamespace;

/// The Group and Object an object names.
///
/// Not [`moqtap_codec::types::Location`], which carries the same pair as a
/// pair of `VarInt`s because it is a field on the wire. This one is compared
/// and maximised rather than encoded, so it holds the numbers themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectLocation {
    /// Group ID.
    pub group: u64,
    /// Object ID.
    pub object: u64,
}

/// Which of the two conditions an end-of-track status carries.
///
/// The distinction is a draft's, not a caller's: drafts 08 through 10 have both
/// statuses and drafts 11 through 13 have only the first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndOfTrackForm {
    /// The status whose Group ID names the track's *last* group — 0x4 on all
    /// six drafts. The Group ID may equal the largest group seen, and the
    /// Object ID must be past everything produced in it.
    LastGroup,
    /// The status whose Group ID names the group *after* the track's last —
    /// 0x5 on drafts 08, 09 and 10, which draft-11 folded into 0x4. The Group
    /// ID must be past every group seen.
    ///
    /// Its Object-ID-must-be-zero half needs no record and is refused by the
    /// codec on the one header that carries it.
    PastLastGroup,
}

/// Why an end-of-track object is not where the track ended.
///
/// Both halves carry what they were measured against, because "this is in the
/// wrong place" and "this is in the wrong place, and here is the place the
/// track had already reached" are different reports and only the second can be
/// read by whoever has to fix it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndOfTrackPlacement {
    /// The Group ID is behind a group the track has already carried.
    GroupBehind {
        /// The largest Group ID the track has carried.
        largest_group: u64,
    },
    /// The Object ID is at or behind the largest object produced in its own
    /// group.
    ObjectBehind {
        /// The largest Object ID produced in that group.
        largest_object: u64,
    },
}

impl std::fmt::Display for EndOfTrackPlacement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EndOfTrackPlacement::GroupBehind { largest_group } => {
                write!(f, "the track has already carried group {largest_group}")
            }
            EndOfTrackPlacement::ObjectBehind { largest_object } => {
                write!(f, "that group's largest object is {largest_object}")
            }
        }
    }
}

/// What went wrong with an object measured against its track's record.
///
/// Two rules meet here and their answers are opposites — one ends the session,
/// the other gives up a track and leaves the session alone — so they are told
/// apart at the point of detection rather than at the point of reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackFault {
    /// An end-of-track object is not where the track ended.
    EndOfTrackOutOfPlace(EndOfTrackPlacement),
    /// An object arrived past the track's final object, carrying where the
    /// track ended so the report can name it.
    PastFinalObject(ObjectLocation),
}

/// One track and how far its objects have reached.
struct TrackRecord {
    namespace: TrackNamespace,
    name: Vec<u8>,
    /// The largest Group ID seen, and the largest Object ID seen in that group.
    /// `None` until the track has carried an object with status Normal.
    reached: Option<ObjectLocation>,
    /// Where the track ended, once an end-of-track object has said so and been
    /// found to be in a place the track could end at.
    ///
    /// `None` on a track still running, and on one whose end-of-track object
    /// was refused — an object the draft calls a protocol error settles
    /// nothing, so nothing after it is measured against where it claimed the
    /// track stopped.
    final_object: Option<ObjectLocation>,
}

/// How far each track's objects have reached, so far.
///
/// A list rather than a map, and for the same reason the endpoint's own table of
/// track aliases is one: a session holds a handful of tracks, and
/// [`TrackNamespace`] has no `Hash`.
#[derive(Default)]
pub struct TrackLocations {
    tracks: Vec<TrackRecord>,
}

impl TrackLocations {
    /// An empty record, for a session that has carried no objects yet.
    pub fn new() -> Self {
        Self { tracks: Vec::new() }
    }

    /// Record an object a track produced.
    ///
    /// Only status Normal reaches here; see the module documentation for why an
    /// End of Group object would raise the largest object by one and refuse the
    /// End of Track object that follows it.
    pub fn observe(&mut self, namespace: &TrackNamespace, name: &[u8], at: ObjectLocation) {
        let Some(record) = self.record_mut(namespace, name) else {
            self.tracks.push(TrackRecord {
                namespace: namespace.clone(),
                name: name.to_vec(),
                reached: Some(at),
                final_object: None,
            });
            return;
        };
        record.reached = Some(match record.reached {
            None => at,
            // A larger group starts the object count again: what is kept is the
            // largest object *in the largest group*, and this is a different
            // group.
            Some(seen) if at.group > seen.group => at,
            Some(seen) if at.group == seen.group && at.object > seen.object => at,
            // A group behind the largest can never be the one an end-of-track
            // object names, so nothing about it is worth keeping.
            Some(seen) => seen,
        });
    }

    /// Judge where an end-of-track object says the track ended.
    ///
    /// `Ok` when the track has carried nothing yet: there is no group for the
    /// object to be behind, and a receiver that refused it would be enforcing an
    /// ordering against an empty record.
    pub fn check_end_of_track(
        &self,
        namespace: &TrackNamespace,
        name: &[u8],
        at: ObjectLocation,
        form: EndOfTrackForm,
    ) -> Result<(), EndOfTrackPlacement> {
        let Some(reached) = self.record(namespace, name).and_then(|record| record.reached) else {
            return Ok(());
        };
        match form {
            EndOfTrackForm::PastLastGroup if at.group <= reached.group => {
                Err(EndOfTrackPlacement::GroupBehind { largest_group: reached.group })
            }
            EndOfTrackForm::PastLastGroup => Ok(()),
            EndOfTrackForm::LastGroup if at.group < reached.group => {
                Err(EndOfTrackPlacement::GroupBehind { largest_group: reached.group })
            }
            // Past the largest group: that group has produced no objects, so
            // there is no largest in it for this one to be at or behind.
            EndOfTrackForm::LastGroup if at.group > reached.group => Ok(()),
            EndOfTrackForm::LastGroup if at.object <= reached.object => {
                Err(EndOfTrackPlacement::ObjectBehind { largest_object: reached.object })
            }
            EndOfTrackForm::LastGroup => Ok(()),
        }
    }

    /// Write down where an end-of-track object says the track ended.
    ///
    /// Called only after [`Self::check_end_of_track`] has accepted it, so a
    /// location this record would refuse never becomes the one later objects
    /// are measured against.
    ///
    /// The first one is kept. A second end-of-track object on a track that has
    /// already ended is itself past the final object on every ordering, so
    /// letting it move the mark would answer the fault by adopting it.
    pub fn note_final_object(
        &mut self,
        namespace: &TrackNamespace,
        name: &[u8],
        at: ObjectLocation,
    ) {
        let Some(record) = self.record_mut(namespace, name) else {
            self.tracks.push(TrackRecord {
                namespace: namespace.clone(),
                name: name.to_vec(),
                reached: None,
                final_object: Some(at),
            });
            return;
        };
        if record.final_object.is_none() {
            record.final_object = Some(at);
        }
    }

    /// Judge an ordinary object against where the track ended.
    ///
    /// `Ok` on a track no end-of-track object has been seen for: there is no
    /// final object for this one to be past, and a receiver that refused it
    /// would be giving up a track for arriving.
    ///
    /// The comparison is the drafts' own Location ordering — Group first, and
    /// the Object only where the Groups are equal — so an object in a later
    /// group is past the end whatever its Object ID.
    pub fn check_not_past_final(
        &self,
        namespace: &TrackNamespace,
        name: &[u8],
        at: ObjectLocation,
    ) -> Result<(), ObjectLocation> {
        let Some(final_object) = self.record(namespace, name).and_then(|r| r.final_object) else {
            return Ok(());
        };
        if (at.group, at.object) > (final_object.group, final_object.object) {
            return Err(final_object);
        }
        Ok(())
    }

    fn record(&self, namespace: &TrackNamespace, name: &[u8]) -> Option<&TrackRecord> {
        self.tracks.iter().find(|t| t.namespace == *namespace && t.name == name)
    }

    fn record_mut(&mut self, namespace: &TrackNamespace, name: &[u8]) -> Option<&mut TrackRecord> {
        self.tracks.iter_mut().find(|t| t.namespace == *namespace && t.name == name)
    }
}

/// What an Object Status makes of an object here.
///
/// Three answers and not two: a status is not only "ends the track or does
/// not". End of Group and Object Does Not Exist are statements *about* objects
/// that neither settle where a track has reached nor test it, and reading them
/// as either would break the rule in one direction or the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectRole {
    /// Status Normal: an object the track produced, and the only kind written
    /// down.
    Produced,
    /// An end-of-track status: the object that settles where the track ended.
    ///
    /// `Some(form)` on a draft that states a rule about where one may be
    /// placed, naming which of the two conditions to judge it by, and `None` on
    /// a draft that states none. Drafts 08 through 13 are the first; drafts 07
    /// and 14 through 19 are the second, and
    /// `a_track_may_end_where_it_has_already_been.rs` asserts the acceptance on
    /// all seven of them. Either way the object settles where the track ended,
    /// which is the other record's business and not that rule's.
    EndsTrack(Option<EndOfTrackForm>),
    /// Every other status.
    Neither,
}

/// One track's record, held by whatever is reading that track's objects.
///
/// # Why the stream holds this and not the endpoint
///
/// The objects are read one at a time off a stream handle the caller owns, and
/// that handle has no way back to the session — the same shape trap the close
/// table has, and the reason `Connection::close_for_data_stream` exists. A
/// record reachable only from the endpoint would leave the rule enforceable
/// only by a caller that remembered to ask, which for a conformance crate is
/// not enforcement. So the endpoint hands one of these to each stream it opens
/// for a track it can name, the stream measures every object it decodes against
/// it, and a stream nobody handed one to behaves exactly as it did before.
///
/// The clone is of the handle, not of the record: every stream on a session
/// measures against the same [`TrackLocations`], which is what makes the
/// largest group a property of the track rather than of one stream.
#[derive(Clone)]
pub struct TrackObjects {
    locations: Arc<Mutex<TrackLocations>>,
    namespace: TrackNamespace,
    name: Vec<u8>,
    /// The Track Alias this handle was resolved from.
    ///
    /// Carried for the report only, so it can name the track the way the wire
    /// did. Nothing is keyed on it — see the module documentation for why the
    /// record itself is keyed on the track.
    alias: u64,
}

impl TrackObjects {
    /// Bind a record to the track an alias resolved to.
    pub fn new(
        locations: Arc<Mutex<TrackLocations>>,
        namespace: TrackNamespace,
        name: Vec<u8>,
        alias: u64,
    ) -> Self {
        Self { locations, namespace, name, alias }
    }

    /// The Track Alias this handle was resolved from.
    pub fn alias(&self) -> u64 {
        self.alias
    }

    /// Record or judge one object, by what its status makes of it.
    ///
    /// The one entry point both data paths use, so a subgroup object and a
    /// datagram cannot come to disagree about which statuses count.
    pub fn note(&self, at: ObjectLocation, role: ObjectRole) -> Result<(), EndOfTrackPlacement> {
        match role {
            ObjectRole::Produced => {
                self.observe(at);
                Ok(())
            }
            ObjectRole::EndsTrack(form) => {
                if let Some(form) = form {
                    self.check_end_of_track(at, form)?;
                }
                self.note_final_object(at);
                Ok(())
            }
            ObjectRole::Neither => Ok(()),
        }
    }

    /// [`Self::note`], and the final-object rule with it, for the drafts that
    /// state one.
    ///
    /// The two rules are checked in the order that gives each the objects it is
    /// about. Where the track ended is asked first, because an object past the
    /// end is one this endpoint is giving up the track over and there is
    /// nothing to be gained by writing it into the record on the way past.
    ///
    /// # Every object, and not only the produced ones
    ///
    /// The sentence names an Object without qualifying it, and this reads it
    /// that way: a second end-of-track object naming a later place, or an End
    /// of Group beyond where the track stopped, is as much a track that carried
    /// on after its end as an ordinary object would be. That is the opposite of
    /// how [`TrackLocations::observe`] treats a status, and the two are not in
    /// tension — a status is not a *produced* object, which is what that record
    /// counts, but it is still an object *received*, which is what this one
    /// asks about.
    pub fn note_with_final_object(
        &self,
        at: ObjectLocation,
        role: ObjectRole,
    ) -> Result<(), TrackFault> {
        self.check_not_past_final(at).map_err(TrackFault::PastFinalObject)?;
        self.note(at, role).map_err(TrackFault::EndOfTrackOutOfPlace)
    }

    /// The final-object rule on its own, for the drafts that state no rule
    /// about where an end-of-track object may be placed.
    ///
    /// The same rule [`Self::note_with_final_object`] applies, and a different
    /// set of answers: a draft that judges nothing about placement has one
    /// fault to report and not two, so its callers are handed the one rather
    /// than an enum with an arm they cannot reach. Which entry point a draft
    /// uses is the whole of what it says about the rule beside this one.
    ///
    /// An end-of-track object settles where the track ended whatever form its
    /// status names, because the form only says how to judge a placement and
    /// this judges none.
    pub fn note_past_final(
        &self,
        at: ObjectLocation,
        role: ObjectRole,
    ) -> Result<(), ObjectLocation> {
        self.check_not_past_final(at)?;
        match role {
            ObjectRole::Produced => self.observe(at),
            ObjectRole::EndsTrack(_) => self.note_final_object(at),
            ObjectRole::Neither => {}
        }
        Ok(())
    }

    /// Write down where an end-of-track object says the track ended. See
    /// [`TrackLocations::note_final_object`].
    pub fn note_final_object(&self, at: ObjectLocation) {
        self.locked().note_final_object(&self.namespace, &self.name, at);
    }

    /// Judge an object against where the track ended. See
    /// [`TrackLocations::check_not_past_final`].
    pub fn check_not_past_final(&self, at: ObjectLocation) -> Result<(), ObjectLocation> {
        self.locked().check_not_past_final(&self.namespace, &self.name, at)
    }

    /// Record an object this track produced. See [`TrackLocations::observe`].
    pub fn observe(&self, at: ObjectLocation) {
        self.locked().observe(&self.namespace, &self.name, at);
    }

    /// Judge an end-of-track object's placement. See
    /// [`TrackLocations::check_end_of_track`].
    pub fn check_end_of_track(
        &self,
        at: ObjectLocation,
        form: EndOfTrackForm,
    ) -> Result<(), EndOfTrackPlacement> {
        self.locked().check_end_of_track(&self.namespace, &self.name, at, form)
    }

    /// The record, with a poisoned lock recovered rather than propagated.
    ///
    /// Nothing here can leave the record in a state a later reader is misled by:
    /// every mutation is one field of one entry, and a panic between the read
    /// and the write leaves the entry as it was.
    fn locked(&self) -> std::sync::MutexGuard<'_, TrackLocations> {
        self.locations.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}
