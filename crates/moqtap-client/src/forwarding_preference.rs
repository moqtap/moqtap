//! What a track's objects have been framed as, for the drafts that make that a
//! property of the track.
//!
//! Nine drafts state one sentence about it, at draft-11 Section 9: "Every Track
//! has a single 'Object Forwarding Preference' and the Original Publisher MUST
//! NOT mix different forwarding preferences within a single track." Drafts 07
//! through 10 and 12 through 15 say the same thing in the same words; what they
//! disagree about is the answer, and that answer belongs to each draft's own
//! close table rather than here. This module holds only the observation.
//!
//! # The framing is the preference
//!
//! No object header carries the value. An object on a subgroup stream has the
//! Subgroup preference and an object in a datagram has the Datagram one, so a
//! single object settles the property for its whole track and every object
//! after it on that track has to agree. Draft-15 Section 10.2.1 says exactly
//! that: "Note that the Original Publisher determines the Forwarding Preference
//! for the entire Track, and is a Track property that is implicitly signaled by
//! the delivery of any Object using either Subgroups or Datagrams. Once the
//! property is established for one Object of a Track, the same value MUST be
//! used for all Objects of the Track."
//!
//! Drafts 07 through 10 name a third preference in the enumeration and give it
//! no framing to arrive in. Draft-08 Section 8.1.1 reads "The preferences are
//! Track, Subgroup, and Datagram", while the stream type table three paragraphs
//! above it lists SUBGROUP_HEADER and FETCH_HEADER and nothing else. It is a
//! name an earlier draft left behind, and no peer can send one, so there are two
//! values here and not three.
//!
//! # Why the key is the track and not the alias
//!
//! The wire names a track by its Track Alias, and the alias would be the cheaper
//! key. It would also be wrong. An alias is free again the moment its
//! subscription ends and may then name a different track, so a record kept
//! against the alias would carry the first track's preference into the second
//! and close a session over traffic the drafts permit. The alias is resolved to
//! the track that holds it before anything is written down, and a track nothing
//! holds an alias for is not recorded at all — objects for an alias no
//! subscription named break a different rule, stated in a different sentence.
//!
//! # Why one record and not one per direction
//!
//! The property is the track's, not a subscription's and not a direction's, so
//! an endpoint that publishes a track over subgroup streams and receives the
//! same track's objects in datagrams has seen the sentence broken and this
//! reports it. What each end does about it differs — a subscriber closes the
//! session, a publisher declines to send — and that is the caller's to decide
//! from the error, not this table's.

use moqtap_codec::types::TrackNamespace;

/// How a publisher sent an object, which the framing settles rather than any
/// field on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectForwardingPreference {
    /// The object travelled on a subgroup stream.
    Subgroup,
    /// The object travelled in a datagram.
    Datagram,
}

impl std::fmt::Display for ObjectForwardingPreference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ObjectForwardingPreference::Subgroup => f.write_str("Subgroup"),
            ObjectForwardingPreference::Datagram => f.write_str("Datagram"),
        }
    }
}

/// One track and the preference its first object settled.
struct TrackPreference {
    namespace: TrackNamespace,
    name: Vec<u8>,
    settled: ObjectForwardingPreference,
}

/// The preference each track's objects have been framed as, so far.
///
/// A session holds a handful of tracks and this is scanned once per data stream
/// and once per datagram, which is why it is a list rather than a map — the same
/// shape, and for the same reason, as the endpoint's own table of track aliases.
#[derive(Default)]
pub struct TrackForwardingPreferences {
    tracks: Vec<TrackPreference>,
}

impl TrackForwardingPreferences {
    /// An empty record, for a session that has carried no objects yet.
    pub fn new() -> Self {
        Self { tracks: Vec::new() }
    }

    /// Record that a track's object was framed as `seen`.
    ///
    /// `Ok` when the track had settled on `seen` already or had settled on
    /// nothing. `Err` carries the preference the track did settle on, which is
    /// the half of the report that says what the rule was broken against.
    pub fn observe(
        &mut self,
        namespace: &TrackNamespace,
        name: &[u8],
        seen: ObjectForwardingPreference,
    ) -> Result<(), ObjectForwardingPreference> {
        for track in &self.tracks {
            if track.namespace == *namespace && track.name == name {
                return if track.settled == seen { Ok(()) } else { Err(track.settled) };
            }
        }
        self.tracks.push(TrackPreference {
            namespace: namespace.clone(),
            name: name.to_vec(),
            settled: seen,
        });
        Ok(())
    }
}
