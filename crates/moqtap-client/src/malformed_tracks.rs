//! What a Malformed Track is in this crate, and what detecting one costs.
//!
//! Draft-12 Section 2.5 opens the definition: "There are multiple ways a
//! publisher can transmit a Track that does not conform to MoQT constraints.
//! Such a Track is considered malformed. Some example conditions that
//! constitute a malformed track when detected by a receiver include:" — and
//! then eleven bullets, closing with "The above list of conditions is not
//! considered exhaustive."
//!
//! The list is examples. What is not an example is the answer, which the same
//! section states once for all of them: "When a subscriber detects a Malformed
//! Track, it MUST UNSUBSCRIBE from the Track and SHOULD deliver an error to
//! the application." That sentence is the whole of what this module exists
//! for. A condition is detected somewhere in the data plane; the track it
//! names is withdrawn; the caller is told which condition it was.
//!
//! # A track is withdrawn, and the session is not
//!
//! Nothing here ends a session. The answer is an UNSUBSCRIBE and an error
//! handed up, and the connection stays exactly where it was — which is why
//! this record and the close table are separate things, and why no condition
//! recorded here reaches [`crate::draft12::endpoint::EndpointError`]'s session
//! error codes. A malformed track costs one track.
//!
//! # The answer is given once, and this record is not what makes it once
//!
//! A publisher that mixes one track's framing will usually go on mixing it,
//! and the draft asks for an UNSUBSCRIBE rather than one per offending
//! object. What keeps it to one is the subscription itself: the first
//! withdrawal ends every request the track was arriving through, and a
//! request that has ended has no second UNSUBSCRIBE in it.
//!
//! So this record does not gate the withdrawal, and the difference matters in
//! one case. An application that subscribes to the same track *again* is
//! opening a request that has never been withdrawn from, and a publisher that
//! mixes its framing again has broken the sentence again. A record that
//! refused the second withdrawal because it recognised the track would leave
//! that subscription running over traffic the draft says to give up on —
//! remembering a track and refusing to act on it are not the same thing.
//!
//! # Why the key is the track and not the alias
//!
//! The same reason [`crate::forwarding_preference`] gives, and it bites harder
//! here. An alias is free again the moment its subscription ends and may then
//! name a different track — so a withdrawal recorded against the alias would
//! make the *next* track's first malformation look like one already answered,
//! and that track would never be withdrawn at all. The alias is resolved
//! through the endpoint's binding table before anything is written down.
//!
//! # What "subscriber" excludes
//!
//! The sentence names a subscriber, so only the paths on which this endpoint
//! *receives* a track owe the withdrawal. The two writing paths detect the
//! same condition — an endpoint is the Original Publisher there and the rule
//! that binds it is a rule about publishing — and they answer it by refusing
//! to write, which withdraws nothing because there is nothing to withdraw.
//!
//! The section's other sentence is a relay's: "If a relay detects a Malformed
//! Track, it MUST immediately terminate downstream subscriptions with
//! SUBSCRIBE_DONE with Status Code Malformed Track." This crate is a client.
//! It has no downstream subscriptions to terminate, so that half is not
//! unimplemented here so much as inapplicable; a relay built on top of this
//! has the condition reported to it and its own downstream to answer for.

use moqtap_codec::types::TrackNamespace;

/// Which condition of the list made a track malformed.
///
/// One variant per condition this crate can actually detect, which is fewer
/// than the drafts list. A condition nothing observes would be a name with no
/// call site, and the list is explicitly not exhaustive in either direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MalformedTrackCondition {
    /// "An Object is received with a different Forwarding Preference than
    /// previously observed from the same Track."
    ///
    /// Detected by [`crate::forwarding_preference`], which holds the framing
    /// each track's first object settled on.
    MixedForwardingPreference,
    /// "An Object is received on a Track whose Group and Object ID are larger
    /// than the final Object in the Track."
    ///
    /// Detected by [`crate::track_locations`], which writes down where an
    /// end-of-track object said the track stopped and measures what arrives
    /// afterwards against it.
    ///
    /// It reaches drafts the condition beside it does not. Draft-16 made the
    /// Forwarding Preference a property of an Object rather than of a Track, so
    /// there is nothing on that draft for a mixed-framing record to contradict;
    /// this condition is stated unchanged from draft-12 on and
    /// depends on nothing that moved.
    ObjectPastFinalObject,
}

impl std::fmt::Display for MalformedTrackCondition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MalformedTrackCondition::MixedForwardingPreference => {
                f.write_str("an Object was received with a different Forwarding Preference")
            }
            MalformedTrackCondition::ObjectPastFinalObject => {
                f.write_str("an Object was received past the track's final Object")
            }
        }
    }
}

/// One track that has been found malformed, and what found it.
struct WithdrawnTrack {
    namespace: TrackNamespace,
    name: Vec<u8>,
    condition: MalformedTrackCondition,
}

/// The tracks this endpoint has withdrawn from for malformation.
///
/// A list rather than a map, for the reason the forwarding-preference record
/// beside it gives: a session holds a handful of tracks, and this is scanned
/// only when a condition has already fired.
#[derive(Default)]
pub struct MalformedTracks {
    tracks: Vec<WithdrawnTrack>,
}

impl MalformedTracks {
    /// An empty record, for a session that has found nothing malformed.
    pub fn new() -> Self {
        Self { tracks: Vec::new() }
    }

    /// Record that a track has been found malformed.
    ///
    /// The first condition is the one kept. A track that goes on being
    /// malformed after it has been withdrawn from is answered by what has
    /// already happened to it, and the condition worth reporting afterwards is
    /// the one that caused that.
    pub fn note(
        &mut self,
        namespace: &TrackNamespace,
        name: &[u8],
        condition: MalformedTrackCondition,
    ) {
        if self.condition(namespace, name).is_some() {
            return;
        }
        self.tracks.push(WithdrawnTrack {
            namespace: namespace.clone(),
            name: name.to_vec(),
            condition,
        });
    }

    /// The condition a track was withdrawn for, or `None` for a track this
    /// endpoint has found nothing wrong with.
    pub fn condition(
        &self,
        namespace: &TrackNamespace,
        name: &[u8],
    ) -> Option<MalformedTrackCondition> {
        self.tracks
            .iter()
            .find(|t| t.namespace == *namespace && t.name == name)
            .map(|t| t.condition)
    }
}
