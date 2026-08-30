#![cfg(any(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14"
))]

//! A connection helper writes the request it was told to write, on the eight
//! drafts below the ones already swept.
//!
//! The same claim `a_request_helper_asks_for_what_it_was_told.rs` makes for
//! drafts 15 and 16, in the shapes these eight draw a request. A helper is a
//! few lines — allocate an ID, build a message, write it — and each of those
//! lines is a place to write the wrong thing. The result is a well-formed
//! request asking for something the caller did not ask for: the session stays
//! up, the peer answers, and nothing returns an error.
//!
//! # Why these eight had nothing
//!
//! Surveyed rather than assumed. Every draft here has tests that drive a real
//! `Connection`, between eight and twenty files each, and on all eight of them
//! those tests drive a helper to get a session into a state and then read the
//! answer. Reading the answer proves a request of the right *type* arrived,
//! because a type is all the peer needed in order to reply. The one exception
//! was `a_malformed_track_is_withdrawn_from.rs`, which checks the Request ID an
//! UNSUBSCRIBE names on drafts 12 through 15 — one field of one withdrawal
//! helper.
//!
//! # What the peer does
//!
//! It reads every message the client writes on the control stream, decodes it,
//! and renders it with [`common::render`] — the message's name, the type
//! number the draft assigns it, and the fields inside it a caller chooses. The
//! gate renders what it asked for the same way. The two strings agree only if
//! the helper wrote the request it was told to.
//!
//! Everything is on the one control stream here. Draft-16 is where a request
//! first gets a bidirectional stream of its own, so the peer in this file has
//! no second loop and the counts are a single number per draft.
//!
//! # What a rendering carries, and why it is not the whole message
//!
//! Every value the caller supplies, plus every value the helper *derives* from
//! what the caller supplied, and the Request ID the helper handed back. An
//! argument that does not reach the rendering is an argument the sweep cannot
//! see dropped; a field the endpoint fills in from its own state is not the
//! helper's to get wrong.
//!
//! The derived values are the reason the Filter Type is rendered. No caller
//! passes one to `subscribe_range` on any of these drafts: the helper picks
//! AbsoluteStart or AbsoluteRange according to whether an end was given, and
//! picking the other one writes a message whose named filter disagrees with
//! the fields it carries. The same goes for a PUBLISH's Content Exists, which
//! these drafts derive from whether a Largest Location was passed.
//!
//! # The shapes, which are the whole cost of the row
//!
//! Six of them for one message. SUBSCRIBE is read six different ways across
//! these eight drafts, and the six do not line up with where the drafts
//! change, which is the part worth knowing before starting.
//!
//! The drafts change it three times in this range. Drafts 07 through 10 draw
//! the range as four fields, a StartGroup and a StartObject and an EndGroup
//! and an EndObject, and draft-07 is the last to define the fourth: drafts 08,
//! 09 and 10 define only three while keeping a Filter Type description that
//! still names "the StartGroup/StartObject and EndGroup/EndObject fields".
//! Draft-11 replaces all four with one Start Location and an End Group, turns
//! the Subscribe ID into a Request ID and adds a Forward. Draft-12 drops the
//! Track Alias, which every draft below it makes the subscriber choose. After
//! that the drafts leave SUBSCRIBE alone until draft-15 moves the Subscriber
//! Priority, the Group Order, the Forward and the Filter Type into the
//! parameters, which is where the sweep next door picks it up.
//!
//! The codec differs again in one place the drafts do not: it holds draft-11's
//! Start Location as two fields on drafts 11, 12 and 13, and as a `Location`
//! on draft-14. The same bytes either way. It matters here only because the
//! peer reads the fields by name, so the two are two arms.
//!
//! And it draws the Filter Type as a bare variable-length integer on drafts 11
//! and 12, with no enum to name its values by, and as a typed value on the
//! other six.
//!
//! Two more ranges sit on top of those. Drafts 07 through 11 have no parameter
//! argument on any request helper at all, so there is no caller's list to
//! drop; the count is rendered all the same, wherever the message has the
//! field, and on those five drafts it is the claim that a helper given nothing
//! attaches nothing of its own. The one message with no such field to render
//! is TRACK_STATUS_REQUEST on drafts 07 through 10 — draft-11 gave it one, and
//! this file's first run found that out by disagreeing with the peer about it.
//! And drafts 07 through 10 give SUBSCRIBE_ANNOUNCES, ANNOUNCE and
//! TRACK_STATUS_REQUEST no Request ID at all, so those three helpers return
//! nothing and the rendering has no id to carry.
//!
//! One more rename runs through the joining fetch, and it is two renames
//! rather than one. The field naming the subscription joined is a Joining
//! Subscribe ID on drafts 08 through 11 and a Joining Request ID from
//! draft-12, which is not the same claim — a Request ID is drawn from the
//! space every request shares, and drafts 08 through 10 have no such space.
//! The field saying where to start is a Preceding Group Offset on drafts 08
//! through 10 and a Joining Start from draft-11. Each is rendered under the
//! name its own draft gives it, so a failure names the field a reader of that
//! draft would look for.
//!
//! The renaming is the cheap part and is worth stating anyway, because a
//! rendering that kept the old name would be reporting a message the draft
//! does not have: SUBSCRIBE_ANNOUNCES becomes SUBSCRIBE_NAMESPACE at draft-13,
//! ANNOUNCE becomes PUBLISH_NAMESPACE at draft-14, and TRACK_STATUS_REQUEST
//! becomes TRACK_STATUS at draft-13 — where it also stops being a two-field
//! message and takes the whole shape of a subscription.
//!
//! # Which helpers each draft has
//!
//! Six on draft-07, seven on drafts 08, 09 and 10, eight on draft-11, nine on
//! drafts 12, 13 and 14. PUBLISH arrives at draft-12.
//!
//! The joining fetch is where the count moves twice. Draft-07 has none.
//! Drafts 08, 09 and 10 draw one, at Fetch Type 0x2, whose second field is a
//! Preceding Group Offset — so they get one helper, because a pair of calls
//! would be inventing a distinction those drafts do not draw. Draft-11 splits
//! it into a Relative Joining Fetch at 0x2 and an Absolute Joining Fetch at
//! 0x3, "Identical to a Relative Joining Fetch except that the Start Group is
//! determined by an absolute Group value rather than a relative offset", so
//! from there it is two.
//!
//! Two calls rather than one taking a Fetch Type, on every draft that has
//! both, and the endpoint under them is named the same way — so no call
//! between an application and the wire carries a Fetch Type that could be
//! given a wrong value, and the absolute form is a name rather than an
//! argument.

#![allow(clippy::items_after_test_module)]

mod common;

use std::time::Duration;

use common::{namespace_text, render, text};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// How long a gate waits on the client or the peer before calling it hung.
const PATIENCE: Duration = Duration::from_secs(10);

/// The track every request in the sweep names.
const TRACK: &[u8] = b"track-1";

/// A second track name, for the gate that holds the rendering to telling two
/// requests apart. Never sent.
const OTHER_TRACK: &[u8] = b"track-2";

/// The Track Alias the subscriber chooses on the drafts that make it choose
/// one, and that a PUBLISH offers on the drafts that have a PUBLISH.
const ALIAS: u64 = 7;

/// The Subscriber Priority every request that has one carries. Not 0 and not
/// 255, so that a helper substituting either end of the range is visible.
const PRIORITY: u8 = 128;

/// A second priority, for the rendering's own gate. Never sent.
const OTHER_PRIORITY: u8 = 12;

/// `GroupOrder::Ascending`, which every request here asks for.
const ASCENDING: u64 = 0x1;

/// `Forward`, the value of the Forward field on the drafts that have one.
const FORWARDING: u64 = 1;

/// Filter Type `LargestObject`, what a plain `subscribe` asks for.
const LARGEST_OBJECT: u64 = 0x2;

/// Filter Type `AbsoluteRange`, which no caller passes: it is what
/// `subscribe_range` derives from being given an end.
const ABSOLUTE_RANGE: u64 = 0x4;

/// The Group a range subscription starts at.
const START_GROUP: u64 = 3;

/// The Object within it.
const START_OBJECT: u64 = 4;

/// The Group a range subscription ends at.
const END_GROUP: u64 = 9;

/// The Object within it, which only draft-07 carries.
const END_OBJECT: u64 = 2;

/// The Group a PUBLISH names as its largest.
const LARGEST_GROUP: u64 = 5;

/// The Object within it.
const LARGEST_OBJECT_ID: u64 = 6;

/// `ContentExists::HasLargestLocation`, which a PUBLISH given a Largest
/// Location derives rather than is told.
const HAS_LARGEST_LOCATION: u64 = 1;

/// The Fetch Type of a standalone FETCH on every draft here that has the
/// field. Draft-07's FETCH has none.
const STANDALONE_FETCH: u64 = 0x1;

/// The Fetch Type of the one joining kind drafts 08, 09 and 10 draw. The same
/// number as the relative form that replaces it at draft-11, which is what
/// makes the two worth naming apart: a draft with one joining kind and a draft
/// with two agree on the byte and not on what it means.
#[cfg(any(feature = "draft08", feature = "draft09", feature = "draft10"))]
const JOINING_FETCH: u64 = 0x2;

/// The Fetch Type of a Relative Joining Fetch.
const RELATIVE_JOINING_FETCH: u64 = 0x2;

/// The Fetch Type of an Absolute Joining Fetch.
const ABSOLUTE_JOINING_FETCH: u64 = 0x3;

/// What drafts 08 through 11 call the field naming the subscription joined.
const JOINED_SUBSCRIBE_ID: &str = "joining subscribe id";

/// What drafts 12 and up call it.
const JOINED_REQUEST_ID: &str = "joining request id";

/// What drafts 08, 09 and 10 call the field that says where to start.
const PRECEDING_GROUP_OFFSET: &str = "preceding group offset";

/// What drafts 11 and up call it.
const JOINING_START_FIELD: &str = "joining start";

/// The Group a relative joining fetch reaches back to.
const JOINING_START: u64 = 2;

/// The Group an absolute joining fetch starts at. Different from
/// [`JOINING_START`], so that a helper calling the wrong builder is visible in
/// the field as well as in the Fetch Type.
const ABSOLUTE_JOINING_START: u64 = 9;

/// The range a standalone FETCH asks for: Start Group, Start Object, End
/// Group, End Object.
const FETCH_RANGE: (u64, u64, u64, u64) = (0, 0, 1, 1);

/// SUBSCRIBE's message type, 0x03 on all eight.
const SUBSCRIBE_TYPE: u64 = 0x03;

/// FETCH's message type, 0x16 on all eight.
const FETCH_TYPE: u64 = 0x16;

/// The message type of a namespace subscription, 0x11 on all eight — under two
/// names, since draft-13 renamed it.
const NAMESPACE_SUBSCRIPTION_TYPE: u64 = 0x11;

/// The message type of an announcement, 0x06 on all eight — under two names,
/// since draft-14 renamed it.
const ANNOUNCEMENT_TYPE: u64 = 0x06;

/// The message type of a track-status request, 0x0D on all eight. Draft-13
/// renamed it to TRACK_STATUS, which on the drafts below it is 0x0E and is the
/// *answer*; the number the request carries does not move.
const TRACK_STATUS_REQUEST_TYPE: u64 = 0x0D;

/// PUBLISH's message type, 0x1D on the three drafts here that have one.
const PUBLISH_TYPE: u64 = 0x1D;

/// The peer's MAX_REQUEST_ID — MAX_SUBSCRIBE_ID on drafts 07 through 10, the
/// same key under the older name — granted as a SETUP parameter (key 0x02) so
/// the client has ids to spend.
const REQUEST_BUDGET: u64 = 100;

/// The namespace every request names.
fn namespace() -> TrackNamespace {
    TrackNamespace(vec![b"one-control-stream".to_vec()])
}

/// A second namespace, for the gate that holds the rendering to telling two
/// requests apart. Never sent.
fn other_namespace() -> TrackNamespace {
    TrackNamespace(vec![b"one-control-stream".to_vec(), b"and-a-suffix".to_vec()])
}

/// A varint, spelled the short way.
fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).unwrap()
}

/// A parameter the sweep attaches to every helper that takes a list, so what
/// the peer reports has something in it only the caller could have put there.
///
/// AUTHORIZATION TOKEN because it is the one parameter every request type
/// admits. Its value is a Token structure rather than opaque bytes — a
/// receiver that cannot decode the Token closes the session — so this is a
/// Token: USE_ALIAS (0x2) and an alias, which is the shortest one there is.
///
/// Behind the features because no request helper on drafts 07 through 11 takes
/// a parameter list, and a build of one of those five would otherwise carry a
/// parameter nothing attaches.
#[cfg(any(feature = "draft12", feature = "draft13", feature = "draft14"))]
fn attached() -> KeyValuePair {
    KeyValuePair { key: v(0x03), value: KvpValue::Bytes(vec![0x2, 0x7]) }
}

/// The SETUP parameters both ends send: an id budget and nothing else.
fn setup_parameters() -> Vec<KeyValuePair> {
    vec![KeyValuePair { key: v(0x02), value: KvpValue::Varint(v(REQUEST_BUDGET)) }]
}

/// The ROLE setup parameter, which draft-07 alone requires of both endpoints.
///
/// Draft-07 Section 6.2.2.1: "Both endpoints MUST send a ROLE parameter with
/// one of the three values specified above. Both endpoints MUST close the
/// session if the ROLE parameter is missing or is not one of the three
/// above-specified values." Without it the client refuses the SERVER_SETUP and
/// no request is ever written. Every draft above 07 dropped the parameter.
#[cfg(feature = "draft07")]
fn role() -> KeyValuePair {
    let mut value = Vec::new();
    v(3).encode(&mut value); // PubSub
    KeyValuePair { key: v(0x00), value: KvpValue::Bytes(value) }
}

// -- the renderings ----------------------------------------------------------
//
// Each is fed by the peer from the message it decoded and by a gate from what
// it asked for, so the values are two claims and the format is one.
//
// A field a draft does not have is left out rather than rendered as zero or as
// an empty list: the two are different claims, and an endpoint that stopped
// writing a field it does have would render the second.

/// Everything a caller chooses when it asks for a subscription, on the drafts
/// that draw those choices as fields of the message rather than as parameters.
///
/// Wider than any one draft. Each field is `Option` where some draft in the
/// range does not carry it, and the arms below fill in exactly what their own
/// draft draws — which is why [`a_rendering_that_dropped_a_field_would_hide_a_helper_asking_for_the_wrong_thing`]
/// varies every one of them on its own.
struct Subscription {
    request_id: u64,
    track_alias: Option<u64>,
    track_namespace: TrackNamespace,
    track_name: Vec<u8>,
    subscriber_priority: u8,
    group_order: u64,
    forward: Option<u64>,
    filter_type: u64,
    start_group: Option<u64>,
    start_object: Option<u64>,
    end_group: Option<u64>,
    end_object: Option<u64>,
    parameters: Option<usize>,
}

impl Default for Subscription {
    /// The fields every draft in the range carries, and nothing else. An arm
    /// that leaves a field at its default is saying its draft has no such
    /// field.
    fn default() -> Self {
        Self {
            request_id: 0,
            track_alias: None,
            track_namespace: namespace(),
            track_name: TRACK.to_vec(),
            subscriber_priority: PRIORITY,
            group_order: ASCENDING,
            forward: None,
            filter_type: LARGEST_OBJECT,
            start_group: None,
            start_object: None,
            end_group: None,
            end_object: None,
            parameters: None,
        }
    }
}

/// A subscription-shaped request, rendered.
///
/// The name and the type are arguments because two messages take this shape:
/// SUBSCRIBE on every draft here, and TRACK_STATUS on drafts 13 and 14, where
/// asking for a track's status became asking for a subscription that answers
/// once.
fn subscription_request(name: &str, message_type: u64, s: &Subscription) -> String {
    let mut fields = vec![("request id", s.request_id.to_string())];
    if let Some(alias) = s.track_alias {
        fields.push(("track alias", alias.to_string()));
    }
    fields.push(("namespace", namespace_text(&s.track_namespace)));
    fields.push(("track", text(&s.track_name)));
    fields.push(("priority", s.subscriber_priority.to_string()));
    fields.push(("order", s.group_order.to_string()));
    if let Some(forward) = s.forward {
        fields.push(("forward", forward.to_string()));
    }
    fields.push(("filter type", s.filter_type.to_string()));
    if let Some(group) = s.start_group {
        fields.push(("start group", group.to_string()));
    }
    if let Some(object) = s.start_object {
        fields.push(("start object", object.to_string()));
    }
    if let Some(group) = s.end_group {
        fields.push(("end group", group.to_string()));
    }
    if let Some(object) = s.end_object {
        fields.push(("end object", object.to_string()));
    }
    if let Some(count) = s.parameters {
        fields.push(("parameters", count.to_string()));
    }
    render(name, message_type, &fields)
}

/// A SUBSCRIBE, rendered.
fn subscribe_request(s: &Subscription) -> String {
    subscription_request("SUBSCRIBE", SUBSCRIBE_TYPE, s)
}

/// A TRACK_STATUS on drafts 13 and 14, where it takes a subscription's shape.
fn track_status_of_a_subscription(s: &Subscription) -> String {
    subscription_request("TRACK_STATUS", TRACK_STATUS_REQUEST_TYPE, s)
}

/// A standalone FETCH's fields, in the shapes these drafts draw them.
///
/// Draft-07 has no Fetch Type at all, and drafts 08, 09 and 10 draw the track
/// and the range as optional fields of the message rather than as a payload
/// belonging to the Fetch Type — so a fetch that omitted one of them is a
/// thing those three drafts can encode, and a rendering that could not say so
/// would not notice.
struct StandaloneFetch {
    request_id: u64,
    fetch_type: Option<u64>,
    track_namespace: Option<TrackNamespace>,
    track_name: Option<Vec<u8>>,
    subscriber_priority: u8,
    group_order: u64,
    start_group: Option<u64>,
    start_object: Option<u64>,
    end_group: Option<u64>,
    end_object: Option<u64>,
    parameters: Option<usize>,
}

impl Default for StandaloneFetch {
    fn default() -> Self {
        Self {
            request_id: 0,
            fetch_type: Some(STANDALONE_FETCH),
            track_namespace: Some(namespace()),
            track_name: Some(TRACK.to_vec()),
            subscriber_priority: PRIORITY,
            group_order: ASCENDING,
            start_group: Some(FETCH_RANGE.0),
            start_object: Some(FETCH_RANGE.1),
            end_group: Some(FETCH_RANGE.2),
            end_object: Some(FETCH_RANGE.3),
            parameters: None,
        }
    }
}

/// A standalone FETCH, rendered.
fn standalone_fetch_request(f: &StandaloneFetch) -> String {
    let mut fields = vec![("request id", f.request_id.to_string())];
    if let Some(kind) = f.fetch_type {
        fields.push(("fetch type", kind.to_string()));
    }
    if let Some(ns) = &f.track_namespace {
        fields.push(("namespace", namespace_text(ns)));
    }
    if let Some(name) = &f.track_name {
        fields.push(("track", text(name)));
    }
    fields.push(("priority", f.subscriber_priority.to_string()));
    fields.push(("order", f.group_order.to_string()));
    if let Some(group) = f.start_group {
        fields.push(("start group", group.to_string()));
    }
    if let Some(object) = f.start_object {
        fields.push(("start object", object.to_string()));
    }
    if let Some(group) = f.end_group {
        fields.push(("end group", group.to_string()));
    }
    if let Some(object) = f.end_object {
        fields.push(("end object", object.to_string()));
    }
    if let Some(count) = f.parameters {
        fields.push(("parameters", count.to_string()));
    }
    render("FETCH", FETCH_TYPE, &fields)
}

/// A joining FETCH of any of the three kinds these drafts draw.
///
/// The Fetch Type is a field rather than part of the name because the relative
/// form and the absolute form are one message and differ in it. It is exactly
/// the difference two connection helpers exist to make.
///
/// The two joining fields carry their own labels because the drafts do not
/// agree on what they are called. The first is a Joining Subscribe ID on
/// drafts 08 through 11 and a Joining Request ID from draft-12; the second is
/// a Preceding Group Offset on drafts 08 through 10 and a Joining Start from
/// draft-11. Rendering all of them under one pair of names would report a
/// field under a name its own draft does not use — and on drafts 08 through 10
/// it would report a Request ID on drafts that have no request-id space at
/// all.
///
/// Both are optional for the reason every other optional field here is: a
/// helper that left one out has to render unlike one that sent it as zero.
struct JoiningFetch {
    request_id: u64,
    fetch_type: u64,
    subscriber_priority: u8,
    group_order: u64,
    joined_label: &'static str,
    joined: Option<u64>,
    start_label: &'static str,
    start: Option<u64>,
    parameters: usize,
}

impl Default for JoiningFetch {
    fn default() -> Self {
        Self {
            request_id: 0,
            fetch_type: RELATIVE_JOINING_FETCH,
            subscriber_priority: PRIORITY,
            group_order: ASCENDING,
            joined_label: JOINED_REQUEST_ID,
            joined: Some(0),
            start_label: JOINING_START_FIELD,
            start: Some(JOINING_START),
            parameters: 0,
        }
    }
}

/// See [`JoiningFetch`].
fn joining_fetch_request(f: &JoiningFetch) -> String {
    let mut fields = vec![
        ("request id", f.request_id.to_string()),
        ("fetch type", f.fetch_type.to_string()),
        ("priority", f.subscriber_priority.to_string()),
        ("order", f.group_order.to_string()),
    ];
    if let Some(joined) = f.joined {
        fields.push((f.joined_label, joined.to_string()));
    }
    if let Some(start) = f.start {
        fields.push((f.start_label, start.to_string()));
    }
    fields.push(("parameters", f.parameters.to_string()));
    render("FETCH", FETCH_TYPE, &fields)
}

/// A namespace subscription, rendered.
///
/// The name is an argument because draft-13 renamed the message, and the
/// Request ID is optional because drafts 07 through 10 do not give it one —
/// their helpers return nothing, so there is no id for a gate to expect.
fn namespace_subscription_request(
    name: &str,
    request_id: Option<u64>,
    namespace_prefix: &TrackNamespace,
    parameters: Option<usize>,
) -> String {
    let mut fields = Vec::new();
    if let Some(id) = request_id {
        fields.push(("request id", id.to_string()));
    }
    fields.push(("prefix", namespace_text(namespace_prefix)));
    if let Some(count) = parameters {
        fields.push(("parameters", count.to_string()));
    }
    render(name, NAMESPACE_SUBSCRIPTION_TYPE, &fields)
}

/// An announcement, rendered. See [`namespace_subscription_request`] for why
/// the name and the Request ID are arguments.
fn announcement_request(
    name: &str,
    request_id: Option<u64>,
    track_namespace: &TrackNamespace,
    parameters: Option<usize>,
) -> String {
    let mut fields = Vec::new();
    if let Some(id) = request_id {
        fields.push(("request id", id.to_string()));
    }
    fields.push(("namespace", namespace_text(track_namespace)));
    if let Some(count) = parameters {
        fields.push(("parameters", count.to_string()));
    }
    render(name, ANNOUNCEMENT_TYPE, &fields)
}

/// A TRACK_STATUS_REQUEST, rendered, on the drafts where it is two fields and
/// a list.
///
/// Drafts 07 through 10 give it no Request ID *and* no Parameters field at
/// all, which is the one message in this file that carries neither.
fn track_status_request(
    request_id: Option<u64>,
    track_namespace: &TrackNamespace,
    track_name: &[u8],
    parameters: Option<usize>,
) -> String {
    let mut fields = Vec::new();
    if let Some(id) = request_id {
        fields.push(("request id", id.to_string()));
    }
    fields.push(("namespace", namespace_text(track_namespace)));
    fields.push(("track", text(track_name)));
    if let Some(count) = parameters {
        fields.push(("parameters", count.to_string()));
    }
    render("TRACK_STATUS_REQUEST", TRACK_STATUS_REQUEST_TYPE, &fields)
}

/// A PUBLISH, rendered.
///
/// Content Exists is here because no caller passes one: these drafts derive it
/// from whether a Largest Location was given, and a PUBLISH that says it has
/// content while carrying no location is a message its receiver cannot read.
#[allow(clippy::too_many_arguments)]
fn publish_request(
    request_id: u64,
    track_namespace: &TrackNamespace,
    track_name: &[u8],
    track_alias: u64,
    group_order: u64,
    content_exists: u64,
    largest_location: Option<(u64, u64)>,
    forward: u64,
    parameters: usize,
) -> String {
    let mut fields = vec![
        ("request id", request_id.to_string()),
        ("namespace", namespace_text(track_namespace)),
        ("track", text(track_name)),
        ("track alias", track_alias.to_string()),
        ("order", group_order.to_string()),
        ("content exists", content_exists.to_string()),
    ];
    if let Some((group, object)) = largest_location {
        fields.push(("largest group", group.to_string()));
        fields.push(("largest object", object.to_string()));
    }
    fields.push(("forward", forward.to_string()));
    fields.push(("parameters", parameters.to_string()));
    render("PUBLISH", PUBLISH_TYPE, &fields)
}

/// The rendering tells two requests apart, which is what the sweep rests on.
///
/// The peer's report and the sweep's expectation are built by the same
/// functions, so a rendering that dropped its fields would drop them on both
/// sides and the sweep would pass against a peer that could not tell one
/// request from another. That is the one thing the sweep cannot assert about
/// itself, and it is asserted here instead.
///
/// Every field is varied on its own, including the ones only some of these
/// eight drafts carry. A rendering that kept eleven of twelve fields would
/// still be wrong about the twelfth, and a single pair of unlike requests
/// would not say which.
///
/// # What it catches
///
/// Making [`common::render`] return the name and the type alone, which is the
/// degenerate rendering the sweep would not notice:
///
/// ```text
/// assertion `left != right` failed: the Request ID has to reach the rendering
///   left: "SUBSCRIBE 0x03"
///  right: "SUBSCRIBE 0x03"
/// ```
#[test]
fn a_rendering_that_dropped_a_field_would_hide_a_helper_asking_for_the_wrong_thing() {
    let plain = || Subscription::default();

    assert_ne!(
        subscribe_request(&Subscription { request_id: 4, ..plain() }),
        subscribe_request(&Subscription { request_id: 5, ..plain() }),
        "the Request ID has to reach the rendering"
    );
    assert_ne!(
        subscribe_request(&Subscription { track_alias: Some(ALIAS), ..plain() }),
        subscribe_request(&plain()),
        "a Track Alias a draft does not have must not render as one that arrived zero"
    );
    assert_ne!(
        subscribe_request(&Subscription { track_alias: Some(ALIAS), ..plain() }),
        subscribe_request(&Subscription { track_alias: Some(ALIAS + 1), ..plain() }),
        "the Track Alias has to reach the rendering"
    );
    assert_ne!(
        subscribe_request(&plain()),
        subscribe_request(&Subscription { track_namespace: other_namespace(), ..plain() }),
        "the namespace has to reach the rendering, every field of it"
    );
    assert_ne!(
        subscribe_request(&plain()),
        subscribe_request(&Subscription { track_name: OTHER_TRACK.to_vec(), ..plain() }),
        "the track name has to reach the rendering"
    );
    assert_ne!(
        subscribe_request(&plain()),
        subscribe_request(&Subscription { subscriber_priority: OTHER_PRIORITY, ..plain() }),
        "the Subscriber Priority has to reach the rendering"
    );
    assert_ne!(
        subscribe_request(&plain()),
        subscribe_request(&Subscription { group_order: 0x2, ..plain() }),
        "the Group Order has to reach the rendering"
    );
    assert_ne!(
        subscribe_request(&Subscription { forward: Some(FORWARDING), ..plain() }),
        subscribe_request(&Subscription { forward: Some(0), ..plain() }),
        "the Forward field has to reach the rendering"
    );
    assert_ne!(
        subscribe_request(&plain()),
        subscribe_request(&Subscription { filter_type: ABSOLUTE_RANGE, ..plain() }),
        "the Filter Type has to reach the rendering: no caller passes one to \
         subscribe_range, so it is the helper's own claim about the fields it wrote"
    );
    assert_ne!(
        subscribe_request(&Subscription { start_group: Some(START_GROUP), ..plain() }),
        subscribe_request(&Subscription { start_group: Some(START_GROUP + 1), ..plain() }),
        "the Start Group has to reach the rendering"
    );
    assert_ne!(
        subscribe_request(&Subscription { start_object: Some(START_OBJECT), ..plain() }),
        subscribe_request(&Subscription { start_object: Some(START_OBJECT + 1), ..plain() }),
        "the Start Object has to reach the rendering"
    );
    assert_ne!(
        subscribe_request(&Subscription { end_group: Some(END_GROUP), ..plain() }),
        subscribe_request(&Subscription { end_group: Some(END_GROUP + 1), ..plain() }),
        "the End Group has to reach the rendering"
    );
    assert_ne!(
        subscribe_request(&Subscription { end_object: Some(END_OBJECT), ..plain() }),
        subscribe_request(&plain()),
        "an End Object only draft-07 carries must not render like its absence"
    );
    assert_ne!(
        subscribe_request(&Subscription { parameters: Some(1), ..plain() }),
        subscribe_request(&Subscription { parameters: Some(0), ..plain() }),
        "the parameter count has to reach the rendering: a helper that dropped \
         the caller's list is the defect this file was opened for"
    );
    assert_ne!(
        subscribe_request(&Subscription { parameters: Some(0), ..plain() }),
        subscribe_request(&plain()),
        "a draft whose helpers take no parameters must not render like one \
         whose helper dropped the list it was given"
    );
    assert_ne!(
        subscribe_request(&plain()),
        track_status_of_a_subscription(&plain()),
        "two requests with the same fields and different names must not render alike"
    );

    let fetch = || StandaloneFetch::default();

    assert_ne!(
        standalone_fetch_request(&fetch()),
        standalone_fetch_request(&StandaloneFetch { fetch_type: None, ..fetch() }),
        "a Fetch Type draft-07 does not have must not render like one that arrived zero"
    );
    assert_ne!(
        standalone_fetch_request(&fetch()),
        standalone_fetch_request(&StandaloneFetch { track_namespace: None, ..fetch() }),
        "a FETCH that left its namespace out must not render like one that named it"
    );
    assert_ne!(
        standalone_fetch_request(&fetch()),
        standalone_fetch_request(&StandaloneFetch { track_name: None, ..fetch() }),
        "a FETCH that left its track out must not render like one that named it"
    );
    assert_ne!(
        standalone_fetch_request(&fetch()),
        standalone_fetch_request(&StandaloneFetch { end_group: Some(9), ..fetch() }),
        "a FETCH's range has to reach the rendering"
    );
    let joining = || JoiningFetch { request_id: 4, ..Default::default() };

    assert_ne!(
        joining_fetch_request(&joining()),
        joining_fetch_request(&JoiningFetch { fetch_type: ABSOLUTE_JOINING_FETCH, ..joining() }),
        "the Fetch Type has to reach the rendering: the relative and absolute \
         forms are one message and differ in it"
    );
    assert_ne!(
        joining_fetch_request(&JoiningFetch { start: Some(ABSOLUTE_JOINING_START), ..joining() }),
        joining_fetch_request(&JoiningFetch {
            joined: Some(ABSOLUTE_JOINING_START),
            start: Some(0),
            ..joining()
        }),
        "the joined request and the start are two fields, not one pair in either order"
    );
    assert_ne!(
        joining_fetch_request(&joining()),
        joining_fetch_request(&JoiningFetch {
            joined_label: JOINED_SUBSCRIBE_ID,
            start_label: PRECEDING_GROUP_OFFSET,
            ..joining()
        }),
        "a draft that calls the two joining fields something else must not \
         render them under a later draft's names"
    );
    assert_ne!(
        joining_fetch_request(&joining()),
        joining_fetch_request(&JoiningFetch { start: None, ..joining() }),
        "a joining fetch that left its start out must not render like one that \
         sent it as zero"
    );

    assert_ne!(
        namespace_subscription_request("SUBSCRIBE_ANNOUNCES", None, &namespace(), None),
        namespace_subscription_request("SUBSCRIBE_NAMESPACE", None, &namespace(), None),
        "a draft that renamed the message must not render it under the old name"
    );
    assert_ne!(
        namespace_subscription_request("SUBSCRIBE_ANNOUNCES", None, &namespace(), None),
        namespace_subscription_request("SUBSCRIBE_ANNOUNCES", Some(0), &namespace(), None),
        "a Request ID a draft does not have must not render as one that arrived zero"
    );
    assert_ne!(
        namespace_subscription_request("SUBSCRIBE_ANNOUNCES", None, &namespace(), None),
        namespace_subscription_request("SUBSCRIBE_ANNOUNCES", None, &other_namespace(), None),
        "the prefix has to reach the rendering"
    );
    assert_ne!(
        announcement_request("ANNOUNCE", None, &namespace(), None),
        announcement_request("PUBLISH_NAMESPACE", None, &namespace(), None),
        "draft-14 renamed the announcement and the rendering has to say so"
    );
    assert_ne!(
        announcement_request("ANNOUNCE", None, &namespace(), None),
        announcement_request("ANNOUNCE", None, &other_namespace(), None),
        "an announcement's namespace has to reach the rendering"
    );
    assert_ne!(
        track_status_request(None, &namespace(), TRACK, None),
        track_status_request(None, &namespace(), OTHER_TRACK, None),
        "a track-status request's track has to reach the rendering"
    );
    assert_ne!(
        track_status_request(None, &namespace(), TRACK, None),
        track_status_request(None, &namespace(), TRACK, Some(0)),
        "a Parameters field drafts 07 through 10 do not have must not render \
         like an empty one"
    );

    let published = |alias, exists, largest, forward, parameters| {
        publish_request(
            4,
            &namespace(),
            TRACK,
            alias,
            ASCENDING,
            exists,
            largest,
            forward,
            parameters,
        )
    };
    let largest = Some((LARGEST_GROUP, LARGEST_OBJECT_ID));
    assert_ne!(
        published(ALIAS, HAS_LARGEST_LOCATION, largest, FORWARDING, 1),
        published(ALIAS + 1, HAS_LARGEST_LOCATION, largest, FORWARDING, 1),
        "a PUBLISH's Track Alias has to reach the rendering"
    );
    assert_ne!(
        published(ALIAS, HAS_LARGEST_LOCATION, largest, FORWARDING, 1),
        published(ALIAS, 0, None, FORWARDING, 1),
        "Content Exists has to reach the rendering: no caller passes one, so it \
         is the helper's own claim about the location it wrote"
    );
    assert_ne!(
        published(ALIAS, HAS_LARGEST_LOCATION, largest, FORWARDING, 1),
        published(ALIAS, HAS_LARGEST_LOCATION, Some((LARGEST_GROUP, 0)), FORWARDING, 1),
        "the Largest Location has to reach the rendering, both halves of it"
    );
    assert_ne!(
        published(ALIAS, HAS_LARGEST_LOCATION, largest, FORWARDING, 1),
        published(ALIAS, HAS_LARGEST_LOCATION, largest, 0, 1),
        "a PUBLISH's Forward has to reach the rendering"
    );
    assert_ne!(
        published(ALIAS, HAS_LARGEST_LOCATION, largest, FORWARDING, 1),
        published(ALIAS, HAS_LARGEST_LOCATION, largest, FORWARDING, 0),
        "a PUBLISH's parameter count has to reach the rendering"
    );
}

// -- the calls, the peer's readings and the gates' expectations --------------
//
// One selector token per message drives all three, so a call, the rendering of
// what arrived and the rendering of what was asked for cannot disagree about
// which draft they are on.

/// SUBSCRIBE, in the six shapes these eight drafts draw it.
#[macro_export]
macro_rules! helper_subscribe {
    (alias_location_end_object, $conn:expr) => {
        helper_subscribe!(alias_typed_call, $conn)
    };
    (alias_location, $conn:expr) => {
        helper_subscribe!(alias_typed_call, $conn)
    };
    (alias_typed_call, $conn:expr) => {
        $conn.subscribe(
            v(ALIAS),
            namespace(),
            TRACK.to_vec(),
            PRIORITY,
            GroupOrder::Ascending,
            FilterType::LargestObject,
        )
    };
    (alias_split_varint, $conn:expr) => {
        $conn.subscribe(
            v(ALIAS),
            namespace(),
            TRACK.to_vec(),
            PRIORITY,
            GroupOrder::Ascending,
            v(LARGEST_OBJECT),
        )
    };
    (split_varint, $conn:expr) => {
        $conn.subscribe(
            namespace(),
            TRACK.to_vec(),
            PRIORITY,
            GroupOrder::Ascending,
            v(LARGEST_OBJECT),
            vec![attached()],
        )
    };
    (split_typed, $conn:expr) => {
        helper_subscribe!(typed_params_call, $conn)
    };
    (location_typed, $conn:expr) => {
        helper_subscribe!(typed_params_call, $conn)
    };
    (typed_params_call, $conn:expr) => {
        $conn.subscribe(
            namespace(),
            TRACK.to_vec(),
            PRIORITY,
            GroupOrder::Ascending,
            FilterType::LargestObject,
            vec![attached()],
        )
    };
}

/// A range subscription. Draft-07 ends at a Location; every draft above it
/// ends at a Group; drafts 12 and up take the caller's parameters.
#[macro_export]
macro_rules! helper_subscribe_range {
    (alias_location_end_object, $conn:expr) => {
        $conn.subscribe_range(
            v(ALIAS),
            namespace(),
            TRACK.to_vec(),
            PRIORITY,
            GroupOrder::Ascending,
            Location { group: v(START_GROUP), object: v(START_OBJECT) },
            Some(Location { group: v(END_GROUP), object: v(END_OBJECT) }),
        )
    };
    (alias_location, $conn:expr) => {
        helper_subscribe_range!(alias_end_group_call, $conn)
    };
    (alias_split_varint, $conn:expr) => {
        helper_subscribe_range!(alias_end_group_call, $conn)
    };
    (alias_end_group_call, $conn:expr) => {
        $conn.subscribe_range(
            v(ALIAS),
            namespace(),
            TRACK.to_vec(),
            PRIORITY,
            GroupOrder::Ascending,
            Location { group: v(START_GROUP), object: v(START_OBJECT) },
            Some(v(END_GROUP)),
        )
    };
    (split_varint, $conn:expr) => {
        helper_subscribe_range!(end_group_params_call, $conn)
    };
    (split_typed, $conn:expr) => {
        helper_subscribe_range!(end_group_params_call, $conn)
    };
    (location_typed, $conn:expr) => {
        helper_subscribe_range!(end_group_params_call, $conn)
    };
    (end_group_params_call, $conn:expr) => {
        $conn.subscribe_range(
            namespace(),
            TRACK.to_vec(),
            PRIORITY,
            GroupOrder::Ascending,
            Location { group: v(START_GROUP), object: v(START_OBJECT) },
            Some(v(END_GROUP)),
            vec![attached()],
        )
    };
}

/// See [`helper_subscribe`]. The peer's side: what arrived, read out of the
/// fields this draft's SUBSCRIBE has.
#[macro_export]
macro_rules! describe_subscribe {
    (alias_location_end_object, $m:expr) => {
        Subscription {
            request_id: $m.subscribe_id.into_inner(),
            track_alias: Some($m.track_alias.into_inner()),
            track_namespace: $m.track_namespace.clone(),
            track_name: $m.track_name.clone(),
            subscriber_priority: $m.subscriber_priority,
            group_order: $m.group_order as u64,
            filter_type: $m.filter_type as u64,
            start_group: $m.start_location.as_ref().map(|l| l.group.into_inner()),
            start_object: $m.start_location.as_ref().map(|l| l.object.into_inner()),
            end_group: $m.end_group.map(|g| g.into_inner()),
            end_object: $m.end_object.map(|o| o.into_inner()),
            parameters: Some($m.parameters.len()),
            ..Default::default()
        }
    };
    (alias_location, $m:expr) => {
        Subscription {
            request_id: $m.subscribe_id.into_inner(),
            track_alias: Some($m.track_alias.into_inner()),
            track_namespace: $m.track_namespace.clone(),
            track_name: $m.track_name.clone(),
            subscriber_priority: $m.subscriber_priority,
            group_order: $m.group_order as u64,
            filter_type: $m.filter_type as u64,
            start_group: $m.start_location.as_ref().map(|l| l.group.into_inner()),
            start_object: $m.start_location.as_ref().map(|l| l.object.into_inner()),
            end_group: $m.end_group.map(|g| g.into_inner()),
            parameters: Some($m.parameters.len()),
            ..Default::default()
        }
    };
    (alias_split_varint, $m:expr) => {
        Subscription {
            request_id: $m.request_id.into_inner(),
            track_alias: Some($m.track_alias.into_inner()),
            track_namespace: $m.track_namespace.clone(),
            track_name: $m.track_name.clone(),
            subscriber_priority: $m.subscriber_priority,
            group_order: $m.group_order as u64,
            forward: Some($m.forward as u64),
            filter_type: $m.filter_type.into_inner(),
            start_group: $m.start_group.map(|g| g.into_inner()),
            start_object: $m.start_object.map(|o| o.into_inner()),
            end_group: $m.end_group.map(|g| g.into_inner()),
            parameters: Some($m.parameters.len()),
            ..Default::default()
        }
    };
    (split_varint, $m:expr) => {
        Subscription {
            request_id: $m.request_id.into_inner(),
            track_namespace: $m.track_namespace.clone(),
            track_name: $m.track_name.clone(),
            subscriber_priority: $m.subscriber_priority,
            group_order: $m.group_order as u64,
            forward: Some($m.forward as u64),
            filter_type: $m.filter_type.into_inner(),
            start_group: $m.start_group.map(|g| g.into_inner()),
            start_object: $m.start_object.map(|o| o.into_inner()),
            end_group: $m.end_group.map(|g| g.into_inner()),
            parameters: Some($m.parameters.len()),
            ..Default::default()
        }
    };
    (split_typed, $m:expr) => {
        Subscription {
            request_id: $m.request_id.into_inner(),
            track_namespace: $m.track_namespace.clone(),
            track_name: $m.track_name.clone(),
            subscriber_priority: $m.subscriber_priority,
            group_order: $m.group_order as u64,
            forward: Some($m.forward as u64),
            filter_type: $m.filter_type as u64,
            start_group: $m.start_group.map(|g| g.into_inner()),
            start_object: $m.start_object.map(|o| o.into_inner()),
            end_group: $m.end_group.map(|g| g.into_inner()),
            parameters: Some($m.parameters.len()),
            ..Default::default()
        }
    };
    (location_typed, $m:expr) => {
        Subscription {
            request_id: $m.request_id.into_inner(),
            track_namespace: $m.track_namespace.clone(),
            track_name: $m.track_name.clone(),
            subscriber_priority: $m.subscriber_priority,
            group_order: $m.group_order as u64,
            forward: Some($m.forward as u64),
            filter_type: $m.filter_type as u64,
            start_group: $m.start_location.as_ref().map(|l| l.group.into_inner()),
            start_object: $m.start_location.as_ref().map(|l| l.object.into_inner()),
            end_group: $m.end_group.map(|g| g.into_inner()),
            parameters: Some($m.parameters.len()),
            ..Default::default()
        }
    };
}

/// See [`helper_subscribe`]. The gate's side, for a plain subscription.
#[macro_export]
macro_rules! expected_subscribe {
    (alias_location_end_object, $id:expr) => {
        Subscription {
            request_id: $id,
            track_alias: Some(ALIAS),
            parameters: Some(0),
            ..Default::default()
        }
    };
    (alias_location, $id:expr) => {
        expected_subscribe!(alias_location_end_object, $id)
    };
    (alias_split_varint, $id:expr) => {
        Subscription {
            request_id: $id,
            track_alias: Some(ALIAS),
            forward: Some(FORWARDING),
            parameters: Some(0),
            ..Default::default()
        }
    };
    (split_varint, $id:expr) => {
        expected_subscribe!(with_parameters, $id)
    };
    (split_typed, $id:expr) => {
        expected_subscribe!(with_parameters, $id)
    };
    (location_typed, $id:expr) => {
        expected_subscribe!(with_parameters, $id)
    };
    (with_parameters, $id:expr) => {
        Subscription {
            request_id: $id,
            forward: Some(FORWARDING),
            parameters: Some(1),
            ..Default::default()
        }
    };
}

/// See [`helper_subscribe_range`]. The gate's side.
#[macro_export]
macro_rules! expected_subscribe_range {
    ($shape:tt, $id:expr) => {
        Subscription {
            filter_type: ABSOLUTE_RANGE,
            start_group: Some(START_GROUP),
            start_object: Some(START_OBJECT),
            end_group: Some(END_GROUP),
            end_object: expected_end_object!($shape),
            ..expected_subscribe!($shape, $id)
        }
    };
}

/// The End Object only draft-07 carries.
#[macro_export]
macro_rules! expected_end_object {
    (alias_location_end_object) => {
        Some(END_OBJECT)
    };
    ($other:tt) => {
        None
    };
}

/// A standalone FETCH, in the three shapes these drafts draw it.
#[macro_export]
macro_rules! helper_fetch {
    (untyped, $conn:expr) => {
        helper_fetch!(no_parameters_call, $conn)
    };
    (typed_flat, $conn:expr) => {
        helper_fetch!(no_parameters_call, $conn)
    };
    (typed_payload, $conn:expr) => {
        helper_fetch!(no_parameters_call, $conn)
    };
    (no_parameters_call, $conn:expr) => {
        $conn.fetch(
            namespace(),
            TRACK.to_vec(),
            PRIORITY,
            GroupOrder::Ascending,
            v(FETCH_RANGE.0),
            v(FETCH_RANGE.1),
            v(FETCH_RANGE.2),
            v(FETCH_RANGE.3),
        )
    };
    (typed_params, $conn:expr) => {
        $conn.fetch(
            namespace(),
            TRACK.to_vec(),
            PRIORITY,
            GroupOrder::Ascending,
            v(FETCH_RANGE.0),
            v(FETCH_RANGE.1),
            v(FETCH_RANGE.2),
            v(FETCH_RANGE.3),
            vec![attached()],
        )
    };
}

/// See [`helper_fetch`]. The peer's side.
///
/// Draft-07's FETCH names its track outright. Drafts 08, 09 and 10 draw the
/// track and the range as optional fields, and every draft from 11 puts them
/// in a payload chosen by the Fetch Type — which is why a joining fetch is a
/// different arm and not a different message.
#[macro_export]
macro_rules! describe_fetch {
    (untyped, $m:expr) => {
        Some(standalone_fetch_request(&StandaloneFetch {
            request_id: $m.subscribe_id.into_inner(),
            fetch_type: None,
            track_namespace: Some($m.track_namespace.clone()),
            track_name: Some($m.track_name.clone()),
            subscriber_priority: $m.subscriber_priority,
            group_order: $m.group_order as u64,
            start_group: Some($m.start_group.into_inner()),
            start_object: Some($m.start_object.into_inner()),
            end_group: Some($m.end_group.into_inner()),
            end_object: Some($m.end_object.into_inner()),
            parameters: Some($m.parameters.len()),
        }))
    };
    (typed_payload, $m:expr) => {
        match &$m.fetch_payload {
            FetchPayload::Standalone {
                track_namespace,
                track_name,
                start_group,
                start_object,
                end_group,
                end_object,
            } => Some(standalone_fetch_request(&StandaloneFetch {
                request_id: $m.request_id.into_inner(),
                fetch_type: Some($m.fetch_type as u64),
                track_namespace: Some(track_namespace.clone()),
                track_name: Some(track_name.clone()),
                subscriber_priority: $m.subscriber_priority,
                group_order: $m.group_order as u64,
                start_group: Some(start_group.into_inner()),
                start_object: Some(start_object.into_inner()),
                end_group: Some(end_group.into_inner()),
                end_object: Some(end_object.into_inner()),
                parameters: Some($m.parameters.len()),
            })),
            // Draft-11 names the joined request a Joining Subscribe ID where
            // every draft from 12 names it a Joining Request ID, and the two
            // are not the same claim: a Request ID is drawn from the space
            // every request shares. The draft's own description has already
            // moved — it calls this field "The Request ID of the existing
            // subscription to be joined" under the older name — so the label
            // follows the field list rather than the sentence under it.
            FetchPayload::Joining { joining_subscribe_id, joining_start } => {
                Some(joining_fetch_request(&JoiningFetch {
                    request_id: $m.request_id.into_inner(),
                    fetch_type: $m.fetch_type as u64,
                    subscriber_priority: $m.subscriber_priority,
                    group_order: $m.group_order as u64,
                    joined_label: JOINED_SUBSCRIBE_ID,
                    joined: Some(joining_subscribe_id.into_inner()),
                    start_label: JOINING_START_FIELD,
                    start: Some(joining_start.into_inner()),
                    parameters: $m.parameters.len(),
                }))
            }
        }
    };
    // The Fetch Type chooses the branch because the draft says it chooses the
    // fields: everything below the type is "present only for" one kind or the
    // other. Rendering a joining fetch through the standalone arm would drop
    // the two fields the joining helper exists to fill in, which is the one
    // pair of fields it could get wrong.
    (typed_flat, $m:expr) => {
        if $m.fetch_type as u64 == STANDALONE_FETCH {
            Some(standalone_fetch_request(&StandaloneFetch {
                request_id: $m.subscribe_id.into_inner(),
                fetch_type: Some($m.fetch_type as u64),
                track_namespace: $m.track_namespace.clone(),
                track_name: $m.track_name.clone(),
                subscriber_priority: $m.subscriber_priority,
                group_order: $m.group_order as u64,
                start_group: $m.start_group.map(|g| g.into_inner()),
                start_object: $m.start_object.map(|o| o.into_inner()),
                end_group: $m.end_group.map(|g| g.into_inner()),
                end_object: $m.end_object.map(|o| o.into_inner()),
                parameters: Some($m.parameters.len()),
            }))
        } else {
            Some(joining_fetch_request(&JoiningFetch {
                request_id: $m.subscribe_id.into_inner(),
                fetch_type: $m.fetch_type as u64,
                subscriber_priority: $m.subscriber_priority,
                group_order: $m.group_order as u64,
                joined_label: JOINED_SUBSCRIBE_ID,
                joined: $m.joining_subscribe_id.map(|i| i.into_inner()),
                start_label: PRECEDING_GROUP_OFFSET,
                start: $m.preceding_group_offset.map(|o| o.into_inner()),
                parameters: $m.parameters.len(),
            }))
        }
    };
    (typed_params, $m:expr) => {
        match &$m.fetch_payload {
            FetchPayload::Standalone {
                track_namespace,
                track_name,
                start_group,
                start_object,
                end_group,
                end_object,
            } => Some(standalone_fetch_request(&StandaloneFetch {
                request_id: $m.request_id.into_inner(),
                fetch_type: Some($m.fetch_type as u64),
                track_namespace: Some(track_namespace.clone()),
                track_name: Some(track_name.clone()),
                subscriber_priority: $m.subscriber_priority,
                group_order: $m.group_order as u64,
                start_group: Some(start_group.into_inner()),
                start_object: Some(start_object.into_inner()),
                end_group: Some(end_group.into_inner()),
                end_object: Some(end_object.into_inner()),
                parameters: Some($m.parameters.len()),
            })),
            FetchPayload::Joining { joining_request_id, joining_start } => {
                Some(joining_fetch_request(&JoiningFetch {
                    request_id: $m.request_id.into_inner(),
                    fetch_type: $m.fetch_type as u64,
                    subscriber_priority: $m.subscriber_priority,
                    group_order: $m.group_order as u64,
                    joined_label: JOINED_REQUEST_ID,
                    joined: Some(joining_request_id.into_inner()),
                    start_label: JOINING_START_FIELD,
                    start: Some(joining_start.into_inner()),
                    parameters: $m.parameters.len(),
                }))
            }
        }
    };
}

/// See [`helper_fetch`]. The gate's side.
#[macro_export]
macro_rules! expected_fetch {
    (untyped, $id:expr) => {
        StandaloneFetch {
            request_id: $id,
            fetch_type: None,
            parameters: Some(0),
            ..Default::default()
        }
    };
    (typed_flat, $id:expr) => {
        StandaloneFetch { request_id: $id, parameters: Some(0), ..Default::default() }
    };
    (typed_payload, $id:expr) => {
        StandaloneFetch { request_id: $id, parameters: Some(0), ..Default::default() }
    };
    (typed_params, $id:expr) => {
        StandaloneFetch { request_id: $id, parameters: Some(1), ..Default::default() }
    };
}

/// A namespace subscription, in the five shapes these drafts draw it.
#[macro_export]
macro_rules! helper_namespace_subscription {
    (anonymous, $conn:expr) => {
        $conn.subscribe_announces(namespace())
    };
    (identified, $conn:expr) => {
        $conn.subscribe_announces(namespace())
    };
    (identified_params, $conn:expr) => {
        $conn.subscribe_announces(namespace(), vec![attached()])
    };
    (renamed_params, $conn:expr) => {
        $conn.subscribe_namespace(namespace(), vec![attached()])
    };
    (renamed_field, $conn:expr) => {
        $conn.subscribe_namespace(namespace(), vec![attached()])
    };
}

/// See [`helper_namespace_subscription`]. The peer's side.
#[macro_export]
macro_rules! describe_namespace_subscription {
    (anonymous, $m:expr) => {
        match $m {
            ControlMessage::SubscribeAnnounces(m) => Some(namespace_subscription_request(
                "SUBSCRIBE_ANNOUNCES",
                None,
                &m.track_namespace_prefix,
                Some(m.parameters.len()),
            )),
            _ => None,
        }
    };
    (identified, $m:expr) => {
        match $m {
            ControlMessage::SubscribeAnnounces(m) => Some(namespace_subscription_request(
                "SUBSCRIBE_ANNOUNCES",
                Some(m.request_id.into_inner()),
                &m.track_namespace_prefix,
                Some(m.parameters.len()),
            )),
            _ => None,
        }
    };
    (identified_params, $m:expr) => {
        match $m {
            ControlMessage::SubscribeAnnounces(m) => Some(namespace_subscription_request(
                "SUBSCRIBE_ANNOUNCES",
                Some(m.request_id.into_inner()),
                &m.track_namespace_prefix,
                Some(m.parameters.len()),
            )),
            _ => None,
        }
    };
    (renamed_params, $m:expr) => {
        match $m {
            ControlMessage::SubscribeNamespace(m) => Some(namespace_subscription_request(
                "SUBSCRIBE_NAMESPACE",
                Some(m.request_id.into_inner()),
                &m.track_namespace_prefix,
                Some(m.parameters.len()),
            )),
            _ => None,
        }
    };
    (renamed_field, $m:expr) => {
        match $m {
            ControlMessage::SubscribeNamespace(m) => Some(namespace_subscription_request(
                "SUBSCRIBE_NAMESPACE",
                Some(m.request_id.into_inner()),
                &m.track_namespace,
                Some(m.parameters.len()),
            )),
            _ => None,
        }
    };
}

/// See [`helper_namespace_subscription`]. The gate's side.
#[macro_export]
macro_rules! expected_namespace_subscription {
    (anonymous, $answer:expr) => {{
        // Drafts 07 through 10 answer with `()`, because the message they
        // wrote has no Request ID to answer with. Bound to that type rather
        // than dropped, so a helper which started returning an id stops
        // compiling here instead of being quietly ignored.
        let _: () = $answer;
        namespace_subscription_request("SUBSCRIBE_ANNOUNCES", None, &namespace(), Some(0))
    }};
    (identified, $answer:expr) => {
        namespace_subscription_request(
            "SUBSCRIBE_ANNOUNCES",
            Some($answer.into_inner()),
            &namespace(),
            Some(0),
        )
    };
    (identified_params, $answer:expr) => {
        namespace_subscription_request(
            "SUBSCRIBE_ANNOUNCES",
            Some($answer.into_inner()),
            &namespace(),
            Some(1),
        )
    };
    (renamed_params, $answer:expr) => {
        expected_namespace_subscription!(renamed_call, $answer)
    };
    (renamed_field, $answer:expr) => {
        expected_namespace_subscription!(renamed_call, $answer)
    };
    (renamed_call, $answer:expr) => {
        namespace_subscription_request(
            "SUBSCRIBE_NAMESPACE",
            Some($answer.into_inner()),
            &namespace(),
            Some(1),
        )
    };
}

/// An announcement, in the four shapes these drafts draw it.
#[macro_export]
macro_rules! helper_announcement {
    (anonymous, $conn:expr) => {
        $conn.announce(namespace())
    };
    (identified, $conn:expr) => {
        $conn.announce(namespace())
    };
    (identified_params, $conn:expr) => {
        $conn.announce(namespace(), vec![attached()])
    };
    (renamed, $conn:expr) => {
        $conn.publish_namespace(namespace(), vec![attached()])
    };
}

/// See [`helper_announcement`]. The peer's side.
#[macro_export]
macro_rules! describe_announcement {
    (anonymous, $m:expr) => {
        match $m {
            ControlMessage::Announce(m) => Some(announcement_request(
                "ANNOUNCE",
                None,
                &m.track_namespace,
                Some(m.parameters.len()),
            )),
            _ => None,
        }
    };
    (identified, $m:expr) => {
        match $m {
            ControlMessage::Announce(m) => Some(announcement_request(
                "ANNOUNCE",
                Some(m.request_id.into_inner()),
                &m.track_namespace,
                Some(m.parameters.len()),
            )),
            _ => None,
        }
    };
    (identified_params, $m:expr) => {
        match $m {
            ControlMessage::Announce(m) => Some(announcement_request(
                "ANNOUNCE",
                Some(m.request_id.into_inner()),
                &m.track_namespace,
                Some(m.parameters.len()),
            )),
            _ => None,
        }
    };
    (renamed, $m:expr) => {
        match $m {
            ControlMessage::PublishNamespace(m) => Some(announcement_request(
                "PUBLISH_NAMESPACE",
                Some(m.request_id.into_inner()),
                &m.track_namespace,
                Some(m.parameters.len()),
            )),
            _ => None,
        }
    };
}

/// See [`helper_announcement`]. The gate's side.
#[macro_export]
macro_rules! expected_announcement {
    (anonymous, $answer:expr) => {{
        let _: () = $answer;
        announcement_request("ANNOUNCE", None, &namespace(), Some(0))
    }};
    (identified, $answer:expr) => {
        announcement_request("ANNOUNCE", Some($answer.into_inner()), &namespace(), Some(0))
    };
    (identified_params, $answer:expr) => {
        announcement_request("ANNOUNCE", Some($answer.into_inner()), &namespace(), Some(1))
    };
    (renamed, $answer:expr) => {
        announcement_request("PUBLISH_NAMESPACE", Some($answer.into_inner()), &namespace(), Some(1))
    };
}

/// A track-status request, in the four shapes these drafts draw it.
#[macro_export]
macro_rules! helper_track_status {
    (anonymous, $conn:expr) => {
        $conn.track_status_request(namespace(), TRACK.to_vec())
    };
    (identified, $conn:expr) => {
        $conn.track_status_request(namespace(), TRACK.to_vec())
    };
    (identified_params, $conn:expr) => {
        $conn.track_status_request(namespace(), TRACK.to_vec(), vec![attached()])
    };
    (subscribe_like_split, $conn:expr) => {
        helper_track_status!(subscribe_like_call, $conn)
    };
    (subscribe_like_location, $conn:expr) => {
        helper_track_status!(subscribe_like_call, $conn)
    };
    (subscribe_like_call, $conn:expr) => {
        $conn.track_status(
            namespace(),
            TRACK.to_vec(),
            PRIORITY,
            GroupOrder::Ascending,
            Forward::Forward,
            FilterType::LargestObject,
            vec![attached()],
        )
    };
}

/// See [`helper_track_status`]. The peer's side.
#[macro_export]
macro_rules! describe_track_status {
    (anonymous, $m:expr) => {
        match $m {
            ControlMessage::TrackStatusRequest(m) => {
                Some(track_status_request(None, &m.track_namespace, &m.track_name, None))
            }
            _ => None,
        }
    };
    (identified, $m:expr) => {
        match $m {
            ControlMessage::TrackStatusRequest(m) => Some(track_status_request(
                Some(m.request_id.into_inner()),
                &m.track_namespace,
                &m.track_name,
                Some(m.parameters.len()),
            )),
            _ => None,
        }
    };
    (identified_params, $m:expr) => {
        describe_track_status!(identified, $m)
    };
    (subscribe_like_split, $m:expr) => {
        match $m {
            ControlMessage::TrackStatus(m) => Some(track_status_of_a_subscription(&Subscription {
                request_id: m.request_id.into_inner(),
                track_namespace: m.track_namespace.clone(),
                track_name: m.track_name.clone(),
                subscriber_priority: m.subscriber_priority,
                group_order: m.group_order as u64,
                forward: Some(m.forward as u64),
                filter_type: m.filter_type as u64,
                start_group: m.start_group.map(|g| g.into_inner()),
                start_object: m.start_object.map(|o| o.into_inner()),
                end_group: m.end_group.map(|g| g.into_inner()),
                parameters: Some(m.parameters.len()),
                ..Default::default()
            })),
            _ => None,
        }
    };
    (subscribe_like_location, $m:expr) => {
        match $m {
            ControlMessage::TrackStatus(m) => Some(track_status_of_a_subscription(&Subscription {
                request_id: m.request_id.into_inner(),
                track_namespace: m.track_namespace.clone(),
                track_name: m.track_name.clone(),
                subscriber_priority: m.subscriber_priority,
                group_order: m.group_order as u64,
                forward: Some(m.forward as u64),
                filter_type: m.filter_type as u64,
                start_group: m.start_location.as_ref().map(|l| l.group.into_inner()),
                start_object: m.start_location.as_ref().map(|l| l.object.into_inner()),
                end_group: m.end_group.map(|g| g.into_inner()),
                parameters: Some(m.parameters.len()),
                ..Default::default()
            })),
            _ => None,
        }
    };
}

/// See [`helper_track_status`]. The gate's side.
#[macro_export]
macro_rules! expected_track_status {
    (anonymous, $answer:expr) => {{
        let _: () = $answer;
        track_status_request(None, &namespace(), TRACK, None)
    }};
    (identified, $answer:expr) => {
        track_status_request(Some($answer.into_inner()), &namespace(), TRACK, Some(0))
    };
    (identified_params, $answer:expr) => {
        track_status_request(Some($answer.into_inner()), &namespace(), TRACK, Some(1))
    };
    (subscribe_like_split, $answer:expr) => {
        expected_track_status!(subscribe_like_call, $answer)
    };
    (subscribe_like_location, $answer:expr) => {
        expected_track_status!(subscribe_like_call, $answer)
    };
    (subscribe_like_call, $answer:expr) => {
        track_status_of_a_subscription(&Subscription {
            request_id: $answer.into_inner(),
            forward: Some(FORWARDING),
            parameters: Some(1),
            ..Default::default()
        })
    };
}

/// A PUBLISH, which arrives at draft-12 and is one shape from there on.
///
/// One macro that calls and expects, rather than the trio the other requests
/// use, because five of these drafts have no such call: an arm that expanded
/// to one would have to expand to something on those five, and there is
/// nothing for it to be.
#[macro_export]
macro_rules! a_publish {
    (absent, $conn:expr, $expected:expr) => {};
    (present, $conn:expr, $expected:expr) => {
        let published = $conn
            .publish(
                namespace(),
                TRACK.to_vec(),
                v(ALIAS),
                GroupOrder::Ascending,
                Some(Location { group: v(LARGEST_GROUP), object: v(LARGEST_OBJECT_ID) }),
                Forward::Forward,
                vec![attached()],
            )
            .await
            .expect("publish");
        $expected.push(expected_publish!(present, published.into_inner()));
    };
}

/// See [`helper_publish`]. The peer's side.
#[macro_export]
macro_rules! describe_publish {
    (absent, $m:expr) => {
        None
    };
    (present, $m:expr) => {
        match $m {
            ControlMessage::Publish(m) => Some(publish_request(
                m.request_id.into_inner(),
                &m.track_namespace,
                &m.track_name,
                m.track_alias.into_inner(),
                m.group_order as u64,
                m.content_exists as u64,
                m.largest_location.as_ref().map(|l| (l.group.into_inner(), l.object.into_inner())),
                m.forward as u64,
                m.parameters.len(),
            )),
            _ => None,
        }
    };
}

/// See [`helper_publish`]. The gate's side.
#[macro_export]
macro_rules! expected_publish {
    (present, $id:expr) => {
        publish_request(
            $id,
            &namespace(),
            TRACK,
            ALIAS,
            ASCENDING,
            HAS_LARGEST_LOCATION,
            Some((LARGEST_GROUP, LARGEST_OBJECT_ID)),
            FORWARDING,
            1,
        )
    };
}

/// The SETUP parameters the client and the peer send.
#[macro_export]
macro_rules! setup_parameters_for {
    (with_role) => {{
        let mut params = vec![role()];
        params.extend(setup_parameters());
        params
    }};
    (plain) => {
        setup_parameters()
    };
}

/// The client's own configuration, which gained a chosen draft at draft-14.
#[macro_export]
macro_rules! client_config_for {
    (no_draft, $version:expr, $setup:tt) => {
        ClientConfig {
            additional_versions: Vec::new(),
            transport: TransportType::Quic,
            skip_cert_verification: true,
            ca_certs: Vec::new(),
            setup_parameters: setup_parameters_for!($setup),
        }
    };
    (with_draft, $version:expr, $setup:tt) => {
        ClientConfig {
            draft: $version,
            additional_versions: Vec::new(),
            transport: TransportType::Quic,
            skip_cert_verification: true,
            ca_certs: Vec::new(),
            setup_parameters: setup_parameters_for!($setup),
        }
    };
}

/// One draft's gates.
macro_rules! request_helper_gates {
    (
        $draft:ident,
        $variant:ident,
        $version:expr,
        $feature:literal,
        $label:literal,
        $subscribe:tt,
        $fetch:tt,
        $namespace:tt,
        $announce:tt,
        $status:tt,
        $publish:tt,
        $joining:tt,
        $setup:tt,
        $config:tt,
        $count:expr
    ) => {
        #[cfg(feature = $feature)]
        mod $draft {
            use super::*;

            use moqtap_client::$draft::connection::{ClientConfig, Connection, TransportType};
            #[allow(unused_imports)]
            use moqtap_codec::types::*;
            #[allow(unused_imports)]
            use moqtap_codec::$draft::message::*;

            fn encode(msg: ControlMessage) -> Vec<u8> {
                let mut out = Vec::new();
                AnyControlMessage::$variant(msg).encode(&mut out).expect("encode");
                out
            }

            /// Render a request the client wrote.
            ///
            /// A message that is not one of this draft's requests reaches here
            /// only if a helper wrote something else entirely, and is rendered
            /// by its own Debug so that it is visible rather than silently
            /// unlike everything the gate expected.
            fn describe(msg: &AnyControlMessage) -> String {
                let msg = match msg {
                    AnyControlMessage::$variant(msg) => msg,
                    // A build enabling one draft leaves this catch-all nothing
                    // to match.
                    #[allow(unreachable_patterns)]
                    other => return format!("a message of another draft: {other:?}"),
                };
                let subscription = match msg {
                    ControlMessage::Subscribe(m) => {
                        Some(crate::subscribe_request(&crate::describe_subscribe!($subscribe, m)))
                    }
                    _ => None,
                };
                let fetch = match msg {
                    ControlMessage::Fetch(m) => crate::describe_fetch!($fetch, m),
                    _ => None,
                };
                subscription
                    .or(fetch)
                    .or_else(|| crate::describe_namespace_subscription!($namespace, msg))
                    .or_else(|| crate::describe_announcement!($announce, msg))
                    .or_else(|| crate::describe_track_status!($status, msg))
                    .or_else(|| crate::describe_publish!($publish, msg))
                    .unwrap_or_else(|| format!("a message that is not a request: {msg:?}"))
            }

            /// Complete the setup, then read and render every request.
            ///
            /// `$count` is the peer's own: every request on these drafts goes
            /// out on the one control stream, so there is one number and no
            /// second loop. Counted rather than drained on a timer so that a
            /// helper which wrote nothing fails by running out of patience
            /// with a message, rather than by the gate quietly comparing a
            /// short list.
            async fn reading_peer(server: quinn::Endpoint) -> Vec<String> {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
                let mut control = crate::common::frame_uni_recv(recv, $version);
                control.read_control(false).await.expect("read CLIENT_SETUP");
                send.write_all(&encode(ControlMessage::ServerSetup(ServerSetup {
                    selected_version: $version.version_varint(),
                    parameters: crate::setup_parameters_for!($setup),
                })))
                .await
                .expect("write SERVER_SETUP");

                let mut seen = Vec::new();
                for n in 0..$count {
                    let (msg, _) = tokio::time::timeout(PATIENCE, control.read_control(false))
                        .await
                        .unwrap_or_else(|_| {
                            panic!(
                                "{}: request {} never reached the control stream; {} did",
                                $label,
                                n + 1,
                                seen.len()
                            )
                        })
                        .expect("read a request off the control stream");
                    seen.push(describe(&msg));
                }
                seen
            }

            /// The numbers the renderings carry are the ones this draft
            /// assigns.
            ///
            /// Every other field in a rendering is a claim about one side
            /// checked against the other: the peer fills it in from the
            /// message it decoded and a gate from what it asked for. The
            /// message type is not — both sides read it from the constants
            /// above, so a wrong one would agree with itself and print a
            /// number no draft uses in every failure message this file can
            /// produce. The codec's registry is where these numbers are read
            /// against the draft, so it is what they are held to.
            ///
            /// # What it catches
            ///
            /// A digit wrong in one of them:
            ///
            /// ```text
            /// assertion `left == right` failed: FETCH
            ///   left: 22
            ///  right: 23
            /// ```
            #[test]
            fn the_numbers_the_renderings_carry_are_this_drafts() {
                assert_eq!(MessageType::Subscribe.id(), SUBSCRIBE_TYPE, "SUBSCRIBE");
                assert_eq!(MessageType::Fetch.id(), FETCH_TYPE, "FETCH");
                crate::assert_namespace_type!($namespace);
                crate::assert_announcement_type!($announce);
                crate::assert_status_type!($status);
                crate::assert_publish_type!($publish);
                crate::assert_fetch_types!($fetch);
                crate::assert_joining_types!($joining);
            }

            /// Every request helper writes the request it was told to write.
            ///
            /// Each helper is asked for something no other one of them would
            /// produce, and all of them are compared at once so a failure
            /// names every helper that got it wrong rather than only the
            /// first. The Request IDs come from the helpers' own return
            /// values, so the gate stays right if the endpoint changes how it
            /// allocates — and a helper that allocated the wrong id still
            /// fails, because the id the peer read is the one on the wire. The
            /// three helpers drafts 07 through 10 give no id to return nothing
            /// instead, and their renderings carry no id to check.
            ///
            /// # What it catches
            ///
            /// Nine cuts, run on these drafts and reverted. A failure prints
            /// both lists whole — six to nine requests each — so only the
            /// element that differs is reproduced here, and the assertion line
            /// above it is verbatim.
            ///
            /// Draft-14's `absolute_joining_fetch` left calling the endpoint's
            /// *relative* builder, which is the cut this pair of files was
            /// opened for:
            ///
            /// ```text
            /// assertion `left == right` failed: draft-14: every helper must write the request it was told to
            ///   left: … "FETCH 0x16 request id=8 fetch type=2 priority=128 order=1 joining request id=0 joining start=9 parameters=1" …
            ///  right: … "FETCH 0x16 request id=8 fetch type=3 priority=128 order=1 joining request id=0 joining start=9 parameters=1" …
            /// ```
            ///
            /// Draft-13's `track_status` handing the endpoint an empty list
            /// instead of the caller's, which asks for the right track without
            /// the authorization it was given:
            ///
            /// ```text
            ///   left: … "TRACK_STATUS 0x0d request id=12 namespace=one-control-stream track=track-1 priority=128 order=1 forward=1 filter type=2 parameters=0" …
            ///  right: … "TRACK_STATUS 0x0d request id=12 namespace=one-control-stream track=track-1 priority=128 order=1 forward=1 filter type=2 parameters=1" …
            /// ```
            ///
            /// Draft-11's `subscribe` dropping the Subscriber Priority it was
            /// passed, which on these drafts is a field of the message and has
            /// nowhere else to be:
            ///
            /// ```text
            ///   left: … "SUBSCRIBE 0x03 request id=0 track alias=7 namespace=one-control-stream track=track-1 priority=0 order=1 forward=1 filter type=2 parameters=0" …
            ///  right: … "SUBSCRIBE 0x03 request id=0 track alias=7 namespace=one-control-stream track=track-1 priority=128 order=1 forward=1 filter type=2 parameters=0" …
            /// ```
            ///
            /// And draft-12's `publish` ignoring the Largest Location it was
            /// given, which changes the Content Exists the helper derives and
            /// takes two fields off the message with it:
            ///
            /// ```text
            ///   left: … "PUBLISH 0x1d request id=6 namespace=one-control-stream track=track-1 track alias=7 order=1 content exists=0 forward=1 parameters=1" …
            ///  right: … "PUBLISH 0x1d request id=6 namespace=one-control-stream track=track-1 track alias=7 order=1 content exists=1 largest group=5 largest object=6 forward=1 parameters=1" …
            /// ```
            ///
            /// Then three the joining-fetch helpers brought with them, one
            /// per shape. Drafts 08, 09 and 10 hand their helper two joining
            /// fields and nothing else to tell them apart, so the order they
            /// go in is the whole of what it can get wrong — draft-09's
            /// `joining_fetch` passing them the wrong way round:
            ///
            /// ```text
            ///   left: … "FETCH 0x16 request id=3 fetch type=2 priority=128 order=1 joining subscribe id=2 preceding group offset=0 parameters=0" …
            ///  right: … "FETCH 0x16 request id=3 fetch type=2 priority=128 order=1 joining subscribe id=0 preceding group offset=2 parameters=0" …
            /// ```
            ///
            /// Draft-11's `absolute_joining_fetch` handing the endpoint a
            /// Relative Fetch Type — the same defect as draft-14's cut above,
            /// on a draft that has only just been given the pair, and the one
            /// that two calls rather than one Fetch Type argument exist to put
            /// out of a caller's reach:
            ///
            /// ```text
            ///   left: … "FETCH 0x16 request id=8 fetch type=2 priority=128 order=1 joining subscribe id=0 joining start=9 parameters=0" …
            ///  right: … "FETCH 0x16 request id=8 fetch type=3 priority=128 order=1 joining subscribe id=0 joining start=9 parameters=0" …
            /// ```
            ///
            /// And draft-13's `joining_fetch` dropping the caller's parameter
            /// list, which no helper below draft-12 could get wrong because
            /// none of them takes one:
            ///
            /// ```text
            ///   left: … "FETCH 0x16 request id=6 fetch type=2 priority=128 order=1 joining request id=0 joining start=2 parameters=0" …
            ///  right: … "FETCH 0x16 request id=6 fetch type=2 priority=128 order=1 joining request id=0 joining start=2 parameters=1" …
            /// ```
            ///
            /// # Two cuts that never reach the wire
            ///
            /// Recorded because they say where this gate's reach ends rather
            /// than what it adds. Draft-07's `subscribe_range` deriving
            /// AbsoluteStart while carrying an end, and draft-09's `fetch`
            /// leaving out the track it is for, both redden — but as a call
            /// that failed, not as a comparison:
            ///
            /// ```text
            /// subscribe_range: Codec(InvalidField)
            /// ```
            ///
            /// ```text
            /// fetch: Codec(InvalidField)
            /// ```
            ///
            /// The encoder already refuses a SUBSCRIBE whose Filter Type
            /// disagrees with the fields it carries, and a FETCH with no
            /// track, so neither of those defects could ever have reached a
            /// peer. What this gate adds is every defect that is well formed:
            /// a message the codec is content to write and the peer is content
            /// to answer, asking for something the caller did not ask for.
            #[tokio::test]
            async fn every_request_helper_asks_for_what_it_was_told() {
                crate::common::init_crypto();
                let (endpoint, addr) = crate::common::spawn_server(&[$version.quic_alpn()]);
                let peer = tokio::spawn(reading_peer(endpoint));

                let mut conn = tokio::time::timeout(
                    PATIENCE,
                    Connection::connect(
                        &addr.to_string(),
                        crate::client_config_for!($config, $version, $setup),
                    ),
                )
                .await
                .expect("connect did not finish")
                .expect("connect");

                let mut expected: Vec<String> = Vec::new();

                let subscription =
                    crate::helper_subscribe!($subscribe, conn).await.expect("subscribe");
                expected.push(crate::subscribe_request(&crate::expected_subscribe!(
                    $subscribe,
                    subscription.into_inner()
                )));

                let ranged = crate::helper_subscribe_range!($subscribe, conn)
                    .await
                    .expect("subscribe_range");
                expected.push(crate::subscribe_request(&crate::expected_subscribe_range!(
                    $subscribe,
                    ranged.into_inner()
                )));

                let fetch = crate::helper_fetch!($fetch, conn).await.expect("fetch");
                expected.push(crate::standalone_fetch_request(&crate::expected_fetch!(
                    $fetch,
                    fetch.into_inner()
                )));

                crate::joining_fetches!($joining, conn, subscription, expected);

                crate::a_publish!($publish, conn, expected);

                let announced = crate::helper_namespace_subscription!($namespace, conn)
                    .await
                    .expect("the namespace subscription");
                expected.push(crate::expected_namespace_subscription!($namespace, announced));

                let announcement =
                    crate::helper_announcement!($announce, conn).await.expect("the announcement");
                expected.push(crate::expected_announcement!($announce, announcement));

                let status =
                    crate::helper_track_status!($status, conn).await.expect("the track status");
                expected.push(crate::expected_track_status!($status, status));

                let seen = tokio::time::timeout(PATIENCE, peer)
                    .await
                    .expect("the peer did not finish")
                    .expect("the peer panicked");

                assert_eq!(
                    seen, expected,
                    "{}: every helper must write the request it was told to",
                    $label
                );

                conn.close(0, b"bye");
            }
        }
    };
}

/// The joining fetches, in the three shapes these drafts give them.
///
/// `one_kind` is drafts 08, 09 and 10, which draw a single Joining Fetch at
/// Fetch Type 0x2 and name its second field a Preceding Group Offset. There is
/// one call because there is one kind, and a pair of calls copied down from
/// draft-14 would be inventing a distinction those three do not draw.
///
/// `two_kinds` is draft-11, where one joining fetch becomes two and the second
/// field becomes a Joining Start meaning an offset or a group depending on
/// which of the two it is. `parameterized` is drafts 12 and up, which is the
/// same pair with a parameter list — no request helper below draft-12 takes
/// one.
///
/// The subscription joined is the one the subscribe helper just made, so the
/// id the gate expects is the id that helper returned rather than a number
/// written down here.
#[macro_export]
macro_rules! joining_fetches {
    (absent, $conn:expr, $parent:expr, $expected:expr) => {};
    (one_kind, $conn:expr, $parent:expr, $expected:expr) => {
        let joining = $conn
            .joining_fetch(PRIORITY, GroupOrder::Ascending, $parent, v(JOINING_START))
            .await
            .expect("joining_fetch");
        $expected.push(joining_fetch_request(&JoiningFetch {
            request_id: joining.into_inner(),
            fetch_type: JOINING_FETCH,
            joined_label: JOINED_SUBSCRIBE_ID,
            joined: Some($parent.into_inner()),
            start_label: PRECEDING_GROUP_OFFSET,
            start: Some(JOINING_START),
            ..Default::default()
        }));
    };
    (two_kinds, $conn:expr, $parent:expr, $expected:expr) => {
        let relative = $conn
            .joining_fetch(PRIORITY, GroupOrder::Ascending, $parent, v(JOINING_START))
            .await
            .expect("joining_fetch");
        $expected.push(joining_fetch_request(&JoiningFetch {
            request_id: relative.into_inner(),
            fetch_type: RELATIVE_JOINING_FETCH,
            joined_label: JOINED_SUBSCRIBE_ID,
            joined: Some($parent.into_inner()),
            start: Some(JOINING_START),
            ..Default::default()
        }));

        let absolute = $conn
            .absolute_joining_fetch(
                PRIORITY,
                GroupOrder::Ascending,
                $parent,
                v(ABSOLUTE_JOINING_START),
            )
            .await
            .expect("absolute_joining_fetch");
        $expected.push(joining_fetch_request(&JoiningFetch {
            request_id: absolute.into_inner(),
            fetch_type: ABSOLUTE_JOINING_FETCH,
            joined_label: JOINED_SUBSCRIBE_ID,
            joined: Some($parent.into_inner()),
            start: Some(ABSOLUTE_JOINING_START),
            ..Default::default()
        }));
    };
    (parameterized, $conn:expr, $parent:expr, $expected:expr) => {
        let relative = $conn
            .joining_fetch(
                PRIORITY,
                GroupOrder::Ascending,
                $parent,
                v(JOINING_START),
                vec![attached()],
            )
            .await
            .expect("joining_fetch");
        $expected.push(joining_fetch_request(&JoiningFetch {
            request_id: relative.into_inner(),
            fetch_type: RELATIVE_JOINING_FETCH,
            joined: Some($parent.into_inner()),
            start: Some(JOINING_START),
            parameters: 1,
            ..Default::default()
        }));

        let absolute = $conn
            .absolute_joining_fetch(
                PRIORITY,
                GroupOrder::Ascending,
                $parent,
                v(ABSOLUTE_JOINING_START),
                vec![attached()],
            )
            .await
            .expect("absolute_joining_fetch");
        $expected.push(joining_fetch_request(&JoiningFetch {
            request_id: absolute.into_inner(),
            fetch_type: ABSOLUTE_JOINING_FETCH,
            joined: Some($parent.into_inner()),
            start: Some(ABSOLUTE_JOINING_START),
            parameters: 1,
            ..Default::default()
        }));
    };
}

/// The message-type assertions, which name the message this draft has.
#[macro_export]
macro_rules! assert_namespace_type {
    (renamed_params) => {
        assert_namespace_type!(renamed)
    };
    (renamed_field) => {
        assert_namespace_type!(renamed)
    };
    (renamed) => {
        assert_eq!(
            MessageType::SubscribeNamespace.id(),
            NAMESPACE_SUBSCRIPTION_TYPE,
            "SUBSCRIBE_NAMESPACE"
        )
    };
    ($other:tt) => {
        assert_eq!(
            MessageType::SubscribeAnnounces.id(),
            NAMESPACE_SUBSCRIPTION_TYPE,
            "SUBSCRIBE_ANNOUNCES"
        )
    };
}

/// See [`assert_namespace_type`].
#[macro_export]
macro_rules! assert_announcement_type {
    (renamed) => {
        assert_eq!(MessageType::PublishNamespace.id(), ANNOUNCEMENT_TYPE, "PUBLISH_NAMESPACE")
    };
    ($other:tt) => {
        assert_eq!(MessageType::Announce.id(), ANNOUNCEMENT_TYPE, "ANNOUNCE")
    };
}

/// See [`assert_namespace_type`].
#[macro_export]
macro_rules! assert_status_type {
    (subscribe_like_split) => {
        assert_status_type!(renamed)
    };
    (subscribe_like_location) => {
        assert_status_type!(renamed)
    };
    (renamed) => {
        assert_eq!(MessageType::TrackStatus.id(), TRACK_STATUS_REQUEST_TYPE, "TRACK_STATUS")
    };
    ($other:tt) => {
        assert_eq!(
            MessageType::TrackStatusRequest.id(),
            TRACK_STATUS_REQUEST_TYPE,
            "TRACK_STATUS_REQUEST"
        )
    };
}

/// See [`assert_namespace_type`].
#[macro_export]
macro_rules! assert_publish_type {
    (absent) => {};
    (present) => {
        assert_eq!(MessageType::Publish.id(), PUBLISH_TYPE, "PUBLISH")
    };
}

/// See [`assert_namespace_type`]. Draft-07's FETCH has no Fetch Type field, so
/// there is no enum on that draft to hold the number to.
#[macro_export]
macro_rules! assert_fetch_types {
    (untyped) => {};
    ($other:tt) => {
        assert_eq!(FetchType::Standalone as u64, STANDALONE_FETCH, "a standalone FETCH")
    };
}

/// See [`assert_namespace_type`].
#[macro_export]
macro_rules! assert_joining_types {
    (absent) => {};
    (one_kind) => {
        assert_eq!(FetchType::Joining as u64, JOINING_FETCH, "a Joining Fetch")
    };
    (parameterized) => {
        assert_joining_types!(two_kinds)
    };
    (two_kinds) => {
        assert_eq!(
            FetchType::RelativeJoining as u64,
            RELATIVE_JOINING_FETCH,
            "a Relative Joining Fetch"
        );
        assert_eq!(
            FetchType::AbsoluteJoining as u64,
            ABSOLUTE_JOINING_FETCH,
            "an Absolute Joining Fetch"
        );
    };
}

request_helper_gates!(
    draft07,
    Draft07,
    DraftVersion::Draft07,
    "draft07",
    "draft-07",
    alias_location_end_object,
    untyped,
    anonymous,
    anonymous,
    anonymous,
    absent,
    absent,
    with_role,
    no_draft,
    6
);
request_helper_gates!(
    draft08,
    Draft08,
    DraftVersion::Draft08,
    "draft08",
    "draft-08",
    alias_location,
    typed_flat,
    anonymous,
    anonymous,
    anonymous,
    absent,
    one_kind,
    plain,
    no_draft,
    7
);
request_helper_gates!(
    draft09,
    Draft09,
    DraftVersion::Draft09,
    "draft09",
    "draft-09",
    alias_location,
    typed_flat,
    anonymous,
    anonymous,
    anonymous,
    absent,
    one_kind,
    plain,
    no_draft,
    7
);
request_helper_gates!(
    draft10,
    Draft10,
    DraftVersion::Draft10,
    "draft10",
    "draft-10",
    alias_location,
    typed_flat,
    anonymous,
    anonymous,
    anonymous,
    absent,
    one_kind,
    plain,
    no_draft,
    7
);
request_helper_gates!(
    draft11,
    Draft11,
    DraftVersion::Draft11,
    "draft11",
    "draft-11",
    alias_split_varint,
    typed_payload,
    identified,
    identified,
    identified,
    absent,
    two_kinds,
    plain,
    no_draft,
    8
);
request_helper_gates!(
    draft12,
    Draft12,
    DraftVersion::Draft12,
    "draft12",
    "draft-12",
    split_varint,
    typed_params,
    identified_params,
    identified_params,
    identified_params,
    present,
    parameterized,
    plain,
    no_draft,
    9
);
request_helper_gates!(
    draft13,
    Draft13,
    DraftVersion::Draft13,
    "draft13",
    "draft-13",
    split_typed,
    typed_params,
    renamed_params,
    identified_params,
    subscribe_like_split,
    present,
    parameterized,
    plain,
    no_draft,
    9
);
request_helper_gates!(
    draft14,
    Draft14,
    DraftVersion::Draft14,
    "draft14",
    "draft-14",
    location_typed,
    typed_params,
    renamed_field,
    renamed,
    subscribe_like_location,
    present,
    parameterized,
    plain,
    with_draft,
    9
);
