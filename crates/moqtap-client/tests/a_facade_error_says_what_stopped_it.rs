#![cfg(all(feature = "draft07", feature = "draft14", feature = "draft16", feature = "draft20"))]

//! What `AnyConnectionError` answers that its message could not.
//!
//! The facade exists so that a caller holding a MoQT connection never has to
//! branch on which of fourteen drafts was negotiated. It buys that by
//! rendering every draft's `ConnectionError` through `Display`, and the price
//! of prose alone is the variant, which is the half most callers actually
//! need. Three questions a sentence cannot answer:
//!
//! - **Did the peer reset this stream, or finish it?** Section 2.2 of every
//!   draft from 08 forbids one Subgroup's Objects on different streams "unless
//!   one of the streams was reset prematurely". A caller that cannot see a
//!   reset cannot apply that sentence in either direction.
//! - **Which rule stopped a decode, and does *this* draft answer it with a
//!   session close?** A decoder refusing a frame is sometimes this build
//!   failing to keep up and sometimes this build doing exactly what the draft
//!   requires, and only the second is a finding about the peer.
//! - **Was the failure on this side at all?**
//!
//! [`ErrorCause`] is the answer to all three, and the tests below are one per
//! question plus the two that keep it honest: that the message is unchanged,
//! and that a draft's own reading of its own text is what fills in `close`.
//!
//! # And the fourth question, which only some drafts can be asked
//!
//! Six of the fourteen add `ConnectionError` variants of their own, for rules
//! stated about frames that read perfectly well — properties on an Object whose
//! status forbids them, a bidirectional stream opened with a message type the
//! draft does not permit, a request stream finished before the response it owes.
//! A decoder sees none of them, so none of them reaches [`ErrorCause::Codec`].
//!
//! They divide two ways and the two are opposite findings: some are this
//! endpoint declining to write something, and some are a peer having broken a
//! rule. Rendered as prose they read exactly alike. `Connection::draft_specific_cause`
//! is each draft's own reading of its own variants, and it lands them on
//! [`ErrorCause::Facade`] and [`ErrorCause::PeerViolation`] respectively.
//!
//! # And the fifth, which every draft can be asked
//!
//! One variant every draft shares — `Endpoint` — wraps a whole error type of its
//! own, twenty-six to forty-one variants deep, holding the same two findings
//! under one name. Flatten it to [`ErrorCause::Endpoint`], which `is_local`
//! counts as **this** side's, and a relay sending a second GOAWAY or reusing a
//! Request ID is filed against this build's state machine, with the code its
//! draft names for the rule dropped on the way past.
//!
//! `EndpointError::fault` divides it by the same rule the connection's own
//! variants take: raised while *reading* what the peer sent, or raised while
//! *writing*. A handful are raised on both and say so rather than picking, and
//! those land on [`ErrorCause::Endpoint`] alongside this side's own.
//!
//! # Why the drafts here are these four
//!
//! Draft-07 and draft-20 are the ends of the range, draft-14 and draft-16 are
//! where two of the rules below change hands. Every assertion about `close`
//! needs at least two drafts to be worth making — a single draft cannot
//! distinguish "the table was consulted" from "the table returns a constant".
//!
//! # Ablation, measured
//!
//! Replacing the `close` computation with `None` — the shape a refactor that
//! lost the per-draft table would produce:
//!
//! ```text
//! a_decode_stopped_by_a_rule_the_draft_closes_on_says_so
//!   draft-14 answers an N-of-0 namespace tuple with a close
//!
//! the_same_decode_failure_is_read_against_each_drafts_own_text
//!   draft-07 states no close for a namespace tuple of 0; draft-14 does
//! ```
//!
//! Replacing `ErrorCause::StreamReset(code)` with `ErrorCause::StreamEnded`
//! reddens `a_stream_the_peer_reset_is_told_from_one_that_ended` alone, which
//! is the finding that was blocked on this distinction. Replacing
//! `ErrorCause::Facade` with `ErrorCause::Unclassified` reddens
//! `a_call_this_facade_refused_is_not_the_peers_doing` alone. Each cut was
//! restored byte for byte afterwards.
//!
//! For the above-codec half, three more cuts, each reddening only its own gate:
//!
//! ```text
//! draft-20's PropertiesOnNonNormalStatus arm answers LocalRefusal
//!   a_rule_the_decoder_could_not_see_is_still_the_peers_doing
//!   the_two_names_one_rule_has_are_one_rule_here
//!
//! draft-19's answers `close: None`
//!   draft19_properties_on_non_normal_status::the_refusal_closes_the_quic_connection
//!
//! DataStreamState classified as Unclassified rather than Facade
//!   an_out_of_order_call_on_a_data_stream_is_this_sides_mistake
//! ```
//!
//! The second is the one worth reading twice. It reddens a gate in another
//! file, one that asserts nothing about this classification, because
//! `close_for_data_stream` takes the code it sends from the same table this
//! file reads — so a draft's answer to its own sentence is written down once,
//! and the value a caller reads is the value the peer was sent.
//!
//! For the endpoint's half, two more:
//!
//! ```text
//! `EndpointError::fault` ignored and the whole type flattened to Endpoint
//!   a_rule_the_endpoint_caught_reading_is_the_peers_doing
//!   the_two_ends_of_one_alias_rule_are_told_apart
//!   a_ceiling_this_endpoint_would_not_lower_is_not_the_peer_lowering_one
//!   (and four in the probe that consumes this)
//!
//! draft-14's MaxRequestIdWouldNotIncrease answers Peer
//! rather than this endpoint
//!   a_ceiling_this_endpoint_would_not_lower_is_not_the_peer_lowering_one
//! ```
//!
//! The second is that counterexample run backwards.
//! Nothing in the *probe* reddens under it, because that side gates on
//! `close: Some` and `session_error_code` answers `None` for the send-side
//! variant — so the accusation would have stopped one layer further out. What
//! would have been wrong is `is_local`, which is a different consumer with no
//! second gate behind it.
//!
//! And one more, for the dial:
//!
//! ```text
//! draft-20's From<DialError> routes LocalSocket to Transport(Connect)
//! rather than folding it onto InvalidAddress
//!   a_socket_this_machine_would_not_open_is_not_the_relays_doing
//! ```
//!
//! That is the cut worth having, because `Transport(Connect)` is the *reading*
//! spelling — a socket failure genuinely is a connect failure in prose — and it
//! is the one that puts `ErrorCause::Transport` on it, so `is_local` answers
//! false and this machine's missing IPv6 stack is published as the relay's. One
//! test reddens and nothing else does, which is also the measurement that the
//! fold is doing work.

use moqtap_client::above_codec_rules::AboveCodecRule;
use moqtap_client::dispatch::{AnyConnectionError, ErrorCause};
use moqtap_client::transport::TransportError;
use moqtap_codec::error::CodecError;

/// The distinction a finding about an abandoned stream depends on.
///
/// A subgroup has no terminator message on any draft — the stream ending *is*
/// the end of it — so every reader's last read fails, and the failure alone
/// does not say whether the peer abandoned the stream or simply had nothing
/// more to send. The cause is what tells the two apart.
#[test]
fn a_stream_the_peer_reset_is_told_from_one_that_ended() {
    use moqtap_client::draft20::connection::ConnectionError;

    let reset =
        AnyConnectionError::from(ConnectionError::Transport(TransportError::StreamReset(4)));
    assert_eq!(reset.cause(), &ErrorCause::StreamReset(4), "the peer's own code, kept");
    assert!(!reset.is_local(), "a reset is the peer's doing");

    let ended = AnyConnectionError::from(ConnectionError::UnexpectedEnd);
    assert_eq!(ended.cause(), &ErrorCause::StreamEnded);

    let finished = AnyConnectionError::from(ConnectionError::StreamFinished);
    assert_eq!(finished.cause(), &ErrorCause::StreamEnded);

    assert_ne!(reset.cause(), ended.cause(), "the whole point of the pair");
}

/// A session close carries the sharpest thing a refusal says, and it is a
/// different event from one stream ending.
#[test]
fn a_session_the_peer_closed_names_its_code() {
    use moqtap_client::draft16::connection::ConnectionError;

    let closed =
        AnyConnectionError::from(ConnectionError::Transport(TransportError::SessionClosed {
            code: 0x3,
            reason: "PROTOCOL_VIOLATION".to_string(),
        }));
    assert_eq!(closed.cause(), &ErrorCause::SessionClosed(0x3));
    assert!(!closed.is_local());

    let stopped =
        AnyConnectionError::from(ConnectionError::Transport(TransportError::Stopped(0x10)));
    assert_eq!(stopped.cause(), &ErrorCause::Stopped(0x10));
}

/// A decode that stopped, with the draft's own answer to it beside it.
///
/// `close` is what separates a relay's defect from this build's shortfall: a
/// decoder stopping is not by itself a finding about the peer, and a decoder
/// stopping on a rule the draft answers with "MUST close the session" is.
#[test]
fn a_decode_stopped_by_a_rule_the_draft_closes_on_says_so() {
    use moqtap_client::draft14::connection::ConnectionError;

    // Draft-14 Section 2.4.1: "If an endpoint receives a Track Namespace tuple
    // with an N of 0 or more than 32, it MUST close the session with a Protocol
    // Violation." 0x3 is PROTOCOL_VIOLATION on every draft that names one.
    let refused =
        AnyConnectionError::from(ConnectionError::Codec(CodecError::InvalidNamespaceTupleSize(0)));
    assert_eq!(
        refused.cause(),
        &ErrorCause::Codec { error: CodecError::InvalidNamespaceTupleSize(0), close: Some(0x3) }
    );

    // And one the draft states nothing about. `InvalidField` is shared by a
    // dozen unrelated malformations, only some of which any draft answers with
    // a close, so no draft claims it.
    let unattributed = AnyConnectionError::from(ConnectionError::Codec(CodecError::InvalidField));
    assert_eq!(
        unattributed.cause(),
        &ErrorCause::Codec { error: CodecError::InvalidField, close: None }
    );

    // Both are this build declining to read something, whatever the draft says
    // about them.
    assert!(refused.is_local() && unattributed.is_local());
}

/// The same decode failure, read against each draft's own text.
///
/// This is what makes `close` worth carrying rather than deriving: the answer
/// is not a property of the error, and three of these four pairs move in a
/// different place.
#[test]
fn the_same_decode_failure_is_read_against_each_drafts_own_text() {
    fn close_on_07(err: CodecError) -> Option<u64> {
        let e = moqtap_client::draft07::connection::ConnectionError::Codec(err);
        match AnyConnectionError::from(e).cause() {
            ErrorCause::Codec { close, .. } => *close,
            other => panic!("a codec error classified as {other:?}"),
        }
    }
    fn close_on_14(err: CodecError) -> Option<u64> {
        let e = moqtap_client::draft14::connection::ConnectionError::Codec(err);
        match AnyConnectionError::from(e).cause() {
            ErrorCause::Codec { close, .. } => *close,
            other => panic!("a codec error classified as {other:?}"),
        }
    }
    fn close_on_16(err: CodecError) -> Option<u64> {
        let e = moqtap_client::draft16::connection::ConnectionError::Codec(err);
        match AnyConnectionError::from(e).cause() {
            ErrorCause::Codec { close, .. } => *close,
            other => panic!("a codec error classified as {other:?}"),
        }
    }
    fn close_on_20(err: CodecError) -> Option<u64> {
        let e = moqtap_client::draft20::connection::ConnectionError::Codec(err);
        match AnyConnectionError::from(e).cause() {
            ErrorCause::Codec { close, .. } => *close,
            other => panic!("a codec error classified as {other:?}"),
        }
    }

    // Draft-07 Section 2.4.1 says only "N can be between 1 and 32" and states
    // no consequence; the "MUST close the session with a Protocol Violation"
    // sentence arrives in draft-08 and stays.
    let tuple = CodecError::InvalidNamespaceTupleSize(0);
    assert_eq!(close_on_07(tuple.clone()), None, "draft-07 states no close for this");
    assert_eq!(close_on_14(tuple.clone()), Some(0x3));
    assert_eq!(close_on_20(tuple), Some(0x3));

    // The Track Namespace *Field* rule is the other way round: it needs the
    // length-prefixed field encoding, which arrives at draft-16.
    let empty = CodecError::EmptyNamespaceField;
    assert_eq!(close_on_14(empty.clone()), None, "draft-14 has no such field to empty");
    assert_eq!(close_on_16(empty.clone()), Some(0x3));
    assert_eq!(close_on_20(empty), Some(0x3));

    // A Content Exists field that is neither 0 nor 1, which drafts 08 through
    // 14 answer with a close. Draft-15 deleted the field.
    let content = CodecError::InvalidContentExists(2);
    assert_eq!(close_on_07(content.clone()), Some(0x3));
    assert_eq!(close_on_14(content.clone()), Some(0x3));
    assert_eq!(close_on_16(content), None, "draft-15 took the field away");

    // And a code that is not PROTOCOL_VIOLATION at all: drafts 07 through 10
    // give the Parameter Length Mismatch rule its own session error code, and
    // the Key-Value Pair encoding that replaces their parameter framing at
    // draft-11 takes the rule with it.
    let length = CodecError::ParameterLengthMismatch(9);
    assert_eq!(close_on_07(length.clone()), Some(0x5), "PARAMETER_LENGTH_MISMATCH");
    assert_eq!(close_on_14(length), None);
}

/// A message that did not fit the session's state is this side's, and it is not
/// a decode failure.
///
/// Both of these are raised on the way out and nothing reached the wire: a
/// filter handed to the call that has nowhere to put its range, and an alias
/// this endpoint was asked to give to a second track while the first still
/// holds it.
#[test]
fn a_message_the_state_machine_refused_is_not_a_decode_failure() {
    use moqtap_client::draft14::connection::ConnectionError;
    use moqtap_client::draft14::endpoint::EndpointError;

    for err in
        [EndpointError::FilterNeedsRange, EndpointError::TrackAliasInUse { alias: 9, held: 2 }]
    {
        let words = err.to_string();
        let refused = AnyConnectionError::from(ConnectionError::Endpoint(err));
        assert_eq!(refused.cause(), &ErrorCause::Endpoint, "{words}");
        assert!(refused.is_local(), "this endpoint's own state machine said no: {words}");
    }
}

/// A rule the *endpoint* caught reading is the peer's doing, not this build's.
///
/// Every draft's `EndpointError` mixes two opposite findings under one name, so
/// the variant alone cannot settle [`AnyConnectionError::is_local`]. Flatten the
/// whole type to [`ErrorCause::Endpoint`] — which `is_local` counts as this
/// side's — and a relay sending a second GOAWAY, or opening a bidirectional
/// stream with a message that does not open one, is published as this build's
/// own state machine having gone wrong, with the code the draft names for it
/// thrown away on the way past. `EndpointError::fault` is what divides the two.
#[test]
fn a_rule_the_endpoint_caught_reading_is_the_peers_doing() {
    use moqtap_client::above_codec_rules::AboveCodecRule as Rule;

    // Draft-20 Section 10.4: "If a server receives a GOAWAY with a non-zero New
    // Session URI Length it MUST close the session with a PROTOCOL_VIOLATION."
    // Draft-14 Section 9.4 states it in the same words, so both answer the same
    // rule with the same code — which is the claim a single draft cannot make.
    for cause in [
        AnyConnectionError::from(moqtap_client::draft14::connection::ConnectionError::Endpoint(
            moqtap_client::draft14::endpoint::EndpointError::GoAwayUriAtServer,
        )),
        AnyConnectionError::from(moqtap_client::draft20::connection::ConnectionError::Endpoint(
            moqtap_client::draft20::endpoint::EndpointError::GoAwayUriAtServer,
        )),
    ] {
        assert_eq!(
            cause.cause(),
            &ErrorCause::PeerViolation { rule: Rule::GoAwayAtServer, close: Some(0x3) }
        );
        assert!(!cause.is_local(), "the peer sent it; this side only refused it");
    }

    // Section 3.3 of draft-20: "Bidirectional streams MUST NOT begin with any
    // other message type unless negotiated. If they do, the peer MUST close the
    // Session with a PROTOCOL_VIOLATION." The connection raises this where it
    // owns the stream and the endpoint where it does not; one rule, so one name.
    let opener =
        AnyConnectionError::from(moqtap_client::draft20::connection::ConnectionError::Endpoint(
            moqtap_client::draft20::endpoint::EndpointError::NotARequest(
                moqtap_codec::draft20::message::MessageType::GoAway,
            ),
        ));
    assert_eq!(
        opener.cause(),
        &ErrorCause::PeerViolation { rule: Rule::BidiStreamOpener, close: Some(0x3) }
    );

    // And one the draft states with no consequence: a fill fetch stream opened
    // against a subscription that asked for no fill. Section 5.1.3 gives the
    // subscriber `STOP_SENDING` on that stream and names no session error, so
    // `close` is `None` and a report gating on it will never publish this —
    // exactly the contract `ErrorCause::Codec` already had.
    let unasked =
        AnyConnectionError::from(moqtap_client::draft20::connection::ConnectionError::Endpoint(
            moqtap_client::draft20::endpoint::EndpointError::UnrequestedFillStream(4),
        ));
    assert_eq!(
        unasked.cause(),
        &ErrorCause::PeerViolation { rule: Rule::UnrequestedFillStream, close: None }
    );
    assert!(!unasked.is_local(), "no consequence is not the same as no fault");
}

/// One rule, two ends, and the pair is why the variant is the wrong key on its
/// own.
///
/// Section 11.1 forbids one Track Alias naming two tracks, and every draft
/// states it twice — once as what a subscriber does on receiving one, once as
/// what a publisher may not send. This endpoint raises a different variant for
/// each, and until this classification existed both reached a caller as
/// `endpoint error: track alias …` and answered `is_local` true.
#[test]
fn the_two_ends_of_one_alias_rule_are_told_apart() {
    use moqtap_client::above_codec_rules::AboveCodecRule as Rule;
    use moqtap_client::draft20::connection::ConnectionError;
    use moqtap_client::draft20::endpoint::EndpointError;

    let peers =
        AnyConnectionError::from(ConnectionError::Endpoint(EndpointError::DuplicateTrackAlias {
            alias: 9,
            established: 2,
            offered: 6,
        }));
    assert_eq!(
        peers.cause(),
        // DUPLICATE_TRACK_ALIAS, not PROTOCOL_VIOLATION: Section 11.1 names this
        // code in the sentence that states the rule and names no other. A close
        // carrying 0x3 would tell the peer a different thing went wrong, which
        // is why the code travels beside the rule rather than being assumed
        // from it.
        &ErrorCause::PeerViolation { rule: Rule::DuplicateTrackAlias, close: Some(0x5) }
    );
    assert!(!peers.is_local());

    let ours =
        AnyConnectionError::from(ConnectionError::Endpoint(EndpointError::TrackAliasInUse {
            alias: 9,
            held: 2,
        }));
    assert_eq!(ours.cause(), &ErrorCause::Endpoint);
    assert!(ours.is_local(), "the alias never reached the peer");

    assert_ne!(peers.cause(), ours.cause(), "the whole point of the pair");
}

/// The counterexample to "a code means the peer", found by looking for one.
///
/// It is tempting to read `EndpointError::session_error_code` as the whole
/// answer: a variant the draft answers with a session close is one a peer broke
/// a rule to reach. Drafts 07 through 16 each hold one place where that reading
/// goes wrong, and they are the only drafts that can: they carry the
/// request-ceiling message — MAX_SUBSCRIBE_ID on drafts 07 through 10,
/// MAX_REQUEST_ID once draft-11 renames it — which draft-17 deletes, so they
/// are the only ones with a send side to get wrong. The send call refusing to
/// advertise a ceiling that does not increase therefore raises a variant of its
/// own — `send_max_subscribe_id` raising `MaxSubscribeIdWouldNotIncrease` on 07
/// through 10, `send_max_request_id` raising `MaxRequestIdWouldNotIncrease` from
/// draft-11 — rather than the one a peer's decreasing ceiling raises; that one
/// answers `Some(PROTOCOL_VIOLATION)`, so sharing it would publish a local
/// refusal to write a message as a relay breaking draft-14's Section 9.5.
///
/// This is the test that holds the two apart.
#[test]
fn a_ceiling_this_endpoint_would_not_lower_is_not_the_peer_lowering_one() {
    use moqtap_client::above_codec_rules::AboveCodecRule as Rule;
    use moqtap_client::draft14::connection::ConnectionError;
    use moqtap_client::draft14::endpoint::EndpointError;
    use moqtap_client::draft14::session::request_id::RequestIdError;

    // Section 9.5: "The Maximum Request ID MUST only increase within a session,
    // and receipt of a MAX_REQUEST_ID message with an equal or smaller Request
    // ID value is a 'Protocol Violation'." Received, so the peer's.
    let peers = AnyConnectionError::from(ConnectionError::Endpoint(EndpointError::RequestId(
        RequestIdError::Decreased(8, 4),
    )));
    assert_eq!(
        peers.cause(),
        &ErrorCause::PeerViolation { rule: Rule::MaxRequestIdDecreased, close: Some(0x3) }
    );
    assert!(!peers.is_local());

    // The same sentence, read at the end that would have broken it. Nothing was
    // written, the ceiling stayed where it was, and there is nothing to say
    // about the relay.
    let ours = AnyConnectionError::from(ConnectionError::Endpoint(
        EndpointError::MaxRequestIdWouldNotIncrease { advertised: 8, offered: 4 },
    ));
    assert_eq!(ours.cause(), &ErrorCause::Endpoint);
    assert!(ours.is_local());
}

/// What cannot be told apart says so, rather than picking a side.
///
/// Two kinds of variant are raised on both a receive path and a send path, and
/// the variant alone cannot say which: the state machines, which render as
/// *invalid transition from X on event Y* whichever end asked for the
/// transition, and the unknown-request errors, whose sixty-odd call sites per
/// draft are about half responses naming an id this session never issued and
/// about half a caller naming one of its own.
///
/// They answer [`ErrorCause::Endpoint`] — the safe direction, and the one this
/// facade takes. That is a separate answer from the ones the facade does tell
/// apart, so which variants are still undecided is a list the compiler can
/// produce rather than a thing to remember.
#[test]
fn a_variant_raised_on_both_paths_says_so_rather_than_guessing() {
    use moqtap_client::above_codec_rules::EndpointFault;
    use moqtap_client::draft20::connection::ConnectionError;
    use moqtap_client::draft20::endpoint::EndpointError;

    let unknown = EndpointError::UnknownRequest(4);
    assert_eq!(unknown.fault(), EndpointFault::EitherEnd);
    assert_eq!(unknown.fault().rule(), None, "an undecided fault names no rule");

    // Told apart, and on this side.
    assert_eq!(
        EndpointError::NotAResponse(moqtap_codec::draft20::message::MessageType::GoAway,).fault(),
        EndpointFault::ThisEndpoint
    );

    // Both reach the same cause, which is the safe direction for the first.
    for err in [EndpointError::UnknownRequest(4), EndpointError::NotActive] {
        let flat = AnyConnectionError::from(ConnectionError::Endpoint(err));
        assert_eq!(flat.cause(), &ErrorCause::Endpoint);
        assert!(flat.is_local());
    }
}

/// A call this facade refused before writing anything is not a relay hanging
/// up, and a caller must not read it as one.
///
/// Classifying by message prefix cannot tell the two apart: a check that
/// recognised `codec error` and `endpoint error` would find neither on a facade
/// refusal and file every one of them as the peer's doing.
#[test]
fn a_call_this_facade_refused_is_not_the_peers_doing() {
    let refused = AnyConnectionError::facade("draft-07's FETCH has no Joining Fetch");
    assert_eq!(refused.cause(), &ErrorCause::Facade);
    assert!(refused.is_local());
    assert_eq!(refused.message(), "draft-07's FETCH has no Joining Fetch");

    // And the prefix check finds nothing to match, which is the paragraph above
    // stated as an assertion.
    assert!(
        !refused.message().starts_with("codec error")
            && !refused.message().starts_with("endpoint error"),
        "if this ever gained a prefix the test above would stop being the point"
    );
}

/// A dial that never sent a packet is not a relay refusing one.
///
/// `DialError` grew a `LocalSocket` variant so that a socket this machine would
/// not open stops being spelled as an invalid address, and the fourteen
/// `From<DialError>` impls fold it back onto `ConnectionError::InvalidAddress`
/// on the way here **on purpose**: that is the variant this facade reads as
/// [`ErrorCause::Facade`], and `is_local` therefore answers true. Routing the
/// new variant to `Transport` instead would read better in prose and would
/// publish a host with no IPv6 stack as a relay that failed a handshake.
///
/// Two drafts because one cannot distinguish a table from a constant, and these
/// two because they are the ends of the range — the fourteen impls are
/// generated from one text and drift as a set or not at all.
#[test]
fn a_socket_this_machine_would_not_open_is_not_the_relays_doing() {
    use moqtap_client::transport::{DialError, DialPhase};

    let bind = || DialError::LocalSocket("could not bind a local IPv6 socket: oh no".to_string());
    assert_eq!(bind().phase(), DialPhase::LocalSocket, "the dial says which stage died");
    assert!(bind().is_local(), "nothing left this machine");

    let oldest =
        AnyConnectionError::from(moqtap_client::draft07::connection::ConnectionError::from(bind()));
    assert_eq!(oldest.cause(), &ErrorCause::Facade);
    assert!(oldest.is_local(), "a socket we could not open is ours on draft-07");

    let newest =
        AnyConnectionError::from(moqtap_client::draft20::connection::ConnectionError::from(bind()));
    assert_eq!(newest.cause(), &ErrorCause::Facade);
    assert!(newest.is_local(), "and on draft-20");

    // The message is what it always was, so nothing reading the prose lost
    // anything by the variant existing.
    assert!(
        newest.message().contains("could not bind a local IPv6 socket"),
        "{}",
        newest.message()
    );

    // And the peer's half of the same type still answers the other way, so this
    // is a distinction rather than a constant.
    let refused = AnyConnectionError::from(
        moqtap_client::draft20::connection::ConnectionError::from(DialError::Transport(
            TransportError::Handshake(moqtap_client::transport::HandshakeFailure::transport(
                0x178,
                "peer doesn't support any known protocol".to_string(),
            )),
        )),
    );
    assert!(!refused.is_local(), "a peer answered this one");
}

/// A rule no decoder could have caught is still the peer's doing.
///
/// The frame reads perfectly well: an Object with a legal properties block and a
/// legal status, forbidden only by the sentence that says the two may not appear
/// together. `CodecError` never hears about it, so a caller reading only
/// [`ErrorCause::Codec`] finds the peer blameless — and an error that arrives
/// as prose, answering `is_local` false with no rule attached, tells that
/// caller nothing about which sentence the peer broke.
#[test]
fn a_rule_the_decoder_could_not_see_is_still_the_peers_doing() {
    use moqtap_client::draft20::connection::ConnectionError;
    use moqtap_codec::draft20::types::ObjectStatus;

    // Draft-20 Section 11.2.1.2: "If an endpoint receives properties on an
    // Object with status that is not Normal, it MUST close the session with a
    // PROTOCOL_VIOLATION."
    let refused = AnyConnectionError::from(ConnectionError::PropertiesOnNonNormalStatus {
        object_id: 7,
        properties_len: 12,
        status: ObjectStatus::EndOfGroup,
    });
    assert_eq!(
        refused.cause(),
        &ErrorCause::PeerViolation {
            rule: AboveCodecRule::PropertiesOnNonNormalStatus,
            close: Some(0x3),
        }
    );
    assert!(!refused.is_local(), "the peer sent it; this side only refused to accept it");

    // And the one of the three the drafts state *without* a consequence. Section
    // 11.2.1.1 makes an empty payload a property of a conforming Object rather
    // than a "MUST close the session" case, so the datagram is refused and the
    // session left running — and a probe gating on `close` will never publish
    // it, which is the correct reading and not an omission.
    let datagram = AnyConnectionError::from(ConnectionError::PayloadOnStatusDatagram {
        object_id: 7,
        payload_len: 4,
        status: Some(ObjectStatus::EndOfTrack),
    });
    assert_eq!(
        datagram.cause(),
        &ErrorCause::PeerViolation { rule: AboveCodecRule::PayloadOnStatusDatagram, close: None }
    );
    assert!(!datagram.is_local());
}

/// Two drafts, two spellings, one rule.
///
/// Drafts 15 and 16 call the block *extension headers* and drafts 17 through 20
/// call it *properties*; draft-16 permits two openers for a bidirectional stream
/// and draft-20 permits any that begins a request stream. Both renames left the
/// requirement alone, so a caller that had to branch on draft to recognise
/// either would be branching on nothing.
#[test]
fn the_two_names_one_rule_has_are_one_rule_here() {
    fn rule(err: AnyConnectionError) -> AboveCodecRule {
        match err.cause() {
            ErrorCause::PeerViolation { rule, .. } => *rule,
            other => panic!("an above-codec violation classified as {other:?}"),
        }
    }

    let extensions = rule(AnyConnectionError::from(
        moqtap_client::draft16::connection::ConnectionError::ExtensionsOnNonNormalStatus {
            object_id: 1,
            extensions_len: 8,
            status: moqtap_codec::draft16::types::ObjectStatus::EndOfGroup,
        },
    ));
    let properties = rule(AnyConnectionError::from(
        moqtap_client::draft20::connection::ConnectionError::PropertiesOnNonNormalStatus {
            object_id: 1,
            properties_len: 8,
            status: moqtap_codec::draft20::types::ObjectStatus::EndOfGroup,
        },
    ));
    assert_eq!(extensions, properties, "the block was renamed; the rule was not");

    let namespace_only = rule(AnyConnectionError::from(
        moqtap_client::draft16::connection::ConnectionError::NonSubscribeNamespaceOnBidiStream(
            moqtap_codec::draft16::message::MessageType::GoAway,
        ),
    ));
    let any_request = rule(AnyConnectionError::from(
        moqtap_client::draft20::connection::ConnectionError::NonRequestOnRequestStream(
            moqtap_codec::draft20::message::MessageType::GoAway,
        ),
    ));
    assert_eq!(namespace_only, any_request, "the permitted set grew; the sentence did not");
    assert_eq!(any_request, AboveCodecRule::BidiStreamOpener);
}

/// Asking a data stream for something out of order is this side's mistake, on
/// every draft.
///
/// `DataStreamState` is the tenth variant every draft carries — an object asked
/// for before the header it is framed against — and being shared by all
/// fourteen, nothing about the negotiated draft settles it. A caller reaching
/// for a stream in the wrong order is this side's mistake, not the relay's.
#[test]
fn an_out_of_order_call_on_a_data_stream_is_this_sides_mistake() {
    let early = AnyConnectionError::from(
        moqtap_client::draft20::connection::ConnectionError::DataStreamState(
            "subgroup header not read yet",
        ),
    );
    assert_eq!(early.cause(), &ErrorCause::Facade);
    assert!(early.is_local());

    let oldest = AnyConnectionError::from(
        moqtap_client::draft07::connection::ConnectionError::DataStreamState(
            "subgroup header not written yet",
        ),
    );
    assert_eq!(oldest.cause(), &ErrorCause::Facade, "the same on the oldest draft");
}

/// The refusals a draft adds of its own are refusals all the same.
///
/// Each of these is this endpoint being asked to write something it will not:
/// nothing reached the wire, so none of them is evidence about anybody. They sit
/// beside a peer violation in the same enum on the same drafts, which is exactly
/// why a sentence could not be trusted to tell them apart.
#[test]
fn a_refusal_a_draft_adds_of_its_own_is_still_this_sides() {
    use moqtap_client::draft20::connection::ConnectionError;

    for err in [
        ConnectionError::RequestOnControlStream(
            moqtap_codec::draft20::message::MessageType::Subscribe,
        ),
        ConnectionError::RespondedToOwnRequest(4),
        // Section 3.3.2 forbids the FIN; this endpoint keeping the rule is not
        // the peer breaking it.
        ConnectionError::FinBeforeResponse(4),
        ConnectionError::FinBeforePublishDone(4),
    ] {
        let words = err.to_string();
        let refused = AnyConnectionError::from(err);
        assert_eq!(refused.cause(), &ErrorCause::Facade, "{words}");
        assert!(refused.is_local(), "{words}");
    }

    let not_ours = AnyConnectionError::from(
        moqtap_client::draft16::connection::ConnectionError::NotOursToAnswer(4),
    );
    assert_eq!(not_ours.cause(), &ErrorCause::Facade);
}

/// Nothing that read the message reads anything different.
///
/// The classification sits beside the words rather than replacing them:
/// `Display` renders the draft-specific error's own words unchanged, so a
/// caller matching on the prose keeps working alongside one that reads the
/// cause.
#[test]
fn the_drafts_own_words_are_unchanged() {
    use moqtap_client::draft14::connection::ConnectionError;

    let err = ConnectionError::Codec(CodecError::InvalidNamespaceTupleSize(0));
    let words = err.to_string();
    assert_eq!(AnyConnectionError::from(err).to_string(), words);
    assert!(words.starts_with("codec error"), "the prefix a prose matcher reads");
}
