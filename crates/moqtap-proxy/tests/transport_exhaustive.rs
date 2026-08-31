//! Exhaustiveness gates on the public enums a downstream caller has to be
//! able to enumerate, run from a crate that is not the one defining them.
//!
//! A file under `tests/` compiles as its own crate, and that is the entire
//! reason this one exists rather than a module beside the types. Inside the
//! defining crate `#[non_exhaustive]` has no effect, so a `match` written
//! there proves nothing about what a downstream consumer is allowed to
//! write. Here it does: every `match` below covers every variant with no `_`
//! arm, which is legal only because `Congestion`, `MtuDiscovery`,
//! `DatagramBuffer`, `TransportProfileError` and `ControlError` deliberately
//! carry no `#[non_exhaustive]`. Adding a variant to any of them stops this
//! crate compiling. The build break *is* the assertion.
//!
//! # If this file stopped compiling because you added a variant
//!
//! Add an arm, and add the variant to the fixture list beside the match.
//! Adding `_ => {}` also makes the build pass, and it silently deletes the
//! only thing this file checks — from then on a further variant compiles
//! green and nobody is told it is unhandled anywhere.
//!
//! # Why each match hands back a slot number
//!
//! An exhaustive match catches a variant nobody handled; it cannot catch a
//! variant somebody handled and then never built. So each match maps its
//! variants onto `0..N` and each test asserts its fixture list fills every
//! slot exactly once. A new arm added without a fixture beside it either
//! returns a slot outside the range or leaves one empty, and the test fails
//! saying which. The two halves together are what make "every variant is
//! matchable *and* constructible outside this crate" a checked statement.

use std::time::Duration;

use moqtap_proxy::transport::{
    AckFrequency, Congestion, DatagramBuffer, MtuDiscovery, TransportProfile, TransportProfileError,
};

use moqtap_proxy::control::ControlError;
use moqtap_proxy::event::{ProxySide, SessionId};
use moqtap_proxy::shape::{
    ClassRule, Discipline, QueueConfig, ShapeError, ShapeProfile, StreamKey,
};
use moqtap_proxy::transport::Leg;

/// The largest value QUIC's variable-length integer encoding carries.
const VARINT_MAX: u64 = (1 << 62) - 1;

/// Build a profile the only way this crate is allowed to.
///
/// `TransportProfile` is `#[non_exhaustive]`, so from out here there is no
/// struct expression and no `..Default::default()`: a profile starts at
/// `default()` — every field `None`, no opinion about anything — and is
/// edited. Routing every fixture through one helper also keeps the tests
/// below about the field under test and nothing else.
fn profile_with(edit: impl FnOnce(&mut TransportProfile)) -> TransportProfile {
    let mut profile = TransportProfile::default();
    edit(&mut profile);
    profile
}

/// Assert that `slots` covers `0..count`, each slot exactly once.
///
/// Reported by slot number rather than by name because the failure is a
/// disagreement between a match and a list, and the number is the thing they
/// disagree about.
#[track_caller]
fn assert_every_slot_filled(count: usize, slots: impl IntoIterator<Item = usize>, what: &str) {
    let mut seen = vec![false; count];
    for slot in slots {
        assert!(
            slot < count,
            "{what}: slot {slot} is outside 0..{count}, so the match gained an arm the fixture \
             list below it never builds"
        );
        assert!(
            !seen[slot],
            "{what}: slot {slot} was produced twice, so one variant is standing in for another \
             and something is unbuilt"
        );
        seen[slot] = true;
    }
    for (slot, filled) in seen.iter().enumerate() {
        assert!(*filled, "{what}: nothing in the fixture list produces slot {slot}");
    }
}

/// How many congestion controllers a profile can name.
const CONGESTION_VARIANTS: usize = 3;

/// Which slot a controller occupies.
///
/// Exhaustive with no `_` arm on purpose: a fourth controller has to be
/// given an arm here, and giving it one is the moment somebody notices it
/// also needs building and applying below.
fn congestion_slot(controller: Congestion) -> usize {
    match controller {
        Congestion::Cubic => 0,
        Congestion::Bbr => 1,
        Congestion::NewReno => 2,
    }
}

#[test]
fn every_congestion_variant_is_matchable_and_installable_from_outside_the_crate() {
    let every: [Congestion; CONGESTION_VARIANTS] =
        [Congestion::Cubic, Congestion::Bbr, Congestion::NewReno];

    for controller in every {
        let profile = profile_with(|p| p.congestion = Some(controller));
        assert_eq!(
            profile.validate(),
            Ok(()),
            "{controller:?} is a controller a profile is allowed to name"
        );
        assert!(
            profile.into_config().is_ok(),
            "{controller:?} has a factory, so naming it produces a config rather than an error"
        );
    }

    assert_every_slot_filled(CONGESTION_VARIANTS, every.map(congestion_slot), "Congestion");
}

/// How many answers there are to "search for a larger path MTU?".
const MTU_DISCOVERY_VARIANTS: usize = 2;

/// Which slot an MTU-discovery setting occupies.
///
/// Exhaustive with no `_` arm on purpose.
fn mtu_discovery_slot(discovery: MtuDiscovery) -> usize {
    match discovery {
        MtuDiscovery::Off => 0,
        MtuDiscovery::UpTo(_) => 1,
    }
}

#[test]
fn every_mtu_discovery_variant_is_matchable_and_applicable_from_outside_the_crate() {
    let every: [MtuDiscovery; MTU_DISCOVERY_VARIANTS] =
        [MtuDiscovery::Off, MtuDiscovery::UpTo(1452)];

    for discovery in every {
        let profile = profile_with(|p| p.mtu_discovery = Some(discovery));
        assert_eq!(profile.validate(), Ok(()), "{discovery:?} is not a value validation refuses");
        assert!(
            profile.into_config().is_ok(),
            "{discovery:?} applies: `Off` and a bounded search are both configurations quinn takes"
        );
    }

    assert_every_slot_filled(MTU_DISCOVERY_VARIANTS, every.map(mtu_discovery_slot), "MtuDiscovery");
}

/// How many answers there are to "how much room for incoming datagrams?".
const DATAGRAM_BUFFER_VARIANTS: usize = 2;

/// Which slot a datagram-buffer setting occupies.
///
/// Exhaustive with no `_` arm on purpose. The distinction this enum exists
/// to keep — refusing datagrams is not the same as having no opinion — only
/// survives while both answers are named, here and everywhere else.
fn datagram_buffer_slot(buffer: DatagramBuffer) -> usize {
    match buffer {
        DatagramBuffer::Disabled => 0,
        DatagramBuffer::Bytes(_) => 1,
    }
}

#[test]
fn every_datagram_buffer_variant_is_matchable_and_applicable_from_outside_the_crate() {
    let every: [DatagramBuffer; DATAGRAM_BUFFER_VARIANTS] =
        [DatagramBuffer::Disabled, DatagramBuffer::Bytes(64 * 1024)];

    for buffer in every {
        let profile = profile_with(|p| p.datagram_receive_buffer = Some(buffer));
        assert_eq!(profile.validate(), Ok(()), "{buffer:?} is not a value validation refuses");
        assert!(
            profile.into_config().is_ok(),
            "{buffer:?} applies: refusing datagrams and sizing their buffer are both settings"
        );
    }

    assert_every_slot_filled(
        DATAGRAM_BUFFER_VARIANTS,
        every.map(datagram_buffer_slot),
        "DatagramBuffer",
    );
}

/// How many ways a profile can be refused.
const ERROR_VARIANTS: usize = 5;

/// Which slot a refusal occupies.
///
/// Exhaustive with no `_` arm on purpose: a sixth reason to refuse a profile
/// cannot be added without an arm here, and the fixture table below then has
/// to show the profile that produces it. A refusal no writable profile
/// reaches is a rule nobody can trip over and nobody can fix.
fn error_slot(error: &TransportProfileError) -> usize {
    match error {
        TransportProfileError::VarIntRange { .. } => 0,
        TransportProfileError::KeepAliveNotBelowIdle { .. } => 1,
        TransportProfileError::MtuInverted { .. } => 2,
        TransportProfileError::MtuBelowFloor { .. } => 3,
        TransportProfileError::TimeThreshold(_) => 4,
    }
}

#[test]
fn every_error_variant_is_reachable_from_a_profile_someone_could_write() {
    // One row per variant: what an author did, the edit that does it, and the
    // exact error back — fields and all, so a validator that returned the
    // right variant naming the wrong field fails here.
    type Edit = fn(&mut TransportProfile);

    let rows: [(&str, Edit, TransportProfileError); ERROR_VARIANTS] = [
        (
            "a connection window one above the varint ceiling",
            |p| p.receive_window = Some(VARINT_MAX + 1),
            TransportProfileError::VarIntRange { field: "receive_window", value: VARINT_MAX + 1 },
        ),
        (
            "a keep-alive due exactly when the connection is already closed",
            |p| {
                p.max_idle_timeout = Some(Duration::from_secs(10));
                p.keep_alive_interval = Some(Duration::from_secs(10));
            },
            TransportProfileError::KeepAliveNotBelowIdle {
                keep_alive: Duration::from_secs(10),
                idle: Duration::from_secs(10),
            },
        ),
        (
            "a discovery floor above the size discovery starts from",
            |p| {
                p.initial_mtu = Some(1300);
                p.min_mtu = Some(1400);
            },
            TransportProfileError::MtuInverted { min: 1400, initial: 1300 },
        ),
        (
            "a constrained path modelled at 900 bytes, which quinn would raise to 1200",
            |p| p.initial_mtu = Some(900),
            TransportProfileError::MtuBelowFloor { field: "initial_mtu", value: 900, floor: 1200 },
        ),
        (
            "a loss-detection multiplier of exactly one",
            // 1.0 rather than NaN: this row compares errors for equality and
            // NaN is not equal to itself, so the NaN case is checked with
            // `matches!` in the crate's own tests instead.
            |p| p.time_threshold = Some(1.0),
            TransportProfileError::TimeThreshold(1.0),
        ),
    ];

    let mut slots = Vec::with_capacity(ERROR_VARIANTS);
    for (label, edit, expected) in rows {
        let returned = profile_with(edit).validate().expect_err(label);
        assert_eq!(returned, expected, "{label}");
        slots.push(error_slot(&returned));
    }

    assert_every_slot_filled(ERROR_VARIANTS, slots, "TransportProfileError");
}

#[test]
fn an_ack_frequency_is_built_downstream_the_one_way_the_attribute_leaves_open() {
    // `AckFrequency` is `#[non_exhaustive]`, which out here forbids both the
    // struct expression and `..Default::default()`. The documented path is
    // `default()` then assignment, and this is that path exercised from a
    // crate the attribute actually applies to — inside the defining crate it
    // is unenforced and the same code proves nothing.
    let mut ack = AckFrequency::default();
    assert_eq!(
        (ack.ack_eliciting_threshold, ack.reordering_threshold, ack.max_ack_delay),
        (1, 2, None),
        "the starting point downstream is quinn's own defaults, not a derived zero"
    );

    ack.ack_eliciting_threshold = VARINT_MAX + 1;
    let profile = profile_with(|p| p.ack_frequency = Some(ack));
    assert_eq!(
        profile.validate(),
        Err(TransportProfileError::VarIntRange {
            field: "ack_frequency.ack_eliciting_threshold",
            value: VARINT_MAX + 1,
        }),
        "a field inside the nested struct is reported dotted, or a reader cannot find it in the file"
    );
}

// ── the control plane's refusals ───────────────────────────────────────

/// How many ways a control-plane request can be refused.
///
/// Seven under the `impair` feature and six without it, because
/// [`ControlError::Impairment`] is compiled with the
/// `ProxyControl::set_impair` that produces it. A build carrying the method
/// and not the refusal, or the refusal and not the method, would be a
/// mismatch this count is the first place to notice.
#[cfg(feature = "impair")]
const CONTROL_ERROR_VARIANTS: usize = 7;
#[cfg(not(feature = "impair"))]
const CONTROL_ERROR_VARIANTS: usize = 6;

/// Which slot a control-plane refusal occupies.
///
/// Exhaustive with no `_` arm on purpose, and this is the one match in the
/// file whose subject is not a transport profile. It is here rather than in
/// a file of its own because it is the same claim about a different type:
/// `ControlError` carries no `#[non_exhaustive]`, so a caller driving a
/// running proxy from out here can enumerate every answer it may be given
/// and will stop compiling when another appears — instead of routing it
/// into a wildcard and reporting it to somebody as "the request failed".
/// Inside the defining crate the attribute is unenforced and the identical
/// match would check nothing.
///
/// The last arm is `#[cfg]`-gated rather than absent, which is the one thing
/// that keeps the claim true in both builds: a `_` arm added "just for the
/// feature-off build" would satisfy the compiler in the feature-on build too
/// and swallow the next variant along with it.
fn control_error_slot(error: &ControlError) -> usize {
    match error {
        ControlError::NoSuchSession(_) => 0,
        ControlError::SessionEnded(_) => 1,
        ControlError::NoSuchStream { .. } => 2,
        ControlError::Unsupported { .. } => 3,
        ControlError::Profile(_) => 4,
        ControlError::Shape(_) => 5,
        #[cfg(feature = "impair")]
        ControlError::Impairment { .. } => 6,
    }
}

/// A [`ShapeError`], obtained the only way this crate can obtain one.
///
/// `ShapeError` **is** `#[non_exhaustive]`, so no variant of it can be named
/// in an expression from out here and the profile constructor that refuses
/// it is the only door. That asymmetry is worth having in front of a reader:
/// the wrapper has to be nameable downstream and the thing it wraps does
/// not, because the wrapper is what a caller writes match arms over.
///
/// The profile refused here is one somebody could plausibly write — a class
/// naming a bucket that was renamed or never added.
fn a_refused_shape_profile() -> ShapeError {
    // Field assignment rather than struct literals: these config types are
    // `#[non_exhaustive]` too, which forbids struct-expression and
    // functional-update syntax from outside the crate.
    let mut class = ClassRule::default();
    class.name = "media".to_string();
    class.bucket = "a bucket nobody declared".to_string();

    ShapeProfile::try_new(Vec::new(), vec![class], QueueConfig::default(), Discipline::Fifo)
        .expect_err("a class naming a bucket that is not in the list is refused")
}

/// Every [`ControlError`] variant can be matched and built by a caller
/// outside this crate.
///
/// The two halves are the same pair the rest of the file makes. The match in
/// [`control_error_slot`] catches a refusal nobody wrote an arm for; the
/// fixture list here catches one somebody wrote an arm for and then could
/// not construct — which for this type is the likelier failure, because a
/// caller needs to construct these to write a table of expected answers, and
/// a variant carrying a field type that is private, or non-exhaustive, or
/// only obtainable from a running proxy, is a variant that cannot appear in
/// one.
///
/// Both wrapped variants are built through their `From` conversion rather
/// than by naming the variant, because that conversion is the path the
/// proxy itself takes and the only path available for
/// [`ControlError::Shape`].
///
/// # Ablation, run
///
/// Adding `#[non_exhaustive]` to `ControlError` in `src/control.rs` does not
/// fail this test — it stops this crate compiling at all, which is the
/// stronger outcome and the reason the attribute is absent. The whole of
/// what `cargo test -p moqtap-proxy --test transport_exhaustive --no-run`
/// then reports:
///
/// ```text
/// error[E0004]: non-exhaustive patterns: `&_` not covered
///    --> crates\moqtap-proxy\tests\transport_exhaustive.rs:308:11
///     |
/// 308 |     match error {
///     |           ^^^^^ pattern `&_` not covered
///     |
/// note: `ControlError` defined here
///   --> crates\moqtap-proxy\src\control.rs:171:1
///    |
/// 171 | pub enum ControlError {
///    | ^^^^^^^^^^^^^^^^^^^^^
///    = note: the matched value is of type `&ControlError`
///    = note: `ControlError` is marked as non-exhaustive, so a wildcard `_`
///      is necessary to match exhaustively
/// ```
///
/// The `171` in that note is the mutated file: the attribute is the line
/// above the enum, so a reader looking for `pub enum ControlError` in the
/// tree as it stands finds it one line higher.
///
/// One error and not two, which is worth knowing before somebody reaches for
/// the attribute as a way of protecting both halves: `#[non_exhaustive]` on
/// an enum stops downstream *matching* and leaves downstream *construction*
/// alone, so the fixture list below still compiles and only the match
/// breaks. Guarding construction as well takes the attribute on each variant
/// — which would also make this file's fixture list impossible to write, and
/// with it any table of expected answers a caller might keep.
#[test]
fn every_control_error_variant_is_matchable_and_constructible_from_outside_the_crate() {
    let profile_error = profile_with(|p| p.receive_window = Some(VARINT_MAX + 1))
        .validate()
        .expect_err("a connection window above the varint ceiling is refused");
    let shape_error = a_refused_shape_profile();

    // Built here rather than provoked out of a proxy: the claim is that a
    // caller can *name* each refusal — to compare an answer against, to
    // write an arm for, to build a fixture from — which is a different claim
    // from the proxy being able to produce it, and it is the one an
    // attribute on the enum can take away.
    //
    // A `Vec` rather than a fixed-size array, because the list is one
    // entry longer under the `impair` feature and an array whose length is a
    // `#[cfg]`-selected constant cannot be written with a conditional
    // element in it.
    #[cfg_attr(not(feature = "impair"), allow(unused_mut))]
    let mut every: Vec<ControlError> = vec![
        ControlError::NoSuchSession(SessionId(9)),
        ControlError::SessionEnded(SessionId(1)),
        ControlError::NoSuchStream {
            id: SessionId(1),
            stream: StreamKey { side: ProxySide::ClientToProxy, id: 0 },
        },
        ControlError::Unsupported {
            what: "transport profile",
            leg: Leg::Upstream,
            transport: "webtransport",
        },
        ControlError::from(profile_error.clone()),
        ControlError::from(shape_error.clone()),
    ];
    // Named rather than converted: this variant carries a leg as well as a
    // reason, so there is no `From` to route it through and a caller writing
    // a table of expected answers has to be able to spell the whole thing.
    // `quinn_netem::ProfileError` carries no `#[non_exhaustive]` either,
    // which is what makes that possible from out here.
    #[cfg(feature = "impair")]
    every.push(ControlError::Impairment {
        leg: Leg::Client,
        source: quinn_netem::ProfileError::EveryNthZero,
    });
    assert_eq!(
        every.len(),
        CONTROL_ERROR_VARIANTS,
        "the fixture list and the variant count have to be kept together, or the slot check below \
         passes over a variant nobody built"
    );

    // The two wrapped variants print the refusal that actually happened
    // rather than a layer of their own. A caller logging one of these gets
    // the field and the value that were refused; a wrapper that printed
    // "invalid profile" would leave that reachable only by destructuring,
    // and every log line about it would be useless.
    assert_eq!(
        every[4].to_string(),
        profile_error.to_string(),
        "a refused transport profile is reported in the words the profile check used"
    );
    assert_eq!(
        every[5].to_string(),
        shape_error.to_string(),
        "a refused shaping profile is reported in the words the profile constructor used"
    );

    // The impairment refusal is not transparent — it names the leg as well,
    // which the two above have no room for — but the reason has to survive
    // verbatim inside it, because the reason is exactly what the refusal it
    // replaced could not carry.
    #[cfg(feature = "impair")]
    assert!(
        every[6].to_string().contains(&quinn_netem::ProfileError::EveryNthZero.to_string()),
        "a refused impairment profile has to print quinn-netem's own words, or a caller reading a \
         log is back to re-running validate() to find out what happened: {}",
        every[6]
    );

    assert_every_slot_filled(
        CONTROL_ERROR_VARIANTS,
        every.iter().map(control_error_slot),
        "ControlError",
    );
}
