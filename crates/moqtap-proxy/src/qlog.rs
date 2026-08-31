//! qlog capture of a leg's QUIC connection, behind the `qlog` feature.
//!
//! A [`QlogSpec`] is a value describing where a capture should be written and
//! what to call it. It is not itself a sink: [`QlogSpec::attach_to`] turns it
//! into the `quinn::QlogStream` that quinn actually writes through and
//! installs that on a `quinn::TransportConfig`, which is the only place
//! quinn accepts one.
//!
//! # What ends up in the file, and what does not
//!
//! quinn emits exactly four event names — `transport:packet_sent`,
//! `transport:packet_received`, `recovery:metrics_updated` and
//! `recovery:packet_lost` — and nothing else. That is the QUIC layer, and
//! only the QUIC layer. No MoQT object, no subgroup, no stream id, no shaping
//! class and no hook decision appears in a capture, because quinn has never
//! heard of any of them. This crate's own reporting —
//! [`crate::event::ProxyEvent`], [`crate::instrument::Counters`],
//! [`crate::shape::ShapeStats`] — is the layer above, and the two are
//! complements: a datagram dropped beneath QUIC is in the capture and in none
//! of them, and an object dropped by a shaping rule is in them and not in the
//! capture.
//!
//! The format is qlog's `JSON-SEQ`: a sequence of records, each one a `0x1E`
//! byte, then compact JSON, then `0x0A`. The first record is a preamble
//! carrying the qlog version, the format name and the title and description
//! from the spec; every record after it is one event.
//!
//! # The file exists before the connection does
//!
//! [`QlogSpec::attach_to`] writes the preamble as it builds the sink, which
//! is before any endpoint has been built, let alone a packet sent. So a
//! non-empty file, a file that parses as JSON-SEQ, and a file carrying a
//! `qlog_version` are all produced by a sink that was attached to a
//! `quinn::TransportConfig` nobody ever connected with. Anything checking a
//! capture has to look at the events: the presence of `transport:packet_sent`
//! records, and the sum of their `header.length`.
//!
//! Nor is the presence of 1-RTT packets by itself evidence that anything was
//! carried. A connection that transfers nothing still sends packets, and with
//! quinn's defaults a good share of those bytes are padded path-MTU probes
//! rather than anything anybody asked for. Measured on loopback by the test
//! at the bottom of this module, over a 100 000-byte transfer against a
//! connection that carried nothing:
//!
//! | path-MTU discovery | transferring 100 000 bytes | idle |
//! |---|---|---|
//! | quinn's default (on) | 108 256 – 108 489 bytes | 1 548 – 1 590 bytes |
//! | [`MtuDiscovery::Off`] | 102 985 – 102 989 bytes | 219 – 222 bytes |
//!
//! Turning discovery off is therefore worth doing on a leg whose capture is
//! going to be measured: it drops the floor by a factor of seven and brings
//! the transfer figure from 8% above the payload to 3% above it, which is
//! what makes a byte total worth bracketing on both sides at all.
//!
//! [`MtuDiscovery::Off`]: crate::transport::MtuDiscovery::Off
//!
//! # There is no end-of-trace record
//!
//! qlog's streamer flushes when it is dropped and writes nothing to mark the
//! end, so a truncated capture and a complete one differ only in that the
//! last record of a truncated one is a fragment. A reader that skips records
//! it cannot parse cannot tell them apart. Two consequences for whoever
//! supplies the writer:
//!
//! * Prefer an unbuffered writer. A `std::io::BufWriter` holds the tail of
//!   the capture until the sink is dropped, and the sink lives as long as the
//!   `quinn::TransportConfig` it was installed on — which usually outlives
//!   the moment a caller wants to read the file.
//! * Parse every record and fail on the one that does not parse, rather than
//!   filtering it out.
//!
//! # What a capture cannot tell you
//!
//! * **Whose view it is.** quinn records the vantage point as `unknown`, so
//!   nothing in the file says whether it is the client leg or the relay leg.
//!   That is known only from which spec the writer was given to.
//! * **Which connection a record belongs to.** Records carry a `group_id`
//!   taken from the original remote connection id, and the client overwrites
//!   that when the server's first Initial arrives — so one connection's
//!   records appear under two different `group_id`s.
//! * **How many connections it covers.** A sink is installed on a
//!   `quinn::TransportConfig`, and every connection made with that config
//!   writes into it. One file can hold several connections interleaved, with
//!   no record saying so.
//! * **How many bytes were received.** quinn fills in a length for packets it
//!   sends and not for packets it receives, so a received-packet record
//!   carries a packet number and a type and no size at all.
//!
//! # Putting one on a leg of this proxy
//!
//! Each leg has a field for it — [`ListenerConfig::qlog`] for the client leg
//! and [`ProxySessionConfig::upstream_qlog`] for the relay leg — and the leg
//! does the rest: it builds the `quinn::TransportConfig` the sink goes on,
//! attaches the sink, and installs the result before its endpoint exists,
//! which is the only order quinn allows.
//!
//! ```
//! use moqtap_proxy::qlog::QlogSpec;
//! use moqtap_proxy::session::ProxySessionConfig;
//! use moqtap_proxy::transport::TransportProfile;
//!
//! let mut spec = QlogSpec::default();
//! spec.writer = Some(Box::new(Vec::new()));
//! spec.title = Some("relay leg".to_string());
//!
//! // Optional, and the one transport field a spec composes with: the
//! // profile is applied to the same config the sink is then attached to.
//! let mut profile = TransportProfile::default();
//! profile.initial_mtu = Some(1350);
//!
//! let session = ProxySessionConfig {
//!     upstream_qlog: Some(spec),
//!     upstream_transport_profile: Some(profile),
//!     ..Default::default()
//! };
//! # let _ = session;
//! ```
//!
//! A spec on its own is enough: a leg that names neither a raw config nor a
//! profile still builds a `quinn::TransportConfig::default()` for the sink
//! and installs it, because installing nothing there would leave the capture
//! attached to a config no connection uses — a file with a preamble and no
//! events, which is exactly the state this module's tests exist to tell
//! apart from a quiet connection.
//!
//! # The one combination that is refused
//!
//! A leg carrying a raw `quinn::TransportConfig` **and** a spec is refused
//! with [`ProxyError::TransportConfigAndQlog`], where the reason is written
//! out in full. In short: quinn accepts a sink only through a method that
//! mutates a `quinn::TransportConfig`, a leg's raw config arrives behind an
//! `Arc`, and that type has no `Clone` — so a leg holding both could take
//! the spec, count it as configured, and deliver it nowhere.
//!
//! A caller who has a config of their own attaches the sink to it with
//! [`QlogSpec::attach_to`] *before* the `Arc` is made, which is the last
//! moment a mutable reference exists, and sets the result as the leg's raw
//! config. That is the same wiring the leg does internally, done a step
//! earlier.
//!
//! # Two caveats, both of which produce a file that looks right and holds
//! nothing
//!
//! A spec is a single-use writer, so a **proxy template cannot carry one**.
//! [`TransparentProxy`] copies its listener config once and its session
//! config once per accepted connection, and there is nothing to copy: both
//! copies leave the field `None`, and a spec set on a `ProxyConfig` reaches
//! no leg. A run that wants a capture per connection builds one spec and one
//! writer per connection and drives [`ProxySession`] — or [`Listener`] —
//! directly. That is not merely a limit of the copy: one sink shared between
//! two connections writes both of them into one file, behind one preamble,
//! with no record saying where either begins.
//!
//! And **a WebTransport upstream ignores its transport configuration
//! entirely**, sink and all. `wtransport` builds that endpoint, so the config
//! this crate resolved is dropped without an error — which is a defensible
//! answer for flow-control windows (the connection still works, with quinn's
//! defaults) and a bad one for a capture: the preamble is written when the
//! sink is *built*, so the caller gets a file that exists, parses, names a
//! `qlog_version` and will never hold a single event. There is no refusal for
//! it, because the sink is attached to a `quinn::TransportConfig` and the step
//! that does it is shared with the client leg, which has no upstream
//! transport to dispatch on. Capture the client leg instead, through
//! [`ListenerConfig::qlog`] — that endpoint is always QUIC, even for a
//! WebTransport client, because the proxy builds the QUIC endpoint and hands
//! the connection up.
//!
//! [`Listener`]: crate::listener::Listener
//! [`ListenerConfig::qlog`]: crate::listener::ListenerConfig::qlog
//! [`ProxyError::TransportConfigAndQlog`]: crate::error::ProxyError::TransportConfigAndQlog
//! [`ProxySession`]: crate::session::ProxySession
//! [`ProxySessionConfig::upstream_qlog`]: crate::session::ProxySessionConfig::upstream_qlog
//! [`TransparentProxy`]: crate::proxy::TransparentProxy

use std::io::Write;

/// Where a leg's qlog capture goes, and what to call it.
///
/// Owned rather than borrowed, and single-use: the writer is moved into
/// quinn's streamer when the spec becomes a sink, so a spec is consumed by
/// [`QlogSpec::attach_to`] and cannot be attached twice. Two connections that
/// each want their own capture need two specs and two writers.
///
/// `#[non_exhaustive]` **with** a [`Default`], as [`TransportProfile`] and
/// [`AckFrequency`] are: the attribute reserves room for a fourth knob —
/// quinn's own qlog configuration also carries the epoch that event times are
/// measured from, and exposing it later should not be a break — and outside
/// this crate it makes both struct-expression and `..Default::default()`
/// syntax illegal, so the [`Default`] is what leaves a construction path open
/// at all.
///
/// That shape is also why [`QlogSpec::writer`] is an `Option` of something
/// that has no sensible default rather than a required field: a type built by
/// `default()` and then assigned into has to be expressible with nothing in
/// it. A spec in that state is refused by [`QlogSpec::validate`], and is the
/// only reason that method exists.
///
/// ```
/// use moqtap_proxy::qlog::QlogSpec;
///
/// // A real capture goes to a `std::fs::File`, which is `Write + Send +
/// // Sync` and unbuffered. Anything else that writes will do; this one keeps
/// // the bytes in memory so the example touches no disk.
/// let mut spec = QlogSpec::default();
/// spec.writer = Some(Box::new(Vec::new()));
/// spec.title = Some("client leg".to_string());
///
/// let mut transport = quinn::TransportConfig::default();
/// spec.attach_to(&mut transport)?;
/// # Ok::<(), moqtap_proxy::qlog::QlogError>(())
/// ```
///
/// [`TransportProfile`]: crate::transport::TransportProfile
/// [`AckFrequency`]: crate::transport::AckFrequency
#[derive(Default)]
#[non_exhaustive]
pub struct QlogSpec {
    /// Where the capture is written.
    ///
    /// Required in practice — a spec without one is refused by
    /// [`QlogSpec::validate`] — and optional in the type for the reason given
    /// on the struct itself.
    ///
    /// Written to from whichever thread is driving the connection, which is
    /// why the bound is `Send + Sync` rather than plain `Write`. Every record
    /// is written as a whole, so a writer that appends is enough; nothing
    /// seeks.
    ///
    /// **Prefer an unbuffered writer.** A `BufWriter` here holds the tail of
    /// the capture until the sink is dropped, and there is no terminator
    /// record to tell a reader that the tail is missing.
    pub writer: Option<Box<dyn Write + Send + Sync>>,
    /// A name for the capture, recorded in its preamble.
    ///
    /// `None` omits the key entirely rather than writing a null, so a capture
    /// with no title is a preamble with no `title` field in it. Worth
    /// setting: nothing else in the file says which leg it is, because the
    /// vantage point quinn records is always `unknown`.
    pub title: Option<String>,
    /// A longer description, recorded in the preamble beside the title.
    ///
    /// `None` omits the key, exactly as for [`QlogSpec::title`].
    pub description: Option<String>,
}

impl std::fmt::Debug for QlogSpec {
    /// Everything but the writer, which has no `Debug` to defer to.
    ///
    /// A `dyn Write` cannot be printed and must not be consumed to find out
    /// what it is, so the most this can say is whether one is there. That is
    /// deliberately not enough to check a capture with: whether a writer is
    /// present says nothing about whether the sink built from it ever reached
    /// a connection, which is the question a reader of a capture actually
    /// has.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QlogSpec")
            .field("writer", &self.writer.as_ref().map(|_| "<dyn Write>"))
            .field("title", &self.title)
            .field("description", &self.description)
            .finish()
    }
}

impl QlogSpec {
    /// Everything wrong with this spec, before a sink exists.
    ///
    /// One rule, and it is here because the type's own shape makes the
    /// mistake expressible: a spec built by `QlogSpec::default()` and then
    /// given a title and no writer is a spec that would produce no capture at
    /// all. quinn's own answer in that case is to return no sink, silently
    /// and without an error, so nothing would be installed anywhere and
    /// nothing would say so — leaving a caller who asked for a capture with a
    /// working connection, a successful build and no file.
    ///
    /// Called by [`QlogSpec::attach_to`] before anything is built, so a
    /// caller who never calls it directly still cannot reach that state.
    pub fn validate(&self) -> Result<(), QlogError> {
        if self.writer.is_none() {
            return Err(QlogError::NoWriter);
        }
        Ok(())
    }

    /// Build the sink this spec describes and install it on `transport`.
    ///
    /// Writes the capture's preamble as a side effect, because that is when
    /// qlog's streamer writes it — so the file exists, and is a valid
    /// JSON-SEQ document, from this call onwards and regardless of whether
    /// `transport` is ever used to make a connection.
    ///
    /// # Why this mutates a config rather than returning one
    ///
    /// quinn exposes the sink in exactly one place: a method that mutates a
    /// `quinn::TransportConfig`. There is no setter on an endpoint, on a
    /// `quinn::ServerConfig` or on a `quinn::ClientConfig`, and no way to
    /// hand a live connection one. So the capture has to be installed on the
    /// config **before** it is shared, and a caller who already holds an
    /// `Arc<quinn::TransportConfig>` cannot have one attached to it: that
    /// type has no `Clone`, and taking a mutable reference out of an `Arc`
    /// fails whenever a second handle exists — which is exactly the situation
    /// an `Arc` in a caller's hand describes.
    ///
    /// That is why this takes `&mut quinn::TransportConfig` and why a spec
    /// belongs beside the config being built rather than beside one already
    /// built. The alternative signature — take the `Arc`, return a new `Arc`
    /// — cannot be written: there is nothing to copy the caller's config
    /// with, so it could only return a fresh default with every setting the
    /// caller made silently discarded.
    ///
    /// # It consumes the spec
    ///
    /// The writer is moved into quinn's streamer, so there is nothing left to
    /// attach a second time. Two connections wanting separate captures need
    /// two specs; one sink shared between two connections writes both of them
    /// into one file, with one preamble and no record saying where one
    /// connection ends and the other begins.
    pub fn attach_to(self, transport: &mut quinn::TransportConfig) -> Result<(), QlogError> {
        let stream = self.into_stream()?;
        transport.qlog_stream(Some(stream));
        Ok(())
    }

    /// The sink itself, for a caller who wants to install it somewhere this
    /// crate does not reach.
    ///
    /// [`QlogSpec::attach_to`] is this followed by the one setter quinn has,
    /// and is what a leg's config is built with. This is the seam under it,
    /// exposed because a
    /// `quinn::QlogStream` is shareable — it is a handle to one streamer, not
    /// a writer — and a caller who deliberately wants two connections in one
    /// capture can clone it. That is a decision worth having to write down,
    /// which is why it is not what `attach_to` does.
    ///
    /// Writes the preamble, as `attach_to` does and for the same reason.
    pub fn into_stream(self) -> Result<quinn::QlogStream, QlogError> {
        // Before quinn's builder is touched. quinn answers a missing writer
        // with `None` and no error at all, so a spec that reached
        // `into_stream` without this check would come back indistinguishable
        // from one whose writer failed on its first byte.
        self.validate()?;

        let mut config = quinn::QlogConfig::default();
        if let Some(writer) = self.writer {
            config.writer(writer);
        }
        config.title(self.title);
        config.description(self.description);

        // `None` here can no longer mean "no writer" — `validate` has ruled
        // that out — so it means the streamer failed to write the preamble.
        // quinn logs the underlying `io::Error` through `tracing` and hands
        // back an `Option`, so the reason is not recoverable here; what is
        // recoverable is the fact, and reporting it is the whole point. The
        // alternative is a leg that installs no sink, connects, runs, and
        // reports success while the file the caller is watching stays empty.
        config.into_stream().ok_or(QlogError::NotStarted)
    }
}

/// Why a [`QlogSpec`] could not become a capture.
///
/// Deliberately **not** `#[non_exhaustive]`, for the reason
/// [`TransportProfileError`] is not: a crate outside this one can match every
/// variant with no wildcard arm, so a third refusal is a visible break rather
/// than a case that silently falls into a catch-all. Both variants below are
/// reachable from a spec a caller could actually write, which is the property
/// worth keeping as the list grows.
///
/// [`TransportProfileError`]: crate::transport::TransportProfileError
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QlogError {
    /// The spec named no writer, so there is nowhere for the capture to go.
    ///
    /// Reported rather than treated as "capture disabled", because a spec is
    /// how a caller asks for a capture: the way to not want one is to have no
    /// spec at all.
    #[error(
        "the qlog spec has no writer, so nothing would be captured; set `writer` to where the \
         capture should go, or drop the spec entirely to run without one"
    )]
    NoWriter,
    /// quinn could not start the capture — the writer refused the preamble.
    ///
    /// Carries no cause, and that is a limit of quinn's interface rather than
    /// a choice: it logs the underlying `std::io::Error` through `tracing` and
    /// returns an `Option`, so by the time the failure is visible here the
    /// error itself is gone. The `tracing` record is the only place the
    /// reason survives.
    #[error(
        "the qlog capture could not be started: the writer failed on the first record; quinn logs \
         the underlying I/O error through `tracing` and does not return it"
    )]
    NotStarted,
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    /// A writer that keeps everything, readable while the sink is still
    /// alive.
    ///
    /// Unbuffered on purpose. A `BufWriter` here would make every assertion
    /// below depend on when the sink is dropped, which is the trap the module
    /// documentation warns about.
    #[derive(Clone)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("no test holds this across a panic").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A writer that refuses every byte, standing in for a full disk or a
    /// path that cannot be written.
    struct Refuses;

    impl Write for Refuses {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "no"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A spec over `sink`, written as a struct expression.
    ///
    /// `QlogSpec::default()` followed by field assignment is what the type's
    /// own documentation shows, because `#[non_exhaustive]` leaves a crate
    /// outside this one no other way to build one. Inside this crate the
    /// attribute does not apply and that form trips
    /// `clippy::field_reassign_with_default`, so the fixtures here use the
    /// struct expression instead. Both reach the same value.
    fn spec_writing_to(
        sink: &Arc<Mutex<Vec<u8>>>,
        title: Option<&str>,
        description: Option<&str>,
    ) -> QlogSpec {
        QlogSpec {
            writer: Some(Box::new(Captured(Arc::clone(sink)))),
            title: title.map(str::to_string),
            description: description.map(str::to_string),
        }
    }

    fn text(sink: &Arc<Mutex<Vec<u8>>>) -> String {
        String::from_utf8(sink.lock().expect("uncontended").clone())
            .expect("qlog writes UTF-8 JSON")
    }

    /// A spec with nowhere to write is refused, and refused as *that*.
    ///
    /// The second half is the one that matters. quinn answers a missing
    /// writer with `None` and no error, which is the same `None` a writer
    /// that failed produces, so the two faults arrive here indistinguishable
    /// unless the missing writer is caught first. Ablation: dropping the
    /// `self.validate()?` line from `into_stream` leaves quinn to answer, and
    /// this fails with `assertion left == right failed: and `into_stream`
    /// must reach the same answer rather than quinn's silent `None`  left:
    /// Some(NotStarted)  right: Some(NoWriter)` — a caller sent to look at
    /// their disk over a spec that named no file.
    #[test]
    fn a_spec_with_no_writer_is_refused_before_any_sink_exists() {
        assert_eq!(
            QlogSpec::default().validate(),
            Err(QlogError::NoWriter),
            "a spec is how a caller asks for a capture; one with nowhere to write is a mistake, \
             not a request for no capture"
        );

        let titled_but_blind =
            QlogSpec { writer: None, title: Some("client leg".to_string()), description: None };
        assert_eq!(
            titled_but_blind.into_stream().err(),
            Some(QlogError::NoWriter),
            "and `into_stream` must reach the same answer rather than quinn's silent `None`"
        );
    }

    /// The other half of the pair above: a writer that exists and fails is
    /// `NotStarted`, never `NoWriter`.
    ///
    /// Between them the two tests pin both directions, which is what stops a
    /// single refusal covering both from looking correct: each test on its
    /// own is satisfied by a `into_stream` that always answers the variant
    /// that test expects.
    #[test]
    fn the_two_refusals_are_told_apart() {
        let refusing = QlogSpec { writer: Some(Box::new(Refuses)), title: None, description: None };
        assert_eq!(
            refusing.into_stream().err(),
            Some(QlogError::NotStarted),
            "a writer that exists and fails is a different fault from no writer at all, and a \
             single refusal covering both would send the caller to the wrong half of their code"
        );
    }

    /// Building the sink writes a whole preamble, framed as JSON-SEQ, and
    /// carrying the two strings the spec was given.
    ///
    /// Ablation: dropping the `config.title(self.title)` line from
    /// `into_stream` fails here with the whole preamble printed —
    /// `{"qlog_version":"0.3","qlog_format":"JSON-SEQ","description":"proxy
    /// to client","trace":{"vantage_point":{"type":"unknown"},…}}` — which is
    /// also the clearest demonstration of the omission rule the next test
    /// pins: the title is not `null` in there, it is simply not a key.
    #[test]
    fn becoming_a_sink_writes_the_preamble_immediately() {
        let sink = Arc::new(Mutex::new(Vec::new()));
        let spec = spec_writing_to(&sink, Some("client leg"), Some("proxy to client"));

        let mut transport = quinn::TransportConfig::default();
        spec.attach_to(&mut transport).expect("a spec with a writer becomes a sink");

        let bytes = sink.lock().expect("uncontended").clone();
        assert_eq!(
            bytes.first().copied(),
            Some(0x1e),
            "JSON-SEQ frames every record with a record-separator byte, and a reader that splits \
             on it has to find the first one at offset zero"
        );
        assert_eq!(bytes.last().copied(), Some(b'\n'), "and terminates each record with a newline");

        let text = text(&sink);
        assert!(
            text.contains(r#""qlog_format":"JSON-SEQ""#),
            "the framing this crate reads back is named in the preamble; a capture in any other \
             format is one no reader here can split: {text}"
        );
        assert!(
            text.contains(r#""title":"client leg""#)
                && text.contains(r#""description":"proxy to client""#),
            "nothing else in the file says which leg it is — quinn records the vantage point as \
             `unknown` — so the two strings the spec carries have to arrive: {text}"
        );
        assert_eq!(
            text.matches('\u{1e}').count(),
            1,
            "attaching a sink writes the preamble and nothing else; a connection has not been \
             made, so there is no event to record yet: {text}"
        );
    }

    /// A capture with no title omits the key rather than writing a null.
    /// Worth pinning because it decides how a reader tells *this capture was
    /// not named* from *this capture was named nothing*, and because the two
    /// look identical to anything that reads the field with a default.
    #[test]
    fn an_unnamed_capture_has_no_title_key_at_all() {
        let sink = Arc::new(Mutex::new(Vec::new()));
        spec_writing_to(&sink, None, None)
            .attach_to(&mut quinn::TransportConfig::default())
            .expect("a sink");

        let text = text(&sink);
        assert!(!text.contains("title"), "an unset title is an absent key, not a null: {text}");
        assert!(
            text.contains(r#""qlog_version""#),
            "the preamble is still a whole preamble without one: {text}"
        );
    }

    // ── The capture over real traffic ──────────────────────────────────

    /// Total up the 1-RTT `transport:packet_sent` records in a capture.
    ///
    /// Hand-written over the bytes, deliberately, rather than through the
    /// `qlog` crate's own `Deserialize`. That derive is the exact inverse of
    /// the `Serialize` quinn wrote the file with, from the same crate at the
    /// same version, so every wire string this function cares about —
    /// `transport:packet_sent`, `1RTT`, `length` — would be read out of the
    /// same `#[serde(rename)]` attribute that put it there. A release that
    /// renamed one of them would keep this passing against a file that had
    /// changed shape. Naming the strings as literals is what makes that
    /// change fail here instead.
    ///
    /// Panics on a record that does not parse and on a 1-RTT sent packet with
    /// no length, rather than skipping either. The format has no end-of-trace
    /// marker, so a truncated capture is only detectable as a final record
    /// that is a fragment, and a missing length is qlog's encoding of `None`
    /// — reading it as zero would turn a capture that stopped recording sizes
    /// into a capture of a connection that sent nothing.
    fn one_rtt_bytes_sent(capture: &[u8]) -> (usize, u64) {
        let mut records = capture.split(|b| *b == 0x1e);
        assert_eq!(
            records.next(),
            Some(&[][..]),
            "a JSON-SEQ capture starts with a record separator, so nothing precedes the first one"
        );

        let (mut count, mut bytes) = (0usize, 0u64);
        let mut records = records.peekable();
        assert!(records.peek().is_some(), "a capture holds at least its preamble");

        for record in records {
            let record = std::str::from_utf8(record).expect("qlog writes UTF-8");
            assert!(
                record.ends_with('\n'),
                "a record with no newline is the tail of a truncated capture, which is the only \
                 way truncation is visible at all: {record}"
            );
            assert!(
                record.trim_end().ends_with('}'),
                "and a record that does not close its object is a fragment: {record}"
            );

            if !record.contains(r#""name":"transport:packet_sent""#) {
                continue;
            }
            if !record.contains(r#""packet_type":"1RTT""#) {
                continue;
            }
            count += 1;

            let Some((_, after)) = record.split_once(r#""length":"#) else {
                panic!(
                    "a 1-RTT sent packet with no length. qlog omits a `None` field rather than \
                     writing a null, so this is a capture that stopped recording sizes, not a \
                     connection that sent none: {record}"
                );
            };
            let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
            bytes += digits.parse::<u64>().expect("a length is a number");
        }

        (count, bytes)
    }

    /// TLS verification is not what is under test here.
    #[derive(Debug)]
    struct AcceptAnyServer;

    impl rustls::client::danger::ServerCertVerifier for AcceptAnyServer {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::RSA_PSS_SHA256,
            ]
        }
    }

    /// A loopback QUIC server that reads one unidirectional stream to its end
    /// and reports how many bytes it got.
    async fn echo_length_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<usize>) {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("a key pair for a test certificate");
        let params =
            rcgen::CertificateParams::new(vec!["localhost".into()]).expect("certificate params");
        let cert = params.self_signed(&key_pair).expect("self-sign");

        let chain = vec![rustls::pki_types::CertificateDer::from(cert.der().to_vec())];
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
        );

        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("a self-signed identity");
        tls.alpn_protocols = vec![b"qlog-probe".to_vec()];

        let quic: quinn::crypto::rustls::QuicServerConfig =
            tls.try_into().expect("a QUIC-capable TLS config");
        let endpoint = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(quic)),
            "127.0.0.1:0".parse().expect("a literal address"),
        )
        .expect("a loopback endpoint");
        let addr = endpoint.local_addr().expect("a bound endpoint has an address");

        let handle = tokio::spawn(async move {
            let Some(incoming) = endpoint.accept().await else {
                return 0;
            };
            // Every failure below answers zero rather than panicking. The
            // idle half of the test connects and closes without opening a
            // stream, and depending on how quickly the close overtakes the
            // handshake that arrives here either as a connection error or as
            // a stream that never appears; neither is a fault, and a panic in
            // a spawned task would be reported as the *client* side failing.
            let Ok(conn) = incoming.await else {
                return 0;
            };
            match conn.accept_uni().await {
                Ok(mut recv) => {
                    recv.read_to_end(1024 * 1024).await.map(|got| got.len()).unwrap_or(0)
                }
                Err(_) => 0,
            }
        });

        (addr, handle)
    }

    /// A client config whose connections write a capture into `sink`, with
    /// path-MTU discovery off.
    fn probing_client(sink: &Arc<Mutex<Vec<u8>>>, title: &str) -> quinn::ClientConfig {
        let mut tls = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServer))
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"qlog-probe".to_vec()];

        let quic: quinn::crypto::rustls::QuicClientConfig =
            tls.try_into().expect("a QUIC-capable TLS config");
        let mut client = quinn::ClientConfig::new(Arc::new(quic));

        let mut transport = quinn::TransportConfig::default();
        // Without this the floor is padded path-MTU probes rather than
        // anything the test sent, which is the measurement the assertions
        // below depend on. See this test's own numbers.
        transport.mtu_discovery_config(None);

        spec_writing_to(sink, Some(title), None)
            .attach_to(&mut transport)
            .expect("a spec with a writer becomes a sink");

        client.transport_config(Arc::new(transport));
        client
    }

    /// The capture records the bytes the connection actually sent, and an
    /// idle connection is distinguishable from a loaded one.
    ///
    /// This is the assertion the whole module exists for, and it is bracketed
    /// on both sides on purpose: a lower bound alone is met by a connection
    /// that carried nothing but noise, and an upper bound alone is met by a
    /// capture with no events in it. The idle half is the control — a sink
    /// attached to a config that made a real, successful handshake and
    /// carried no payload — and it is what makes the loaded figure mean
    /// something.
    ///
    /// Observed here, MTU discovery off, over five runs: the 100 000-byte
    /// transfer recorded 89 1-RTT sent packets totalling 102 985–102 989
    /// bytes, and the idle connection 3 packets totalling 219–222 bytes. With
    /// discovery left on, over three runs, the same two figures were 83–88
    /// packets / 108 256–108 489 bytes and 4–5 packets / 1 548–1 590 bytes.
    /// The thresholds below are far outside both spreads, because the numbers
    /// move with the machine and with quinn's version; what does not move is
    /// that a loaded connection and an idle one are two orders of magnitude
    /// apart.
    ///
    /// Ablation, the failure this is really here for: attaching the sink to a
    /// `quinn::TransportConfig` built beside the one the client is actually
    /// configured with — which is a two-line mistake and produces a capture
    /// file that exists, parses and names a qlog version — fails here with
    /// `the capture cannot record fewer bytes than the connection carried: 0
    /// over 0 packets`, while the 100 000-byte transfer still succeeds and
    /// the server still reports every byte.
    #[tokio::test]
    async fn a_capture_counts_the_bytes_the_connection_sent() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        const PAYLOAD: usize = 100_000;

        let loaded = Arc::new(Mutex::new(Vec::new()));
        let (addr, server) = echo_length_server().await;
        {
            let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("a literal"))
                .expect("a client endpoint");
            endpoint.set_default_client_config(probing_client(&loaded, "loaded"));
            let conn = endpoint
                .connect(addr, "localhost")
                .expect("a dialable address")
                .await
                .expect("a handshake");
            let mut send = conn.open_uni().await.expect("a stream");
            send.write_all(&vec![0x5au8; PAYLOAD]).await.expect("the payload");
            send.finish().expect("a clean finish");
            assert_eq!(
                server.await.expect("the server task"),
                PAYLOAD,
                "the transfer has to have happened, or the capture below is measuring nothing"
            );
            conn.close(0u32.into(), b"done");
            endpoint.wait_idle().await;
        }

        let idle = Arc::new(Mutex::new(Vec::new()));
        let (addr, server) = echo_length_server().await;
        {
            let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("a literal"))
                .expect("a client endpoint");
            endpoint.set_default_client_config(probing_client(&idle, "idle"));
            let conn = endpoint
                .connect(addr, "localhost")
                .expect("a dialable address")
                .await
                .expect("a handshake");
            conn.close(0u32.into(), b"done");
            endpoint.wait_idle().await;
            let _ = server.await;
        }

        let (loaded_count, loaded_bytes) = one_rtt_bytes_sent(&loaded.lock().expect("uncontended"));
        let (idle_count, idle_bytes) = one_rtt_bytes_sent(&idle.lock().expect("uncontended"));

        assert!(
            loaded_bytes >= PAYLOAD as u64,
            "the capture cannot record fewer bytes than the connection carried: {loaded_bytes} \
             over {loaded_count} packets"
        );
        assert!(
            loaded_bytes <= PAYLOAD as u64 * 6 / 5,
            "nor much more than it — QUIC framing and acknowledgements are a few percent, and a \
             figure half again as large means the total is counting something else: \
             {loaded_bytes} over {loaded_count} packets"
        );
        assert!(
            idle_bytes * 20 < loaded_bytes,
            "a connection that carried nothing must not be mistakable for one that carried \
             100 000 bytes: idle {idle_bytes} bytes over {idle_count} packets against loaded \
             {loaded_bytes} over {loaded_count}"
        );
    }

    /// A sink attached to a config nothing connects with still produces a
    /// file, and the file still parses.
    /// The negative control for the test above: it is the exact shape of a
    /// build where the capture was wired to a connection that was never made,
    /// and it shows that "the file is there", *the file is valid JSON-SEQ* and
    /// *the file names a qlog version* are all satisfied by it. Only the events
    /// tell the two apart.
    #[test]
    fn a_sink_that_reaches_no_connection_still_writes_a_file_that_parses() {
        let sink = Arc::new(Mutex::new(Vec::new()));
        let mut transport = quinn::TransportConfig::default();
        spec_writing_to(&sink, None, None).attach_to(&mut transport).expect("a sink");
        drop(transport);

        let bytes = sink.lock().expect("uncontended").clone();
        assert!(!bytes.is_empty(), "a preamble was written before any connection existed");
        assert_eq!(
            one_rtt_bytes_sent(&bytes),
            (0, 0),
            "and it holds no events at all, which is the only thing that distinguishes it from a \
             capture of a connection that ran"
        );
    }
}
