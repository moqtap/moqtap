//! What a qlog capture of a proxy leg is worth, measured over real
//! traffic.
//!
//! `qlog::QlogSpec` turns a writer into the sink quinn writes a QUIC-layer
//! capture through, and the capture is the only view this crate has of the
//! layer beneath its own reporting. The claim worth gating is not that a
//! file appears — a file appears whatever happens, and the next section
//! says why — but that the file's contents are a function of the bytes the
//! leg carried.
//!
//! # The file exists before the connection does
//!
//! `QlogSpec::attach_to` writes the capture's preamble as it builds the
//! sink. That happens while a `quinn::TransportConfig` is still being
//! assembled: before an endpoint is bound, before a packet is sent, and
//! whether or not the config is ever handed to anything. So all of
//! "the file is there", "the file is non-empty", "the file is valid
//! JSON-SEQ" and "the file names a qlog version" are satisfied by a build
//! whose sink was attached to a config nobody connected with.
//!
//! Everything here therefore reads *events*, and the two tests at the top
//! are a pair rather than one test and a variation:
//!
//! * [`the_relay_legs_capture_counts_the_payload_the_proxy_forwarded`]
//!   says the 1-RTT byte total exceeds the payload the session carried.
//!   Alone, that is satisfied by any total large enough — including one
//!   assembled from something other than this session's traffic.
//! * [`a_relay_leg_that_carried_nothing_captures_its_handshake_and_little_else`]
//!   runs the same wiring over a session that connects and transfers
//!   nothing, and says the same total is an order of magnitude *below* the
//!   payload — while still holding the Initial and Handshake packets that
//!   prove the connection really happened and really was captured.
//!
//! Together they bracket the number from both sides. The second is not a
//! duplicate of the first: it is the control that makes the first one's
//! figure mean "this payload" instead of "some traffic".
//!
//! # Why the sink goes on the relay leg
//!
//! quinn records a length for packets it **sends** and none at all for
//! packets it receives, so a byte total is always a total of one
//! direction. The proxy *receives* the payload on its client-facing leg
//! and *sends* it on its relay-facing leg, so a capture attached to the
//! listener would count this proxy's acknowledgements — a few hundred
//! bytes against a hundred thousand — and the headline assertion would be
//! false against a perfectly correct build. The sink goes on
//! `ProxySessionConfig::upstream_transport_config`, where the payload
//! leaves.
//!
//! # Why the reader here is hand-written
//!
//! quinn writes the capture by serialising the `qlog` crate's own types,
//! so `qlog`'s `Deserialize` is the exact inverse of the `Serialize` that
//! produced the file, from the same crate at the same version. Every wire
//! string that matters — `transport:packet_sent`, `1RTT`, `length` —
//! would then be read out of the same `#[serde(rename)]` attribute that
//! wrote it, and a release that renamed one would keep this file green
//! against a capture that had changed shape. [`Capture`] names those
//! strings as literals instead, so that change fails here.
//!
//! Three reading rules follow from the format rather than from taste, and
//! [`Capture`] enforces all three:
//!
//! * **Every record must parse.** JSON-SEQ has no end-of-trace marker, so
//!   a truncated capture differs from a complete one only in that its last
//!   record is a fragment. A reader that skips what it cannot parse cannot
//!   tell them apart.
//! * **A missing packet length is a broken fixture, not a zero.** qlog
//!   omits a `None` field rather than writing a null, so a build that
//!   stopped recording sizes would read as a session that sent no bytes —
//!   which is a *pass* for the idle test and a wrong-reason failure for
//!   the loaded one.
//! * **The 1-RTT packet type is named exactly.** The data packet-number
//!   space yields two of them, `0RTT` and `1RTT`, and a loose match would
//!   silently fold in a space this proxy never uses.
//!
//! # Path-MTU discovery is off on the captured leg
//!
//! With quinn's defaults a connection that carries nothing still sends
//! several padded path-MTU probes, and on an idle leg they are most of
//! what the capture holds. Measured here, by running both fixtures below
//! with the one line that turns discovery off commented out and then
//! restored:
//!
//! | path-MTU discovery | 1-RTT bytes sent forwarding 100 000 | idle |
//! |---|---|---|
//! | quinn's default (on) | 108 248–108 334 over 82–84 packets | 3 038 over 7 packets |
//! | off | 103 007–103 018 over 89 packets | 323 over 5 packets |
//!
//! Turning it off is worth a line on any leg whose capture is going to be
//! measured. It moves the loaded figure from 8% above the payload to 3%,
//! which is what makes an upper bracket worth stating at all, and it drops
//! the idle floor by a factor of nine — so the separation the pair rests
//! on goes from 36x to 320x. Both captured legs here set
//! `mtu_discovery_config(None)` for those two reasons.
//!
//! # A leg that carries the spec itself
//!
//! The two fixtures above attach the sink to a `quinn::TransportConfig`
//! and hand that to the leg as its raw config, which is one of the two
//! ways to reach a capture. The other is
//! `ProxySessionConfig::upstream_qlog`, where the leg builds the config and
//! attaches the sink itself, and it brings two claims of its own:
//!
//! * [`a_relay_leg_carrying_only_a_spec_still_captures_what_it_sent`] — a
//!   leg naming a spec and *neither* of the two transport fields still
//!   installs a config for the sink to go on. This is the case most likely
//!   to be silently wrong, because "install nothing" is the right answer
//!   for a leg naming neither of those fields and no spec either, and a
//!   sink on a config nobody installs produces a file that exists, parses,
//!   names a qlog version and holds no event.
//! * [`a_leg_given_both_a_raw_config_and_a_spec_is_refused_and_captures_nothing`]
//!   — the pair that cannot be honoured, refused where the leg is built.
//!   quinn installs a sink by mutating a `quinn::TransportConfig`, and a
//!   leg's raw config arrives behind an `Arc` that can be neither cloned
//!   nor mutated, so a leg accepting both could only count the spec as
//!   configured and deliver it nowhere.
//! * [`a_proxy_template_carrying_a_spec_is_refused_on_either_leg`] — the
//!   other way a spec can be handed to something that cannot deliver it. A
//!   `TransparentProxy` **copies** both configurations, and a `QlogSpec` has
//!   no `Clone`, so a proxy could only leave the field behind. This row is
//!   the one whose failure mode has no other symptom at all: the proxy
//!   would bind, accept, forward and report success, and nothing but an
//!   uncreated file would say the capture never happened.
//!
//! All three read the file's *absence* as well as its contents, which is
//! why they write through [`LazyFile`] rather than a `std::fs::File` opened
//! with the spec: an eagerly created file is left behind whether or not a
//! sink was ever built, so "nothing was written" would be false against a
//! correct build. Written lazily, the file exists exactly when a sink
//! exists — the preamble is the first thing through the writer.

#![cfg(all(
    feature = "qlog",
    any(
        feature = "draft07",
        feature = "draft08",
        feature = "draft09",
        feature = "draft10",
        feature = "draft11",
        feature = "draft12",
        feature = "draft13",
        feature = "draft14",
        feature = "draft15",
        feature = "draft16",
        feature = "draft17",
        feature = "draft18",
        feature = "draft19",
        feature = "draft20"
    )
))]

mod common;

use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use moqtap_codec::version::DraftVersion;

use moqtap_proxy::error::ProxyError;
use moqtap_proxy::event::SessionId;
use moqtap_proxy::hook::{NoOpHook, ProxyHook};
use moqtap_proxy::listener::ListenerConfig;
use moqtap_proxy::observer::{NoOpProxyObserver, ProxyObserver};
use moqtap_proxy::proxy::{ProxyConfig, TransparentProxy};
use moqtap_proxy::qlog::{QlogError, QlogSpec};
use moqtap_proxy::session::{ProxySession, ProxySessionConfig};
use moqtap_proxy::transport::Leg;

use tokio_util::sync::CancellationToken;

use common::{FakeRelay, SpawnedProxy};

// ── what the fixtures speak ────────────────────────────────────────────

/// Every draft this build compiled, oldest first. Each element carries its
/// own `#[cfg]`, so the array is the enabled set; the file-level gate above
/// guarantees it is non-empty, which makes [`DRAFT`]'s index a compile-time
/// fact rather than a panic.
///
/// Lifted from `backpressure_window.rs` for the same reason it exists
/// there: a hardcoded draft reddens every reduced-draft build whose draft
/// is not that one, and nothing in this file reads a draft anyway.
const COMPILED_DRAFTS: &[DraftVersion] = &[
    #[cfg(feature = "draft07")]
    DraftVersion::Draft07,
    #[cfg(feature = "draft08")]
    DraftVersion::Draft08,
    #[cfg(feature = "draft09")]
    DraftVersion::Draft09,
    #[cfg(feature = "draft10")]
    DraftVersion::Draft10,
    #[cfg(feature = "draft11")]
    DraftVersion::Draft11,
    #[cfg(feature = "draft12")]
    DraftVersion::Draft12,
    #[cfg(feature = "draft13")]
    DraftVersion::Draft13,
    #[cfg(feature = "draft14")]
    DraftVersion::Draft14,
    #[cfg(feature = "draft15")]
    DraftVersion::Draft15,
    #[cfg(feature = "draft16")]
    DraftVersion::Draft16,
    #[cfg(feature = "draft17")]
    DraftVersion::Draft17,
    #[cfg(feature = "draft18")]
    DraftVersion::Draft18,
    #[cfg(feature = "draft19")]
    DraftVersion::Draft19,
    #[cfg(feature = "draft20")]
    DraftVersion::Draft20,
];

/// The draft every session here is configured with: the newest one this
/// build compiled.
const DRAFT: DraftVersion = COMPILED_DRAFTS[COMPILED_DRAFTS.len() - 1];

/// The ALPN both legs speak.
///
/// `moq-00` leaves the session's draft unfixed, which only affects the
/// control parser — and nothing here builds one, because every session
/// runs behind `NoOpProxyObserver` and `NoOpHook` and is therefore a byte
/// pump. That is deliberate: this file measures QUIC packets, and a
/// framer between the payload and the wire would put a second thing
/// between the number asserted and the bytes that produced it.
const ALPN: &[u8] = b"moq-00";

/// The payload one session pushes through the proxy, in bytes.
///
/// Large enough that the capture's byte total is dominated by it rather
/// than by handshake and acknowledgement traffic, and small enough that
/// the whole file stays around a second of wall time. Every threshold
/// below is expressed as a fraction or multiple of this, so changing it
/// moves the brackets with it.
const PAYLOAD: usize = 100_000;

/// Cap for `read_to_end` on the forwarded stream.
const READ_CAP: usize = 4 * 1024 * 1024;

/// How long a wait that *must* end is given before it reports what it was
/// waiting for. A failure ceiling, never spent by a correct build.
const LIVENESS: Duration = Duration::from_secs(10);

/// How long the fixture waits before claiming a directory is **empty**.
///
/// The one wait here that a poll cannot replace, because the claim is
/// negative: no capture is written, and the only evidence for that is a
/// window in which none appeared. Every other wait in this file reads
/// [`Capture::read_when_whole`] instead, which waits for the file rather
/// than for the clock.
///
/// It was the wait before *every* read until 2026-08-26. What it was for
/// is real — the capture is a plain unbuffered `std::fs::File` and one
/// record reaches it as several small writes, so a read that raced the
/// very last one sees a fragment and is reported as truncation — but 200 ms
/// was a guess at how long that takes, and on a loaded box a guess that
/// short turns a whole capture into a truncation failure.
const SETTLE: Duration = Duration::from_millis(200);

/// How often [`Capture::read_when_whole`] looks again.
const RE_READ: Duration = Duration::from_millis(5);

// ── the capture, read as bytes ─────────────────────────────────────────

/// A qlog capture split into whole records.
///
/// Construction is where the format contract is enforced: JSON-SEQ frames
/// every record with a leading `0x1E` and a trailing newline, and a
/// capture whose last record has neither is the tail of a truncated file.
/// Nothing here filters — a record that does not parse fails the run,
/// because the format carries no end-of-trace marker and a skipped
/// fragment is the only evidence truncation ever leaves.
struct Capture {
    /// Record zero is the preamble; everything after it is one event.
    records: Vec<String>,
}

impl Capture {
    /// Read and split the capture at `path`.
    fn read(path: &Path) -> Self {
        let bytes = std::fs::read(path).unwrap_or_else(|e| {
            panic!(
                "no capture at {}: {e}. The preamble is written when the sink is built, so a \
                 missing file means the spec never became a sink at all",
                path.display()
            )
        });
        Self::parse(&bytes, path)
    }

    /// Read the capture at `path` once every record in it is whole.
    ///
    /// Called after the session has been torn down, so the writer is idle
    /// and the only thing between the file and its final record is one
    /// `write` that has not landed yet. That makes "every record is whole"
    /// the completion condition — an observable fact about the file, asked
    /// again every [`RE_READ`] until it holds.
    ///
    /// What it replaces is a flat 200 ms sleep before each read. The two
    /// agree on an idle machine and part company on a loaded one, where the
    /// sleep expires with the last record half-written and [`Self::parse`]
    /// reports the truncation it was put there to prevent. Giving up takes
    /// the same path, so a capture that is *really* truncated still fails
    /// with the message that says so rather than with a timeout.
    ///
    /// *Ablation:* drop the last byte of the capture between the teardown
    /// and this call. The wait then runs its full [`LIVENESS`] and gives up
    /// into `a record that is neither newline-terminated nor a closed
    /// object is the tail of a truncated capture` — the fragment named in
    /// the message, and the message this file already had.
    async fn read_when_whole(path: &Path) -> Self {
        let deadline = tokio::time::Instant::now() + LIVENESS;
        loop {
            if std::fs::read(path).is_ok_and(|bytes| Self::is_whole(&bytes)) {
                return Self::read(path);
            }
            if tokio::time::Instant::now() >= deadline {
                return Self::read(path);
            }
            tokio::time::sleep(RE_READ).await;
        }
    }

    /// [`Self::parse`]'s question, asked without failing the run.
    ///
    /// Deliberately not `parse(..).is_ok()`: `parse` answers by panicking,
    /// which is what it is for, and a read that has caught the writer
    /// mid-record is not a failure yet.
    fn is_whole(bytes: &[u8]) -> bool {
        let mut parts = bytes.split(|b| *b == 0x1e);
        if parts.next() != Some(&[][..]) {
            return false;
        }
        let mut any = false;
        for part in parts {
            any = true;
            let whole = std::str::from_utf8(part)
                .is_ok_and(|r| r.ends_with('\n') && r.trim_end().ends_with('}'));
            if !whole {
                return false;
            }
        }
        any
    }

    /// Split `bytes`, checking every record is whole.
    fn parse(bytes: &[u8], path: &Path) -> Self {
        let mut parts = bytes.split(|b| *b == 0x1e);
        assert_eq!(
            parts.next(),
            Some(&[][..]),
            "a JSON-SEQ capture opens with a record separator, so nothing precedes the first \
             record of {}",
            path.display()
        );

        let mut records = Vec::new();
        for part in parts {
            let record = std::str::from_utf8(part)
                .unwrap_or_else(|e| panic!("qlog writes UTF-8; {} does not: {e}", path.display()));
            assert!(
                record.ends_with('\n') && record.trim_end().ends_with('}'),
                "a record that is neither newline-terminated nor a closed object is the tail of \
                 a truncated capture, which is the only way truncation is visible in a format \
                 with no end-of-trace marker: {record:?}"
            );
            records.push(record.to_string());
        }

        assert!(
            !records.is_empty(),
            "a capture holds at least its preamble, written when the sink was built: {}",
            path.display()
        );
        Self { records }
    }

    /// The preamble, which names the qlog version and the framing.
    fn preamble(&self) -> &str {
        &self.records[0]
    }

    /// The `packet_type` of every `transport:packet_sent` record, in order.
    ///
    /// A sent-packet record with no packet type is a broken fixture rather
    /// than a packet of unknown kind: quinn fills the field on every
    /// packet it encodes, so its absence means the reader and the writer
    /// have stopped agreeing about the shape of a record.
    fn sent_packet_types(&self) -> Vec<String> {
        self.records
            .iter()
            .filter(|record| record.contains(r#""name":"transport:packet_sent""#))
            .map(|record| {
                let (_, after) = record.split_once(r#""packet_type":""#).unwrap_or_else(|| {
                    panic!("a sent packet with no packet type: {record}");
                });
                after
                    .split_once('"')
                    .unwrap_or_else(|| panic!("an unterminated packet type: {record}"))
                    .0
                    .to_string()
            })
            .collect()
    }

    /// How many 1-RTT packets this capture recorded sending, and how many
    /// bytes they carried.
    ///
    /// `1RTT` is matched exactly. The data packet-number space produces
    /// `0RTT` as well, and a substring match would fold a space this proxy
    /// never uses into the same total.
    ///
    /// A 1-RTT sent packet with no length panics rather than contributing
    /// zero. qlog encodes an absent field by omitting it, so a build that
    /// stopped recording sizes reads exactly like a connection that sent
    /// none — and "sent none" is the *passing* answer for the idle
    /// fixture, which is precisely where a silent zero would hide.
    fn one_rtt_sent(&self) -> (usize, u64) {
        let mut count = 0usize;
        let mut bytes = 0u64;

        for record in &self.records {
            if !record.contains(r#""name":"transport:packet_sent""#) {
                continue;
            }
            if !record.contains(r#""packet_type":"1RTT""#) {
                continue;
            }
            count += 1;

            let Some((_, after)) = record.split_once(r#""length":"#) else {
                panic!(
                    "a 1-RTT sent packet with no length. qlog omits an absent field rather than \
                     writing a null, so this is a capture that stopped recording sizes, not a \
                     connection that sent none: {record}"
                );
            };
            let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
            bytes += digits.parse::<u64>().unwrap_or_else(|e| {
                panic!("a packet length that is not a number ({digits:?}): {e}")
            });
        }

        (count, bytes)
    }
}

// ── somewhere to write ─────────────────────────────────────────────────

/// Distinguishes concurrent directories within one process. Test binaries
/// run their rows on several threads, so a name derived from the process
/// alone would be shared.
static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

/// A fresh, empty directory for one fixture's captures.
///
/// Emptied rather than merely created: two of the assertions below are
/// that *nothing* was written, and a directory holding a previous run's
/// artifact would answer them wrongly in the one direction that looks like
/// a pass.
fn capture_dir(name: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "moqtap-qlog-{}-{name}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("a capture directory: {e}"));
    dir
}

/// The names of everything in `dir`, sorted.
fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
        .map(|entry| entry.expect("a directory entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// A writer that creates its file on the first byte and not before.
///
/// The fixtures that read a capture open their file when they build the
/// spec, which is fine when the file is going to be read. It is useless for
/// asserting that *nothing* was written: `File::create` leaves an empty file
/// behind whether or not a sink was ever built, so a directory listing would
/// answer the same way for a leg that refused its spec and for one that
/// wrote a whole capture somewhere else.
///
/// Written lazily, the file exists exactly when a sink exists — the preamble
/// is the first thing through any capture's writer — so its presence is the
/// fact under test rather than an artefact of the fixture.
struct LazyFile {
    /// Where the capture goes, when there is one.
    path: PathBuf,
    /// Opened on the first write and kept.
    file: Option<std::fs::File>,
}

impl Write for LazyFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.file.is_none() {
            self.file = Some(std::fs::File::create(&self.path)?);
        }
        self.file.as_mut().expect("opened on the line above").write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match &mut self.file {
            Some(file) => file.flush(),
            // Nothing has been written, so there is nothing to flush and no
            // file to create in order to flush it.
            None => Ok(()),
        }
    }
}

/// A spec that would write to `path`, through [`LazyFile`].
///
/// `QlogSpec` is `#[non_exhaustive]`, so from outside the crate a struct
/// expression is illegal and `default()` plus assignment is the only
/// construction path there is.
fn lazy_spec(path: &Path) -> QlogSpec {
    let mut spec = QlogSpec::default();
    spec.writer = Some(Box::new(LazyFile { path: path.to_path_buf(), file: None }));
    spec.title = Some("relay leg".to_string());
    spec.description = Some("proxy to relay".to_string());
    spec
}

/// A writer that refuses every byte, standing in for a full disk or a path
/// that cannot be written.
struct Refuses;

impl Write for Refuses {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "no"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// ── the leg under capture ──────────────────────────────────────────────

/// A `quinn::TransportConfig` writing its capture to `path`, with path-MTU
/// discovery off.
///
/// The order is the whole of the wiring and each step is forced: the sink
/// is attached while a mutable reference to the config still exists,
/// because quinn's only setter for it mutates a `TransportConfig` and
/// there is no way to reach one through the `Arc` a leg is handed. See
/// this file's header for why discovery is off.
///
/// `std::fs::File` and not a `BufWriter`: the capture has no end-of-trace
/// record, so a buffered tail held until the sink is dropped is
/// indistinguishable from a run that stopped early.
fn captured_transport(path: &Path) -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport.mtu_discovery_config(None);

    let file = std::fs::File::create(path)
        .unwrap_or_else(|e| panic!("a capture file at {}: {e}", path.display()));

    // `QlogSpec` is `#[non_exhaustive]`, so from outside the crate a
    // struct expression is illegal and `default()` plus assignment is the
    // only construction path there is.
    let mut spec = QlogSpec::default();
    spec.writer = Some(Box::new(file));
    spec.title = Some("relay leg".to_string());
    spec.description = Some("proxy to relay".to_string());
    spec.attach_to(&mut transport).expect("a spec with a writer becomes a sink");

    Arc::new(transport)
}

/// A session config pointed at `upstream`, whose relay leg installs
/// `transport`.
fn captured_session(
    upstream: SocketAddr,
    transport: Arc<quinn::TransportConfig>,
) -> ProxySessionConfig {
    let mut config = common::session_config(DRAFT, upstream);
    config.upstream_transport_config = Some(transport);
    config
}

/// Start a byte-pump session in front of `upstream`.
fn spawn(config: ProxySessionConfig) -> SpawnedProxy {
    common::spawn_proxy_with(
        config,
        ALPN,
        Arc::new(NoOpProxyObserver) as Arc<dyn ProxyObserver>,
        Arc::new(NoOpHook) as Arc<dyn ProxyHook>,
    )
}

/// Run one session over one client connection and report what it returned.
///
/// The shared harness spawns a session and drops its result, which is right
/// for every fixture that measures traffic and wrong for one that is about a
/// refusal: the refusal *is* the return value. This is the same wiring with
/// the `Result` kept.
///
/// The client is closed as soon as it is connected. A leg that refuses never
/// gets that far — it fails before it dials the relay — but a build that
/// accepted the contradiction would forward happily until this fixture's
/// timeout, and a timeout reports which future was still pending rather than
/// what the leg decided.
async fn run_one_session(config: ProxySessionConfig) -> Result<(), ProxyError> {
    let (front_ep, addr) = common::spawn_quic_server(&[ALPN]);
    let cancel = CancellationToken::new();

    let session = ProxySession::new(
        SessionId(1),
        config,
        ALPN.to_vec(),
        Arc::new(NoOpProxyObserver) as Arc<dyn ProxyObserver>,
        Arc::new(NoOpHook) as Arc<dyn ProxyHook>,
        cancel,
    );
    let task = tokio::spawn(async move {
        let incoming = front_ep.accept().await.expect("the client's connection");
        let client = incoming.await.expect("the client's handshake");
        session.run(client).await
    });

    let (_client_ep, client) = common::connect_client(addr, ALPN).await;
    client.close(0u32.into(), b"done");

    tokio::time::timeout(LIVENESS, task)
        .await
        .expect("the session ended")
        .expect("the session task did not panic")
}

// ── the pair ───────────────────────────────────────────────────────────

/// The relay leg's capture records the payload the proxy forwarded onto
/// it.
///
/// The load-bearing claim of the whole module, and it is bracketed on both
/// sides. A lower bound alone is met by a capture totalling anything large;
/// an upper bound alone is met by a capture with no events in it at all.
/// Between them the total is pinned to the payload — QUIC framing and
/// acknowledgements are a few percent, so a figure half again as large is
/// counting something other than this session's traffic.
///
/// The `read_to_end` above the assertions is the anchor that makes them
/// about a capture rather than about a fixture: the relay confirms every
/// byte arrived, so a zero total below is the *capture* failing and not
/// the proxy.
///
/// Observed here, over five runs: 89 1-RTT packets totalling 103 009
/// bytes, then 89 / 103 009, 89 / 103 018, 89 / 103 016 and 89 / 103 007 —
/// 3.0% above the payload, against an upper bracket 20% above it. Whole
/// captures of 204 to 209 records.
///
/// *Ablation, and the failure this test exists for:* attach the sink to a
/// `quinn::TransportConfig` built beside the one the leg installs, which
/// is a two-line mistake and still produces a capture file that exists,
/// parses and names a qlog version. The 100 000 bytes still cross the
/// proxy and the relay still confirms them, and this fails with
///
/// ```text
/// the capture cannot record fewer bytes than the leg carried: 0 bytes over 0
/// 1-RTT packets, from a capture holding 1 record(s) in total
/// ```
///
/// One record: the preamble, written when the sink was built, and nothing
/// after it. In the same run the other three tests in this file stayed
/// green — which is what makes the idle test a control rather than a copy
/// of this one, and also what makes it worth its own ablation.
#[tokio::test]
async fn the_relay_legs_capture_counts_the_payload_the_proxy_forwarded() {
    common::init_crypto();

    let dir = capture_dir("forwarded");
    let path = dir.join("relay-leg.qlog");

    let relay = FakeRelay::bind(ALPN);
    let proxy = spawn(captured_session(relay.addr, captured_transport(&path)));

    let (_client_ep, client) = common::connect_client(proxy.addr, ALPN).await;
    let mut send = client.open_uni().await.expect("open_uni");
    send.write_all(&vec![0x5Au8; PAYLOAD]).await.expect("the payload");
    send.finish().expect("a clean finish");

    let mut recv = tokio::time::timeout(LIVENESS, relay.accept_uni())
        .await
        .expect("the proxy forwarded the client's stream to the relay");
    let forwarded = tokio::time::timeout(LIVENESS, recv.read_to_end(READ_CAP))
        .await
        .expect("the relay read the forwarded stream to its end")
        .expect("the forwarded stream did not fail");
    assert_eq!(
        forwarded.len(),
        PAYLOAD,
        "the payload has to have crossed the proxy, or the capture below is measuring nothing"
    );

    client.close(0u32.into(), b"done");
    proxy.shutdown().await;

    let capture = Capture::read_when_whole(&path).await;
    let (count, bytes) = capture.one_rtt_sent();

    assert!(
        bytes > PAYLOAD as u64,
        "the capture cannot record fewer bytes than the leg carried: {bytes} bytes over {count} \
         1-RTT packets, from a capture holding {} record(s) in total",
        capture.records.len()
    );
    assert!(
        bytes <= PAYLOAD as u64 * 6 / 5,
        "nor much more than it — QUIC framing and acknowledgements are a few percent, and a \
         figure half again as large means the total is counting something else: {bytes} bytes \
         over {count} 1-RTT packets"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A relay leg that connected and carried nothing captures its handshake,
/// and almost nothing else.
///
/// The control for the test above, and the reason that one's figure means
/// "this payload" rather than "some traffic". Same wiring, same proxy,
/// same capture reader; the only difference is that no stream is opened.
///
/// Note what is *not* claimed. A session that merely connects still sends
/// packets — quinn records one `transport:packet_sent` per encoded packet
/// in every packet-number space, so a handshake alone produces a handful
/// of them and a few 1-RTT packets after it. "The capture holds no sent
/// packets" would be red against a correct build. What separates the two
/// fixtures is the *size* of the 1-RTT total, and the Initial and
/// Handshake assertions are what stop "small" from being satisfiable by a
/// capture of nothing at all.
///
/// Observed here, over five runs, identically every time: 5 1-RTT packets
/// totalling 323 bytes, from a capture whose sent packets were two
/// Initials, one Handshake and those five. Against a ceiling of 10 000 and
/// a loaded figure of about 103 000, so the two fixtures are separated by
/// a factor of roughly 320.
///
/// *Ablation:* attaching the sink to a config this fixture does not
/// install — the same mistake the loaded test is built around — leaves
/// this test's size bound trivially satisfied at zero, and it is the
/// packet-type assertions that catch it instead:
///
/// ```text
/// a leg that completed a handshake sent Initial packets; a capture without them is a
/// capture of a connection that never happened, which would satisfy every size bound
/// below it: []
/// ```
///
/// That is the reason those two assertions are here at all. Without them
/// this test would be green against an empty capture, which is precisely
/// the state a broken sink leaves behind — and a control that passes when
/// the thing it controls for has happened is worse than no control, since
/// its green would be read as evidence.
#[tokio::test]
async fn a_relay_leg_that_carried_nothing_captures_its_handshake_and_little_else() {
    common::init_crypto();

    let dir = capture_dir("idle");
    let path = dir.join("relay-leg.qlog");

    let relay = FakeRelay::bind(ALPN);
    let proxy = spawn(captured_session(relay.addr, captured_transport(&path)));

    let (_client_ep, client) = common::connect_client(proxy.addr, ALPN).await;
    // The relay's side of the handshake completing is what makes this a
    // session that *connected* and carried nothing, rather than one that
    // never dialled.
    let _relay_conn = tokio::time::timeout(LIVENESS, relay.connection())
        .await
        .expect("the proxy dialled the relay and completed a handshake");

    client.close(0u32.into(), b"done");
    proxy.shutdown().await;

    let capture = Capture::read_when_whole(&path).await;

    assert!(
        capture.preamble().contains(r#""qlog_format":"JSON-SEQ""#),
        "the framing this file splits on is named in the preamble; a capture in any other \
         format is one nothing here can read: {}",
        capture.preamble()
    );

    let types = capture.sent_packet_types();
    assert!(
        types.iter().any(|kind| kind == "initial"),
        "a leg that completed a handshake sent Initial packets; a capture without them is a \
         capture of a connection that never happened, which would satisfy every size bound \
         below it: {types:?}"
    );
    assert!(
        types.iter().any(|kind| kind == "handshake"),
        "and Handshake packets after them — the Initial space alone is reached by a dial that \
         was never answered: {types:?}"
    );

    let (count, bytes) = capture.one_rtt_sent();
    assert!(
        bytes * 10 < PAYLOAD as u64,
        "a leg that carried nothing must not be mistakable for one that carried {PAYLOAD} \
         bytes: {bytes} bytes over {count} 1-RTT packets"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ── the feature that is off by default ─────────────────────────────────

/// Ask cargo what it resolves for this crate under `extra`.
fn cargo_tree(extra: &[&str]) -> String {
    let output = std::process::Command::new(env!("CARGO"))
        .args(["tree", "-p", "moqtap-proxy"])
        .args(extra)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap_or_else(|e| panic!("running `cargo tree {}`: {e}", extra.join(" ")));
    assert!(
        output.status.success(),
        "`cargo tree {}` failed: {}",
        extra.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("cargo writes UTF-8")
}

/// Without the feature there is nothing in the build that could write a
/// capture.
///
/// The absence of an artifact is asserted at its cause rather than by
/// looking at a directory, and the difference matters: an empty directory
/// is equally the answer for a run that never started, so it would be
/// satisfied by a broken fixture. What is checked instead is that the code
/// which writes captures is not compiled at all, in two independent
/// places:
///
/// * the `qlog` crate — the serialiser that produces every record — is
///   absent from the resolved dependency graph; and
/// * quinn is resolved *without* its own `qlog` feature, which is what
///   compiles the sink, the four emit sites and the one setter that
///   installs one.
///
/// Each is asserted against both resolutions, on and off, so neither half
/// can pass by always answering the same way. Together they say a
/// default-featured build has no sink type to construct, no setter to
/// install it with and no serialiser to write it, so no path to an
/// artifact exists — which is a stronger statement than any run of that
/// build could make, since a run only ever demonstrates the paths it took.
///
/// This test itself runs only when the feature is on, because the file it
/// lives in does. That is not circular: it asks the resolver about the
/// build it is not, which is the one question a process compiled one way
/// can answer about the other.
///
/// *Ablation:* give the crate's `quinn` dependency `features = ["qlog"]`
/// directly, so the capture code is compiled whether or not this crate's
/// own feature is on — which is exactly the mistake of wiring a writer
/// outside the switch that is supposed to gate it. Both halves fail on the
/// default build, the first reporting
///
/// ```text
/// the qlog crate writes every record of a capture; a default build that resolves it is a
/// build carrying the whole serialiser for a feature nobody asked for
/// ```
#[test]
fn with_the_feature_off_nothing_that_writes_a_capture_is_compiled() {
    let default_crates = cargo_tree(&["-e", "normal", "--prefix", "none"]);
    let qlog_crates = cargo_tree(&["-e", "normal", "--prefix", "none", "--features", "qlog"]);

    let resolves_qlog = |tree: &str| tree.lines().any(|line| line.starts_with("qlog v"));

    assert!(
        !resolves_qlog(&default_crates),
        "the qlog crate writes every record of a capture; a default build that resolves it is a \
         build carrying the whole serialiser for a feature nobody asked for"
    );
    assert!(
        resolves_qlog(&qlog_crates),
        "and it must be there when the feature is on, or the assertion above is true of every \
         build and says nothing about this one"
    );

    let default_features = cargo_tree(&["-e", "features", "-i", "quinn"]);
    let qlog_features = cargo_tree(&["-e", "features", "-i", "quinn", "--features", "qlog"]);
    let sink_compiled = |tree: &str| tree.contains(r#"quinn feature "qlog""#);

    assert!(
        !sink_compiled(&default_features),
        "quinn's own qlog feature is what compiles the sink and the one method that installs \
         it; without the feature there is no type a leg could be given"
    );
    assert!(
        sink_compiled(&qlog_features),
        "and turning this crate's feature on is what turns quinn's on — that edge is the whole \
         of the wiring, so a build where it is missing has a feature that does nothing"
    );
}

// ── a spec that names nowhere to write ─────────────────────────────────

/// A spec with no writer is refused where it is built, and the leg that
/// would have carried it captures nothing anywhere.
///
/// Two halves, and the second is why this is an integration test rather
/// than a unit one. The refusal on its own would be a claim about a return
/// value; what makes it a claim about the proxy is that the config the
/// refused spec was handed carries no sink, so a whole session run over it
/// — a real handshake, a real payload, a real forward — leaves the
/// directory it was pointed at empty.
///
/// The control arm is what stops "the directory is empty" from being the
/// answer a fixture that never ran would also give: the same directory,
/// the same session, one field changed, and a capture appears in it.
///
/// The refusal is also checked to be the *right* one. quinn answers a
/// missing writer with no sink and no error at all, which is the same
/// answer it gives for a writer that failed on its first byte, so a single
/// refusal covering both would send a caller who named no file off to look
/// at their disk. `NoWriter` and `NotStarted` are asserted against each
/// other here for that reason.
///
/// *Ablation:* give the control arm a writer-less spec too — that is, put
/// both halves in the state the refused arm is in — and the emptiness
/// assertion above stops being able to distinguish them:
///
/// ```text
/// assertion `left == right` failed: a spec that does name a writer produces a capture
/// in the same place the refused one did not, which is what makes the emptiness above a
/// fact about the refusal
///   left: []
///  right: ["relay-leg.qlog"]
/// ```
///
/// *A second ablation, not run here:* dropping the validation from
/// `QlogSpec::into_stream` and letting quinn answer a missing writer would
/// turn the first assertion's `NoWriter` into `NotStarted` — a caller who
/// named no file sent off to look at their disk. That mutation is in the
/// crate's own source rather than in this file, and the unit test beside
/// it carries the recorded run.
#[tokio::test]
async fn a_spec_with_no_writer_is_refused_and_its_leg_captures_nothing() {
    common::init_crypto();

    let dir = capture_dir("no-writer");

    // ── the refusal ──
    let mut transport = quinn::TransportConfig::default();
    transport.mtu_discovery_config(None);

    let mut blind = QlogSpec::default();
    blind.title = Some("relay leg".to_string());
    let refusal = blind.attach_to(&mut transport).expect_err(
        "a spec is how a caller asks for a capture; one with nowhere to write is a \
                     mistake, not a request for no capture",
    );
    assert_eq!(
        refusal,
        QlogError::NoWriter,
        "and it has to be refused as *that*: quinn's silent answer covers a missing writer and \
         a failing one alike, so a refusal that did not tell them apart would send a caller who \
         named no file to go and look at their disk"
    );

    let mut writes_nothing = QlogSpec::default();
    writes_nothing.writer = Some(Box::new(Refuses));
    assert_eq!(
        writes_nothing.attach_to(&mut quinn::TransportConfig::default()).err(),
        Some(QlogError::NotStarted),
        "a writer that exists and fails is the other fault, and pinning both directions is what \
         stops one refusal standing in for both"
    );

    // ── the leg that would have carried it ──
    let relay = FakeRelay::bind(ALPN);
    let proxy = spawn(captured_session(relay.addr, Arc::new(transport)));

    let (_client_ep, client) = common::connect_client(proxy.addr, ALPN).await;
    let mut send = client.open_uni().await.expect("open_uni");
    send.write_all(&vec![0x5Au8; PAYLOAD]).await.expect("the payload");
    send.finish().expect("a clean finish");

    let mut recv = tokio::time::timeout(LIVENESS, relay.accept_uni())
        .await
        .expect("the proxy forwarded the client's stream to the relay");
    let forwarded = tokio::time::timeout(LIVENESS, recv.read_to_end(READ_CAP))
        .await
        .expect("the relay read the forwarded stream to its end")
        .expect("the forwarded stream did not fail");
    assert_eq!(
        forwarded.len(),
        PAYLOAD,
        "the session must really have run, or the empty directory below is the answer for a \
         fixture that never started"
    );

    client.close(0u32.into(), b"done");
    proxy.shutdown().await;
    // A window, not a poll: the claim is that nothing appears, and only a
    // window is evidence of that. See [`SETTLE`].
    tokio::time::sleep(SETTLE).await;

    assert_eq!(
        entries(&dir),
        Vec::<String>::new(),
        "a refused spec installs nothing, so a session run over the config it was handed writes \
         no capture at all — not an empty one, and not one somewhere else"
    );

    // ── the control: the same directory, one field changed ──
    let path = dir.join("relay-leg.qlog");
    let relay = FakeRelay::bind(ALPN);
    let proxy = spawn(captured_session(relay.addr, captured_transport(&path)));

    let (_control_ep, control_client) = common::connect_client(proxy.addr, ALPN).await;
    let _relay_conn = tokio::time::timeout(LIVENESS, relay.connection())
        .await
        .expect("the proxy dialled the relay and completed a handshake");

    control_client.close(0u32.into(), b"done");
    proxy.shutdown().await;

    // The capture first, because waiting for it is waiting for the file the
    // assertion below is about. The directory listing is then read at an
    // instant when the capture is known to be there and whole.
    let capture = Capture::read_when_whole(&path).await;
    assert_eq!(
        entries(&dir),
        vec!["relay-leg.qlog".to_string()],
        "a spec that does name a writer produces a capture in the same place the refused one \
         did not, which is what makes the emptiness above a fact about the refusal"
    );
    assert!(
        !capture.sent_packet_types().is_empty(),
        "and one holding real packets rather than a bare preamble"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ── a leg that carries the spec itself ─────────────────────────────────

/// A leg that names a spec and nothing else still captures what it sent.
///
/// The case most likely to be silently wrong: "install nothing" is a
/// perfectly good answer for a leg with no transport opinion, which is what
/// a leg naming neither a raw config nor a profile otherwise looks like,
/// and it is the wrong answer for a leg whose one opinion is a capture. A
/// sink attached to a `quinn::TransportConfig` that no connection is made
/// with still writes its preamble, so such a build produces a file which
/// exists, parses, names a qlog version and can never hold an event — the
/// one failure a caller watching their disk cannot see.
///
/// So the assertion is on the bytes, as everywhere else in this file, and it
/// is bracketed on both sides for the same reason the pair at the top is.
/// The `read_to_end` above it is the anchor: the relay confirms the whole
/// payload arrived, so a zero total below is the capture failing rather than
/// the proxy.
///
/// Path-MTU discovery is **on** here, unlike the fixtures above, and that is
/// forced rather than chosen: turning it off needs a `TransportProfile`, and
/// a leg carrying one would no longer be the spec-alone case this exists to
/// pin. Observed here over five runs: 84 1-RTT packets totalling 108 338
/// bytes, then 83 / 108 278, 83 / 108 280, 82 / 108 244 and 82 / 108 244 —
/// 8.3% above the payload against the same 20% upper bracket, out of whole
/// captures of 185 to 202 records. That matches the discovery-on column of
/// this file's header table, which is what says the extra 5% over the
/// fixtures above is padded MTU probes rather than anything this session
/// sent.
///
/// *Ablation, and the failure this test exists for:* answer a leg carrying a
/// spec and neither transport field with "install nothing" — a one-arm
/// change. The 100 000 bytes still cross the proxy and the relay still
/// confirms every one, and this fails with
///
/// ```text
/// no capture at C:\Users\...\Temp\moqtap-qlog-64612-spec-alone-0\relay-leg.qlog: The
/// system cannot find the file specified. (os error 2). The preamble is written when the
/// sink is built, so a missing file means the spec never became a sink at all
/// ```
///
/// The file is missing rather than empty because the writer here creates it
/// on its first byte; with an eagerly opened file the same build would leave
/// a zero-length capture behind, which is why this fixture writes through
/// [`LazyFile`].
#[tokio::test]
async fn a_relay_leg_carrying_only_a_spec_still_captures_what_it_sent() {
    common::init_crypto();

    let dir = capture_dir("spec-alone");
    let path = dir.join("relay-leg.qlog");

    let relay = FakeRelay::bind(ALPN);
    // The whole fixture: a spec, and neither `upstream_transport_config` nor
    // `upstream_transport_profile`. Everything the leg installs is built
    // because the spec is there.
    let mut config = common::session_config(DRAFT, relay.addr);
    config.upstream_qlog = Some(lazy_spec(&path));
    let proxy = spawn(config);

    let (_client_ep, client) = common::connect_client(proxy.addr, ALPN).await;
    let mut send = client.open_uni().await.expect("open_uni");
    send.write_all(&vec![0x5Au8; PAYLOAD]).await.expect("the payload");
    send.finish().expect("a clean finish");

    let mut recv = tokio::time::timeout(LIVENESS, relay.accept_uni())
        .await
        .expect("the proxy forwarded the client's stream to the relay");
    let forwarded = tokio::time::timeout(LIVENESS, recv.read_to_end(READ_CAP))
        .await
        .expect("the relay read the forwarded stream to its end")
        .expect("the forwarded stream did not fail");
    assert_eq!(
        forwarded.len(),
        PAYLOAD,
        "the payload has to have crossed the proxy, or the capture below is measuring nothing"
    );

    client.close(0u32.into(), b"done");
    proxy.shutdown().await;

    let capture = Capture::read_when_whole(&path).await;
    let (count, bytes) = capture.one_rtt_sent();

    assert!(
        bytes > PAYLOAD as u64,
        "a leg that built its own config for the sink has to have installed it: {bytes} bytes \
         over {count} 1-RTT packets, from a capture holding {} record(s) in total",
        capture.records.len()
    );
    assert!(
        bytes <= PAYLOAD as u64 * 6 / 5,
        "nor much more than it — QUIC framing, acknowledgements and the padded MTU probes this \
         leg cannot turn off are a few percent each, and a figure half again as large means the \
         total is counting something else: {bytes} bytes over {count} 1-RTT packets"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A leg given a raw transport config *and* a spec is refused where it is
/// built, and captures nothing anywhere.
///
/// The contradiction that had no producer until each leg could carry a spec
/// of its own. quinn accepts a capture sink through exactly one method, and
/// that method mutates a `quinn::TransportConfig`; a leg's raw config arrives
/// as an `Arc<quinn::TransportConfig>`, which has no `Clone` and yields no
/// mutable reference while a second handle exists. A leg holding both could
/// therefore do one thing only: take the spec, count it as configured, and
/// deliver it nowhere.
///
/// Both halves are load-bearing and neither is enough alone.
///
/// The refusal has to be `TransportConfigAndQlog` and not
/// `TransportConfigAndProfile`: the two pairs have different fixes — apply
/// the profile to your own config, versus attach the sink to your own config
/// — and a caller told the wrong one goes looking at the wrong half of their
/// configuration. That is why it is a variant of its own rather than a
/// widening, and why this asserts the variant rather than that an error came
/// back.
///
/// And the directory has to be empty, because "refused" would otherwise be a
/// claim about a return value. A leg that refused *after* building the sink
/// would leave a file holding a preamble, which is indistinguishable from
/// the capture of a connection that carried nothing — the state the idle
/// fixture above exists to be told apart from.
///
/// *Ablation, the mutation this gate is built around:* accept the pair and
/// drop the spec — one arm of `transport::resolve`, and the only behaviour
/// available to a leg that tried to honour both. The session then dials the
/// relay, connects, and ends where every session in this file ends, on the
/// client's own close. The directory listing printed `[]` in that run, so
/// the emptiness assertion below passed exactly as it does against a correct
/// build and would have caught nothing. It is the refusal that fails, and it
/// fails on the variant rather than on there being no error at all:
///
/// ```text
/// the relay leg's contradiction has to be reported as the relay leg's, and as the
/// config-and-spec pair rather than the config-and-profile one — the two have different
/// fixes: transport error: connection error: closed by peer: done (code 0)
/// ```
///
/// That message is the session reporting a perfectly ordinary end. Which is
/// the whole point: a leg that accepts the pair is indistinguishable from a
/// correct one in everything except the capture that never appears.
#[tokio::test]
async fn a_leg_given_both_a_raw_config_and_a_spec_is_refused_and_captures_nothing() {
    common::init_crypto();

    let dir = capture_dir("both");
    let path = dir.join("relay-leg.qlog");

    // A real relay, *and* something driving its accept, so that a build
    // which accepted the pair connects and runs to a clean end. Without the
    // second half the mutation this gate is built around would be caught by
    // the upstream connect timing out, which is a fact about the fixture
    // rather than about the leg. Under a correct build nothing ever arrives
    // here and the task is aborted below having done nothing.
    let relay = Arc::new(FakeRelay::bind(ALPN));
    let accepting = {
        let relay = Arc::clone(&relay);
        tokio::spawn(async move {
            let _ = tokio::time::timeout(LIVENESS, relay.connection()).await;
        })
    };

    let mut config = common::session_config(DRAFT, relay.addr);
    config.upstream_transport_config = Some(Arc::new(quinn::TransportConfig::default()));
    config.upstream_qlog = Some(lazy_spec(&path));

    let err = run_one_session(config)
        .await
        .expect_err("naming both is a contradiction, not a configuration a leg can honour");
    accepting.abort();
    assert!(
        matches!(err, ProxyError::TransportConfigAndQlog { leg: Leg::Upstream }),
        "the relay leg's contradiction has to be reported as the relay leg's, and as the \
         config-and-spec pair rather than the config-and-profile one — the two have different \
         fixes: {err}"
    );

    assert_eq!(
        entries(&dir),
        Vec::<String>::new(),
        "a refused leg installs no sink, and a sink writes its preamble the instant it is built, \
         so a file here would be a capture begun on the way to refusing — one holding a preamble \
         and no event, which is exactly what the capture of a quiet connection looks like"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ── a spec handed to something that copies its configuration ───────────

/// A `TransparentProxy` whose template carries a spec is refused before it
/// binds, on either leg, and captures nothing.
///
/// A `TransparentProxy` holds both configurations as a **template** and
/// copies them — the listener's once when it binds, the session's once per
/// accepted connection. A `QlogSpec` owns its writer, has no `Clone`, and is
/// consumed when it becomes a sink, so a copy has nothing to hand over and
/// one writer cannot be divided between the connections a proxy accepts
/// anyway.
///
/// The only two things a proxy could do with such a template are refuse it
/// and drop it, and dropping it is this crate's cardinal failure with
/// nothing at all to give it away: the proxy binds, accepts, forwards and
/// reports success, and the single symptom is a file that was never created
/// — which a caller reads as *the run produced no events*, not as *the
/// capture was never installed*. Every other refusal in this file is loud
/// because a connection failed; this one has to be loud on its own.
///
/// Both legs get a row, because they are two fields on two different structs
/// reached by two different copies, and a check written for one of them
/// compiles green with the other left out. Each row asserts the leg it names,
/// not merely that an error came back.
///
/// The directory assertion is what makes "refused" a claim about the world
/// rather than about a return value: the refusal is answered before a socket
/// exists, so no sink is built and no preamble is written. It works only
/// because these specs write through [`LazyFile`] — an eagerly opened file
/// would be there whatever the proxy decided.
///
/// # Ablation, run
///
/// The two-leg check at the top of `TransparentProxy::run` in `src/proxy.rs`
/// made unreachable, which is the whole of the mutation: the copies below it
/// already write `None`, so removing the refusal restores exactly the silent
/// drop. What comes back is what the mutation *is* — the proxy binds and
/// serves:
///
/// ```text
/// a spec set on a proxy template has to be refused rather than dropped, and as the leg
/// it was set on: the copy the proxy makes cannot carry it, so a proxy that came up
/// would report success and never create the file — Err(Elapsed(()))
/// ```
///
/// `test result: FAILED. 0 passed; 1 failed ... finished in 10.01s`, against
/// 0.03 s green. The first attempt at this row awaited `run()` bare and did
/// not fail at all under the mutation — it **hung**, because a proxy that
/// accepts the template is a proxy whose accept loop never returns, and a
/// gate that hangs is worse than one that is missing. That is why the call is
/// bounded, and why `Elapsed` rather than `Ok(())` is the message on record.
///
/// The capture directory listed `[]` under the mutation too, exactly as it
/// does against a correct build — which is what makes the refusal assertion
/// the load-bearing half and the listing the half that proves nothing was
/// begun on the way to it.
///
/// Recorded without the `file:line` prefix rustc prints and without the
/// per-run thread id, because editing this paragraph moves the line it would
/// name.
#[tokio::test]
async fn a_proxy_template_carrying_a_spec_is_refused_on_either_leg() {
    common::init_crypto();

    for leg in [Leg::Client, Leg::Upstream] {
        let dir = capture_dir("template");
        let path = dir.join("templated-leg.qlog");

        let relay = FakeRelay::bind(ALPN);
        let (cert_chain, key_der) = common::self_signed_localhost();
        let mut session = common::session_config(DRAFT, relay.addr);
        let mut listener = ListenerConfig {
            bind_addr: "127.0.0.1:0".parse().expect("a literal address"),
            cert_chain,
            key_der,
            transport_config: None,
            transport_profile: None,
            installer: None,
            qlog: None,
        };
        match leg {
            Leg::Client => listener.qlog = Some(lazy_spec(&path)),
            Leg::Upstream => session.upstream_qlog = Some(lazy_spec(&path)),
        }

        let proxy = TransparentProxy::new(
            ProxyConfig { listener, session },
            Arc::new(NoOpProxyObserver) as Arc<dyn ProxyObserver>,
        );
        // Bounded, because the failure this row is about is a proxy that
        // comes *up*: `run` is an accept loop that returns only on a refusal
        // or on cancellation, so a build that dropped the spec would leave
        // this row hanging rather than reddening. The ceiling turns that into
        // a sentence. A correct build refuses before it binds and never
        // spends any of it.
        let outcome = tokio::time::timeout(LIVENESS, proxy.run()).await;
        proxy.cancel_token().cancel();

        assert!(
            matches!(&outcome, Ok(Err(ProxyError::QlogOnProxyTemplate { leg: reported }))
                     if *reported == leg),
            "a spec set on a proxy template has to be refused rather than dropped, and as the leg \
             it was set on: the copy the proxy makes cannot carry it, so a proxy that came up \
             would report success and never create the file — {outcome:?}"
        );
        assert_eq!(
            entries(&dir),
            Vec::<String>::new(),
            "and the refusal arrives before a sink is built, so there is no preamble on disk to \
             read as the start of a capture that never happened"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
