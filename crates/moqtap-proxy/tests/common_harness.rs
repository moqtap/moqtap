//! The shared harness, exercised against a live proxy session.
//!
//! `tests/common/mod.rs` is the shared harness every test unit in this
//! crate is written against. None of the older test files touches its
//! newer half — `TimedReceiver`, `FakeRelay`,
//! `RecordingObserver`, `SpawnedProxy::counters`, `assert_no_bytes_for`,
//! `assert_no_uni_stream_for` — so without this file those helpers would
//! ship unrun and five units would discover their defects one at a time.
//!
//! What is asserted here is the *harness*, not the proxy: that a
//! `TimedReceiver` really reports per-object bytes and the instant each
//! arrived, that `Ending` distinguishes a FIN from a reset and carries the
//! code, that a `FakeRelay` can initiate teardown in **either** direction,
//! and that a session's counters are readable while it runs.

//! Every fixture here is a draft-19 subgroup stream, and `DRAFT` pins the
//! session to draft-19, so the file is gated on that draft: it compiles
//! and runs on the rows that can speak it, and vanishes on the rest.

#![cfg(feature = "draft19")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use moqtap_codec::dispatch::{AnySubgroupHeader, AnySubgroupObject, AnySubgroupObjectWriter};
use moqtap_codec::version::DraftVersion;

use moqtap_proxy::event::ProxySide;
use moqtap_proxy::hook::NoOpHook;
use moqtap_proxy::observer::ProxyObserver;

use common::{Ending, FakeRelay, RecordingObserver, TimedReceiver};

const DRAFT: DraftVersion = DraftVersion::Draft19;
const RESET_CODE: u64 = 0x2A;
const STOP_CODE: u64 = 0x0B;

/// How long the client waits between objects.
const GAP: Duration = Duration::from_millis(120);

/// How much of that gap the recorded instants must reproduce. Well under
/// `GAP`, so a loaded machine cannot fail this by being slow — only a
/// receiver that is not stamping per read can.
const MIN_GAP: Duration = Duration::from_millis(60);

/// The Track Aliases the two-stream demux fixture tells its streams apart
/// by. Neither is `0x01`, the single-stream fixture's alias, so a demux
/// that ignored the header and answered with a default could not pass by
/// accident.
const ALIAS_VIDEO: u8 = 0x07;
const ALIAS_AUDIO: u8 = 0x09;

/// A draft-19 subgroup stream, split at object boundaries: the header and
/// three objects, each returned separately so the test can write them with
/// a real gap between them.
///
/// The gap is what makes the timing claim falsifiable. A `TimedReceiver`
/// must record an instant at each `read` return, not once at end of stream;
/// one that stamped every chunk at end of stream would report three
/// identical instants and pass any assertion that only checked
/// monotonicity.
fn subgroup_pieces() -> (Vec<u8>, Vec<Vec<u8>>) {
    subgroup_stream(0x01, &[(0, vec![0xA0; 8]), (1, vec![0xA1; 4]), (2, vec![0xA2; 2048])])
}

/// The same, for an explicit Track Alias and object list.
///
/// The alias is a fixture choice — it is what
/// [`FakeRelay::timed_uni_by_alias`] demuxes on, so two streams built here
/// with different aliases are tellable apart on the wire and not just by
/// the order a test happened to write them in. Single-byte varint range
/// only (`< 64`), so the header stays five bytes whatever the caller
/// picks.
fn subgroup_stream(track_alias: u8, objects: &[(u64, Vec<u8>)]) -> (Vec<u8>, Vec<Vec<u8>>) {
    assert!(track_alias < 64, "track alias {track_alias} needs a multi-byte varint");
    let head = vec![0x14u8, track_alias, 0x00, 0x00, 0x80];
    let mut cursor = &head[..];
    let header =
        AnySubgroupHeader::decode_stream(DRAFT, &mut cursor).expect("subgroup header decode");
    let mut writer = AnySubgroupObjectWriter::new(&header).expect("subgroup object writer");

    let mut encoded = Vec::new();
    for (object_id, payload) in objects {
        let obj = AnySubgroupObject {
            object_id: *object_id,
            extension_headers: Vec::new(),
            extension_count: None,
            status: None,
            payload: payload.clone(),
        };
        let mut buf = Vec::new();
        writer.write_object(&obj, &mut buf).expect("write object");
        encoded.push(buf);
    }
    (head, encoded)
}

/// A `TimedReceiver` reports the bytes, the objects inside them, the
/// instant each object arrived, and a clean FIN; the `RecordingObserver`
/// sees the same objects; and the session's counters are readable while
/// the session is still up.
#[tokio::test]
async fn the_harness_reports_objects_bytes_timing_and_counters() {
    common::init_crypto();

    let (head, objects) = subgroup_pieces();
    let stream: Vec<u8> = head.iter().copied().chain(objects.iter().flatten().copied()).collect();
    let relay = Arc::new(FakeRelay::bind(b"moq-00"));

    let observer = Arc::new(RecordingObserver::new());
    let proxy = common::spawn_proxy_with(
        common::session_config(DRAFT, relay.addr),
        b"moq-00",
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::new(NoOpHook),
    );

    let relay_for_task = Arc::clone(&relay);
    let uni = tokio::spawn(async move { relay_for_task.timed_uni().await });

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, b"moq-00").await;
    let mut send = client_conn.open_uni().await.expect("open_uni");
    // Header and object 0 together, then a real pause before each of the
    // next two. `GAP` is the timing signal the assertions below read back.
    send.write_all(&head).await.expect("write header");
    send.write_all(&objects[0]).await.expect("write object 0");
    for object in &objects[1..] {
        tokio::time::sleep(GAP).await;
        // In small pieces, so the 2 KiB object straddles read boundaries
        // and `into_objects` has to reassemble rather than read one chunk.
        for piece in object.chunks(64) {
            send.write_all(piece).await.expect("write object");
        }
    }
    send.finish().expect("finish");

    let rx: TimedReceiver = tokio::time::timeout(common::TIMEOUT, uni)
        .await
        .expect("relay saw the stream")
        .expect("join");

    let got = rx.wait_for_bytes(stream.len()).await;
    assert_eq!(got, stream, "the harness must capture every forwarded byte");
    assert_eq!(rx.wait_for_ending().await, Ending::Fin, "a clean FIN must read back as a FIN");
    assert_eq!(rx.ending().and_then(|e| e.reset_code()), None, "a FIN carries no reset code");

    // Nothing more arrives after the FIN. The same helper a later unit
    // points at a `Delay` window.
    common::assert_no_bytes_for(&rx, Duration::from_millis(100)).await;

    let objects = rx.into_objects(DRAFT);
    assert_eq!(
        objects.iter().map(|(_, meta, _)| meta.object_id).collect::<Vec<_>>(),
        vec![0, 1, 2],
        "per-object re-framing of the captured stream"
    );
    assert_eq!(
        objects.iter().map(|(_, meta, _)| meta.payload_len).collect::<Vec<_>>(),
        vec![8, 4, 2048],
        "each object's payload length, read off the wire the harness captured"
    );
    // The point of the helper: per-object *bytes*, not just metadata. The
    // header plus every object's raw slice must reproduce the stream.
    let mut rebuilt = stream[..5].to_vec();
    for (_, _, raw) in &objects {
        rebuilt.extend_from_slice(raw);
    }
    assert_eq!(rebuilt, stream, "object raw slices must concatenate back to the wire");

    // Timing. The client paused `GAP` before each of objects 1 and 2, so
    // their recorded instants must be that far apart — which is only true
    // if the stamp was taken when each `read` returned. A `TimedReceiver`
    // that stamped everything once at end of stream reports three equal
    // instants and fails here while every byte assertion above still
    // passes; that contrast is the reason this assertion is written
    // against a measured gap rather than against monotonicity.
    let stamps: Vec<_> = objects.iter().map(|(at, _, _)| *at).collect();
    assert!(stamps[0] >= rx.started(), "an arrival instant must not precede the receiver");
    for i in 1..stamps.len() {
        let apart = stamps[i].duration_since(stamps[i - 1]);
        assert!(
            apart >= MIN_GAP,
            "objects {} and {i} were recorded {apart:?} apart; the client left {GAP:?} between \
             them, so the stamps are not per-read",
            i - 1
        );
    }

    assert_eq!(
        observer.objects().iter().map(|m| m.object_id).collect::<Vec<_>>(),
        vec![0, 1, 2],
        "RecordingObserver must record framed objects"
    );
    assert!(
        observer.applied().is_empty() && observer.refused().is_empty(),
        "a NoOpHook session takes no actions: {:?} / {:?}",
        observer.applied(),
        observer.refused()
    );

    let counters = proxy.counters();
    assert!(
        counters.framer_object_polls > 0,
        "the session's counters must be readable while it runs, and this one framed a stream"
    );
    assert_eq!(counters.objects_elided, 0, "nothing was elided");

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

/// A relay-initiated `RESET_STREAM` reaches the client with its code —
/// `FakeRelay::push_then_reset`, the relay-initiated sending direction.
#[tokio::test]
async fn the_fake_relay_can_reset_a_stream_it_sends() {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(b"moq-00"));
    let observer = Arc::new(RecordingObserver::new());
    let proxy = common::spawn_proxy_with(
        common::session_config(DRAFT, relay.addr),
        b"moq-00",
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::new(NoOpHook),
    );

    const PUSHED: &[u8] = &[0x04, 0x01, 0x02, 0x03];

    let (held_tx, held_rx) = tokio::sync::oneshot::channel::<()>();
    let relay_for_task = Arc::clone(&relay);
    let push = tokio::spawn(async move {
        relay_for_task.push_then_reset(PUSHED, held_rx, RESET_CODE).await;
    });

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, b"moq-00").await;
    let mut recv = tokio::time::timeout(common::TIMEOUT, client_conn.accept_uni())
        .await
        .expect("client saw the forwarded stream")
        .expect("accept_uni");

    // Held before the relay is told it may reset, so the reset cannot
    // overtake the bytes it is supposed to follow.
    let mut held = vec![0u8; PUSHED.len()];
    tokio::time::timeout(common::TIMEOUT, recv.read_exact(&mut held))
        .await
        .expect("the pushed bytes arrived")
        .expect("the bytes written before the reset must reach the client");
    let _ = held_tx.send(());

    let (rest, ending) = tokio::time::timeout(common::TIMEOUT, common::drain(&mut recv))
        .await
        .expect("stream terminated");

    assert_eq!(ending, Ending::Reset(RESET_CODE), "the relay's reset code must survive the proxy");
    assert_eq!(ending.reset_code(), Some(RESET_CODE), "Ending::reset_code reads the code back");
    assert_eq!(held, PUSHED, "the bytes written before the reset still arrive, unaltered");
    assert_eq!(rest, 0, "and nothing else arrives after them");
    assert!(
        observer.resets().contains(&(ProxySide::RelayToProxy, RESET_CODE)),
        "RecordingObserver must record the teardown: {:?}",
        observer.resets()
    );

    let _ = push.await;
    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

/// A relay-initiated `STOP_SENDING` reaches the client with its code —
/// `FakeRelay::accept_then_stop`, the receiving direction. Without this
/// half the harness could only drive teardown from the client, and every
/// relay-initiated teardown path would go untested.
#[tokio::test]
async fn the_fake_relay_can_stop_a_stream_it_receives() {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(b"moq-00"));
    let observer = Arc::new(RecordingObserver::new());
    let proxy = common::spawn_proxy_with(
        common::session_config(DRAFT, relay.addr),
        b"moq-00",
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::new(NoOpHook),
    );

    let relay_for_task = Arc::clone(&relay);
    let stopper = tokio::spawn(async move { relay_for_task.accept_then_stop(STOP_CODE).await });

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, b"moq-00").await;
    let mut send = client_conn.open_uni().await.expect("open_uni");
    send.write_all(&[0x14, 0x01]).await.expect("write");

    // Keep writing until the proxy mirrors the relay's STOP_SENDING back
    // onto this stream.
    let observed = tokio::time::timeout(common::TIMEOUT, async {
        loop {
            match send.write_all(&[0u8; 256]).await {
                Ok(()) => tokio::time::sleep(Duration::from_millis(20)).await,
                Err(quinn::WriteError::Stopped(code)) => return code.into_inner(),
                Err(e) => panic!("unexpected client write error: {e:?}"),
            }
        }
    })
    .await
    .expect("the client was stopped");

    assert_eq!(observed, STOP_CODE, "the relay's STOP_SENDING code must survive the proxy");

    // Held so the deliberate stop is not immediately followed by the
    // default-code stop that dropping a `RecvStream` sends.
    let _held = stopper.await.expect("join");
    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

/// Two destination streams in flight at once, told apart by the Track
/// Alias in their headers — `FakeRelay::timed_uni_by_alias`, over
/// `timed_uni_n`.
///
/// The claim is that the demux is keyed on *identity*, not on arrival
/// order. So the fixture makes the two orders disagree, deterministically
/// and with no sleep anywhere:
///
/// * the client opens the video stream first, so the proxy accepts it
///   first and opens its destination stream first — quinn reports remote
///   streams in stream-ID order, which is open order, so the relay's
///   *accept* order is video, then audio;
/// * the test asks for `[audio, video]`, the reverse.
///
/// That accept order is not assumed on faith: with the demux ablated to
/// return accept order, this test failed with `left: Some(7)` (video)
/// where it wanted `Some(9)` (audio) on 9 runs out of 9.
///
/// A demux that handed back accept order would therefore return video
/// where this test reads audio, and every byte assertion below would be
/// comparing one stream against the other's bytes. That the two streams
/// differ in length as well as content is what makes that comparison fail
/// loudly rather than by one byte.
///
/// The second claim is concurrency: the receivers come back while **both**
/// streams are still open, which is asserted directly — neither has an
/// `ending` yet, because the client has not finished either. A helper that
/// drained each stream to its end before accepting the next could not
/// return here at all.
#[tokio::test]
async fn the_relay_can_take_two_streams_and_tell_them_apart() {
    common::init_crypto();

    let (video_head, video_objects) =
        subgroup_stream(ALIAS_VIDEO, &[(0, vec![0xE0; 16]), (1, vec![0xE1; 512])]);
    let (audio_head, audio_objects) = subgroup_stream(ALIAS_AUDIO, &[(0, vec![0xD0; 4])]);
    let video: Vec<u8> =
        video_head.iter().copied().chain(video_objects.iter().flatten().copied()).collect();
    let audio: Vec<u8> =
        audio_head.iter().copied().chain(audio_objects.iter().flatten().copied()).collect();
    assert_ne!(video.len(), audio.len(), "the two streams must not be confusable by length");

    let relay = Arc::new(FakeRelay::bind(b"moq-00"));
    let observer = Arc::new(RecordingObserver::new());
    let proxy = common::spawn_proxy_with(
        common::session_config(DRAFT, relay.addr),
        b"moq-00",
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::new(NoOpHook),
    );

    // Audio first: the opposite of the order the client opens them in.
    let relay_for_task = Arc::clone(&relay);
    let demux = tokio::spawn(async move {
        relay_for_task
            .timed_uni_by_alias(&[u64::from(ALIAS_AUDIO), u64::from(ALIAS_VIDEO)], DRAFT)
            .await
    });

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, b"moq-00").await;
    let mut video_send = client_conn.open_uni().await.expect("open_uni video");
    let mut audio_send = client_conn.open_uni().await.expect("open_uni audio");

    // Interleaved object by object, so neither stream is a prefix of a
    // quiet period on the other and both really are in flight together.
    video_send.write_all(&video_head).await.expect("write video header");
    audio_send.write_all(&audio_head).await.expect("write audio header");
    for i in 0..video_objects.len().max(audio_objects.len()) {
        if let Some(object) = video_objects.get(i) {
            video_send.write_all(object).await.expect("write video object");
        }
        if let Some(object) = audio_objects.get(i) {
            audio_send.write_all(object).await.expect("write audio object");
        }
    }

    let got: Vec<TimedReceiver> = tokio::time::timeout(common::TIMEOUT, demux)
        .await
        .expect("the relay demuxed both streams")
        .expect("join");
    assert_eq!(got.len(), 2, "one receiver per requested alias");
    let (audio_rx, video_rx) = (&got[0], &got[1]);

    // Neither stream has been finished, so the demux cannot have waited
    // for one to end before accepting the other.
    assert_eq!(audio_rx.ending(), None, "the audio stream must still be open");
    assert_eq!(video_rx.ending(), None, "the video stream must still be open");

    assert_eq!(
        audio_rx.track_alias(DRAFT),
        Some(u64::from(ALIAS_AUDIO)),
        "the receiver returned for the audio alias must carry the audio header"
    );
    assert_eq!(
        video_rx.track_alias(DRAFT),
        Some(u64::from(ALIAS_VIDEO)),
        "the receiver returned for the video alias must carry the video header"
    );

    assert_eq!(
        audio_rx.wait_for_bytes(audio.len()).await,
        audio,
        "the audio receiver must carry the audio stream's bytes and no others"
    );
    assert_eq!(
        video_rx.wait_for_bytes(video.len()).await,
        video,
        "the video receiver must carry the video stream's bytes and no others"
    );

    // The same identity, read back through the re-framed objects: a test
    // that holds one of these receivers can key on `ObjectMeta` too.
    assert_eq!(
        video_rx
            .into_objects(DRAFT)
            .iter()
            .map(|(_, m, _)| (m.track_alias, m.payload_len))
            .collect::<Vec<_>>(),
        vec![(Some(u64::from(ALIAS_VIDEO)), 16), (Some(u64::from(ALIAS_VIDEO)), 512)],
        "every object on the video receiver belongs to the video track"
    );
    assert_eq!(
        audio_rx
            .into_objects(DRAFT)
            .iter()
            .map(|(_, m, _)| (m.track_alias, m.payload_len))
            .collect::<Vec<_>>(),
        vec![(Some(u64::from(ALIAS_AUDIO)), 4)],
        "every object on the audio receiver belongs to the audio track"
    );

    // Two distinct streams really did cross the proxy, not one seen twice.
    let mut aliases: Vec<Option<u64>> = observer.objects().iter().map(|m| m.track_alias).collect();
    aliases.sort_unstable();
    aliases.dedup();
    let mut want = vec![Some(u64::from(ALIAS_VIDEO)), Some(u64::from(ALIAS_AUDIO))];
    want.sort_unstable();
    assert_eq!(aliases, want, "the session must have framed objects on both tracks");

    video_send.finish().expect("finish video");
    audio_send.finish().expect("finish audio");
    assert_eq!(video_rx.wait_for_ending().await, Ending::Fin, "the video stream ends cleanly");
    assert_eq!(audio_rx.wait_for_ending().await, Ending::Fin, "the audio stream ends cleanly");

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

/// `assert_no_uni_stream_for` holds when the client opens nothing.
///
/// The helper `tests/actions_streams.rs` uses to prove a stream rejected
/// at `Site::StreamOpen` never reached the far end.
#[tokio::test]
async fn no_uni_stream_reaches_a_relay_the_client_never_opened_one_towards() {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(b"moq-00"));
    let proxy = common::spawn_proxy_with(
        common::session_config(DRAFT, relay.addr),
        b"moq-00",
        Arc::new(moqtap_proxy::observer::NoOpProxyObserver),
        Arc::new(NoOpHook),
    );

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, b"moq-00").await;
    let relay_conn = tokio::time::timeout(common::TIMEOUT, relay.connection())
        .await
        .expect("the proxy connected upstream");

    common::assert_no_uni_stream_for(&relay_conn, Duration::from_millis(300)).await;

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}
