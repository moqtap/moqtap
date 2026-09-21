#![cfg(feature = "draft14")]

//! A fetch stream a client accepts reports the header it decoded.
//!
//! `Connection::accept_subgroup_stream` emits two events — `StreamOpened` and
//! `DataStreamHeader` — so an observer learns both that a stream arrived and
//! what its header said. `accept_fetch_stream` emitted only the first, and the
//! header it had just decoded reached nobody.
//!
//! `DataStreamHeader` cannot carry one: its `header` field is an
//! `AnySubgroupHeader`. `ClientEvent::FetchStreamHeader` is the variant for
//! this — typed `AnyFetchHeader`, documented "A fetch response stream header
//! was decoded", defined on all the drafts since this crate's first
//! release, and emitted by nothing in any commit before this gate. A consumer
//! writing a trace from these events recorded a header for every subgroup
//! stream and none for a fetch stream, while recording the objects on both.
//!
//! # Why both events are asserted, and in order
//!
//! A header event that arrived before the `StreamOpened` naming its stream
//! would be a report about a stream the observer has not been told about, so
//! the order is part of the claim rather than an artefact of how the assertion
//! is written. Both carry the same `stream_id` for the same reason: two events
//! about one stream that disagree on which stream it is are worse than one.
//!
//! The absence of `DataStreamHeader` is asserted too. It is what separates
//! "the fetch header is reported" from "some header is reported": an
//! implementation that reached for the subgroup event would be typed out of
//! it, but one that emitted both would be describing a fetch stream as a
//! subgroup one.
//!
//! # Ablation, measured
//!
//! Dropping the `FetchStreamHeader` emission from
//! `draft14::connection::accept_fetch_stream` — the state this crate was in
//! before this file existed — and running under `--features draft14`:
//!
//! ```text
//! a fetch stream must report the header it decoded, and no FetchStreamHeader was emitted; the observer saw ["ControlMessage", "ControlMessage", "SetupComplete", "StreamOpened"]
//! ```
//!
//! The file was restored byte for byte afterwards and the gate is green again.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use moqtap_client::draft14::connection::{
    ClientConfig, Connection, FramedSendStream, TransportType,
};
use moqtap_client::draft14::event::{ClientEvent, Direction, StreamKind};
use moqtap_client::draft14::observer::ConnectionObserver;
use moqtap_client::transport::SendStream;
use moqtap_codec::dispatch::{AnyControlMessage, AnyFetchHeader};
use moqtap_codec::draft14::data_stream::FetchHeader;
use moqtap_codec::draft14::message::{ControlMessage, ServerSetup};
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// Carried on the header so the assertion reads a value the writer chose
/// rather than a default any header would have.
const REQUEST_ID: u64 = 7;

const PATIENCE: Duration = Duration::from_secs(10);

#[derive(Clone)]
struct Recorder {
    events: Arc<Mutex<Vec<ClientEvent>>>,
}

impl ConnectionObserver for Recorder {
    fn on_event(&self, event: &ClientEvent) {
        self.events.lock().unwrap().push(event.clone());
    }
}

impl Recorder {
    fn new() -> Self {
        Recorder { events: Arc::new(Mutex::new(Vec::new())) }
    }

    fn snapshot(&self) -> Vec<ClientEvent> {
        self.events.lock().unwrap().clone()
    }
}

/// Event names in arrival order, for a failure message that says what the
/// observer actually saw rather than only what it did not.
fn labels(events: &[ClientEvent]) -> Vec<&'static str> {
    events
        .iter()
        .map(|e| match e {
            ClientEvent::SetupComplete { .. } => "SetupComplete",
            ClientEvent::ControlMessage { .. } => "ControlMessage",
            ClientEvent::StreamOpened { .. } => "StreamOpened",
            ClientEvent::StreamClosed { .. } => "StreamClosed",
            ClientEvent::DataStreamHeader { .. } => "DataStreamHeader",
            ClientEvent::FetchStreamHeader { .. } => "FetchStreamHeader",
            ClientEvent::SubgroupObjectReceived { .. } => "SubgroupObjectReceived",
            ClientEvent::FetchObjectReceived { .. } => "FetchObjectReceived",
            ClientEvent::DatagramReceived { .. } => "DatagramReceived",
            ClientEvent::Draining { .. } => "Draining",
            ClientEvent::Closed { .. } => "Closed",
            ClientEvent::Error { .. } => "Error",
            _ => "Unknown",
        })
        .collect()
}

fn client_config() -> ClientConfig {
    ClientConfig {
        draft: DraftVersion::Draft14,
        additional_versions: Vec::new(),
        transport: TransportType::Quic,
        skip_cert_verification: true,
        ca_certs: Vec::new(),
        setup_parameters: Vec::new(),
    }
}

/// Answer CLIENT_SETUP and hand back the live connection.
async fn server_handshake(endpoint: quinn::Endpoint) -> quinn::Connection {
    let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");
    let (send, recv) = conn.accept_bi().await.expect("accept_bi");
    let (mut framed_send, mut framed_recv) = common::frame_bi(send, recv, DraftVersion::Draft14);

    let (msg, _) = framed_recv.read_control(false).await.expect("read CLIENT_SETUP");
    let selected = match msg {
        AnyControlMessage::Draft14(ControlMessage::ClientSetup(cs)) => cs.supported_versions[0],
        other => panic!("expected CLIENT_SETUP, got {other:?}"),
    };
    let server_setup = AnyControlMessage::Draft14(ControlMessage::ServerSetup(ServerSetup {
        selected_version: selected,
        parameters: Vec::new(),
    }));
    framed_send.write_control(&server_setup).await.expect("write SERVER_SETUP");
    conn
}

#[tokio::test]
async fn accepting_a_fetch_stream_reports_the_header_it_decoded() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft14.quic_alpn()]);

    let server = tokio::spawn(async move {
        let quic = server_handshake(endpoint).await;
        let send = quic.open_uni().await.expect("open_uni");
        let mut framed = FramedSendStream::new(SendStream::Quic(send), DraftVersion::Draft14);
        let header = AnyFetchHeader::Draft14(FetchHeader {
            request_id: VarInt::from_u64(REQUEST_ID).unwrap(),
        });
        framed.write_fetch_header(&header).await.expect("write fetch header");
        framed.finish().await.expect("finish");
        // Hold the connection open: a close here would race the client's read
        // and turn a missing event into a transport error.
        let _ = quic.closed().await;
    });

    let mut conn =
        Connection::connect(&addr.to_string(), client_config()).await.expect("client connect");

    // Attached after the handshake, which does not keep the setup traffic out
    // of the recording: `set_observer` drains `pending_events` into the new
    // observer, so the two CLIENT_SETUP/SERVER_SETUP `ControlMessage`s and the
    // `SetupComplete` arrive first. That is why the ordering assertion below
    // is relative rather than positional.
    let recorder = Recorder::new();
    conn.set_observer(Box::new(recorder.clone()));

    let (header, _stream) = tokio::time::timeout(PATIENCE, conn.accept_fetch_stream())
        .await
        .expect("a fetch stream within the timeout")
        .expect("accept_fetch_stream");

    match &header {
        AnyFetchHeader::Draft14(h) => assert_eq!(
            h.request_id.into_inner(),
            REQUEST_ID,
            "the returned header must be the one the writer wrote"
        ),
        // With draft14 as the only enabled draft `AnyFetchHeader` has a single
        // variant, the arm above is exhaustive and this one unreachable.
        #[cfg(any(
            feature = "draft07",
            feature = "draft08",
            feature = "draft09",
            feature = "draft10",
            feature = "draft11",
            feature = "draft12",
            feature = "draft13",
            feature = "draft15",
            feature = "draft16",
            feature = "draft17",
            feature = "draft18",
            feature = "draft19",
            feature = "draft20",
            feature = "draft21"
        ))]
        other => panic!("expected a draft-14 fetch header, got {other:?}"),
    }

    let events = recorder.snapshot();
    let seen = labels(&events);

    let opened = events.iter().find_map(|e| match e {
        ClientEvent::StreamOpened { stream_kind: StreamKind::Fetch, direction, stream_id } => {
            Some((*direction, *stream_id))
        }
        _ => None,
    });
    let (opened_direction, opened_stream) = opened.unwrap_or_else(|| {
        panic!("accepting a fetch stream must report the stream; the observer saw {seen:?}")
    });
    assert_eq!(opened_direction, Direction::Receive, "the stream was accepted, not opened");

    let reported = events.iter().find_map(|e| match e {
        ClientEvent::FetchStreamHeader { stream_id, direction, header } => {
            Some((*stream_id, *direction, header.clone()))
        }
        _ => None,
    });
    let (header_stream, header_direction, reported_header) = reported.unwrap_or_else(|| {
        panic!(
            "a fetch stream must report the header it decoded, and no FetchStreamHeader was \
             emitted; the observer saw {seen:?}"
        )
    });

    assert_eq!(header_direction, Direction::Receive, "the header arrived, it was not written");
    assert_eq!(
        header_stream, opened_stream,
        "both events are about one stream and must name the same one"
    );
    match reported_header {
        AnyFetchHeader::Draft14(h) => assert_eq!(
            h.request_id.into_inner(),
            REQUEST_ID,
            "the reported header must be the one that was decoded, not a default"
        ),
        // Unreachable for the same reason as the match above.
        #[cfg(any(
            feature = "draft07",
            feature = "draft08",
            feature = "draft09",
            feature = "draft10",
            feature = "draft11",
            feature = "draft12",
            feature = "draft13",
            feature = "draft15",
            feature = "draft16",
            feature = "draft17",
            feature = "draft18",
            feature = "draft19",
            feature = "draft20",
            feature = "draft21"
        ))]
        other => panic!("expected a draft-14 fetch header on the event, got {other:?}"),
    }

    assert!(
        !events.iter().any(|e| matches!(e, ClientEvent::DataStreamHeader { .. })),
        "a fetch stream is not a subgroup stream and must not be reported as one; the observer \
         saw {seen:?}"
    );

    assert!(
        seen.iter().position(|l| *l == "StreamOpened")
            < seen.iter().position(|l| *l == "FetchStreamHeader"),
        "the stream must be announced before anything is said about its header; the observer \
         saw {seen:?}"
    );

    drop(conn);
    let _ = tokio::time::timeout(PATIENCE, server).await;
}
