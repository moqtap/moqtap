use std::fs::File;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};

use moqtap_client::connection::{ClientConfig, Connection, ConnectionError, TransportType};
use moqtap_codec::dispatch::{AnyObjectHeader, AnySubgroupHeader};
use moqtap_codec::draft14::message::ControlMessage;
use moqtap_codec::types::*;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;
use moqtap_trace::event::{Direction, EventData, TraceEvent};
use moqtap_trace::header::{DetailLevel, Perspective, TraceHeader};
use moqtap_trace::reader::MoqTraceReader;
use moqtap_trace::writer::MoqTraceWriter;
use moqtap_trace::Value;

/// moqtap — MoQT debugging and tracing tool
#[derive(Parser)]
#[command(name = "moqtap", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Connect to a MoQT server and subscribe to a track
    Subscribe {
        /// Server address (host:port)
        #[arg(short, long)]
        server: String,

        /// Track namespace (slash-separated, e.g. "live/stream")
        #[arg(short, long)]
        namespace: String,

        /// Track name
        #[arg(short, long)]
        track: String,

        /// Filter type: next-group, largest, absolute-start, absolute-range
        #[arg(short, long, default_value = "next-group")]
        filter: String,

        /// Subscriber priority (0-255)
        #[arg(long, default_value = "128")]
        priority: u8,

        /// Skip TLS certificate verification
        #[arg(long, default_value = "false")]
        insecure: bool,

        /// Write trace to this .moqtrace file
        #[arg(long)]
        trace: Option<String>,
    },

    /// Connect to a MoQT server and fetch a track range
    Fetch {
        /// Server address (host:port)
        #[arg(short, long)]
        server: String,

        /// Track namespace (slash-separated)
        #[arg(short, long)]
        namespace: String,

        /// Track name
        #[arg(short, long)]
        track: String,

        /// Start group ID
        #[arg(long, default_value = "0")]
        start_group: u64,

        /// Start object ID
        #[arg(long, default_value = "0")]
        start_object: u64,

        /// Skip TLS certificate verification
        #[arg(long, default_value = "false")]
        insecure: bool,

        /// Write trace to this .moqtrace file
        #[arg(long)]
        trace: Option<String>,
    },

    /// Read and display a .moqtrace file
    Trace {
        /// Path to the .moqtrace file
        file: String,

        /// Output format: text, json
        #[arg(short, long, default_value = "text")]
        format: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Subscribe { server, namespace, track, filter, priority, insecure, trace } => {
            cmd_subscribe(server, namespace, track, filter, priority, insecure, trace).await
        }
        Commands::Fetch {
            server,
            namespace,
            track,
            start_group,
            start_object,
            insecure,
            trace,
        } => cmd_fetch(server, namespace, track, start_group, start_object, insecure, trace).await,
        Commands::Trace { file, format } => cmd_trace(file, format),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        process::exit(1);
    }
}

fn parse_namespace(s: &str) -> TrackNamespace {
    let elements: Vec<Vec<u8>> = s.split('/').map(|p| p.as_bytes().to_vec()).collect();
    TrackNamespace(elements)
}

fn parse_filter(s: &str) -> Result<FilterType, String> {
    match s {
        "next-group" => Ok(FilterType::NextGroupStart),
        "largest" => Ok(FilterType::LargestObject),
        "absolute-start" => Ok(FilterType::AbsoluteStart),
        "absolute-range" => Ok(FilterType::AbsoluteRange),
        other => Err(format!("unknown filter type: {other}")),
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

fn msg_type_name(msg: &ControlMessage) -> &'static str {
    match msg {
        ControlMessage::ClientSetup(_) => "CLIENT_SETUP",
        ControlMessage::ServerSetup(_) => "SERVER_SETUP",
        ControlMessage::GoAway(_) => "GOAWAY",
        ControlMessage::MaxRequestId(_) => "MAX_REQUEST_ID",
        ControlMessage::RequestsBlocked(_) => "REQUESTS_BLOCKED",
        ControlMessage::Subscribe(_) => "SUBSCRIBE",
        ControlMessage::SubscribeOk(_) => "SUBSCRIBE_OK",
        ControlMessage::SubscribeError(_) => "SUBSCRIBE_ERROR",
        ControlMessage::SubscribeUpdate(_) => "SUBSCRIBE_UPDATE",
        ControlMessage::Unsubscribe(_) => "UNSUBSCRIBE",
        ControlMessage::Publish(_) => "PUBLISH",
        ControlMessage::PublishOk(_) => "PUBLISH_OK",
        ControlMessage::PublishError(_) => "PUBLISH_ERROR",
        ControlMessage::PublishDone(_) => "PUBLISH_DONE",
        ControlMessage::PublishNamespace(_) => "PUBLISH_NAMESPACE",
        ControlMessage::PublishNamespaceOk(_) => "PUBLISH_NAMESPACE_OK",
        ControlMessage::PublishNamespaceError(_) => "PUBLISH_NAMESPACE_ERROR",
        ControlMessage::PublishNamespaceDone(_) => "PUBLISH_NAMESPACE_DONE",
        ControlMessage::PublishNamespaceCancel(_) => "PUBLISH_NAMESPACE_CANCEL",
        ControlMessage::SubscribeNamespace(_) => "SUBSCRIBE_NAMESPACE",
        ControlMessage::SubscribeNamespaceOk(_) => "SUBSCRIBE_NAMESPACE_OK",
        ControlMessage::SubscribeNamespaceError(_) => "SUBSCRIBE_NAMESPACE_ERROR",
        ControlMessage::UnsubscribeNamespace(_) => "UNSUBSCRIBE_NAMESPACE",
        ControlMessage::Fetch(_) => "FETCH",
        ControlMessage::FetchOk(_) => "FETCH_OK",
        ControlMessage::FetchError(_) => "FETCH_ERROR",
        ControlMessage::FetchCancel(_) => "FETCH_CANCEL",
        ControlMessage::TrackStatus(_) => "TRACK_STATUS",
        ControlMessage::TrackStatusOk(_) => "TRACK_STATUS_OK",
        ControlMessage::TrackStatusError(_) => "TRACK_STATUS_ERROR",
    }
}

fn msg_request_id(msg: &ControlMessage) -> Option<u64> {
    match msg {
        ControlMessage::Subscribe(m) => Some(m.request_id.into_inner()),
        ControlMessage::SubscribeOk(m) => Some(m.request_id.into_inner()),
        ControlMessage::SubscribeError(m) => Some(m.request_id.into_inner()),
        ControlMessage::SubscribeUpdate(m) => Some(m.request_id.into_inner()),
        ControlMessage::Unsubscribe(m) => Some(m.request_id.into_inner()),
        ControlMessage::PublishDone(m) => Some(m.request_id.into_inner()),
        ControlMessage::Fetch(m) => Some(m.request_id.into_inner()),
        ControlMessage::FetchOk(m) => Some(m.request_id.into_inner()),
        ControlMessage::FetchError(m) => Some(m.request_id.into_inner()),
        ControlMessage::FetchCancel(m) => Some(m.request_id.into_inner()),
        ControlMessage::MaxRequestId(m) => Some(m.request_id.into_inner()),
        ControlMessage::SubscribeNamespace(m) => Some(m.request_id.into_inner()),
        ControlMessage::SubscribeNamespaceOk(m) => Some(m.request_id.into_inner()),
        ControlMessage::SubscribeNamespaceError(m) => Some(m.request_id.into_inner()),
        ControlMessage::UnsubscribeNamespace(m) => Some(m.request_id.into_inner()),
        ControlMessage::PublishNamespace(m) => Some(m.request_id.into_inner()),
        ControlMessage::PublishNamespaceOk(m) => Some(m.request_id.into_inner()),
        ControlMessage::PublishNamespaceError(m) => Some(m.request_id.into_inner()),
        ControlMessage::PublishNamespaceDone(m) => Some(m.request_id.into_inner()),
        ControlMessage::PublishNamespaceCancel(m) => Some(m.request_id.into_inner()),
        ControlMessage::Publish(m) => Some(m.request_id.into_inner()),
        ControlMessage::PublishOk(m) => Some(m.request_id.into_inner()),
        ControlMessage::PublishError(m) => Some(m.request_id.into_inner()),
        ControlMessage::TrackStatus(m) => Some(m.request_id.into_inner()),
        ControlMessage::TrackStatusOk(m) => Some(m.request_id.into_inner()),
        ControlMessage::TrackStatusError(m) => Some(m.request_id.into_inner()),
        ControlMessage::RequestsBlocked(m) => Some(m.maximum_request_id.into_inner()),
        _ => None,
    }
}

fn msg_type_id(msg: &ControlMessage) -> u64 {
    use moqtap_codec::draft14::message::MessageType;
    match msg {
        ControlMessage::ClientSetup(_) => MessageType::ClientSetup.id(),
        ControlMessage::ServerSetup(_) => MessageType::ServerSetup.id(),
        ControlMessage::GoAway(_) => MessageType::GoAway.id(),
        ControlMessage::MaxRequestId(_) => MessageType::MaxRequestId.id(),
        ControlMessage::RequestsBlocked(_) => MessageType::RequestsBlocked.id(),
        ControlMessage::Subscribe(_) => MessageType::Subscribe.id(),
        ControlMessage::SubscribeOk(_) => MessageType::SubscribeOk.id(),
        ControlMessage::SubscribeError(_) => MessageType::SubscribeError.id(),
        ControlMessage::SubscribeUpdate(_) => MessageType::SubscribeUpdate.id(),
        ControlMessage::Unsubscribe(_) => MessageType::Unsubscribe.id(),
        ControlMessage::Publish(_) => MessageType::Publish.id(),
        ControlMessage::PublishOk(_) => MessageType::PublishOk.id(),
        ControlMessage::PublishError(_) => MessageType::PublishError.id(),
        ControlMessage::PublishDone(_) => MessageType::PublishDone.id(),
        ControlMessage::PublishNamespace(_) => MessageType::PublishNamespace.id(),
        ControlMessage::PublishNamespaceOk(_) => MessageType::PublishNamespaceOk.id(),
        ControlMessage::PublishNamespaceError(_) => MessageType::PublishNamespaceError.id(),
        ControlMessage::PublishNamespaceDone(_) => MessageType::PublishNamespaceDone.id(),
        ControlMessage::PublishNamespaceCancel(_) => MessageType::PublishNamespaceCancel.id(),
        ControlMessage::SubscribeNamespace(_) => MessageType::SubscribeNamespace.id(),
        ControlMessage::SubscribeNamespaceOk(_) => MessageType::SubscribeNamespaceOk.id(),
        ControlMessage::SubscribeNamespaceError(_) => MessageType::SubscribeNamespaceError.id(),
        ControlMessage::UnsubscribeNamespace(_) => MessageType::UnsubscribeNamespace.id(),
        ControlMessage::Fetch(_) => MessageType::Fetch.id(),
        ControlMessage::FetchOk(_) => MessageType::FetchOk.id(),
        ControlMessage::FetchError(_) => MessageType::FetchError.id(),
        ControlMessage::FetchCancel(_) => MessageType::FetchCancel.id(),
        ControlMessage::TrackStatus(_) => MessageType::TrackStatus.id(),
        ControlMessage::TrackStatusOk(_) => MessageType::TrackStatusOk.id(),
        ControlMessage::TrackStatusError(_) => MessageType::TrackStatusError.id(),
    }
}

/// Build a CBOR map with the message's key fields (e.g. requestId).
fn msg_to_cbor(msg: &ControlMessage) -> Value {
    let mut pairs: Vec<(Value, Value)> = Vec::new();

    pairs.push((Value::Text("type".into()), Value::Text(msg_type_name(msg).into())));

    if let Some(rid) = msg_request_id(msg) {
        pairs.push((Value::Text("requestId".into()), Value::Integer(rid.into())));
    }

    Value::Map(pairs)
}

// ── Trace helpers ────────────────────────────────────────────

struct TraceSession {
    writer: MoqTraceWriter<File>,
    seq: u64,
    start_time: u64,
}

impl TraceSession {
    fn new(path: &str, server: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let start_time = now_ms();
        let header = TraceHeader {
            protocol: "moq-transport-14".into(),
            perspective: Perspective::Client,
            detail: DetailLevel::Headers,
            start_time,
            end_time: None,
            transport: Some("raw-quic".into()),
            source: Some(format!("moqtap/{}", env!("CARGO_PKG_VERSION"))),
            endpoint: Some(server.to_string()),
            session_id: None,
            custom: None,
        };
        let file = File::create(path)?;
        let writer = MoqTraceWriter::new(file, &header)?;
        Ok(Self { writer, seq: 0, start_time })
    }

    fn timestamp_us(&self) -> i64 {
        let now = now_ms();
        ((now - self.start_time) * 1000) as i64
    }

    fn write_control(
        &mut self,
        msg: &ControlMessage,
        direction: Direction,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let event = TraceEvent {
            seq: self.seq,
            timestamp: self.timestamp_us(),
            data: EventData::ControlMessage {
                direction,
                message_type: msg_type_id(msg),
                message: msg_to_cbor(msg),
                raw: None,
            },
        };
        self.seq += 1;
        self.writer.write_event(&event)?;
        Ok(())
    }

    fn write_state_change(
        &mut self,
        from: &str,
        to: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let event = TraceEvent {
            seq: self.seq,
            timestamp: self.timestamp_us(),
            data: EventData::StateChange { from: from.into(), to: to.into() },
        };
        self.seq += 1;
        self.writer.write_event(&event)?;
        Ok(())
    }

    fn write_stream_opened(
        &mut self,
        stream_id: u64,
        direction: Direction,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let event = TraceEvent {
            seq: self.seq,
            timestamp: self.timestamp_us(),
            data: EventData::StreamOpened {
                stream_id,
                direction,
                stream_type: moqtap_trace::event::StreamType::Subgroup,
            },
        };
        self.seq += 1;
        self.writer.write_event(&event)?;
        Ok(())
    }

    fn write_object_header(
        &mut self,
        stream_id: u64,
        group: u64,
        object_status: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let event = TraceEvent {
            seq: self.seq,
            timestamp: self.timestamp_us(),
            data: EventData::ObjectHeader {
                stream_id,
                group,
                object: 0,
                publisher_priority: 128,
                object_status,
            },
        };
        self.seq += 1;
        self.writer.write_event(&event)?;
        Ok(())
    }

    fn write_object_payload(
        &mut self,
        stream_id: u64,
        group: u64,
        size: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let event = TraceEvent {
            seq: self.seq,
            timestamp: self.timestamp_us(),
            data: EventData::ObjectPayload { stream_id, group, object: 0, size, payload: None },
        };
        self.seq += 1;
        self.writer.write_event(&event)?;
        Ok(())
    }

    fn write_stream_closed(&mut self, stream_id: u64) -> Result<(), Box<dyn std::error::Error>> {
        let event = TraceEvent {
            seq: self.seq,
            timestamp: self.timestamp_us(),
            data: EventData::StreamClosed { stream_id, error_code: 0 },
        };
        self.seq += 1;
        self.writer.write_event(&event)?;
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.writer.flush()?;
        Ok(())
    }
}

// ── Subscribe command ───────────────────────────────────────

async fn cmd_subscribe(
    server: String,
    namespace: String,
    track: String,
    filter: String,
    priority: u8,
    insecure: bool,
    trace_path: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let filter_type = parse_filter(&filter)?;
    let ns = parse_namespace(&namespace);
    let track_name = track.as_bytes().to_vec();

    let mut trace = trace_path.as_ref().map(|p| TraceSession::new(p, &server)).transpose()?;

    eprintln!("connecting to {server}...");
    let config = ClientConfig {
        draft: DraftVersion::Draft14,
        transport: TransportType::Quic,
        skip_cert_verification: insecure,
        ca_certs: Vec::new(),
    };
    let mut conn = Connection::connect(&server, config).await?;
    eprintln!(
        "connected, version: 0x{:x}",
        conn.negotiated_version().map(|v| v.into_inner()).unwrap_or(0)
    );

    if let Some(ref mut t) = trace {
        t.write_state_change("idle", "connected")?;
    }

    // Need MAX_REQUEST_ID before we can subscribe
    eprintln!("waiting for MAX_REQUEST_ID...");
    loop {
        let msg = conn.recv_and_dispatch().await?;
        eprintln!("  <- {}", msg_type_name(&msg));

        if let Some(ref mut t) = trace {
            t.write_control(&msg, Direction::Receive)?;
        }

        if matches!(msg, ControlMessage::MaxRequestId(_)) {
            break;
        }
    }

    eprintln!("subscribing to {namespace}/{track}...");
    let req_id =
        conn.subscribe(ns, track_name, priority, GroupOrder::Ascending, filter_type).await?;
    eprintln!("  -> SUBSCRIBE (request_id={})", req_id.into_inner());

    if let Some(ref mut t) = trace {
        // Record the SUBSCRIBE we just sent
        let msg_cbor = Value::Map(vec![
            (Value::Text("type".into()), Value::Text("SUBSCRIBE".into())),
            (Value::Text("requestId".into()), Value::Integer(req_id.into_inner().into())),
        ]);
        let event = TraceEvent {
            seq: t.seq,
            timestamp: t.timestamp_us(),
            data: EventData::ControlMessage {
                direction: Direction::Send,
                message_type: 0x03, // SUBSCRIBE
                message: msg_cbor,
                raw: None,
            },
        };
        t.seq += 1;
        t.writer.write_event(&event)?;
    }

    // Read responses
    eprintln!("waiting for response...");
    loop {
        let msg = match conn.recv_and_dispatch().await {
            Ok(m) => m,
            Err(ConnectionError::Transport(_)) => {
                eprintln!("connection closed by server");
                break;
            }
            Err(ConnectionError::UnexpectedEnd) => {
                eprintln!("stream ended");
                break;
            }
            Err(e) => return Err(e.into()),
        };

        if let Some(ref mut t) = trace {
            t.write_control(&msg, Direction::Receive)?;
        }

        match &msg {
            ControlMessage::SubscribeOk(ok) => {
                eprintln!(
                    "  <- SUBSCRIBE_OK (request_id={}, track_alias={})",
                    ok.request_id.into_inner(),
                    ok.track_alias.into_inner()
                );
                eprintln!("subscription active, reading data streams...");
                read_data_streams(&conn, &mut trace).await?;
                break;
            }
            ControlMessage::SubscribeError(err) => {
                eprintln!(
                    "  <- SUBSCRIBE_ERROR (request_id={}, code={}): {}",
                    err.request_id.into_inner(),
                    err.error_code.into_inner(),
                    String::from_utf8_lossy(&err.reason_phrase),
                );
                break;
            }
            ControlMessage::GoAway(ga) => {
                eprintln!("  <- GOAWAY (uri={})", String::from_utf8_lossy(&ga.new_session_uri));
                break;
            }
            other => {
                eprintln!("  <- {}", msg_type_name(other));
            }
        }
    }

    if let Some(ref mut t) = trace {
        t.write_state_change("connected", "closed")?;
        t.flush()?;
        eprintln!("trace written to {}", trace_path.unwrap());
    }

    conn.close(0, b"done");
    Ok(())
}

async fn read_data_streams(
    conn: &Connection,
    trace: &mut Option<TraceSession>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream_counter: u64 = 0;

    loop {
        match conn.accept_subgroup_stream().await {
            Ok((any_header, mut stream)) => {
                let stream_id = stream_counter;
                stream_counter += 1;

                // Unwrap to draft-14 (CLI only supports draft-14 for now)
                let header = match any_header {
                    AnySubgroupHeader::Draft14(h) => h,
                    _ => panic!("CLI only supports draft-14"),
                };

                eprintln!(
                    "  <- subgroup stream: track_alias={}, \
                     group={}, subgroup={}",
                    header.track_alias.into_inner(),
                    header.group.into_inner(),
                    header.subgroup.into_inner(),
                );

                if let Some(ref mut t) = trace {
                    t.write_stream_opened(stream_id, Direction::Receive)?;
                }

                loop {
                    match stream.read_object_header().await {
                        Ok(any_obj) => {
                            let obj_header = match any_obj {
                                AnyObjectHeader::Draft14(h) => h,
                                _ => panic!("CLI only supports draft-14"),
                            };
                            let payload_len =
                                obj_header.payload_length.map(|v| v.into_inner()).unwrap_or(0)
                                    as usize;

                            let payload = if payload_len > 0 {
                                stream.read_payload(payload_len).await?
                            } else {
                                Vec::new()
                            };

                            eprintln!(
                                "    object: status={:?}, \
                                 payload={} bytes",
                                obj_header.object_status,
                                payload.len()
                            );

                            let os = match obj_header.object_status {
                                ObjectStatus::Normal => 0,
                                ObjectStatus::EndOfGroup => 1,
                                ObjectStatus::EndOfTrack => 2,
                                ObjectStatus::DoesNotExist => 3,
                            };

                            if let Some(ref mut t) = trace {
                                t.write_object_header(stream_id, header.group.into_inner(), os)?;
                                if !payload.is_empty() {
                                    t.write_object_payload(
                                        stream_id,
                                        header.group.into_inner(),
                                        payload.len() as u64,
                                    )?;
                                }
                            }

                            if !payload.is_empty() {
                                if let Ok(text) = std::str::from_utf8(&payload) {
                                    println!("{text}");
                                } else {
                                    println!("[{} bytes binary data]", payload.len());
                                }
                            }

                            if obj_header.object_status == ObjectStatus::EndOfTrack {
                                eprintln!("  end of track");
                                return Ok(());
                            }
                        }
                        Err(ConnectionError::UnexpectedEnd) => {
                            eprintln!("  stream ended");
                            break;
                        }
                        Err(e) => return Err(e.into()),
                    }
                }

                if let Some(ref mut t) = trace {
                    t.write_stream_closed(stream_id)?;
                }
            }
            Err(ConnectionError::Transport(_)) => {
                eprintln!("connection closed");
                break;
            }
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

// ── Fetch command ───────────────────────────────────────────

async fn cmd_fetch(
    server: String,
    namespace: String,
    track: String,
    start_group: u64,
    start_object: u64,
    insecure: bool,
    trace_path: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ns = parse_namespace(&namespace);
    let track_name = track.as_bytes().to_vec();

    let mut trace = trace_path.as_ref().map(|p| TraceSession::new(p, &server)).transpose()?;

    eprintln!("connecting to {server}...");
    let config = ClientConfig {
        draft: DraftVersion::Draft14,
        transport: TransportType::Quic,
        skip_cert_verification: insecure,
        ca_certs: Vec::new(),
    };
    let mut conn = Connection::connect(&server, config).await?;
    eprintln!(
        "connected, version: 0x{:x}",
        conn.negotiated_version().map(|v| v.into_inner()).unwrap_or(0)
    );

    // Wait for MAX_REQUEST_ID
    eprintln!("waiting for MAX_REQUEST_ID...");
    loop {
        let msg = conn.recv_and_dispatch().await?;
        eprintln!("  <- {}", msg_type_name(&msg));
        if matches!(msg, ControlMessage::MaxRequestId(_)) {
            break;
        }
    }

    let sg = VarInt::from_u64(start_group)?;
    let so = VarInt::from_u64(start_object)?;

    eprintln!(
        "fetching {namespace}/{track} from \
         group={start_group} object={start_object}..."
    );
    let req_id = conn.fetch(ns, track_name, sg, so).await?;
    eprintln!("  -> FETCH (request_id={})", req_id.into_inner());

    // Read responses
    loop {
        let msg = match conn.recv_and_dispatch().await {
            Ok(m) => m,
            Err(ConnectionError::Transport(_)) => {
                eprintln!("connection closed");
                break;
            }
            Err(ConnectionError::UnexpectedEnd) => {
                eprintln!("stream ended");
                break;
            }
            Err(e) => return Err(e.into()),
        };

        match &msg {
            ControlMessage::FetchOk(ok) => {
                eprintln!("  <- FETCH_OK (request_id={})", ok.request_id.into_inner());
                eprintln!("fetch active, reading data...");
                read_data_streams(&conn, &mut trace).await?;
                break;
            }
            ControlMessage::FetchError(err) => {
                eprintln!(
                    "  <- FETCH_ERROR (request_id={}, code={}): {}",
                    err.request_id.into_inner(),
                    err.error_code.into_inner(),
                    String::from_utf8_lossy(&err.reason_phrase),
                );
                break;
            }
            other => {
                eprintln!("  <- {}", msg_type_name(other));
            }
        }
    }

    if let Some(ref mut t) = trace {
        t.flush()?;
        eprintln!("trace written to {}", trace_path.unwrap());
    }

    conn.close(0, b"done");
    Ok(())
}

// ── Trace command ───────────────────────────────────────────

fn cmd_trace(file: String, format: String) -> Result<(), Box<dyn std::error::Error>> {
    let f = File::open(&file)?;
    let reader = MoqTraceReader::new(f)?;
    let header = reader.header().clone();

    let mut events = Vec::new();
    for result in reader.into_iter() {
        let event = result?;
        events.push(event);
    }

    // Display header info
    eprintln!("--- Header ---");
    eprintln!("Protocol:    {}", header.protocol);
    eprintln!("Perspective: {:?}", header.perspective);
    eprintln!("Detail:      {:?}", header.detail);
    eprintln!("Start time:  {} ms", header.start_time);
    if let Some(end) = header.end_time {
        eprintln!("End time:    {} ms", end);
    }
    if let Some(ref t) = header.transport {
        eprintln!("Transport:   {t}");
    }
    if let Some(ref s) = header.source {
        eprintln!("Source:      {s}");
    }
    if let Some(ref e) = header.endpoint {
        eprintln!("Endpoint:    {e}");
    }
    eprintln!("Events:      {}", events.len());
    eprintln!();

    match format.as_str() {
        "json" => {
            for event in &events {
                let cbor: Value = event.into();
                // Convert CBOR value to JSON for display
                let json = cbor_to_json(&cbor);
                println!("{json}");
            }
        }
        _ => {
            println!("{:<8} {:<12} {:<20} {:>10}", "SEQ", "TIME(us)", "EVENT", "DETAILS");
            println!("{}", "-".repeat(60));
            for event in &events {
                let (name, details) = format_event(&event.data);
                println!("{:<8} {:<12} {:<20} {:>10}", event.seq, event.timestamp, name, details,);
            }
        }
    }

    Ok(())
}

fn format_event(data: &EventData) -> (&'static str, String) {
    match data {
        EventData::ControlMessage { direction, message_type, .. } => {
            let dir = match direction {
                Direction::Send => "tx",
                Direction::Receive => "rx",
            };
            ("control", format!("{dir} mt=0x{message_type:x}"))
        }
        EventData::StreamOpened { stream_id, direction, stream_type } => {
            let dir = match direction {
                Direction::Send => "tx",
                Direction::Receive => "rx",
            };
            ("stream-opened", format!("{dir} sid={stream_id} st={stream_type:?}"))
        }
        EventData::StreamClosed { stream_id, error_code } => {
            ("stream-closed", format!("sid={stream_id} ec={error_code}"))
        }
        EventData::ObjectHeader { stream_id, group, object, .. } => {
            ("object-header", format!("sid={stream_id} g={group} o={object}"))
        }
        EventData::ObjectPayload { stream_id, group, object, size, .. } => {
            ("object-payload", format!("sid={stream_id} g={group} o={object} sz={size}"))
        }
        EventData::StateChange { from, to } => ("state-change", format!("{from} -> {to}")),
        EventData::Error { error_code, reason } => ("error", format!("ec={error_code} {reason}")),
        EventData::Annotation { label, .. } => ("annotation", label.clone()),
    }
}

fn cbor_to_json(value: &Value) -> String {
    let json = cbor_value_to_serde_json(value);
    serde_json::to_string(&json).unwrap_or_else(|_| "null".into())
}

fn cbor_value_to_serde_json(value: &Value) -> serde_json::Value {
    match value {
        Value::Integer(i) => {
            if let Ok(n) = i64::try_from(*i) {
                serde_json::Value::Number(n.into())
            } else if let Ok(n) = u64::try_from(*i) {
                serde_json::Value::Number(n.into())
            } else {
                serde_json::Value::Null
            }
        }
        Value::Text(s) => serde_json::Value::String(s.clone()),
        Value::Bool(b) => serde_json::Value::Bool(*b),
        Value::Null => serde_json::Value::Null,
        Value::Bytes(b) => serde_json::Value::String(hex::encode(b)),
        Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(cbor_value_to_serde_json).collect())
        }
        Value::Map(pairs) => {
            let map: serde_json::Map<String, serde_json::Value> = pairs
                .iter()
                .filter_map(|(k, v)| {
                    k.as_text().map(|key| (key.to_string(), cbor_value_to_serde_json(v)))
                })
                .collect();
            serde_json::Value::Object(map)
        }
        Value::Float(f) => serde_json::Number::from_f64(*f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        Value::Tag(_, inner) => cbor_value_to_serde_json(inner),
        _ => serde_json::Value::Null,
    }
}
