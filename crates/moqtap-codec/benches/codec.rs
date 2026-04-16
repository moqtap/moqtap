//! Codec micro-benchmarks.
//!
//! Two data sources:
//!   1. Conformance test vectors under `test-vectors/transport/draft17/codec/`
//!      (realistic, small — same bytes the tests exercise).
//!   2. Synthetic subgroup streams built in-process so we can sweep object
//!      count and payload size past conformance sizes.
//!
//! Run with: `cargo bench -p moqtap-codec`

use std::path::{Path, PathBuf};

use bytes::BufMut;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use serde::Deserialize;

use moqtap_codec::draft17::data_stream::{DatagramHeader, FetchHeader, SubgroupHeader};
use moqtap_codec::draft17::message::ControlMessage;
use moqtap_codec::kvp::KeyValuePair;
use moqtap_codec::varint::VarInt;

// ── Vector loading ────────────────────────────────────────────

#[derive(Deserialize)]
struct VectorFile {
    vectors: Vec<TestVector>,
}

#[derive(Deserialize)]
struct TestVector {
    #[allow(dead_code)]
    id: String,
    hex: String,
    #[serde(default)]
    decoded: Option<serde_json::Value>,
    #[serde(default)]
    error: Option<String>,
}

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("test-vectors")
}

fn load_bytes(relative: &str) -> Vec<Vec<u8>> {
    let path = vectors_dir().join(relative);
    let data =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let file: VectorFile =
        serde_json::from_str(&data).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
    file.vectors
        .into_iter()
        .filter(|v| v.decoded.is_some() && v.error.is_none())
        .map(|v| hex::decode(&v.hex).expect("valid hex"))
        .collect()
}

// ── Varint ────────────────────────────────────────────────────

fn bench_varint(c: &mut Criterion) {
    // One value per prefix class so each branch is measured.
    let values: [u64; 4] = [63, 16_383, 1_073_741_823, 4_611_686_018_427_387_903];

    let mut group = c.benchmark_group("varint");
    for v in values {
        let vi = VarInt::from_u64(v).unwrap();
        let mut encoded = Vec::with_capacity(8);
        vi.encode(&mut encoded);

        group.bench_with_input(BenchmarkId::new("encode", v), &vi, |b, vi| {
            let mut buf = Vec::with_capacity(8);
            b.iter(|| {
                buf.clear();
                vi.encode(&mut buf);
                black_box(&buf);
            });
        });

        group.bench_with_input(BenchmarkId::new("decode", v), &encoded, |b, bytes| {
            b.iter(|| {
                let mut cur: &[u8] = bytes;
                black_box(VarInt::decode(&mut cur).unwrap())
            });
        });
    }
    group.finish();
}

// ── Control messages (from test vectors) ──────────────────────

const CONTROL_FILES: &[&str] = &[
    "setup.json",
    "subscribe.json",
    "subscribe-ok.json",
    "publish.json",
    "publish-ok.json",
    "publish-namespace.json",
    "namespace.json",
    "fetch.json",
    "fetch-ok.json",
    "track-status.json",
    "request-ok.json",
    "request-error.json",
];

fn bench_control_messages(c: &mut Criterion) {
    let mut group = c.benchmark_group("control_message");
    for name in CONTROL_FILES {
        let rel = format!("transport/draft17/codec/messages/{name}");
        let vectors = load_bytes(&rel);
        if vectors.is_empty() {
            continue;
        }
        let total_bytes: usize = vectors.iter().map(|v| v.len()).sum();
        group.throughput(Throughput::Bytes(total_bytes as u64));

        group.bench_with_input(BenchmarkId::new("decode", name), &vectors, |b, vs| {
            b.iter(|| {
                for bytes in vs {
                    let mut cur: &[u8] = bytes;
                    let msg = ControlMessage::decode(&mut cur).unwrap();
                    black_box(msg);
                }
            });
        });

        let decoded: Vec<ControlMessage> =
            vectors.iter().map(|b| ControlMessage::decode(&mut &b[..]).unwrap()).collect();
        group.bench_with_input(BenchmarkId::new("encode", name), &decoded, |b, msgs| {
            let mut buf = Vec::with_capacity(total_bytes);
            b.iter(|| {
                buf.clear();
                for m in msgs {
                    m.encode(&mut buf).unwrap();
                }
                black_box(&buf);
            });
        });
    }
    group.finish();
}

// ── Data-stream headers ───────────────────────────────────────

fn bench_data_stream_headers(c: &mut Criterion) {
    let subgroup_vectors = load_bytes("transport/draft17/codec/data-streams/subgroup.json");
    let datagram_vectors = load_bytes("transport/draft17/codec/data-streams/datagram.json");
    let fetch_vectors = load_bytes("transport/draft17/codec/data-streams/fetch-header.json");

    let mut group = c.benchmark_group("data_stream");

    if !subgroup_vectors.is_empty() {
        group.bench_function("subgroup_header_decode", |b| {
            b.iter(|| {
                for bytes in &subgroup_vectors {
                    let mut cur: &[u8] = bytes;
                    black_box(SubgroupHeader::decode(&mut cur).unwrap());
                }
            });
        });
    }

    if !datagram_vectors.is_empty() {
        group.bench_function("datagram_decode", |b| {
            b.iter(|| {
                for bytes in &datagram_vectors {
                    let mut cur: &[u8] = bytes;
                    black_box(DatagramHeader::decode(&mut cur).unwrap());
                }
            });
        });
    }

    if !fetch_vectors.is_empty() {
        group.bench_function("fetch_header_decode", |b| {
            b.iter(|| {
                for bytes in &fetch_vectors {
                    let mut cur: &[u8] = bytes;
                    black_box(FetchHeader::decode(&mut cur).unwrap());
                }
            });
        });
    }

    group.finish();
}

// ── Synthetic subgroup generator ──────────────────────────────
//
// Builds a subgroup stream with `n_objects` objects of `payload_size` bytes.
// Header type = 0x10 (base bit only: explicit subgroup_id disabled via mode 0,
// no properties, no end-of-group, priority byte present).

fn build_synthetic_subgroup(n_objects: usize, payload_size: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + n_objects * (8 + payload_size));

    // Header: mode 0 (subgroup_id = 0, no field), priority byte present.
    buf.put_u8(0x10);
    VarInt::from_u64(42).unwrap().encode(&mut buf); // track_alias
    VarInt::from_u64(100).unwrap().encode(&mut buf); // group_id
    buf.put_u8(128); // publisher_priority

    // Objects. No properties bit, so each object is: delta, payload_len, payload.
    let payload = vec![0xABu8; payload_size];
    for _ in 0..n_objects {
        // Monotonic objects with no gaps: every delta is zero.
        VarInt::from_u64(0).unwrap().encode(&mut buf);
        VarInt::from_usize(payload_size).encode(&mut buf);
        buf.put_slice(&payload);
    }
    buf
}

fn decode_synthetic_subgroup(mut cur: &[u8], n_objects: usize) {
    use bytes::Buf;
    let _header = SubgroupHeader::decode(&mut cur).unwrap();
    for _ in 0..n_objects {
        let _delta = VarInt::decode(&mut cur).unwrap();
        let len = VarInt::decode(&mut cur).unwrap().into_inner() as usize;
        cur.advance(len);
    }
}

fn bench_synthetic_subgroup(c: &mut Criterion) {
    let mut group = c.benchmark_group("synthetic_subgroup");

    // Sweep payload sizes (objects count fixed) and object counts (payload fixed).
    let configs: &[(usize, usize)] = &[(64, 128), (64, 1024), (64, 8192), (256, 1024), (1024, 256)];

    for &(n, p) in configs {
        let bytes = build_synthetic_subgroup(n, p);
        let label = format!("n{n}_p{p}");
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_with_input(BenchmarkId::new("decode", &label), &bytes, |b, bytes| {
            b.iter(|| decode_synthetic_subgroup(black_box(bytes), n));
        });
    }

    group.finish();
}

// ── KVP list (synthetic) ──────────────────────────────────────

fn bench_kvp(c: &mut Criterion) {
    use moqtap_codec::kvp::KvpValue;

    // Mix of varint (even key) and byte (odd key) entries, typical size.
    let pairs: Vec<KeyValuePair> = (0..16)
        .map(|i| {
            if i % 2 == 0 {
                KeyValuePair {
                    key: VarInt::from_u64(i * 2).unwrap(),
                    value: KvpValue::Varint(VarInt::from_u64(12345).unwrap()),
                }
            } else {
                KeyValuePair {
                    key: VarInt::from_u64(i * 2 + 1).unwrap(),
                    value: KvpValue::Bytes(vec![0x42; 32]),
                }
            }
        })
        .collect();

    let mut encoded = Vec::new();
    KeyValuePair::encode_list(&pairs, &mut encoded);

    let mut group = c.benchmark_group("kvp");
    group.throughput(Throughput::Bytes(encoded.len() as u64));

    group.bench_function("decode_list", |b| {
        b.iter(|| {
            let mut cur: &[u8] = &encoded;
            black_box(KeyValuePair::decode_list(&mut cur).unwrap())
        });
    });

    group.bench_function("encode_list", |b| {
        let mut buf = Vec::with_capacity(encoded.len());
        b.iter(|| {
            buf.clear();
            KeyValuePair::encode_list(&pairs, &mut buf);
            black_box(&buf);
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_varint,
    bench_kvp,
    bench_control_messages,
    bench_data_stream_headers,
    bench_synthetic_subgroup,
);
criterion_main!(benches);
