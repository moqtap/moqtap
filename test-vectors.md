# moqtap-test-vectors — Specification

## Purpose

A language-agnostic repository of test vectors for MoQT (Media over QUIC Transport).
Vectors describe wire bytes and their expected interpretation. They are consumed by
any MoQT implementation in any language to validate codec correctness and protocol
conformance.

This repository ships **data, not code**.

## Design principles

1. **Draft-first organization** — loading vectors for a specific draft is the primary use case
2. **Self-contained drafts** — each draft directory works in isolation, no inheritance chains
3. **Language-agnostic** — JSON + hex-encoded wire bytes, consumable everywhere
4. **Schema-validated** — JSON Schema defines the vector format, not language-specific types
5. **No native helpers** — consumers write their own 10-line loader; we provide examples

## Version naming convention

| Phase | Directory name | Rationale |
|-------|---------------|-----------|
| IETF drafts | `draft14/`, `draft15/` | Short, unambiguous, matches draft number |
| First RFC | `v1/` | Intentional naming shift signals stability |
| Subsequent RFCs | `v2/`, `v3/` | Matches version negotiation identifiers |

The naming change from `draftNN` to `vN` is deliberate — it communicates that the
protocol has stabilized and the rules around backwards compatibility have changed.

## Repository structure

```
moqtap-test-vectors/
├── LICENSE                        # MIT
├── README.md
├── manifest.json                  # Machine-readable index of all versions
├── package.json                   # npm: JSON-only package, zero code
│
├── schema/                        # JSON Schema (shared across all versions)
│   ├── manifest.schema.json
│   ├── meta.schema.json
│   ├── codec-vector.schema.json
│   └── session-vector.schema.json
│
├── draft14/                       # One directory per draft/version
│   ├── meta.json
│   ├── codec/
│   │   ├── varint.json
│   │   ├── parameters.json
│   │   └── messages/
│   │       ├── client-setup.json
│   │       ├── server-setup.json
│   │       ├── subscribe.json
│   │       ├── subscribe-ok.json
│   │       ├── subscribe-error.json
│   │       ├── subscribe-update.json
│   │       ├── unsubscribe.json
│   │       ├── publish.json
│   │       ├── publish-ok.json
│   │       ├── publish-error.json
│   │       ├── publish-done.json
│   │       ├── publish-namespace.json
│   │       ├── publish-namespace-ok.json
│   │       ├── publish-namespace-error.json
│   │       ├── publish-namespace-done.json
│   │       ├── publish-namespace-cancel.json
│   │       ├── subscribe-namespace.json
│   │       ├── subscribe-namespace-ok.json
│   │       ├── subscribe-namespace-error.json
│   │       ├── unsubscribe-namespace.json
│   │       ├── fetch.json
│   │       ├── fetch-ok.json
│   │       ├── fetch-error.json
│   │       ├── fetch-cancel.json
│   │       ├── goaway.json
│   │       ├── max-request-id.json
│   │       ├── requests-blocked.json
│   │       ├── track-status.json
│   │       ├── track-status-ok.json
│   │       └── track-status-error.json
│   ├── codec/
│   │   └── data-streams/
│   │       ├── subgroup-header.json
│   │       ├── datagram-header.json
│   │       ├── fetch-header.json
│   │       └── object-header.json
│   └── session/
│       ├── setup-exchange.json
│       ├── version-negotiation.json
│       ├── request-id-parity.json
│       ├── request-id-bounds.json
│       └── goaway-no-new-requests.json
│
├── draft15/                       # Same shape, fully independent
│   ├── meta.json
│   ├── codec/...
│   └── session/...
│
├── v1/                            # When RFC lands
│   ├── meta.json
│   ├── codec/...
│   └── session/...
│
└── examples/                      # Copy-pasteable integration examples
    ├── README.md
    ├── rust/
    │   ├── Cargo.toml
    │   └── tests/codec_vectors.rs
    ├── typescript/
    │   ├── package.json
    │   └── codec-vectors.test.ts
    ├── go/
    │   ├── go.mod
    │   └── codec_vectors_test.go
    ├── python/
    │   └── test_codec_vectors.py
    └── c/
        ├── Makefile
        └── test_codec_vectors.c
```

## Manifest

```jsonc
// manifest.json
{
  "schema_version": 1,
  "versions": [
    {
      "id": "draft14",
      "spec": "draft-ietf-moq-transport-14",
      "status": "active",
      "path": "draft14/"
    }
  ]
}
```

### Manifest fields

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | `integer` | Manifest format version. Currently `1`. |
| `versions` | `array` | List of available test vector versions. |
| `versions[].id` | `string` | Short identifier used in directory names and API calls. |
| `versions[].spec` | `string` | Full IETF document name or RFC number. |
| `versions[].status` | `string` | One of: `"active"`, `"superseded"`, `"stable"`. |
| `versions[].path` | `string` | Relative path to the version directory. |
| `versions[].aliases` | `string[]` | Optional. Aliases like `"latest-stable"` for CI convenience. |
| `versions[].based_on` | `string` | Optional. For stable versions, which draft it was based on. |
| `versions[].superseded_by` | `string` | Optional. Points to the replacement version. |

### Status lifecycle

```
active  →  superseded  (when a new draft is published)
active  →  stable      (when an RFC is published, for the final draft → v1 transition)
```

Only one version should be `"active"` at a time (the current working draft).
`"stable"` versions are never superseded — they may coexist (v1, v2).

## Per-version metadata

```jsonc
// draft14/meta.json
{
  "id": "draft14",
  "spec": "draft-ietf-moq-transport-14",
  "spec_url": "https://www.ietf.org/archive/id/draft-ietf-moq-transport-14.txt",
  "status": "active",
  "superseded_by": null,
  "categories": ["codec", "session"]
}
```

## Vector file format

### Codec vectors

Each file contains a single JSON object with a `vectors` array. Every vector describes
one encode/decode test case: the hex-encoded wire bytes and the expected decoded
structure.

```jsonc
// draft14/codec/messages/subscribe.json
{
  "$schema": "../../schema/codec-vector.schema.json",
  "category": "codec",
  "subcategory": "messages",
  "message_type": "subscribe",
  "message_type_id": "0x03",
  "spec_section": "7.4",
  "vectors": [
    {
      "id": "subscribe-minimal",
      "description": "Minimal SUBSCRIBE with required fields only",
      "hex": "0304000100016101620000000000",
      "decoded": {
        "request_id": 4,
        "track_namespace": ["a"],
        "track_name": "b",
        "subscriber_priority": 0,
        "group_order": 0,
        "filter_type": 0,
        "parameters": []
      },
      "expect": "success"
    },
    {
      "id": "subscribe-truncated",
      "description": "SUBSCRIBE truncated mid-track-name",
      "hex": "030400010001610162",
      "decoded": null,
      "expect": "error",
      "error_reason": "incomplete message: missing fields after track_name"
    }
  ]
}
```

### Vector fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | `string` | Yes | Unique identifier within the file. Kebab-case. |
| `description` | `string` | Yes | Human-readable description of what this vector tests. |
| `hex` | `string` | Yes | Hex-encoded wire bytes (lowercase, no separators). |
| `decoded` | `object\|null` | Yes | Expected decoded structure, or `null` for error cases. |
| `expect` | `string` | Yes | `"success"` or `"error"`. |
| `error_reason` | `string` | No | Human-readable explanation for error cases. |

### Decoded field conventions

The `decoded` object uses **plain JSON with string keys** — not language-specific types.

- Integers are JSON numbers
- Byte strings are hex-encoded JSON strings
- Enums are their numeric values (not symbolic names)
- Arrays of tuples (like track namespace) are JSON arrays
- Optional/absent fields are omitted (not `null`)

This means consumers map `decoded` to their own types — the vectors don't assume any
particular type system.

### VarInt vectors

```jsonc
// draft14/codec/varint.json
{
  "$schema": "../schema/codec-vector.schema.json",
  "category": "codec",
  "subcategory": "varint",
  "spec_section": "RFC 9000 §16",
  "vectors": [
    {
      "id": "varint-1byte-zero",
      "description": "Zero encodes as single byte 0x00",
      "hex": "00",
      "decoded": { "value": 0 },
      "expect": "success"
    },
    {
      "id": "varint-1byte-max",
      "description": "Maximum 1-byte varint (63)",
      "hex": "3f",
      "decoded": { "value": 63 },
      "expect": "success"
    },
    {
      "id": "varint-2byte-min",
      "description": "Minimum 2-byte varint (64)",
      "hex": "4040",
      "decoded": { "value": 64 },
      "expect": "success"
    },
    {
      "id": "varint-4byte-min",
      "description": "Minimum 4-byte varint (16384)",
      "hex": "80004000",
      "decoded": { "value": 16384 },
      "expect": "success"
    },
    {
      "id": "varint-8byte-min",
      "description": "Minimum 8-byte varint (1073741824)",
      "hex": "c000000040000000",
      "decoded": { "value": 1073741824 },
      "expect": "success"
    },
    {
      "id": "varint-8byte-max",
      "description": "Maximum varint (2^62 - 1)",
      "hex": "ffffffffffffffff",
      "decoded": { "value": 4611686018427387903 },
      "expect": "success"
    },
    {
      "id": "varint-empty",
      "description": "Empty buffer should fail",
      "hex": "",
      "decoded": null,
      "expect": "error",
      "error_reason": "insufficient data"
    }
  ]
}
```

### Session vectors

Session vectors test protocol-level behavior: valid and invalid message sequences,
state machine transitions, and constraint violations.

```jsonc
// draft14/session/setup-exchange.json
{
  "$schema": "../schema/session-vector.schema.json",
  "category": "session",
  "subcategory": "setup",
  "spec_section": "6.2",
  "vectors": [
    {
      "id": "setup-valid-exchange",
      "description": "Valid CLIENT_SETUP → SERVER_SETUP exchange",
      "sequence": [
        {
          "direction": "tx",
          "message_type": "client_setup",
          "hex": "2001ff000000040000010474657374",
          "decoded": {
            "supported_versions": [4278190080],
            "parameters": [{"key": 1, "value": "test"}]
          }
        },
        {
          "direction": "rx",
          "message_type": "server_setup",
          "hex": "21ff00000004000001047465737432",
          "decoded": {
            "selected_version": 4278190080,
            "parameters": [{"key": 1, "value": "test2"}]
          }
        }
      ],
      "expect": "success"
    },
    {
      "id": "setup-no-common-version",
      "description": "Server selects version not offered by client",
      "sequence": [
        {
          "direction": "tx",
          "message_type": "client_setup",
          "hex": "2001ff000000040000",
          "decoded": {
            "supported_versions": [4278190080],
            "parameters": []
          }
        },
        {
          "direction": "rx",
          "message_type": "server_setup",
          "hex": "21ff000000050000",
          "decoded": {
            "selected_version": 4278190081,
            "parameters": []
          }
        }
      ],
      "expect": "error",
      "error_reason": "server selected version not in client's offered list"
    }
  ]
}
```

### Data stream vectors

```jsonc
// draft14/codec/data-streams/subgroup-header.json
{
  "$schema": "../../schema/codec-vector.schema.json",
  "category": "codec",
  "subcategory": "data-streams",
  "spec_section": "8.1",
  "vectors": [
    {
      "id": "subgroup-header-basic",
      "description": "Basic subgroup header with track alias, group, subgroup, publisher priority",
      "hex": "040102000300",
      "decoded": {
        "stream_type": 4,
        "track_alias": 1,
        "group_id": 2,
        "subgroup_id": 0,
        "publisher_priority": 3
      },
      "expect": "success"
    }
  ]
}
```

## Duplication policy

Each draft directory is **fully self-contained**. Vectors are duplicated across drafts
even when the encoding hasn't changed (e.g., VarInt encoding is identical across all
MoQT drafts since it comes from RFC 9000).

This is the right tradeoff:

- **Consumers load one directory** — no resolution logic, no overlay merging
- **Correctness is local** — validate `draft15/` without looking at `draft14/`
- **Deletion is safe** — removing an old draft breaks nothing
- **Contributions are isolated** — editing a file affects only one draft
- **Files are small** — kilobytes of JSON, duplication cost is negligible

### Scaffolding a new draft

When a new draft is published, copy the previous draft and modify only what changed:

```bash
cp -r draft14/ draft15/
# Edit draft15/meta.json
# Modify only the vector files affected by spec changes
# Update manifest.json
```

## Distribution

| Channel | What ships | Maintenance cost |
|---------|-----------|-----------------|
| **Git repository** | Primary distribution. Pin a tag, clone, or submodule. | None beyond the repo itself. |
| **npm package** (`@moqtap/test-vectors`) | JSON files only, zero code, zero dependencies. | Publish on tag. Trivial. |

### What we do NOT publish

- **No Rust crate.** Rust consumers use a git dependency or submodule. Publishing test
  data to crates.io adds versioning and semver overhead for static JSON files.
- **No Go module.** Go consumers use `go:embed` from a cloned/submoduled directory.
- **No native helpers in any language.** Loading JSON and iterating is 5-10 lines in
  any language. Shipping helpers means maintaining N libraries with coupled types.

### npm package

```jsonc
// package.json
{
  "name": "@moqtap/test-vectors",
  "version": "0.14.0",
  "description": "MoQT protocol test vectors",
  "type": "module",
  "exports": {
    "./manifest": "./manifest.json",
    "./schema/*": "./schema/*",
    "./draft14/*": "./draft14/*"
  },
  "files": [
    "manifest.json",
    "schema/",
    "draft14/"
  ]
}
```

Zero dependencies. Zero code. Just JSON with proper `exports` so
`import vectors from '@moqtap/test-vectors/draft14/codec/messages/subscribe.json'`
works in TypeScript/Node.

### Versioning strategy

The npm package version tracks the **primary active draft**:

| Active draft | npm version | Notes |
|-------------|-------------|-------|
| draft-14 | `0.14.x` | `0.` prefix signals pre-stable |
| draft-15 | `0.15.x` | |
| v1 (RFC) | `1.0.x` | Major version = stable MoQT version |
| v2 (RFC) | `2.0.x` | |

Patch versions (`0.14.1`, `0.14.2`) are used when vectors are added or corrected
within the same draft.

## Integration examples

The `examples/` directory contains minimal, copy-pasteable test files. These are
**not maintained libraries** — they demonstrate the pattern. If they drift slightly
from the latest vector schema, the pattern still holds.

### Rust

```rust
// examples/rust/tests/codec_vectors.rs
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct VectorFile {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    id: String,
    hex: String,
    expect: String,
    decoded: Option<serde_json::Value>,
}

#[test]
fn test_subscribe_vectors() {
    // Use as git submodule at tests/test-vectors/
    let data = fs::read_to_string("tests/test-vectors/draft14/codec/messages/subscribe.json")
        .expect("test vectors not found — did you clone the submodule?");
    let file: VectorFile = serde_json::from_str(&data).unwrap();

    for v in &file.vectors {
        let bytes = hex::decode(&v.hex).unwrap();
        match v.expect.as_str() {
            "success" => {
                let msg = moqtap_codec::ControlMessage::decode(&mut bytes.as_slice().into())
                    .unwrap_or_else(|e| panic!("vector '{}' should decode: {}", v.id, e));
                // Compare fields against v.decoded as needed
                let _ = msg;
            }
            "error" => {
                assert!(
                    moqtap_codec::ControlMessage::decode(&mut bytes.as_slice().into()).is_err(),
                    "vector '{}' should fail to decode",
                    v.id
                );
            }
            other => panic!("unknown expect value: {}", other),
        }
    }
}
```

### TypeScript

```typescript
// examples/typescript/codec-vectors.test.ts
import { describe, it, expect } from "vitest";
import { decodeMessage } from "moqtap"; // consumer's own library
import vectors from "@moqtap/test-vectors/draft14/codec/messages/subscribe.json";

describe("subscribe vectors", () => {
  for (const v of vectors.vectors) {
    it(v.id, () => {
      const bytes = hexToBytes(v.hex);
      if (v.expect === "success") {
        const msg = decodeMessage(bytes);
        expect(msg).toBeDefined();
        // Compare fields against v.decoded
      } else {
        expect(() => decodeMessage(bytes)).toThrow();
      }
    });
  }
});

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}
```

### Go

```go
// examples/go/codec_vectors_test.go
package vectors_test

import (
    "encoding/hex"
    "encoding/json"
    "os"
    "testing"
)

type VectorFile struct {
    Vectors []Vector `json:"vectors"`
}

type Vector struct {
    ID      string           `json:"id"`
    Hex     string           `json:"hex"`
    Expect  string           `json:"expect"`
    Decoded *json.RawMessage `json:"decoded"`
}

func TestSubscribeVectors(t *testing.T) {
    // Use as git submodule at testdata/test-vectors/
    data, err := os.ReadFile("testdata/test-vectors/draft14/codec/messages/subscribe.json")
    if err != nil {
        t.Skip("test vectors not found — clone the submodule")
    }

    var file VectorFile
    if err := json.Unmarshal(data, &file); err != nil {
        t.Fatal(err)
    }

    for _, v := range file.Vectors {
        t.Run(v.ID, func(t *testing.T) {
            bytes, err := hex.DecodeString(v.Hex)
            if err != nil {
                t.Fatal(err)
            }
            msg, decodeErr := moqt.DecodeMessage(bytes) // consumer's own library
            if v.Expect == "success" {
                if decodeErr != nil {
                    t.Fatalf("expected success, got error: %v", decodeErr)
                }
                _ = msg // compare fields against v.Decoded
            } else {
                if decodeErr == nil {
                    t.Fatal("expected error, got success")
                }
            }
        })
    }
}
```

### Python

```python
# examples/python/test_codec_vectors.py
import json
import pytest

def load_vectors(path):
    with open(path) as f:
        return json.load(f)["vectors"]

@pytest.mark.parametrize("v", load_vectors("test-vectors/draft14/codec/messages/subscribe.json"),
                         ids=lambda v: v["id"])
def test_subscribe(v):
    wire_bytes = bytes.fromhex(v["hex"])
    if v["expect"] == "success":
        msg = decode_message(wire_bytes)  # consumer's own library
        assert msg is not None
        # compare fields against v["decoded"]
    else:
        with pytest.raises(Exception):
            decode_message(wire_bytes)
```

### C

```c
// examples/c/test_codec_vectors.c
// Uses cJSON (header-only): https://github.com/DaveGamble/cJSON
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"

// Consumer provides: int decode_message(const uint8_t *buf, size_t len, message_t *out);

int hex_to_bytes(const char *hex, uint8_t *out, size_t *out_len) {
    size_t len = strlen(hex);
    *out_len = len / 2;
    for (size_t i = 0; i < len; i += 2) {
        sscanf(hex + i, "%2hhx", &out[i / 2]);
    }
    return 0;
}

int main(void) {
    FILE *f = fopen("test-vectors/draft14/codec/messages/subscribe.json", "r");
    // ... read file, parse with cJSON, iterate vectors ...
    // Pattern is identical: hex → bytes → decode → compare
    cJSON_Delete(root);
    fclose(f);
    return 0;
}
```

## JSON Schema

Schemas live in `schema/` and are referenced by vector files via `$schema`. They
validate the vector file format itself — not the MoQT protocol.

### codec-vector.schema.json (sketch)

```jsonc
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://moqtap.dev/test-vectors/schema/codec-vector.schema.json",
  "type": "object",
  "required": ["category", "subcategory", "spec_section", "vectors"],
  "properties": {
    "category": { "type": "string", "enum": ["codec"] },
    "subcategory": { "type": "string" },
    "message_type": { "type": "string" },
    "message_type_id": { "type": "string", "pattern": "^0x[0-9a-f]+$" },
    "spec_section": { "type": "string" },
    "vectors": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["id", "description", "hex", "expect"],
        "properties": {
          "id": { "type": "string", "pattern": "^[a-z0-9-]+$" },
          "description": { "type": "string" },
          "hex": { "type": "string", "pattern": "^[0-9a-f]*$" },
          "decoded": {},
          "expect": { "type": "string", "enum": ["success", "error"] },
          "error_reason": { "type": "string" }
        },
        "if": { "properties": { "expect": { "const": "success" } } },
        "then": { "required": ["decoded"] }
      }
    }
  }
}
```

## CI integration

The test-vectors repository has its own CI that validates:

1. All JSON files are valid JSON
2. All vector files validate against their `$schema`
3. All `hex` fields contain valid lowercase hex strings
4. All vector `id` fields are unique within their file
5. `manifest.json` entries match actual directories
6. Each `meta.json` is consistent with `manifest.json`

This CI does NOT run any MoQT implementation — it validates the vectors themselves.

Consumer repositories (moqtap, moqtap-js, etc.) run their own CI that loads vectors
and tests their implementation against them.

## Tagging and releases

Tags follow the pattern: `draft14/v0.14.0`, `draft14/v0.14.1`, etc.

When vectors for a new draft are added, the old draft's vectors are frozen (no more
patches unless a bug is found in the vectors themselves).

## Future considerations

- **Interop test vectors**: vectors that describe multi-party exchanges (client A ↔ relay ↔ client B). These would live under a new `interop/` category within each draft directory.
- **Fuzz corpus**: wire bytes that are intentionally malformed in interesting ways. Could live under `fuzz/` within each draft directory as a set of raw binary files.
- **QPACK/WebTransport vectors**: if MoQT gains WebTransport-specific framing, vectors for that would be a new category.
