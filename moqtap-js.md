# moqtap-js — JavaScript/TypeScript Library Specification

## Overview

moqtap-js is the JavaScript/TypeScript implementation of MoQT (Media over QUIC
Transport) draft-14. It provides codec, session logic, and trace tooling for use in
browsers, Node.js, and Deno.

## Package strategy

### Decision: multiple npm packages

The JS ecosystem mirrors the Rust workspace crate structure, with packages split
along the same boundaries and for the same reasons.

| npm package | Rust equivalent | Runtime dependency? | Purpose |
|-------------|----------------|-------------------|---------|
| `@moqtap/codec` | `moqtap-codec` | Yes | Wire encoding/decoding, pure functions, zero I/O |
| `@moqtap/session` | `moqtap-session` | Yes | Session state machine, setup negotiation, request ID allocation |
| `@moqtap/trace` | `moqtap-trace` | **Dev/optional** | Trace events, `.moqtrace` reader/writer, session metrics |
| `@moqtap/test-vectors` | *(git repo)* | Dev only | JSON test vectors, zero code |

### Open question: codec + session separation

Whether `@moqtap/codec` and `@moqtap/session` should be one package or two is
**deferred to a separate discussion**. Arguments on both sides:

**Separate (current plan):**
- Mirrors Rust crate structure exactly
- Some consumers only need codec (e.g., a wire inspector tool)
- Smaller bundle for codec-only use cases

**Combined:**
- Session depends on codec — most consumers need both
- One fewer package to version and publish
- Simpler dependency graph for downstream consumers

For now, this spec assumes they are **separate** but designed so that merging them
later is a non-breaking change (session re-exports codec types it uses in its public
API).

### What we do NOT ship

- **No `@moqtap/client`** — QUIC transport in JS requires WebTransport (browser) or
  Node.js bindings. This is tightly coupled to the runtime environment and is the
  consumer's responsibility. We provide the protocol logic; they provide the transport.
- **No `@moqtap/conformance`** — conformance rules are a CLI/CI tool, not a library
  consumers embed. The Rust CLI covers this.

## @moqtap/codec

### Purpose

Pure codec for MoQT control messages, data stream headers, VarInt encoding, and
key-value parameters. Zero dependencies beyond what's needed for byte manipulation.

### Design principles

- **No I/O** — operates on `Uint8Array` / `DataView`, never touches network or filesystem
- **No async** — all operations are synchronous
- **Tree-shakeable** — individual message encoders/decoders can be imported independently
- **Spec-faithful** — type names and field names match the MoQT draft

### Dependencies

```
None (or minimal: a small buffer utility if needed)
```

The codec must work in browsers without polyfills. No Node.js built-ins (`Buffer`,
`stream`, etc.) in the core path.

### Public API surface

```typescript
// --- VarInt ---
export function encodeVarInt(value: number | bigint, buf: Uint8Array, offset: number): number;
export function decodeVarInt(buf: Uint8Array, offset: number): { value: number | bigint; bytesRead: number };
export function varIntEncodedLength(value: number | bigint): 1 | 2 | 4 | 8;

// --- Key-Value Parameters ---
export interface KeyValuePair {
  key: number | bigint;
  value: Uint8Array | number | bigint;  // bytes or varint
}
export function encodeParameters(params: KeyValuePair[], buf: Uint8Array, offset: number): number;
export function decodeParameters(buf: Uint8Array, offset: number): { params: KeyValuePair[]; bytesRead: number };

// --- Control Messages ---
export type ControlMessage =
  | { type: "client_setup"; supportedVersions: number[]; parameters: KeyValuePair[] }
  | { type: "server_setup"; selectedVersion: number; parameters: KeyValuePair[] }
  | { type: "subscribe"; requestId: number; trackNamespace: Uint8Array[]; trackName: Uint8Array; subscriberPriority: number; groupOrder: number; filterType: number; /* ... */ }
  | { type: "subscribe_ok"; requestId: number; contentExists: number; /* ... */ }
  // ... all 30 message types from draft-14
  ;

export function encodeControlMessage(msg: ControlMessage, buf: Uint8Array, offset: number): number;
export function decodeControlMessage(buf: Uint8Array, offset: number): { message: ControlMessage; bytesRead: number };

// --- Data Stream Headers ---
export interface SubgroupHeader {
  trackAlias: number;
  groupId: number;
  subgroupId: number;
  publisherPriority: number;
}
export function encodeSubgroupHeader(header: SubgroupHeader, buf: Uint8Array, offset: number): number;
export function decodeSubgroupHeader(buf: Uint8Array, offset: number): { header: SubgroupHeader; bytesRead: number };

// Similarly for DatagramHeader, FetchHeader, ObjectHeader

// --- Error Codes ---
export const SessionErrorCode: Record<string, number>;
export const RequestErrorCode: Record<string, number>;
```

### VarInt handling

JavaScript `number` is a 64-bit float with 53 bits of integer precision. MoQT VarInt
supports up to 2^62 - 1. Strategy:

- Values ≤ `Number.MAX_SAFE_INTEGER` (2^53 - 1): use `number`
- Values > 2^53 - 1: use `bigint`
- The API accepts `number | bigint` for encoding and returns `number` when safe,
  `bigint` when the value exceeds safe integer range

### Build targets

| Target | Format | Notes |
|--------|--------|-------|
| ESM | `dist/esm/` | Primary. Tree-shakeable. |
| CJS | `dist/cjs/` | For legacy Node.js consumers. |
| Types | `dist/types/` | TypeScript declarations. |
| Browser | Works via ESM | No Node.js built-ins in codec. |

### package.json

```jsonc
{
  "name": "@moqtap/codec",
  "version": "0.14.0",
  "type": "module",
  "main": "./dist/cjs/index.js",
  "module": "./dist/esm/index.js",
  "types": "./dist/types/index.d.ts",
  "exports": {
    ".": {
      "import": "./dist/esm/index.js",
      "require": "./dist/cjs/index.js",
      "types": "./dist/types/index.d.ts"
    }
  },
  "sideEffects": false,
  "files": ["dist/"],
  "engines": { "node": ">=18" }
}
```

## @moqtap/session

### Purpose

Protocol session logic: state machine, setup negotiation, request ID allocation.
Pure functions, no I/O. Depends on `@moqtap/codec` for message types.

### Public API surface

```typescript
// --- Session State Machine ---
export type SessionState = "connecting" | "setup_exchange" | "active" | "draining" | "closed";

export class Session {
  get state(): SessionState;
  onConnect(): void;
  onSetupComplete(): void;
  onGoAway(): void;
  onClose(): void;
}

// --- Request ID Allocator ---
export type Role = "client" | "server";

export class RequestIdAllocator {
  constructor(role: Role);
  allocate(): number;
  updateMax(newMax: number): void;
  validatePeerId(id: number): void;
  isBlocked(): boolean;
}

// --- Setup Negotiation ---
export function validateClientSetup(msg: ClientSetup): void;  // throws on invalid
export function validateServerSetup(msg: ServerSetup): void;
export function negotiateVersion(clientVersions: number[], serverVersion: number): number;
```

### Re-exports

`@moqtap/session` re-exports the codec types it uses in its public API so consumers
don't need to depend on both packages for common use cases:

```typescript
// Re-exported from @moqtap/codec
export type { ClientSetup, ServerSetup, ControlMessage } from "@moqtap/codec";
```

## @moqtap/trace

### Purpose

Trace event types, `.moqtrace` file reader/writer, and session metrics. This package
serves two audiences:

1. **moqtap DevTools extension** — exports live MoQ sessions as `.moqtrace` files
   from the browser for offline analysis
2. **Third-party MoQT libraries** — optional runtime instrumentation for players,
   relays, and tools that want to record sessions for debugging or send traces to
   a server for analysis

### Dependency classification

`@moqtap/trace` is designed as a **dev/optional runtime dependency**:

- Players and libraries add it as a **dev dependency** during development to inspect
  live sessions, then optionally keep it as a runtime dependency if they want to offer
  trace export to their users
- The DevTools extension bundles it directly
- It should add minimal weight — target < 5KB minified + gzipped

### Public API surface

```typescript
// --- Trace Events ---
export type Direction = "tx" | "rx";

export type TraceEventType =
  | "control_message_sent"
  | "control_message_received"
  | "data_stream_opened"
  | "data_stream_closed"
  | "object_sent"
  | "object_received"
  | "session_established"
  | "session_closed"
  | "error";

export interface TraceEvent {
  timestamp_us: number;
  event_type: TraceEventType;
  direction: Direction;
  message_type?: number;
  request_id?: number;
  track_alias?: number;
  group?: number;
  object?: number;
  payload_size?: number;
  error_code?: number;
  reason?: string;
}

// --- .moqtrace File Format ---
export const MOQTRACE_MAGIC: Uint8Array;  // "MOQTRACE" (8 bytes)
export const MOQTRACE_VERSION: number;     // 1

export class MoqTraceWriter {
  constructor();
  addEvent(event: TraceEvent): void;
  toUint8Array(): Uint8Array;   // Serializes header + JSON-lines
  toBlob(): Blob;               // For browser download
}

export class MoqTraceReader {
  constructor(data: Uint8Array);
  get version(): number;
  events(): Iterable<TraceEvent>;
  toArray(): TraceEvent[];
}

// --- Session Metrics ---
export interface SessionMetrics {
  totalObjectsSent: number;
  totalObjectsReceived: number;
  totalBytesSent: number;
  totalBytesReceived: number;
  controlMessagesSent: number;
  controlMessagesReceived: number;
  sessionDurationUs: number;
  errorCount: number;
}

export function computeMetrics(events: TraceEvent[]): SessionMetrics;

// --- Live Session Recorder ---
export class SessionRecorder {
  constructor();
  record(event: TraceEvent): void;
  get events(): readonly TraceEvent[];
  get metrics(): SessionMetrics;
  export(): Uint8Array;          // .moqtrace bytes
  exportBlob(): Blob;            // For download
  clear(): void;
}
```

### .moqtrace file format (matching Rust)

```
Bytes 0-7:   "MOQTRACE" (ASCII magic)
Bytes 8-11:  Version (uint32 LE, currently 1)
Bytes 12+:   JSON-lines (one TraceEvent per line, LF-terminated)
```

Binary-identical to the Rust implementation. A `.moqtrace` file written by the JS
library is readable by the Rust CLI (`moqtap trace <file>`) and vice versa.

### Use case: DevTools extension

```typescript
// In the DevTools extension
import { SessionRecorder } from "@moqtap/trace";

const recorder = new SessionRecorder();

// Hook into WebTransport events
session.onControlMessage((direction, bytes) => {
  recorder.record({
    timestamp_us: performance.now() * 1000,
    event_type: direction === "tx" ? "control_message_sent" : "control_message_received",
    direction,
    message_type: bytes[0],  // first byte is message type
    // ... extract other fields
  });
});

// Export button in DevTools panel
downloadButton.onclick = () => {
  const blob = recorder.exportBlob();
  const url = URL.createObjectURL(blob);
  chrome.downloads.download({ url, filename: "session.moqtrace" });
};
```

### Use case: third-party player instrumentation

```typescript
// In a video player library
import { SessionRecorder, type TraceEvent } from "@moqtap/trace";

class MoQPlayer {
  private recorder?: SessionRecorder;

  enableTracing() {
    this.recorder = new SessionRecorder();
  }

  // Called internally whenever a message is sent/received
  private onMessage(direction: "tx" | "rx", msg: ControlMessage) {
    this.recorder?.record({
      timestamp_us: performance.now() * 1000,
      event_type: direction === "tx" ? "control_message_sent" : "control_message_received",
      direction,
      message_type: msg.typeId,
    });
  }

  // Player exposes trace data to its consumers
  getTraceBlob(): Blob | undefined {
    return this.recorder?.exportBlob();
  }

  getMetrics(): SessionMetrics | undefined {
    return this.recorder?.metrics;
  }

  // Or send to analytics server
  async uploadTrace(endpoint: string) {
    if (!this.recorder) return;
    const data = this.recorder.export();
    await fetch(endpoint, { method: "POST", body: data });
  }
}
```

### Dependencies

```
@moqtap/codec (peer dependency — for message type constants only)
```

No other dependencies. File I/O uses `Uint8Array` and `TextEncoder`/`TextDecoder`
which are available in all modern runtimes.

## Test strategy

### Test vector integration

All packages use `@moqtap/test-vectors` as a dev dependency to validate compliance
before release.

```jsonc
// In each package's package.json
{
  "devDependencies": {
    "@moqtap/test-vectors": "0.14.0"
  }
}
```

### Codec test matrix

The codec package runs **every** vector in `draft14/codec/` automatically:

```typescript
// packages/codec/tests/vectors.test.ts
import { describe, it, expect } from "vitest";
import { encodeControlMessage, decodeControlMessage } from "@moqtap/codec";
import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const vectorDir = resolve(
  import.meta.dirname,
  "../node_modules/@moqtap/test-vectors/draft14/codec/messages"
);

for (const file of readdirSync(vectorDir).filter(f => f.endsWith(".json"))) {
  const vectorFile = JSON.parse(readFileSync(resolve(vectorDir, file), "utf-8"));

  describe(`${vectorFile.message_type} vectors`, () => {
    for (const v of vectorFile.vectors) {
      it(v.id, () => {
        const bytes = hexToBytes(v.hex);

        if (v.expect === "success") {
          // Decode
          const { message, bytesRead } = decodeControlMessage(bytes, 0);
          expect(bytesRead).toBe(bytes.length);

          // Verify decoded fields match expected
          for (const [key, value] of Object.entries(v.decoded)) {
            expect((message as any)[camelCase(key)]).toEqual(value);
          }

          // Roundtrip: encode the decoded message, compare bytes
          const encoded = new Uint8Array(bytes.length);
          const written = encodeControlMessage(message, encoded, 0);
          expect(encoded.subarray(0, written)).toEqual(bytes);
        } else {
          expect(() => decodeControlMessage(bytes, 0)).toThrow();
        }
      });
    }
  });
}
```

### Session test matrix

Session vectors test message sequences and state transitions:

```typescript
// packages/session/tests/vectors.test.ts
import vectors from "@moqtap/test-vectors/draft14/session/setup-exchange.json";
import { Session, validateClientSetup, validateServerSetup } from "@moqtap/session";

describe("setup exchange vectors", () => {
  for (const v of vectors.vectors) {
    it(v.id, () => {
      const session = new Session();
      try {
        for (const step of v.sequence) {
          const { message } = decodeControlMessage(hexToBytes(step.hex), 0);
          if (step.message_type === "client_setup") validateClientSetup(message);
          if (step.message_type === "server_setup") validateServerSetup(message);
        }
        expect(v.expect).toBe("success");
      } catch (e) {
        expect(v.expect).toBe("error");
      }
    });
  }
});
```

### Trace roundtrip tests

Trace tests verify `.moqtrace` interop with the Rust implementation:

```typescript
// packages/trace/tests/moqtrace.test.ts
import { MoqTraceWriter, MoqTraceReader, MOQTRACE_MAGIC } from "@moqtap/trace";

it("roundtrip: write then read", () => {
  const writer = new MoqTraceWriter();
  writer.addEvent({
    timestamp_us: 1000,
    event_type: "session_established",
    direction: "tx",
  });

  const bytes = writer.toUint8Array();

  // Verify header
  expect(bytes.subarray(0, 8)).toEqual(MOQTRACE_MAGIC);

  // Read back
  const reader = new MoqTraceReader(bytes);
  const events = reader.toArray();
  expect(events).toHaveLength(1);
  expect(events[0].event_type).toBe("session_established");
});
```

### Cross-implementation interop test

The CI pipeline also verifies that `.moqtrace` files written by the JS library are
readable by the Rust CLI, and vice versa:

```yaml
# In CI
- name: Generate trace with JS
  run: node scripts/generate-test-trace.js > /tmp/js-trace.moqtrace

- name: Read JS trace with Rust CLI
  run: cargo run -p moqtap-cli -- trace /tmp/js-trace.moqtrace --format json

- name: Generate trace with Rust
  run: cargo run -p moqtap-cli -- trace --generate /tmp/rs-trace.moqtrace

- name: Read Rust trace with JS
  run: node scripts/read-trace.js /tmp/rs-trace.moqtrace
```

### Release gate

No package is published unless:

1. All test vectors pass (100% of vectors in the target draft)
2. `.moqtrace` roundtrip tests pass
3. Cross-implementation interop tests pass
4. TypeScript compiles with `strict: true`
5. Bundle size is within budget (`@moqtap/codec` < 10KB, `@moqtap/trace` < 5KB gzipped)

## Monorepo structure

```
moqtap-js/
├── package.json              # Workspace root
├── vitest.config.ts
├── tsconfig.json             # Shared TS config
├── packages/
│   ├── codec/
│   │   ├── package.json
│   │   ├── tsconfig.json
│   │   ├── src/
│   │   │   ├── index.ts
│   │   │   ├── varint.ts
│   │   │   ├── parameters.ts
│   │   │   ├── messages.ts
│   │   │   ├── data-streams.ts
│   │   │   └── error-codes.ts
│   │   └── tests/
│   │       ├── varint.test.ts
│   │       ├── messages.test.ts
│   │       └── vectors.test.ts    # Test vector integration
│   ├── session/
│   │   ├── package.json
│   │   ├── src/
│   │   │   ├── index.ts
│   │   │   ├── state.ts
│   │   │   ├── setup.ts
│   │   │   └── request-id.ts
│   │   └── tests/
│   │       ├── state.test.ts
│   │       └── vectors.test.ts
│   └── trace/
│       ├── package.json
│       ├── src/
│       │   ├── index.ts
│       │   ├── event.ts
│       │   ├── moqtrace.ts
│       │   ├── metrics.ts
│       │   └── recorder.ts
│       └── tests/
│           ├── moqtrace.test.ts
│           ├── metrics.test.ts
│           └── recorder.test.ts
└── scripts/
    ├── generate-test-trace.js
    └── read-trace.js
```

### Toolchain

| Tool | Purpose |
|------|---------|
| **pnpm** | Package manager (workspaces) |
| **vitest** | Test runner |
| **tsup** | Build (ESM + CJS bundles) |
| **TypeScript** | Type checking (`strict: true`) |
| **publint** | Validate package.json exports before publish |

### Versioning

All packages in the monorepo share the same version number, tracking the MoQT draft:

| MoQT draft | npm version |
|------------|-------------|
| draft-14 | `0.14.x` |
| draft-15 | `0.15.x` |
| v1 (RFC) | `1.0.x` |

Packages are published together — there is no scenario where `@moqtap/codec@0.14.2`
works with `@moqtap/session@0.15.0`.

## Browser compatibility

| Feature | Minimum browser version |
|---------|------------------------|
| `Uint8Array` | All modern browsers |
| `DataView` | All modern browsers |
| `TextEncoder` / `TextDecoder` | Chrome 38+, Firefox 19+, Safari 10.1+ |
| `BigInt` | Chrome 67+, Firefox 68+, Safari 14+ |
| `Blob` | All modern browsers |

No polyfills required for any browser released after 2020.

Node.js minimum version: **18** (LTS).

## What this spec does NOT cover

- **WebTransport client** — transport layer is the consumer's responsibility
- **Media codecs** — MoQT is transport-level, media encoding/decoding is out of scope
- **Relay implementation** — server-side relay logic is a separate project
- **Conformance runner** — use the Rust CLI (`moqtap conformance <file>`)
- **DevTools extension UI** — separate project that depends on `@moqtap/trace`
