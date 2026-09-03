# Cross-draft architecture

This workspace implements fourteen versions of one protocol. Every crate here
answers the question "how do you span drafts" and **three of them answer it
differently**. That was never written down, and this file is that omission being
fixed.

Read this before sharing code across drafts, and before adding a draft.

---

## 1. The rule

> **Share the observation. Never share the answer.**
>
> A module may be draft-neutral when the *question* it asks is identical on
> every draft it serves and the drafts differ only in what they answer. The
> moment a draft's answer has to be encoded in the shared module — a `match` on
> the draft, a boolean parameter meaning "the new way", a table keyed by draft
> number — the module has stopped being shared and has become a fourth copy of
> the per-draft code with a dispatch table bolted on.

The rule is not new. It is already written in the modules that follow it.
`moqtap-client/src/forwarding_preference.rs` states it outright:

> "what they disagree about is the answer, and that answer belongs to each
> draft's own close table rather than here. This module holds only the
> observation."

`track_locations.rs` states it in the same words — "This module holds only the
observation. What each draft does about it is its own close table's business" —
and `malformed_tracks.rs` states the same separation in its own: "this record
and the close table are separate things".

Those three plus `moqtap-client/src/transport/` are the only shared code in the
tree whose rule *predicts* what belongs in it, and they are the only shared code
that costs **zero lines** to extend to a new draft. That is the test: if adding
a draft means editing the shared module, the sharing did not work.

### The three corollaries

**(a) Wire format is never shared.** Not between drafts, not between eras, not
"just the header". The correctness of this workspace is conformance to fourteen
separate specifications that were each edited by hand, and the measurement bears
it out: `moqtap-codec/src/draftNN/message.rs` and `error_codes.rs` have
**fourteen distinct variants across fourteen drafts** — zero redundancy. There is
nothing there to extract. A shared encoder is a place where a change made for
draft-21 silently reaches draft-11.

**(b) A shared module must not name a draft.** No `DraftVersion` parameter, no
`d07` suffix, no `if draft >= 15`. Where drafts genuinely need different
behaviour from one shared record, give them **different entry points** rather
than a draft argument — `track_locations.rs` does exactly this, offering
`check_end_of_track`, `note_final_object` and `check_not_past_final` over one
record and saying why in the doc comment above them. Which entry point a draft
calls is that draft's own statement about which rule it states, and it lives in
that draft's module where it can be read against that draft's text.

**(c) Anything reachable from a single draft belongs to that draft's module.**
This is the invariant `moqtap-codec/src/fields/mod.rs` is built on, and it is
enforced by the compiler under a single-draft build: violating it produced
**16 dead-code errors**. A helper that only draft-14 calls is draft-14's helper
however draft-neutral its type signature looks.

### What "shared" costs, stated plainly

Drafts 07 through 16 are shipped and interop-tested. Nothing can perturb them,
because **nothing else compiles them**. That guarantee is a property of the
per-draft seam and a shared abstraction removes it permanently. So the burden of
proof is on sharing, not on copying: the recurring cost of copying a file is
minutes, and the recurring cost of a shared abstraction is that it must be
re-opened and re-risked every time a draft diverges.

How often does it diverge? Public function names in
`moqtap-client/src/draftNN/connection.rs`:

| window | drafts | common | union | overlap |
|---|---|---|---|---|
| 07-20 (all) | 14 | 34 | 122 | **28%** |
| 17-20 | 4 | 64 | 78 | 82% |
| 19-20 | 2 | 72 | 76 | 95% |

A universal fourteen-draft trait could cover 28% of the surface. It is not hard;
it is impossible. Within an *era* the overlap is 82-95%, which is why the
era-grouped macros in `data_dispatch.rs` work — and note that the era boundary
there has already moved twice (subgroup at draft-14, fetch at draft-15), which
is the argument against betting on any era being stable.

---

## 2. Which strategy applies where

Three strategies, three crates, and the choice is not stylistic — it follows
from what each crate holds.

| crate | per-draft lines | shared | strategy |
|---|---|---|---|
| `moqtap-codec/src` | 60,443 | 12.6% | per-draft modules behind cargo features + `Any*` enums |
| `moqtap-client/src` | 103,722 | 2.9% | per-draft modules behind cargo features + `Any*` enums |
| `moqtap-proxy/src` | **0** | **100%** | **no draft modules at all** — runtime `match DraftVersion` |

*(Measured 2026-09-02.)*

### `moqtap-codec` — per-draft modules, and this is not negotiable

The codec holds fourteen wire formats. Each is `src/draftNN/`, behind a
`draftNN` cargo feature, with an independent `message.rs`, `data_stream.rs`,
`error_codes.rs`, `fields.rs`, `types.rs` and `mod.rs`. A build that enables one
draft compiles one draft.

**Why:** corollary (a). The measurement above says there is no duplication worth
removing, and the isolation is worth a great deal: a change to `draft20/` cannot
reach draft-11's shipped behaviour, and the compiler proves it.

### `moqtap-client` — per-draft modules, same seam, for a different reason

The client holds fourteen session state machines. Same layout, same features,
same `Any*` facade.

**Why:** not because the code is all distinct — 79.9% of it is duplicated, and
twelve of its fourteen per-draft files have seven or fewer distinct variants
across all fourteen drafts. It is because 77% of the *mass* sits in
`connection.rs` and `endpoint.rs`, which have fourteen and twelve distinct
variants respectively, and because those files are where every draft's real work
and every draft's real bug lives. The duplication in the other twelve files is a
**write-once** cost against shipped drafts nobody edits again.

If that ever changes, `fetch.rs` is the one to look at first — two distinct
variants across fourteen drafts, and
`crates/moqtap-client/tests/fetch_answer_order_on_every_draft.rs` already proves
the `FetchStateMachine` API is identical on all fourteen. It is the only
candidate in the crate where the evidence is already in.

### `moqtap-proxy` — no draft modules, runtime dispatch

The proxy has **no `src/draftNN/` directory at all**. It spans fourteen drafts
with several hundred `DraftVersion::` references and a handful of
`cfg(any(...))` sites, every one of which is inside a `#[cfg(test)]` module.

**Why:** the proxy does not implement the protocol, it *observes* one. It reads
what the codec decoded and decides what to do with it, and that decision is
draft-neutral far more often than not — a rule that says "drop the third object
of every group" does not care which draft framed it. Where it does care, the
difference is a small predicate over `DraftVersion` and not a different
implementation.

**Do not add a `draftNN` module to the proxy.** If a proxy behaviour differs by
draft, that is a predicate on `DraftVersion` — and see §4(c) for how to write
one that cannot silently answer for a draft it has never met.

---

## 3. Shared layers that exist today, and the rule each is under

### `moqtap-client` — the four that follow the rule

| module | lines | draft dispatch inside |
|---|---|---|
| `src/track_locations.rs` | 521 | **0** |
| `src/forwarding_preference.rs` | 117 | **0** |
| `src/malformed_tracks.rs` | 165 | **0** |
| `src/transport/` | 874 | **0** |

The first three hold an observation whose answer lives in each draft's own
module. The fourth sits *below* the protocol layer entirely — see the
`transport` paragraph in `src/lib.rs`. All four cost nothing per draft. Copy this shape.

Note that `forwarding_preference` is compiled for drafts 07-15 and
`malformed_tracks` for drafts 12-20, both with a paragraph naming the sentence
each draft states. **A shared module serving a subset of drafts is fine.** What
is not fine is a shared module that serves all of them by asking which one it is.

### `moqtap-codec/src/fields/` — the shared field layer

`FieldValue` and `FieldMap` in `fields/mod.rs` are **public API**:
`AnyControlMessage::fields()` returns a `FieldMap`. They are draft-agnostic
types, and they are the rendering seam for the trace writer, the vector tests
and the inspector.

`fields/params.rs` is `pub(crate)` and gated `any(draft07, draft08, draft09,
draft10)`. It holds **only what more than one draft shares**: one non-SETUP
parameter table across drafts 07-10, and the generic `kvp_to_json_d07_inner`
that reads it. Draft-07's SETUP table is draft-07-only; the 08-10 SETUP table —
the ROLE-less cohort — is gated to those three. Every other draft's parameter
handling lives in its own `draftNN/fields.rs`, draft-14's included, which was
moved out of the shared file to get it there.

That gating is the specification talking, not an accident: draft-08 removed
ROLE, so the 07 boundary is real, and draft-11 keeps its own tables by design.
**No gate here should be widened to `all drafts` for tidiness.**

`params.rs` is also the sharpest counterexample to "no wire-level code is
shared", and worth reading as a caution rather than a template:
`kvp_to_json_d07_inner` calls `VarInt::decode` on a length-prefixed parameter
value, which is wire decoding, across four drafts, from one table — and that is
exactly where a remotely-triggerable panic lived, four drafts sharing one table
while their own decoders disagreed about which parameter types are integers.
Sharing a table across drafts shares its failure modes too.

### `moqtap-codec/src/{dispatch,data_dispatch}.rs` — ~4,900 lines, and the honest name for them

These are **wire-level code at the crate root**. They decode and encode object
headers, extension blocks, delta-encoded object IDs and stream-type fields
across all fourteen drafts. Calling them "shared primitives" would be false.

What makes them acceptable under §1 is that they are *dispatchers* rather than
implementations: `dispatch_enum!` and the three macro families in
`data_dispatch.rs` generate one arm per draft that forwards to that draft's own
module. No draft's format is decided here; the arm decides which draft's decoder
runs. `data_dispatch.rs` groups its macro families by **wire era**
(`legacy_subgroup_glue!` for drafts 07-13, `modern_subgroup_glue!` for 14-20,
`fetch_glue!` for 07-13) with hand-written modules `fo14`..`fo20` where no macro
shape captured the flags — and the era boundary having moved twice is why there
are three families and a hand-written tail.

**The rule for this layer:** an arm per draft, forwarding. The moment a
dispatcher's arm contains protocol logic that is not in some draft's module, it
has become a fifteenth implementation.

And see §4 — a dispatcher's `_` arm is the single most dangerous construct in
this workspace.

### `moqtap-codec` — structured parameter values

`auth_token`, `subscription_filter` (drafts 15-19) and `range_filter` (drafts
19-20) are crate-root modules serving explicit draft subsets. Same rule as the
client's four: the subset is a specification fact, stated in the module doc.
Draft-20 rebuilt the LOCATION_FILTER value and therefore reads its own through
`draft20::message::decode_location_filter` — which is corollary (b) working
correctly.

---

## 4. Adding a draft

The mechanical part is about forty files and five thousand lines. It is boring
and safe. **The tail is where the bugs are**, and roughly a dozen edit sites fail
*silently* when missed: the code compiles, the tests pass, and the new draft
quietly gets some other draft's answer.

So the checklist is not prose. It is four gates, and they are all in `just check`
and in CI.

### The gates, and what each one can see

| gate | recipe | what it answers |
|---|---|---|
| `scripts/check-draft-parity.py` | `just draft-parity` | the draft set agrees on every axis that states it — including the per-draft rows in the `justfile` and in CI, so a matrix that was not extended is a failure rather than fourteen green rows that skipped the new draft; no list of drafts names draft N-1 and stops; no draft-enumerating `match` closes with a quiet catch-all |
| `scripts/check-draft-cfg.py` | `just draft-cfg` | every per-draft rejection `cfg(any(...))` names all thirteen other drafts — all 91 pairs, without compiling any of them |
| the per-draft CI matrix | `just draft-matrix`, `just draft-pairs`, `just draft-targets` | each draft alone, `--all-targets`, `-D warnings`, with the *resolved feature list* asserted rather than inferred from an exit code; plus the two-draft rows |
| `scripts/check-drafts.py` | `just drafts` | every citation and every quotation under `crates/` against the draft it names |

**None of the three python gates writes a draft number down**, and where the
`justfile` and CI necessarily do — a matrix is a list of rows — those lists are
themselves an axis of `check-draft-parity.py`, so a row that was not added is a
failure rather than a silence. That is deliberate and it is the defect these
exist to prevent: `check-drafts.py` carried `list(range(7, 20))` and went on
printing identical counts over a tree that had grown a draft;
`check-draft-cfg.py` carried `range(7, 21)` under a comment reading "Add a row
here when a draft is added, or this check passes by asking for too little";
`shape/matcher.rs` declared `[DraftVersion; 13]` under a doc comment reading
"All fourteen". All three have been derived or removed; the fourth kind — a
literal `range(7, N)` in any `scripts/*.py` — is now an axis so the next one
cannot be written quietly.

### The three silent constructs, by name

**(a) The cross-draft rejection `cfg`.** A per-draft module matches one variant
of an `Any*` enum and rejects the rest with a `_` arm that must be compiled out
when this draft is the only one enabled. Written as
`#[cfg(any(feature = "draft07", ...))]` it must name every other draft, a copy
from the previous draft names one too few, and the failure needs *two* drafts
enabled to appear. Eight of forty-one were wrong when this was measured.
`check-draft-cfg.py` covers all 91 pairs; `just draft-pairs` compiles the two
that matter. Prefer the always-compiled form — `#[allow(unreachable_patterns)]
_ => {}` — which is total under all 2^14 feature sets and needs no edit per
draft.

**(b) The quiet catch-all in a dispatcher.** The other side of (a). A `match`
that answers for every draft and then falls through to `_ => false`,
`_ => None`, `_ => FieldMap::new()` gives a **plausible value** for a draft it
has never met, and nothing distinguishes that from a right answer. An arm that
`panic!`s, returns an `Err` or is `unreachable!` is loud and roughly correct.
`check-draft-parity.py` rule 3 reports the quiet ones.

The distinction that matters: a match naming **one** draft variant is a
rejection guard and stays correct forever — a draft-21 header really is not
draft-20's. A match naming **all of them** and then guessing is the defect.

**(c) The `matches!` predicate over `DraftVersion`.** `matches!(draft,
DraftVersion::Draft15 | ... | DraftVersion::Draft20)` desugars to `_ => false`,
so a new draft is answered "no" by a predicate nobody edited. Where the
predicate really is open-ended, write it as an exhaustive `match` so the
compiler refuses the build until somebody has read the new draft — which is the
argument `moqtap-codec/src/version.rs`'s `varint_encoding` already makes, and the reason
`DraftVersion` itself is deliberately **not** cfg-gated. Where it is genuinely
bounded, `moqtap-proxy/src/capability.rs` prescribes the
independent-restatement discipline in bold: "Nothing that checks this list may
read it."

### What no gate covers

Stated so nobody mistakes a green run for a complete one:

- **Whether a per-draft module's code is right.** That is the test suite, read
  against the draft text.
- **Test-file parity.** `tests/draft21_*.rs` existing wherever
  `tests/draft20_*.rs` does is deliberately not checked: drafts delete features
  as well as adding them, and
  `moqtap-codec/tests/encode_discriminator_agreement.rs` excludes draft-20 in
  twelve lines of rationale because draft-20 deleted the FETCH discriminator. A
  gate over that would report the rationale.
- **A test target rendered empty by a whole-file `#![cfg]`.** The
  target-accounting step catches a target that stopped *building*; a target that
  still builds and no longer *tests* the draft it names is invisible.
- **Whether a draft is covered by the tests at all.** `check-draft-parity.py`
  gates its `cfg(any(...))` rule under `src/` only, and *counts* the test-tree
  half without failing on it — 27 lists across 7 files the day it was written.
  The reason is that in a test tree "this draft is not compiled here" is
  sometimes a specification fact:
  `moqtap-client/tests/uni_control_plane.rs` excludes draft-20 because draft-20
  restructured FETCH and the file cannot yet express it. Read that count when
  adding a draft; it is a to-do list, not a defect list.
- **Anything a macro spells by token concatenation.** If the draft number never
  appears in the text, no text gate can see it.
- **Runtime data** — registry JSON, test vectors, the ALPN table on the wire.

---

## 5. If you are about to share something

Four questions, in order. A "no" to any of them is the end of it.

1. Is the thing being shared an **observation**, or an answer?
2. Can the shared module be written **without naming a draft** — no
   `DraftVersion` parameter, no draft-keyed table, no `if draft >= N`?
3. Does adding a draft cost the shared module **zero lines**?
4. Is it **not wire format**?

If all four are yes, write the rule into the module's own doc comment the way
`forwarding_preference.rs` does, naming what the observation is and where the
answer lives. That sentence is what makes the module predictive instead of
merely factored, and it is the only thing that stops it accreting.
