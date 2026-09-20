# Extracted registries

One JSON file per MoQ Transport Internet-Draft, `draft-07.json` through
`draft-20.json`, holding the code point registries transcribed into this
crate's `draftNN::error_codes` and `draftNN::types` modules. They are produced
by `../extract-registries.py` and committed so that every number this crate
asserts about a draft can be re-derived and diffed without re-running the
extraction, and so that a change to one of those numbers shows up as a diff
rather than as a test that quietly starts agreeing with something new.

## What is in them

Three families, counted separately and never summed.

**Outcome codes** — the registries that report how a request or a session
ended. Four of them in drafts 15-20 (Session Termination, REQUEST_ERROR,
PUBLISH_DONE, Stream Reset); more in the earlier drafts, which had a separate
error registry per message type before drafts 15+ merged them into
REQUEST_ERROR. They live under `registries` and are totalled in `totals.rows`.

**Object Status** — the status a single Object carries (Normal, End of Group,
End of Track). It lives under `object_status` and is totalled in
`totals.object_status_rows`. It is kept apart from the outcome codes because
it is a different kind of thing — drafts 19 and 20 give it its own IANA
subsection, a sibling of rather than a part of the Error Codes section — and
because it is identified by a different rule: only drafts 19 and 20 print it as
a table at all, and drafts 07-18 assign the same code points as a run of bullets with no IANA
registry anywhere. `extract-registries.py` states both rules in full in its
module docstring, under `WHAT COUNTS AS A ROW` and `OBJECT STATUS: A SECOND
FAMILY, COUNTED SEPARATELY`. Read that before changing what the tool matches;
getting the definition wrong has already produced one wrong count in this
project's history, and the docstring is where that is written down.

Object Status rows carry the `Payload` column drafts 19 and 20 print (draft-19
Section 15.9, Table 16)
where the draft prints one, and where it does not, `payload_source` says so:
`payload-column` means the draft registered that answer, `blanket-rule` means
it follows from the pre-draft-19 sentence "any object with a status code other
than zero MUST have an empty payload", and `blanket-rule-complement` means it
was inferred from that sentence's silence about status zero. Consumers that
will only accept a value the draft states can filter on that field.

**Parameters, properties, setup options and auth tokens** — the code points a
control message parameter, an object or track property, a setup option or an
AUTHORIZATION TOKEN alias carries. They live under `parameters` and are totalled
in `totals.parameter_rows`. They are not outcome codes and have nothing to do
with Object Status, so they are a third family rather than an addition to
either; the tool's docstring states the rule under `PARAMETERS, PROPERTIES,
SETUP OPTIONS AND AUTH TOKENS`.

Two things about this family a consumer has to know. Rows carry no description
except in drafts 11-14, whose AUTHORIZATION TOKEN table prints a
`Serialization and behavior` column — the sections the other tables point at are
prose rather than the definition lists the error-code sections use, so
`description_source` is `null` there as a fact about the drafts rather than a
gap. And registries within one family share a code space: in drafts 18 and 19
Property Type `0x06` is `SUBGROUP_DELIVERY_TIMEOUT` in the Properties table and
`TIMESTAMP` in the provisional one beside it, and in draft 20 all eight
`FILL PARAMETERS` codes are also Message Parameters. Join by
(`registry_id`, `code`), never by `code` alone;
`totals.parameter_codes_registered_more_than_once_in_a_family` counts where it
matters.

Drafts 07-10 have `parameters.present` false. That is not the same fact as those
drafts assigning no parameters: they assign them inside the prose sentence that
introduces each one ("AUTHORIZATION INFO parameter (Parameter Type 0x02)
identifies a track's authorization information"), with no table for a
table-anchored extraction to read. `reason_absent` says so in the file.

Per draft, as committed:

| draft | 07 | 08 | 09 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| outcome registries | 3 | 6 | 6 | 6 | 7 | 8 | 8 | 8 | 4 | 4 | 4 | 4 | 4 | 4 |
| outcome rows | 21 | 40 | 40 | 40 | 65 | 71 | 71 | 73 | 47 | 49 | 59 | 62 | 64 | 61 |
| object status rows | 5 | 5 | 5 | 5 | 4 | 4 | 4 | 4 | 4 | 3 | 3 | 3 | 3 | 3 |
| object status form | \* | \* | \* | \* | \* | \* | \* | \* | \* | \* | \* | \* | table | table |
| parameter registries | 0 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 2 | 3 | 4 | 6 | 6 | 7 |
| parameter rows | 0 | 0 | 0 | 0 | 4 | 4 | 4 | 4 | 16 | 21 | 25 | 40 | 47 | 60 |

`\*` is `prose-list`: bullets under the section that defines the field, no
IANA registry. Drafts 19 and 20 are the only drafts of the fourteen with an
IANA table for Object Status, and the only ones with a `Payload` column.

The three row counts are never added. 763 outcome rows, 55 object statuses and
225 parameter rows are three answers to three questions, and a single number for
all three would mean something different on draft 09 than on draft 20.

## Where the input comes from

The rendered drafts are **not in this repository**. They are the HTML that
xml2rfc produces for draft-ietf-moq-transport-07 through -20 — the same
documents published at the IETF datatracker — one file per draft, named
`draft-NN.html`.

`extract-registries.py` looks for them in a directory you point it at, with
`--spec-dir` or the `MOQT_SPEC_DIR` environment variable. Its `--help` and its
module docstring give the default it falls back to. Nothing in this crate's
build or test path reaches for them: the committed JSON is what the tests read,
which is the point of committing it.

Each JSON records `source_sha256`, the SHA-256 of the rendered draft **as bytes
on disk**, taken before any decoding — a hash of decoded text would be blind to
line endings and would call two different files the same file. That hash is
what ties a count to the exact document it came from.

## Re-deriving the numbers

With a directory of rendered drafts in hand:

```
python ../extract-registries.py --all --spec-dir <dir>          # regenerate
python ../extract-registries.py --all --spec-dir <dir> --check  # verify only
python ../extract-registries.py 19  --spec-dir <dir> --audit    # show the spread
```

`--check` writes nothing and exits non-zero if the committed JSON would change.
That is the one to run against a fresh copy of the drafts: a zero exit says the
files here are exactly what those bytes produce.

`--audit` prints what three candidate definitions of "a registry row" yield for
a draft, so the gap between them stays reproducible rather than asserted. On
draft-19 it is 140 / 87 / 64; only the last is the registries.

**The tool writes in place by default.** Running it against a modified or
partial copy of the drafts overwrites the committed JSON next to this file. Use
`--out-dir` to send experimental output somewhere else, or `--check`, which
writes nothing at all.

CI runs `--check` in the `drafts` job, against drafts it downloads from the IETF
archive itself (`.github/workflows/ci.yml`, and `just drafts` locally), so the
committed files are verified against the published documents rather than against
whatever copy a contributor has. It fails closed if the archive cannot be
reached: an unverifiable extraction is not a verified one. The other half is
covered without the drafts at all — see `tests/registry_extraction_health.rs`
below — so an extraction that silently degraded fails a Rust test even where the
document that degraded it is not available.

## What the tests do with these files

- `tests/registry_conformance.rs` compares all fourteen drafts against the
  crate's own enums in both directions — a code point the draft assigns and the
  crate refuses, and one the crate accepts and the draft does not assign, are
  separate failures with separate messages — and compares names as well as code
  points, which is what catches a row copied forward from the previous draft.
  Each draft's `registries` list is required to name every registry it carries,
  so that array cannot grow an entry that nothing compares. That requirement is
  scoped to `registries`: the `parameters` family is extracted and committed but
  is not yet compared against anything in this crate, so a row there is a
  transcription of the draft and not a claim that the crate agrees with it.
  The names it compares change source partway through the range:
  drafts 14 and later print a symbolic name per code and the extraction records
  it, drafts 07 through 13 print only a Reason column and the name is
  normalized from that, and which drafts do which is asserted rather than
  assumed.
- `tests/object_status_payload_rule.rs` drives draft-19's `Payload` column
  through the encoders as behaviour, and asserts draft-18 reads the same
  question off a payload length instead.
  `tests/object_status_payload_rule_draft20.rs` does the same for draft-20.
- `tests/registry_extraction_health.rs` gates the extractions themselves:
  no committed extraction may carry a warning, the two row definitions may not
  claim the same source table, every Object Status assignment must record a
  payload permission, and drafts 19 and later must be the only drafts whose
  permissions come from a column — the test is
  `object_status_permissions_come_from_a_column_from_draft19_on`, keyed off each
  draft's own `iana_registry` flag rather than a hardcoded draft number, so it
  covers draft-20 and every draft after it without editing.
  Together those fail if a future revision moves the
  Object Status heading and the tool falls back to reading bullets — the one
  degradation that costs the `Payload` column without changing a row count.

None of these read the rendered drafts. They read the JSON here, which is why
the `source_sha256` chain matters: it is the only link back to the document.
