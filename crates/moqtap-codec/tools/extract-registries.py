#!/usr/bin/env python3
"""Extract the error, status and termination code registries, and the Object
Status registry, from the rendered MoQ Transport Internet-Drafts, one per
draft this crate has a `src/draftNN/` module for.

Usage
-----
    python extract-registries.py --all
    python extract-registries.py 19
    python extract-registries.py 19 --audit          # compare row definitions
    python extract-registries.py --all --check       # re-run, fail if JSON differs
    python extract-registries.py 19 --full           # keep the prose fields
    python extract-registries.py --all --fetch       # download the drafts first

The rendered drafts are not part of this repository. ``--fetch`` downloads the
ones that are missing from the IETF archive, which is where they are published
and where anyone can read them:

    https://www.ietf.org/archive/id/draft-ietf-moq-transport-NN.html

``--spec-dir`` or ``MOQT_SPEC_DIR`` points at a directory of ``draft-NN.html``
instead. The default is ``<checkout parent>/site/spec-sources``, a local copy
that happens to sit beside this checkout; nothing here depends on it.

Output goes to ``tools/registries/draft-NN.json`` next to this script. Those files
are committed so that every count this tool reports can be re-derived and diffed
by anyone, without re-running the extraction. Each carries ``source_sha256``, the
SHA-256 of the rendered draft as bytes on disk, so a count can be tied to the
exact input it came from. It is taken before decoding, because a hash of decoded
text would be blind to line endings and would match two files that are not the
same file.

That hash identifies a file, not a document. The IETF re-renders these pages, so
a draft downloaded today can hash differently from the same draft downloaded last
year with no change to a single registry row: the extraction from a fresh
download of all thirteen 07-19 renderings was compared field by field against the
committed files
and is identical everywhere except ``source_sha256`` and ``source_file``. So a
hash that does not match is a prompt to diff the extraction, not evidence that
the document changed.

Only the Python standard library is used.


================================================================================
WHAT COUNTS AS A ROW
================================================================================

This is the part of the script that matters. Everything else is plumbing.

Three plausible definitions of "a registry row" were on the table, and running
them over the same document gives three different answers. They are not three
noisy measurements of one quantity; they are three different populations. Only
the third one answers the question this tool exists to answer.

  (A) Symbol-adjacent grep over the whole document.
      "Count every place a hex code point sits next to an ALL-CAPS identifier."

      Wrong, for two independent reasons.

      First, it counts mentions, not assignments. In the later drafts every
      session termination code is written out at least twice: once in the prose
      section that defines it (``NO_ERROR (0x0): The session is being
      terminated...``) and once in the IANA table that assigns it. Codes also
      recur in the change log, in cross-references, and in narrative sentences
      that name a code while explaining some other rule. A count of mentions
      rises when an editor adds a sentence and falls when one is deleted, which
      is not a property of the registry. Over draft-19 this definition measures
      140 against 64 actual rows.

      Second, it has no notion of which registry it is in. Control message type
      IDs, unidirectional stream types, datagram type bit matrices, parameter
      types and auth token alias types are all "a hex number next to an
      ALL-CAPS name", so a grep sweeps them in alongside the error codes.

      Draft 07 is the cautionary case. This definition measures 22 there, and
      the true row count is 21 -- close enough to look like a rounding argument
      between two careful readers. The two sets have no members in common. All
      22 matches are control message type IDs and stream type IDs
      (``0x2 SUBSCRIBE_UPDATE``, ``0x40 CLIENT_SETUP``, ``0x5 FETCH_HEADER``,
      ...), because in draft 07 the error codes have no symbolic names at all --
      they are written ``0x3 | Protocol Violation``, a code and an English
      phrase. The definition scores 0 out of 21 and reports 22.

  (B) The same match, anchored on table cells.
      "Count table rows anywhere in the document that pair an ALL-CAPS name
      with a hex code point."

      Better than (A) -- it drops prose mentions and the change log -- but it
      still has no notion of which registry a row belongs to, so it keeps every
      code-point table in the document, and it still depends on the codes having
      ALL-CAPS names. Over draft-19 it measures 87 against 64: it adds 35 rows
      from registries that are not error codes (Setup Options 5, Authorization
      Token Alias Type 2, Message Parameters 16, Properties 12) and it loses 12
      real ones.

      Those 12 are worth naming, because they are lost silently. Four are the
      row each modern registry ends with to reserve the greasing code space,
      printed ``Reserved for greasing | 0x7f * N + 0x9D`` -- the name is not an
      identifier and the code is an arithmetic expression, so an
      ALL-CAPS-plus-literal-hex filter discards it. The other eight are ordinary
      assignments -- eight rows spelled with six distinct names (UNAUTHORIZED
      three times, plus TIMEOUT, UNINTERESTED, REDIRECT, EXPIRED, CANCELLED) --
      whose only disqualifying property is that they are single words. A filter
      tuned on names like ``MALFORMED_AUTH_TOKEN`` drops them without complaint.

      On drafts 07 through 10 this definition returns 0. Not "a low number" --
      zero rows, for four entire drafts, because none of those tables have a
      symbolic-name column. A run of zeros reads like "these drafts define no
      error codes", which is how a whole cohort gets skipped while the tooling
      looks like it worked.

  (C) Rows of the tables that ARE the registries.  <-- what this tool implements
      A row is one ``<tr>`` of a table that has been identified as an error,
      status or termination code registry, and that assigns a code point.

      This is the only definition that survives contact with the fact that the
      registry set moves between drafts (see below). It is anchored on the
      document's own structure -- the drafts are consistent about how they lay
      out a code registry -- rather than on the shape of the strings inside it.
      It is therefore indifferent to whether a code has a symbolic name, whether
      that name has an underscore in it, and whether the code point is a literal
      or an expression.

The measured spread, from ``--audit`` (drafts 07-20):

    draft   07  08  09  10  11  12  13   14   15   16   17   18   19   20
    (A)     22  24  24  24  26  28  29  143  117  115  119  132  140  148
    (B)      0   0   0   0   2   2   2   59   54   59   66   78   87   96
    (C)     21  40  40  40  65  71  71   73   47   49   59   62   64   61

(A) and (B) as spelled here are this tool's implementations of those two
definitions; the exact figures they produce depend on how the pattern is
written, and small variations move them. What does not move is the shape of the
error: both count a population that has no fixed relationship to the registries,
so their answers cannot be reconciled with (C) by adjusting anything. They are
answers to different questions.

Under (C), row-level rules, all of which come from how xml2rfc renders these
tables:

  * The header row is not a row. It is the row that tells us the table is a
    registry in the first place.
  * A ``<tr>`` whose code cell is empty is a line-wrap continuation of the row
    above it: xml2rfc breaks a long description across extra ``<tr>`` elements
    with empty leading cells. It is merged into the preceding row's description
    and not counted separately. (No in-scope table in drafts 07-20 currently
    wraps, but the auth token table two sections away does, so the rule earns
    its keep as a guard against a future edit.)
  * A row whose code cell holds a range (``0x08-0x0D``) or an arithmetic
    expression (``0x7f * N + 0x9D``) IS a row. The registry assigns that code
    space and the draft prints it as one row, so it is one row. Such rows are
    tagged ``"kind": "reserved"`` so a consumer that wants only concrete
    assignments can filter them out by an explicit choice rather than by an
    accident of regex.

``--audit`` implements all three definitions and prints what each one yields for
a given draft, so the spread between them is reproducible rather than asserted.


================================================================================
WHICH TABLES ARE REGISTRIES
================================================================================

The registry set is not stable across the fourteen drafts, in two ways.

Location. Drafts 07-13 have no IANA registry for these codes at all. Draft 07's
IANA Considerations section is literally a TODO list of registries that do not
yet exist ("Subscribe Error codes", "Announce Error codes", ...). The codes are
defined inline, next to the message that carries them: session termination codes
in the Termination section of the session chapter, per-message error codes under
each ``*_ERROR`` message, status codes under ``SUBSCRIBE_DONE``, stream reset
codes under "Closing Subgroup Streams". Drafts 14-20 collect them into an IANA
"Error Codes" section with one subsection per registry. A tool that looks under
IANA Considerations finds nothing for seven of the fourteen drafts and reports a
clean, confident, empty result for the entire early cohort.

Membership. The set of registries also changes: draft 07 has three, draft 12 has
eight, draft 15 has four -- and the four in draft 15 are not a subset of the
eight in draft 12, because drafts 15+ merged every per-message error registry
into a single ``REQUEST_ERROR`` registry. Rows are not comparable across drafts
by position, only by (registry_id, code).

So the tool identifies registries by the two table layouts the drafts use for a
code registry of request and session outcomes:

    legacy shape  ``Code | Reason``               (drafts 07-13, inline)
    IANA shape    ``Name | Code | Specification`` (drafts 14-20, IANA section)

Both shapes are used in these documents only for this family of registries. That
is an observation about the source, not an assumption, so it is verified rather
than trusted:

  * Every table matching a shape is put through a semantic guard (its section
    heading or its lead-in sentence must be about termination, an error code, a
    status code, a done code, or resetting a stream). A table that matches a
    shape but fails the guard is still extracted, with a warning recorded in the
    JSON, so that a future draft that reuses the layout for something else shows
    up as a warning instead of as a quietly wrong number.
  * Every table that does NOT match a shape but does contain hex code points is
    recorded in ``excluded_candidates`` with its heading, its header row and its
    hex row count, tagged ``"kind": "table"``. Nothing is dropped without leaving
    a receipt. That list is where a reviewer looks to confirm the boundary is
    drawn where they expect.
  * A registry does not have to be a table, so a table-shaped sweep alone cannot
    honestly claim to have drawn a boundary. In drafts 07-12 the TRACK_STATUS
    status codes are printed as a run of paragraphs or bullets, one per code
    point -- ``0x00: The track is in progress...`` -- with no table anywhere.
    Those runs are recorded in ``excluded_candidates`` too, tagged
    ``"kind": "prose-list"`` and carrying the code points they assign. Without
    them the JSON could not distinguish "out of scope by decision" from "never
    noticed", which are the same shape from the outside and not the same thing.
    Object Status is printed the same way in drafts 07-18 and used to be listed
    there; it is now extracted in its own right, under the extension described
    in the next section, and so no longer appears in ``excluded_candidates``.

Deliberately out of scope, and visible in ``excluded_candidates`` of every draft
that has them:

  * control message type IDs, unidirectional stream types, datagram and subgroup
    header type matrices -- wire type codes, not outcome codes;
  * parameter / property / setup option / auth token alias registries -- these
    are IANA registries in the later drafts, but they are not error, status or
    termination codes;
  * the ``TRACK_STATUS`` status codes. These describe the state of a track, not
    the outcome of a request or a session.

The "status" in "error, status and termination codes" is the Status Code field
of ``SUBSCRIBE_DONE`` / ``PUBLISH_DONE``, which the drafts have called a status
code since draft 07 and which lives inside the Error Codes section from draft 14
onward.


================================================================================
OBJECT STATUS: A SECOND FAMILY, COUNTED SEPARATELY
================================================================================

Object Status (``0x0`` Normal, ``0x3`` End of Group, ``0x4`` End of Track) is
extracted as well, and it does NOT fit definition (C) above. It is admitted by an
explicit extension of the definition, not by relaxing it, and the extension is
spelled out here so that a reader can see exactly what changed.

Two things about Object Status put it outside (C):

  * Subject. (C) is scoped to codes that report the outcome of a request or of a
    session. An Object Status reports the state of an object. The drafts agree
    that these are different things: draft 19 gives Object Status its own IANA
    subsection (15.9), a sibling of, not a part of, the "Error Codes" section
    (15.11) that holds the four outcome registries.
  * Form. (C) is anchored on ``<tr>`` elements, which is what makes it immune to
    the spelling of the strings inside a row. Only draft 19 prints Object Status
    as a table. In drafts 07 through 18 the same code points are assigned by a
    run of bullets under an "Object Status" heading, one bullet per code
    (``0x0 := Normal object. ...``), and there is no IANA registry for them at
    all. A ``<tr>``-anchored definition scores zero on twelve of the fourteen
    drafts.

So the extension is:

  (D) One code point assigned by the draft's Object Status registry, whether the
      draft prints that registry as a table (draft 19) or as a run of bullets
      under the section that defines the field (drafts 07-18).

The counts under (C) and the counts under (D) are NEVER added together. They are
reported in different places in the JSON -- (C) in ``totals.rows`` and
``registries``, (D) in ``totals.object_status_rows`` and ``object_status`` -- and
``totals.rows`` is byte-for-byte what it was before Object Status was extracted
at all. This is the whole reason for the separation. Summing two definitions
across a range of drafts is how this project produced a wrong count once already;
a total that silently means "outcome codes" on one draft and "outcome codes plus
object statuses" on another is the same mistake wearing a different hat. A
consumer that wants one number for both must add them itself, having decided that
it wants to.

For the same reason ``--audit`` is unchanged: it compares three candidate
definitions of an OUTCOME-code row, and its (C) column stays comparable with the
figures printed in the table above.

The Payload column
------------------

Draft 19 added a "Payload" column to the Object Status registry, recording per
status whether an Object with that status may carry a non-empty payload:
``0x0`` Normal Yes, ``0x3`` End of Group No, ``0x4`` End of Track No. Drafts 07
through 18 have no such column. They state one blanket rule in prose instead:
"Any object with a status code other than zero MUST have an empty payload."

Those two are not the same fact, and the JSON must not let them blur. Every row
carries ``payload`` (``"yes"``, ``"no"`` or ``null``) and ``payload_source``,
which is one of:

  * ``payload-column`` -- read out of the draft's own Payload column. The draft
    registered this answer for this status.
  * ``blanket-rule`` -- there is no column; the draft's blanket sentence covers
    this row directly, because the row's code is non-zero and the sentence is
    about non-zero status codes.
  * ``blanket-rule-complement`` -- there is no column, and the blanket sentence
    does not constrain this row: it speaks only of non-zero status codes, and
    this row is ``0x0``. Recorded as ``"yes"`` by inference from the rule's
    silence, corroborated by the Normal bullet itself ("The payload is array of
    bytes and can be empty" in drafts 07-08, "This status is implicit for any
    non-zero length object" from draft 09 on). It is the one payload value in
    this tool's output that the draft does not state somewhere as a rule, and it
    is tagged so that a consumer can refuse it.

The registry object also carries ``payload_column`` (a boolean: did the draft
print the column at all), ``payload_rule`` (the blanket sentence verbatim, where
there is one) and ``payload_rule_kind``. So "no column, blanket rule applies,
answer derived" and "column present, draft registered No" are distinguishable
without reading the draft: the first has ``payload_column: false`` and a
``blanket-rule`` source, the second has ``payload_column: true`` and a
``payload-column`` source.

Draft 19 keeps a blanket sentence too, but it now defers to the registry -- "An
Object MUST have an empty payload unless its Object Status value is registered as
permitting a payload in the Object Status registry" -- so it is recorded with
``payload_rule_kind: "defers-to-registry"`` and no payload value is derived from
it. That deferral is the substantive change: draft 18 fixed the payload rule in
prose, draft 19 made it a property of each registration.

Names and descriptions under (D)
--------------------------------

``name`` follows the same rule as everywhere else in this tool: verbatim where
the draft has a name column (draft 19), ``null`` where it does not (drafts
07-18, which print only a code and a sentence). ``name_normalized`` is DERIVED in
both cases, and ``name_source`` says which. For a bullet the derivation takes the
bullet's first sentence, drops a leading "Indicates"/"Indicates that" and a
trailing "object", and upper-cases the rest: "Indicates End of Group." becomes
``END_OF_GROUP``, which is what draft 19's Name column spells, so a draft-11 row
joins to a draft-19 row. It is a convenience for joining, not a quotation.

Descriptions come from the bullets in the section that defines the field, for
both forms -- draft 19's Specification column points at exactly that section, and
that section is a bulleted list rather than the ``<dt>``/``<dd>`` definition list
the error-code sections use, so the (C) description path cannot read it.


================================================================================
DESCRIPTIONS
================================================================================

The two table shapes carry different things, so descriptions are sourced
differently and the source is always recorded in ``description_source``:

  * legacy ``Code | Reason``: the Reason cell is the human phrase ("Internal
    Error"). It is used verbatim as the description. That is all it is: a label,
    not the draft's rule for the code. Where those drafts say more, they say it
    in prose after the table -- draft 07's ``Parameter Length Mismatch`` is
    defined in section 6.1, two chapters from the table that assigns it -- and
    this tool does not follow that prose. So a legacy-shape draft reaches full
    description coverage by having a Reason column at all, which is a much
    weaker fact than the count makes it look. The totals name which is which:
    ``rows_described_from_reason_column`` versus
    ``rows_described_from_section_prose``. Drafts 07-13 score their whole row
    count in the first and zero in the second.
  * IANA ``Name | Code | Specification``: the table carries a symbolic name and
    a section pointer, no prose. The tool follows the printed section reference
    ("Section 3.5") to that section and its subsections, and reads the
    definition list the drafts use there -- ``<dt>NAME (0x0):</dt><dd>...</dd>``
    or, where the codes are listed without their values, ``<dt>NAME:</dt>``.
    Rows the section does not describe get ``null``, and are the only reason
    ``rows_described_from_section_prose`` falls short of the row count in
    drafts 17-20. Nothing is invented.

``name`` is verbatim: the Name cell in the IANA shape, ``null`` in the legacy
shape, which has no symbolic name column. ``name_normalized`` is DERIVED -- for
the legacy shape it is the Reason phrase upper-cased with separators replaced by
underscores -- and exists so that a draft-08 row can be joined to the draft-14
row for the same code. The derivation reproduces the drafts' own later spelling
("Track Does Not Exist" -> ``TRACK_DOES_NOT_EXIST``, "Key-Value Formatting
Error" -> ``KEY_VALUE_FORMATTING_ERROR``), but it is a convenience for joining,
not a quotation, and consumers that need the exact words of a draft must read
``description``.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = SCRIPT_DIR / "registries"

# The drafts to process, read off this crate's own per-draft modules rather
# than written down.
#
# A hard-coded range goes stale in the silent direction. `--all` would extract
# the drafts the range names and not the one the crate had grown; `--check`
# would compare those same files and report nothing at all about the new
# draft's, which is committed and read by `registry_conformance.rs`; and that
# test would go on passing, because it compares this crate against a JSON file
# nobody regenerated. Every count in the report would stay where it was.
#
# Deriving it also settles what `--fetch` may reach for, which is the question
# a range cannot answer. The set is what this crate has a module for, and a
# module is only ever written for a published draft - so a draft-NN that the
# IETF's server has and this tree does not is not downloaded and not extracted.
# Nothing here should be reaching for a draft nobody has implemented.
DRAFT_FLOOR = frozenset(range(7, 21))

DRAFT_DIR_NAME = re.compile(r"^draft(\d\d)$")


def implemented_drafts():
    """Every draft this crate has a module for, from the tree itself."""
    found = set()
    for child in sorted((SCRIPT_DIR.parent / "src").iterdir()):
        m = DRAFT_DIR_NAME.match(child.name)
        if m and child.is_dir():
            found.add(int(m.group(1)))
    # A derivation that can grow can also shrink, and shrinking is the silent
    # direction: fewer drafts extracted, fewer compared, no count that moves.
    # The floor is the set that existed when the range was replaced. It may be
    # added to and not taken from.
    missing = DRAFT_FLOOR - found
    if missing:
        sys.exit("no src/draftNN module for %s. This set is read off the tree, "
                 "so a renamed or deleted module narrows every extraction below "
                 "without moving a count. If a draft has really been dropped, "
                 "lower DRAFT_FLOOR in the same commit."
                 % ", ".join("draft-%02d" % n for n in sorted(missing)))
    return sorted(found)


DRAFTS = implemented_drafts()

# This script sits at <checkout>/crates/moqtap-codec/tools, so parents[2] is the
# checkout root and parents[3] is the directory holding it. The rendered drafts
# live in a sibling checkout there, not in this repository.
DEFAULT_SPEC_DIR = SCRIPT_DIR.parents[3] / "site" / "spec-sources"

# Where --fetch gets a draft this machine does not already have. These are the
# published Internet-Drafts, readable by anyone; the default directory above is
# just a local copy that happens to be next to this checkout.
SPEC_URL = "https://www.ietf.org/archive/id/draft-ietf-moq-transport-{number:02d}.html"
USER_AGENT = "moqtap-codec extract-registries"

# The two table layouts the drafts use for an outcome-code registry. Compared
# after whitespace collapsing and entity decoding, case-insensitively.
LEGACY_SHAPE = ("code", "reason")
IANA_SHAPE = ("name", "code", "specification")

# Row fields the extraction needs but the committed JSON does not carry.
#
# All five are prose or position copied out of the draft, and nothing reads them
# back: the gates compare code points, names and provenance. `description` is
# built and used during extraction — a reason cell is folded into it, and the
# definition list is matched against it — so these are dropped when the file is
# written rather than never collected. `description_source` stays: it says which
# path produced the description, which is the part a gate asserts.
#
# Use --full to keep them when reading an extraction by hand.
VERBOSE_ROW_FIELDS = ("description", "specification", "table", "reason", "row_index")


def without_verbose_fields(result: dict) -> dict:
    """Strip `VERBOSE_ROW_FIELDS` from every row, in place."""
    groups = list(result.get("registries", []))
    status = result.get("object_status")
    if isinstance(status, dict):
        groups.append(status)
    for group in groups:
        for row in group.get("rows", []):
            for field in VERBOSE_ROW_FIELDS:
                row.pop(field, None)
    return result

# A table that matches a shape must also look like it is about outcomes. This is
# a guard against a future draft reusing the layout, not a selection criterion.
SEMANTIC_GUARD = re.compile(
    r"termination|error|status|done|closing\s+\w+\s+streams|stream\s+reset",
    re.IGNORECASE,
)

ALLCAPS_TOKEN = re.compile(r"\b([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)\b")
LEADIN_REGISTRY = re.compile(
    r"(?:error|status)\s+code\s+in\s+([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)"
)
HEX_LITERAL = re.compile(r"^0x[0-9A-Fa-f]+$")
HEX_ANYWHERE = re.compile(r"0x[0-9A-Fa-f]+")
SECTION_REF = re.compile(r"Section\s+([0-9]+(?:\.[0-9]+)*)")
# <dt>NAME (0x1):</dt> and <dt>NAME:</dt>, the two forms the drafts use.
DT_WITH_CODE = re.compile(
    r"^([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*)\s*\((0x[0-9A-Fa-f]+)\)\s*:?\s*$"
)
# Not every code name contains an underscore: REDIRECT, TIMEOUT and UNAUTHORIZED
# are single words, so this must not require one.
DT_NAME_ONLY = re.compile(r"^([A-Z][A-Z0-9_]{2,})\s*:?\s*$")

# A paragraph or list item that assigns a code point without a table around it.
# The drafts use two spellings: "0x0 := Normal object..." for Object Status and
# "0x00: The track is in progress..." for the TRACK_STATUS status codes.
PROSE_ASSIGNMENT = re.compile(r"^(0x[0-9A-Fa-f]+)\s*(?::=|:)\s+\S")
PROSE_ASSIGNMENT_SPLIT = re.compile(r"^(0x[0-9A-Fa-f]+)\s*(?::=|:)\s+(\S.*)$", re.S)
PROSE_BLOCK = re.compile(r"<(p|li)[^>]*>(.*?)</\1>", re.S)

# --- Object Status (definition (D) in the header) --------------------------
#
# Every draft from 07 on has a section headed exactly "Object Status" that
# defines the field and assigns its code points as bullets. Draft 19 adds a
# second section with the same heading, under IANA Considerations, holding the
# registry table. Matching the heading rather than a table layout is what lets
# one code path cover both, and it keeps the auth-token and setup-option tables
# -- which share draft 19's Code|Name|Specification layout -- out of it.
OBJECT_STATUS_HEADING = re.compile(r"^object\s+status$", re.IGNORECASE)
# Deliberately looser than the heading match above. Its only job is to notice a
# code point table filed under a heading that mentions Object Status which the
# exact match did not claim, so that the exact match cannot fail in silence.
OBJECT_STATUS_MENTION = re.compile(r"object\s+status", re.IGNORECASE)
# The blanket payload rule of drafts 07-18, and draft 19's replacement for it.
BLANKET_NONZERO_EMPTY = re.compile(
    r"status\s+code\s+other\s+than\s+zero\s+MUST\s+have\s+an\s+empty\s+payload",
    re.IGNORECASE,
)
REGISTRY_DEFERRAL = re.compile(
    r"registered\s+as\s+permitting\s+a\s+payload", re.IGNORECASE
)
EMPTY_PAYLOAD = re.compile(r"empty\s+payload", re.IGNORECASE)
# End of sentence: a period followed by whitespace and a capital. Good enough for
# these paragraphs, whose only internal periods are in "Section 3.5" references
# that xml2rfc renders with the digits, not a capital, after the space.
SENTENCE_END = re.compile(r"(?<=\.)\s+(?=[A-Z])")
# "Indicates that ..." / "Indicates ..." open most Object Status bullets.
STATUS_LEADIN = re.compile(r"^indicates\s+(?:that\s+)?", re.IGNORECASE)
STATUS_TRAILING_NOUN = re.compile(r"\s+objects?\s*$", re.IGNORECASE)


# --------------------------------------------------------------------------
# HTML helpers
#
# The rendered drafts are machine-generated xml2rfc output: well-formed, with a
# fixed and simple table/heading/definition-list structure. Regex extraction is
# adequate here and keeps the tool dependency-free; it would not be adequate for
# HTML in general.
# --------------------------------------------------------------------------

TAG = re.compile(r"<[^>]+>")
PILCROW = "¶"


def text_of(fragment: str) -> str:
    """Strip tags and entities from an HTML fragment, collapsing whitespace."""
    plain = html.unescape(TAG.sub(" ", fragment)).replace(PILCROW, " ")
    return " ".join(plain.split())


class Draft:
    """One rendered draft, indexed by heading and by table."""

    def __init__(self, number: int, path: Path):
        self.number = number
        self.path = path
        # Hash the file as it sits on disk, before any decoding. read_text()
        # applies universal newlines, so hashing its result would report the
        # same digest for a CRLF and an LF copy of the draft -- a digest that
        # identifies a normalisation of the input rather than the input, and so
        # cannot be used to check that a count came from the bytes it claims.
        raw = path.read_bytes()
        self.sha256 = hashlib.sha256(raw).hexdigest()
        self.source = raw.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
        self.headings = self._index_headings()
        self.tables = self._index_tables()

    def _index_headings(self) -> list[dict]:
        headings = []
        for match in re.finditer(r"<h([1-6])[^>]*>(.*?)</h\1>", self.source, re.S):
            title = text_of(match.group(2))
            number = None
            numbered = re.match(r"^((?:[0-9]+|[A-Z])(?:\.[0-9]+)*)\.\s*(.*)$", title)
            if numbered:
                number, title = numbered.group(1), numbered.group(2)
            headings.append(
                {
                    "start": match.start(),
                    "end": match.end(),
                    "level": int(match.group(1)),
                    "number": number,
                    "title": title,
                    "full": text_of(match.group(2)),
                }
            )
        return headings

    def _index_tables(self) -> list[dict]:
        tables = []
        for match in re.finditer(r"<table[^>]*>", self.source):
            start = match.start()
            end = self.source.find("</table>", start)
            body = self.source[start:end]
            rows = [
                self._cells(row)
                for row in re.findall(r"<tr[^>]*>(.*?)</tr>", body, re.S)
            ]
            if not rows:
                continue
            anchor = re.search(r'id="([^"]+)"', match.group(0))
            tables.append(
                {
                    "id": anchor.group(1) if anchor else f"table@{start}",
                    "start": start,
                    "header": rows[0],
                    "rows": rows[1:],
                    "heading": self.heading_before(start),
                    "leadin": self._leadin(start),
                    "raw": body,
                }
            )
        return tables

    @staticmethod
    def _cells(row: str) -> list[str]:
        return [
            text_of(cell)
            for cell in re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", row, re.S)
        ]

    def heading_before(self, offset: int) -> dict | None:
        found = None
        for heading in self.headings:
            if heading["start"] < offset:
                found = heading
            else:
                break
        return found

    def _leadin(self, offset: int) -> str:
        paragraphs = re.findall(r"<p[^>]*>(.*?)</p>", self.source[:offset], re.S)
        return text_of(paragraphs[-1]) if paragraphs else ""

    def prose_code_lists(self) -> list[dict]:
        """Runs of prose that assign code points with no table anywhere in sight.

        A registry does not have to be a table. In the early drafts the
        TRACK_STATUS status codes are printed as a list of paragraphs or
        bullets, one per code point. Nothing in the table-shaped extraction can
        see them, and until they are recorded here nothing in the output says
        they exist -- so "not in this tool's scope" and "this tool never noticed
        it" look identical from the JSON. Grouped by enclosing heading; a
        heading needs at least two code points before it counts as a list, so a
        lone sentence that happens to open with a code point does not.

        Object Status is found by this sweep too, in every draft. It is not an
        exclusion any more, so the caller drops its heading from the result and
        extracts it properly instead.
        """
        by_heading: dict[int, dict] = {}
        for match in PROSE_BLOCK.finditer(self.source):
            assignment = PROSE_ASSIGNMENT.match(text_of(match.group(2)))
            if not assignment:
                continue
            heading = self.heading_before(match.start())
            key = heading["start"] if heading else -1
            entry = by_heading.setdefault(
                key,
                {
                    "section": heading["full"] if heading else "(no enclosing heading)",
                    "heading_start": key,
                    "codes": [],
                },
            )
            code = assignment.group(1)
            if code not in entry["codes"]:
                entry["codes"].append(code)
        return [entry for entry in by_heading.values() if len(entry["codes"]) > 1]

    def section_body(self, number: str) -> str:
        """Text of the section with this number, including its subsections."""
        chunks = []
        for index, heading in enumerate(self.headings):
            if heading["number"] is None:
                continue
            if heading["number"] == number or heading["number"].startswith(number + "."):
                stop = (
                    self.headings[index + 1]["start"]
                    if index + 1 < len(self.headings)
                    else len(self.source)
                )
                chunks.append(self.source[heading["end"] : stop])
        return "".join(chunks)


# --------------------------------------------------------------------------
# Registry identification and naming
# --------------------------------------------------------------------------


def shape_of(header: list[str]) -> str | None:
    normalised = tuple(cell.strip().lower() for cell in header)
    if normalised == LEGACY_SHAPE:
        return "legacy"
    if normalised == IANA_SHAPE:
        return "iana"
    return None


def registry_name(table: dict) -> str:
    """The registry's name as the draft presents it.

    Preference order matters. The heading wins when it names a message, because
    a lead-in sentence may name a different message than the registry it
    introduces -- "Closing Subgroup Streams" is introduced by a sentence about
    RESET_STREAM, which is the QUIC frame, not the registry.
    """
    heading = table["heading"]
    title = heading["title"] if heading else ""

    token = ALLCAPS_TOKEN.search(title)
    if token:
        return title  # e.g. "SUBSCRIBE_ERROR", "PUBLISH_DONE Codes"
    if re.search(r"termination", title, re.IGNORECASE):
        return title
    if re.search(r"closing\s+.*streams|stream\s+reset", title, re.IGNORECASE):
        return title

    # Draft 07 puts two registries under a heading that names neither of them
    # ("Subscriber Interactions"); the lead-in sentence is what identifies them.
    from_leadin = LEADIN_REGISTRY.search(table["leadin"])
    if from_leadin:
        return from_leadin.group(1)
    return title


def registry_id(name: str) -> tuple[str, str | None]:
    """A stable slug for joining the same registry across drafts.

    Returns (slug, warning). The slug is what lets a draft-08 SUBSCRIBE_ERROR row
    line up with the draft-14 one, and what shows that drafts 15+ replaced the
    per-message registries with a single REQUEST_ERROR registry.
    """
    token = ALLCAPS_TOKEN.search(name)
    if token:
        return token.group(1).lower(), None
    if re.search(r"termination", name, re.IGNORECASE):
        return "session_termination", None
    if re.search(r"closing\s+.*streams|stream\s+reset", name, re.IGNORECASE):
        return "stream_reset", None
    slug = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    return slug, f"registry {name!r} has no known slug; fell back to {slug!r}"


def normalize_name(text: str) -> str:
    """Derive a SCREAMING_SNAKE identifier from a Reason phrase."""
    return re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_").upper()


# --------------------------------------------------------------------------
# Row extraction
# --------------------------------------------------------------------------


def code_value(code: str) -> int | None:
    return int(code, 16) if HEX_LITERAL.match(code) else None


def extract_rows(table: dict, shape: str) -> tuple[list[dict], int]:
    """Rows of one registry table. Returns (rows, merged_continuation_count)."""
    code_column = 0 if shape == "legacy" else 1
    rows: list[dict] = []
    merged = 0

    for index, cells in enumerate(table["rows"]):
        if len(cells) <= code_column:
            continue
        code = cells[code_column].strip()

        if not code:
            # Line-wrap continuation: xml2rfc splits long cell text across extra
            # <tr> elements whose leading cells are empty. Fold it into the row
            # above rather than counting it.
            if rows:
                extra = " ".join(cell for cell in cells if cell).strip()
                if extra:
                    tail = rows[-1]["description"]
                    rows[-1]["description"] = f"{tail} {extra}".strip() if tail else extra
                merged += 1
            continue

        if not HEX_ANYWHERE.search(code):
            continue

        if shape == "legacy":
            reason = cells[1].strip() if len(cells) > 1 else ""
            row = {
                "code": code,
                "code_value": code_value(code),
                "kind": "assignment" if HEX_LITERAL.match(code) else "reserved",
                "name": None,
                "name_normalized": normalize_name(reason) if reason else None,
                "description": reason or None,
                "description_source": "reason-column" if reason else None,
                "specification": None,
                "row_index": index,
            }
        else:
            name = cells[0].strip()
            spec = cells[2].strip() if len(cells) > 2 else ""
            row = {
                "code": code,
                "code_value": code_value(code),
                "kind": "assignment" if HEX_LITERAL.match(code) else "reserved",
                "name": name or None,
                "name_normalized": normalize_name(name) if name else None,
                "description": None,
                "description_source": None,
                "specification": spec or None,
                "row_index": index,
            }
        rows.append(row)

    return rows, merged


def describe_from_section(draft: Draft, rows: list[dict]) -> None:
    """Fill in descriptions for IANA-shape rows from the referenced section."""
    by_section: dict[str, list[dict]] = {}
    for row in rows:
        if not row["specification"]:
            continue
        ref = SECTION_REF.search(row["specification"])
        if ref:
            by_section.setdefault(ref.group(1), []).append(row)

    for number, section_rows in by_section.items():
        body = draft.section_body(number)
        if not body:
            continue
        by_code: dict[str, str] = {}
        by_name: dict[str, str] = {}
        for item in re.finditer(
            r"<dt[^>]*>(.*?)</dt>\s*(?:<dd[^>]*>(.*?)</dd>)?", body, re.S
        ):
            term = text_of(item.group(1))
            definition = text_of(item.group(2) or "")
            if not definition:
                continue
            with_code = DT_WITH_CODE.match(term)
            if with_code:
                by_code[with_code.group(2).lower()] = definition
                by_name[with_code.group(1)] = definition
                continue
            name_only = DT_NAME_ONLY.match(term)
            if name_only:
                by_name[name_only.group(1)] = definition

        for row in section_rows:
            if row["code"].lower() in by_code:
                row["description"] = by_code[row["code"].lower()]
                row["description_source"] = f"section {number} definition list (by code)"
            elif row["name"] and row["name"] in by_name:
                row["description"] = by_name[row["name"]]
                row["description_source"] = f"section {number} definition list (by name)"


# --------------------------------------------------------------------------
# Object Status: definition (D)
# --------------------------------------------------------------------------


def status_name_from_bullet(text: str) -> str | None:
    """Derive a joinable identifier from an Object Status bullet.

    "Indicates End of Group. Indicates that no objects..." -> END_OF_GROUP,
    "Normal object. This status is implicit..."            -> NORMAL.

    Derived, not quoted: these drafts print no name for a status. The target is
    draft 19's Name column, so that rows for the same code join across drafts.
    """
    first = SENTENCE_END.split(text.strip(), 1)[0].strip().rstrip(".")
    first = STATUS_LEADIN.sub("", first).strip()
    first = STATUS_TRAILING_NOUN.sub("", first).strip()
    return normalize_name(first) or None


def column_reader(columns: dict[str, int], cells: list[str]):
    """Read a row's cells by column heading rather than by position.

    Draft 19 orders the Object Status registry Code | Name | Payload |
    Specification, which is neither of the two layouts the outcome registries
    use, and the Payload column exists in no other draft. Reading by heading is
    what lets one code path handle a column that comes and goes.
    """

    def read(column: str) -> str:
        at = columns.get(column)
        return cells[at].strip() if at is not None and at < len(cells) else ""

    return read


def object_status_bullets(draft: Draft, heading: dict) -> list[tuple[str, str]]:
    """(code, definition text) for each bullet under an Object Status heading."""
    body = draft.section_body(heading["number"]) if heading["number"] else ""
    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    for match in PROSE_BLOCK.finditer(body):
        split = PROSE_ASSIGNMENT_SPLIT.match(text_of(match.group(2)))
        if not split:
            continue
        code = split.group(1)
        if code in seen:
            continue
        seen.add(code)
        found.append((code, split.group(2).strip()))
    return found


def object_status_payload_rule(
    draft: Draft, heading: dict
) -> tuple[str | None, str | None]:
    """The draft's blanket payload sentence, and which kind of rule it is.

    Only paragraphs that are not themselves code assignments are considered, so
    draft 07's "0x0 := Normal object. The payload is array of bytes and can be
    empty." cannot be mistaken for the rule.
    """
    body = draft.section_body(heading["number"]) if heading["number"] else ""
    for paragraph in re.findall(r"<p[^>]*>(.*?)</p>", body, re.S):
        text = text_of(paragraph)
        if PROSE_ASSIGNMENT.match(text):
            continue
        for sentence in SENTENCE_END.split(text):
            if not EMPTY_PAYLOAD.search(sentence):
                continue
            if BLANKET_NONZERO_EMPTY.search(sentence):
                return sentence.strip(), "nonzero-must-be-empty"
            if REGISTRY_DEFERRAL.search(sentence):
                return sentence.strip(), "defers-to-registry"
            return sentence.strip(), None
    return None, None


def extract_object_status(
    draft: Draft,
) -> tuple[dict, str | None, int | None, list[str]]:
    """The Object Status registry of one draft.

    Returns (registry, consumed_table_id, consumed_heading_start, warnings). The
    two "consumed" values tell the caller which table and which prose run have
    been extracted here, so they are not also reported as excluded candidates.
    """
    warnings: list[str] = []
    headings = [h for h in draft.headings if OBJECT_STATUS_HEADING.match(h["title"])]
    if not headings:
        return (
            {
                "registry": "Object Status",
                "registry_id": "object_status",
                "present": False,
                "form": None,
                "iana_registry": False,
                "reason_absent": "no section headed 'Object Status' in this draft",
                "row_count": 0,
                "rows": [],
            },
            None,
            None,
            warnings,
        )

    # The section that defines the field is the one with the bullets; the IANA
    # section, when there is one, is the one with the table under it.
    definition = None
    bullets: list[tuple[str, str]] = []
    for heading in headings:
        found = object_status_bullets(draft, heading)
        if found and (definition is None or len(found) > len(bullets)):
            definition, bullets = heading, found

    table = None
    for candidate in draft.tables:
        if candidate["heading"] in headings and any(
            cell.strip().lower() == "code" for cell in candidate["header"]
        ):
            table = candidate
            break

    rule, rule_kind = (
        object_status_payload_rule(draft, definition) if definition else (None, None)
    )
    if rule and rule_kind is None:
        warnings.append(
            f"object status: payload rule {rule!r} matches neither the blanket "
            "non-zero rule nor a deferral to the registry; no payload value "
            "derived from it"
        )

    by_code = {code: text for code, text in bullets}
    definition_section = definition["full"] if definition else None
    definition_number = definition["number"] if definition else None
    rows: list[dict] = []

    if table is not None:
        columns = {cell.strip().lower(): i for i, cell in enumerate(table["header"])}
        code_at = columns["code"]
        for index, cells in enumerate(table["rows"]):
            if len(cells) <= code_at:
                continue
            code = cells[code_at].strip()
            if not code or not HEX_ANYWHERE.search(code):
                continue
            named = column_reader(columns, cells)

            payload_cell = named("payload")
            payload = payload_cell.lower() or None
            if payload is not None and payload not in ("yes", "no"):
                warnings.append(
                    f"object status: {code} has Payload {payload_cell!r}, which is "
                    "neither Yes nor No; recorded verbatim"
                )
            name = named("name") or None
            description = by_code.get(code.lower()) or by_code.get(code)
            rows.append(
                {
                    "code": code,
                    "code_value": code_value(code),
                    "kind": "assignment" if HEX_LITERAL.match(code) else "reserved",
                    "name": name,
                    "name_normalized": normalize_name(name) if name else None,
                    "name_source": "name-column" if name else None,
                    "payload": payload,
                    "payload_source": "payload-column" if payload else None,
                    "description": description,
                    "description_source": (
                        f"section {definition_number} bullet list (by code)"
                        if description
                        else None
                    ),
                    "specification": named("specification") or None,
                    "row_index": index,
                }
            )
        form = "iana-table"
        payload_column = "payload" in columns
        section = table["heading"]["full"] if table["heading"] else None
    else:
        for index, (code, text) in enumerate(bullets):
            value = code_value(code)
            if rule_kind == "nonzero-must-be-empty" and value is not None:
                payload = "yes" if value == 0 else "no"
                payload_source = (
                    "blanket-rule-complement" if value == 0 else "blanket-rule"
                )
            else:
                payload, payload_source = None, None
            derived = status_name_from_bullet(text)
            rows.append(
                {
                    "code": code,
                    "code_value": value,
                    "kind": "assignment" if HEX_LITERAL.match(code) else "reserved",
                    "name": None,
                    "name_normalized": derived,
                    "name_source": (
                        "derived from the bullet's first sentence" if derived else None
                    ),
                    "payload": payload,
                    "payload_source": payload_source,
                    "description": text,
                    "description_source": f"section {definition_number} bullet list",
                    "specification": None,
                    "row_index": index,
                }
            )
        form = "prose-list" if rows else None
        payload_column = False
        section = definition_section

    for row in rows:
        row["draft"] = draft.number
        row["registry"] = "Object Status"
        row["registry_id"] = "object_status"
        row["table"] = table["id"] if table is not None else None

    if not rows:
        warnings.append(
            "object status: a section headed 'Object Status' exists but assigns no "
            "code points in a table or in bullets; nothing extracted"
        )

    registry = {
        "registry": "Object Status",
        "registry_id": "object_status",
        "present": bool(rows),
        "form": form,
        "iana_registry": table is not None,
        "row_definition": (
            "One code point assigned by the draft's Object Status registry. Draft 19 "
            "prints that registry as an IANA table; drafts 07-18 have no IANA registry "
            "for it and assign the same code points as one bullet each under the "
            "section defining the field. Counted separately from totals.rows, which "
            "covers the error, status and termination code registries only; the two "
            "are never summed."
        ),
        "section": section,
        "definition_section": definition_section,
        "table": table["id"] if table is not None else None,
        "payload_column": payload_column,
        "payload_rule": rule,
        "payload_rule_kind": rule_kind,
        "payload_note": (
            "payload_source is payload-column when the draft's own Payload column "
            "supplied the value; blanket-rule when there is no column and the draft's "
            "blanket sentence covers the row directly (its code is non-zero and the "
            "sentence is about non-zero status codes); blanket-rule-complement for 0x0 "
            "under such a rule, where the value is inferred from the rule's silence "
            "rather than stated. A row with payload_column false and payload 'no' is "
            "therefore a different fact from a row with payload_column true and "
            "payload 'no': the first is this tool applying the draft's blanket rule, "
            "the second is the draft registering an answer for that status."
        ),
        "row_count": len(rows),
        "rows_with_payload": sum(1 for row in rows if row["payload"]),
        "rows": rows,
    }
    consumed_table = table["id"] if table is not None else None
    consumed_heading = definition["start"] if definition else None
    return registry, consumed_table, consumed_heading, warnings


# --------------------------------------------------------------------------
# Per-draft extraction
# --------------------------------------------------------------------------


def extract(draft: Draft) -> dict:
    registries = []
    excluded = []
    warnings: list[str] = []

    object_status, os_table, os_heading, os_warnings = extract_object_status(draft)
    warnings.extend(os_warnings)

    for table in draft.tables:
        shape = shape_of(table["header"])
        heading = table["heading"]
        section = heading["full"] if heading else "(no enclosing heading)"

        if table["id"] == os_table:
            # Extracted above under definition (D), so it is not a candidate the
            # tool passed over -- listing it as excluded would be a false receipt.
            continue

        if shape is None:
            hex_rows = sum(
                1 for cells in table["rows"] if any(HEX_ANYWHERE.search(c) for c in cells)
            )
            if hex_rows:
                # A table of code points sitting under a heading that talks
                # about Object Status, which the Object Status extraction did
                # not claim. Under definition (D) that table is in scope, so
                # the generic "not an error, status or termination registry"
                # reason would be a false receipt -- it answers definition (C),
                # which was never the one that governs this table.
                #
                # This is the failure mode of anchoring (D) on an exact heading:
                # the extraction matches "Object Status" and nothing else, so a
                # revision that retitles the section to "Object Status Codes"
                # -- the spelling every error registry already uses -- drops the
                # table here and falls back to the prose bullets, losing the
                # Payload column while still reporting three rows. Every visible
                # count stays the same, so the only thing that can report it is
                # a warning raised at the point the table is passed over.
                orphan = bool(OBJECT_STATUS_MENTION.search(section)) and not object_status[
                    "iana_registry"
                ]
                if orphan:
                    warnings.append(
                        f"{table['id']}: a code point table under '{section}' was not "
                        "extracted as the Object Status registry, and no Object Status "
                        "registry table was found anywhere in this draft. The section "
                        "heading no longer reads exactly 'Object Status', so the "
                        "extraction fell back to the prose bullets and any Payload "
                        "column in this table has been dropped"
                    )
                excluded.append(
                    {
                        "kind": "table",
                        "table": table["id"],
                        "section": section,
                        "header": table["header"],
                        "hex_rows": hex_rows,
                        "codes": None,
                        "reason": (
                            "under a heading naming Object Status, but not matched as "
                            "the Object Status registry; see warnings"
                            if orphan
                            else "header is not a Code|Reason or Name|Code|Specification "
                            "registry layout; not an error, status or termination registry"
                        ),
                    }
                )
            continue

        name = registry_name(table)
        slug, slug_warning = registry_id(name)
        if slug_warning:
            warnings.append(f"{table['id']}: {slug_warning}")

        guard_text = f"{section} {table['leadin']}"
        if not SEMANTIC_GUARD.search(guard_text):
            warnings.append(
                f"{table['id']} in {section!r} has a registry layout but neither its "
                "heading nor its lead-in mentions termination, an error, a status, a "
                "done code or a stream reset; extracted anyway -- check it"
            )

        rows, merged = extract_rows(table, shape)
        if merged:
            warnings.append(
                f"{table['id']}: merged {merged} line-wrap continuation row(s) "
                "into the preceding row"
            )
        if shape == "iana":
            describe_from_section(draft, rows)

        for row in rows:
            row["draft"] = draft.number
            row["registry"] = name
            row["registry_id"] = slug
            row["table"] = table["id"]

        registries.append(
            {
                "registry": name,
                "registry_id": slug,
                "shape": shape,
                "table": table["id"],
                "section": section,
                "leadin": table["leadin"],
                "row_count": len(rows),
                "rows": rows,
            }
        )

    for prose in draft.prose_code_lists():
        if prose["heading_start"] == os_heading:
            continue
        excluded.append(
            {
                "kind": "prose-list",
                "table": None,
                "section": prose["section"],
                "header": None,
                "hex_rows": len(prose["codes"]),
                "codes": prose["codes"],
                "reason": "code points assigned in prose, one paragraph or bullet per "
                "code, with no table to match either registry layout; out of scope for "
                "this tool and recorded so the boundary stays auditable",
            }
        )

    rows = [row for reg in registries for row in reg["rows"]]
    from_reason = sum(1 for row in rows if row["description_source"] == "reason-column")
    from_prose = sum(
        1
        for row in rows
        if row["description_source"] and row["description_source"].startswith("section ")
    )
    total_rows = sum(reg["row_count"] for reg in registries)
    # The two definitions are kept apart by WHERE a row came from, so that is
    # what this counts: outcome-registry rows that were read out of the same
    # table the Object Status registry was read out of.
    #
    # Comparing code points instead would measure nothing. 0x0, 0x3 and 0x4 are
    # live assignments in the outcome registries as well -- 0x0 is NO_ERROR in
    # Session Termination -- so a code-point overlap is large and expected in
    # every draft, and a count of it could never be read as a failure.
    #
    # Sharing a source table is the failure, and it is reachable: draft 19's
    # Object Status table is skipped by the shape filter only because its
    # header is Code|Name|Payload|Specification. A revision that dropped the
    # Payload column would leave Name|Code|Specification, the IANA registry
    # shape, and the semantic guard admits it on the word "status" -- so the
    # same table would be extracted twice, once under each definition, and
    # totals.rows would silently absorb the Object Status assignments.
    status_tables = {object_status["table"]} - {None}
    double_counted = sum(1 for row in rows if row["table"] in status_tables)

    return {
        "draft": draft.number,
        "source_file": draft.path.name,
        "source_sha256": draft.sha256,
        "source_sha256_of": "the draft-NN.html file as bytes on disk",
        "generated_by": "crates/moqtap-codec/tools/extract-registries.py",
        "row_definition": (
            "One <tr> of a table identified as an error, status or termination code "
            "registry that assigns a code point. Header rows are excluded; empty-code "
            "line-wrap continuation rows are merged into the row above; range and "
            "expression code points count as one row each and are tagged "
            'kind="reserved".'
        ),
        "description_coverage_note": (
            "rows_described_from_reason_column counts rows whose description is the "
            "Reason cell of the table itself, copied verbatim -- a phrase such as "
            "'Internal Error', not the draft's full rule for the code. Where those "
            "drafts say more about a code, they say it in prose after the table, and "
            "this tool does not follow that prose. A legacy-shape draft therefore "
            "reaches full coverage by having a Reason column, which is a weaker claim "
            "than it looks. rows_described_from_section_prose is the strong one: it "
            "counts rows whose description was read from the definition list in the "
            "section the table's Specification column points at."
        ),
        "object_status_note": (
            "object_status is a second registry family, counted under its own "
            "definition and reported separately. totals.rows and the registries list "
            "cover the error, status and termination code registries only, and are "
            "unchanged by its presence; totals.object_status_rows is not included in "
            "totals.rows and must not be added to it without a deliberate decision to "
            "do so. Drafts 19 and 20 have an IANA registry for Object Status "
            "(object_status.iana_registry); in drafts 07-18 the same code points are "
            "assigned in prose and object_status.form is 'prose-list'."
        ),
        "totals": {
            "registries": len(registries),
            "rows": total_rows,
            "rows_with_description": from_reason + from_prose,
            "rows_described_from_reason_column": from_reason,
            "rows_described_from_section_prose": from_prose,
            "object_status_rows": object_status["row_count"],
            # Computed, not asserted: outcome-registry rows taken from the very
            # table the Object Status registry was taken from. It is 0 in every
            # draft, and a non-zero value is the separation of the two
            # definitions failing -- one table counted under both, which is the
            # failure mode this split exists to prevent. Measured by source
            # table, not by code point: see the comment where it is computed for
            # why a code-point overlap would be meaningless here.
            "object_status_rows_also_counted_in_rows": double_counted,
        },
        "registries": registries,
        "object_status": object_status,
        "excluded_candidates": excluded,
        "warnings": warnings,
    }


# --------------------------------------------------------------------------
# Audit mode: the three candidate row definitions, side by side
# --------------------------------------------------------------------------


def audit(draft: Draft, result: dict) -> dict:
    """Count the same draft under all three candidate definitions of a row.

    The point is that the spread between them is reproducible. These are this
    tool's implementations of the three definitions, not a replay of any earlier
    measurement, so the absolute numbers depend on how each definition is spelled
    out; what does not depend on the spelling is that (A) > (B) > (C) and that
    the gaps are made of mentions and of unrelated registries.
    """
    text = text_of(draft.source)
    adjacency = re.compile(
        r"\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b[^A-Za-z0-9]{0,3}0x[0-9A-Fa-f]+"
        r"|0x[0-9A-Fa-f]+[^A-Za-z0-9]{0,3}\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b"
    )
    a = len(adjacency.findall(text))

    b = 0
    for table in draft.tables:
        for cells in table["rows"]:
            has_name = any(
                re.fullmatch(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+", cell) for cell in cells
            )
            has_code = any(HEX_LITERAL.match(cell) for cell in cells)
            if has_name and has_code:
                b += 1

    return {
        "A_symbol_adjacent_anywhere": a,
        "B_any_table_cell_name_plus_code": b,
        "C_registry_rows": result["totals"]["rows"],
        "C_registries": result["totals"]["registries"],
    }


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------


def spec_path(spec_dir: Path, number: int) -> Path:
    return spec_dir / f"draft-{number:02d}.html"


# Which file the extraction came from, as opposed to what it found in it.
PROVENANCE_FIELDS = ("source_sha256", "source_file")


def same_extraction(left: str, right: str) -> bool:
    """Whether two emitted files agree on everything but `PROVENANCE_FIELDS`."""
    try:
        a, b = json.loads(left), json.loads(right)
    except json.JSONDecodeError:
        return False
    for document in (a, b):
        for field in PROVENANCE_FIELDS:
            document.pop(field, None)
    return a == b


def fetch_missing(spec_dir: Path, numbers: list[int]) -> None:
    """Download any draft in `numbers` that `spec_dir` does not already hold."""
    import urllib.request

    spec_dir.mkdir(parents=True, exist_ok=True)
    for number in numbers:
        destination = spec_path(spec_dir, number)
        if destination.is_file():
            continue
        url = SPEC_URL.format(number=number)
        print(f"fetching {url}", file=sys.stderr)
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=60) as response:
            destination.write_bytes(response.read())


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Extract MoQT error, status and termination code registries."
    )
    parser.add_argument("drafts", nargs="*", type=int, help="draft numbers, e.g. 19")
    parser.add_argument(
        "--all",
        action="store_true",
        help="process every draft with a module here (currently %02d-%02d)"
        % (DRAFTS[0], DRAFTS[-1]),
    )
    parser.add_argument(
        "--spec-dir",
        type=Path,
        default=Path(os.environ.get("MOQT_SPEC_DIR", DEFAULT_SPEC_DIR)),
        help="directory holding draft-NN.html",
    )
    parser.add_argument(
        "--out-dir", type=Path, default=OUTPUT_DIR, help="where to write draft-NN.json"
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help="also report the three candidate row definitions",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="do not write; exit non-zero if the committed JSON would change",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help=f"keep the row fields the committed files drop: {', '.join(VERBOSE_ROW_FIELDS)}",
    )
    parser.add_argument(
        "--fetch",
        action="store_true",
        help="download any draft --spec-dir does not hold, from the IETF archive",
    )
    args = parser.parse_args(argv)

    # --check compares against files written without --full, so the two together
    # would report every draft as stale and mean nothing.
    if args.check and args.full:
        parser.error("--check compares against the committed form; drop --full")

    numbers = DRAFTS if args.all else sorted(set(args.drafts))
    if not numbers:
        parser.error("give one or more draft numbers, or --all")

    if args.fetch:
        fetch_missing(args.spec_dir, numbers)

    missing = [n for n in numbers if not spec_path(args.spec_dir, n).is_file()]
    if missing:
        print(
            f"error: no rendered draft(s) {missing} under {args.spec_dir}\n"
            "       pass --fetch to download them, --spec-dir to point elsewhere,\n"
            "       or set MOQT_SPEC_DIR",
            file=sys.stderr,
        )
        return 2

    if not args.check:
        args.out_dir.mkdir(parents=True, exist_ok=True)

    stale: list[str] = []
    rerendered: list[str] = []
    all_warnings: list[str] = []
    total_registries = 0
    total_rows = 0
    total_status_rows = 0

    header = (
        f"{'draft':>5}  {'registries':>10}  {'rows':>5}  "
        f"{'reason':>7}  {'prose':>6}  {'excluded':>8}  "
        f"{'objstatus':>9}  {'form':>10}"
    )
    if args.audit:
        header += f"  {'A':>6}  {'B':>6}  {'C':>6}"
    print(header)
    print("-" * len(header))

    for number in numbers:
        draft = Draft(number, spec_path(args.spec_dir, number))
        result = extract(draft)
        # Reported on the console only. The committed JSON must not depend on
        # which flags were passed, or --check stops meaning anything.
        audited = audit(draft, result) if args.audit else None

        if not args.full:
            without_verbose_fields(result)
        payload = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
        destination = args.out_dir / f"draft-{number:02d}.json"
        if args.check:
            current = (
                destination.read_text(encoding="utf-8")
                if destination.is_file()
                else None
            )
            if current != payload:
                # A draft downloaded today hashes differently from the same
                # draft downloaded last year, because the IETF re-renders these
                # pages. Comparing whole files would report every draft as
                # stale for anyone who did not save the exact bytes on disk
                # here, which is everyone. What the check is for is whether a
                # row moved, so the provenance is set aside and reported apart.
                if current is not None and same_extraction(current, payload):
                    rerendered.append(destination.name)
                else:
                    stale.append(destination.name)
        else:
            destination.write_text(payload, encoding="utf-8")

        totals = result["totals"]
        total_registries += totals["registries"]
        total_rows += totals["rows"]
        total_status_rows += totals["object_status_rows"]
        line = (
            f"{number:>5}  {totals['registries']:>10}  {totals['rows']:>5}  "
            f"{totals['rows_described_from_reason_column']:>7}  "
            f"{totals['rows_described_from_section_prose']:>6}  "
            f"{len(result['excluded_candidates']):>8}  "
            f"{totals['object_status_rows']:>9}  "
            f"{result['object_status']['form'] or '-':>10}"
        )
        if audited:
            line += (
                f"  {audited['A_symbol_adjacent_anywhere']:>6}"
                f"  {audited['B_any_table_cell_name_plus_code']:>6}"
                f"  {audited['C_registry_rows']:>6}"
            )
        print(line)
        all_warnings.extend(f"draft-{number:02d}: {w}" for w in result["warnings"])

    print("-" * len(header))
    # The two totals are printed apart and never added: they count different
    # populations under different definitions of a row.
    print(
        f"{'total':>5}  {total_registries:>10}  {total_rows:>5}"
        f"{'':>25}  {total_status_rows:>9}"
    )

    if all_warnings:
        print("\nwarnings:")
        for warning in all_warnings:
            print(f"  {warning}")

    if args.check and rerendered:
        print(
            f"\nsame rows, different source bytes: {', '.join(rerendered)}\n"
            "  the committed extraction still holds; only source_sha256 moved",
        )
    if args.check and stale:
        print(f"\nout of date: {', '.join(stale)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
