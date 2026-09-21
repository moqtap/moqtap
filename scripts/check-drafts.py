#!/usr/bin/env python3
"""Check every citation and every quotation in this workspace against the drafts.

The house style is to quote the draft rather than paraphrase it, and to name the
section the sentence came from. That makes a doc comment evidence — and evidence
is worth exactly what the last check of it was worth. Nothing in `cargo` can
read it: a misquoted sentence compiles, a citation naming a section that does
not exist compiles, and a quotation filed under the wrong section compiles and
reads as though somebody had looked.

Eight rules, over three objects.

**Citations.** Rule 1 asks that every `draft-NN Section X.Y` anywhere under
`crates/` names a section that draft has. Rule 2 asks the same of every bare
`Section X.Y` inside a file that names a draft, read as a citation to that
draft, which is what a bare one means there.

**Quotations.** Rule 3 asks that every quotation in a per-draft file appears in
that file's draft — or, when the block around it names other drafts, in one of
them, which is what a comparison with a neighbour looks like. Rule 4 asks
that a quotation and the single citation beside it are about the same section: a
sentence filed under a neighbouring section is a citation that reads as checked
and is not. Rule 5 asks that a long normative quotation in a draft-neutral file
appears in *some* draft, which needs no attribution to be worth asking — if no
draft has the sentence, it is wrong whichever draft was meant. Rule 6 asks that
a quotation a block claims for *several* drafts is in every one of them, which
is the one thing rule 3 is built not to ask: rule 3 is satisfied by any one of
the drafts a block names, so "drafts 08 through 13 write the same rule as X"
passes on draft-13 alone having X and says nothing about the other five.
Rule 7 asks that a quotation in a draft-neutral file does not close on a mark
the draft has not got, which is the half of rule 3's question that needs no
attribution: a sentence found in a draft the moment its last full stop is
dropped is that draft's sentence with its ending changed, whichever draft was
meant.

**A citation the tree stores as a value rather than as prose.** Rule 8 is the
odd one and reads the third object: `AboveCodecRule::citations` in
`moqtap-client`, which is a table of quoted draft sentences held as Rust data
because a consumer publishes them per negotiated draft. Rules 3 to 7 read
comments, and deliberately — a quotation in a string literal is as likely to be
a recorded panic message as a draft's sentence. That leaves a table like this
one read by nothing at all, which is the state such a table is in wherever no
gate walks it: one sentence per rule, printed beside whichever draft was
negotiated, and no gate anywhere near it. So rule 8 reads the
table's own rows and asks all three of the questions a row makes: that the
sentence is in every draft of the run it claims, that it sits in the section the
row names, and that the code name the row carries is a name the sentence itself
uses. It fails closed — a table it cannot find or cannot parse stops the run
rather than passing silently, which is the failure mode a rule reading one file
at a fixed path is otherwise exactly one rename away from.

**A file names its draft two ways, and only one of them was being read.** A
`src/draft14/` directory says it, and so does a `tests/draft14_wire_rules.rs`
file name — but the quotation rules walked `src` alone until 2026-08-26, and
rule 2 resolved a bare citation against a directory alone. That left 209
quotations in 67 per-draft test files and 203 in the neutral ones unread, along
with 234 bare citations, in the part of the tree where most of the conformance
prose actually lives: a rule and the gate that watches it sit together, so the
sentence gets quoted next to the test rather than next to the code.

Reading them found two citations naming a section their draft does not have,
one naming a different section from the one its sentence sits in, two naming
that section's parent, a range claimed for six drafts that only three of them
state, four sentences transcribed with a word added or a word wrong, and two
dozen full stops the tree had supplied where the draft's sentence goes on —
about half of those because the rendering carries a cross-reference inside the
sentence and the tree had quoted around it. A file naming its draft in its own
name is the ordinary shape for a test, so the blind spot was the shape rather
than a corner of it.

Each rule carries the floor it is allowed to report and the reason every member
of that floor is there, by name rather than by count. A count alone lets a new
defect hide behind a known one the moment a known one is fixed.

## What this has caught, and what it costs to get wrong

**A citation form nothing matches is not a clean citation, it is an unchecked
one.** Rule 1 once matched `draft-NN` case-sensitively while rule 2 excluded
both cases from its own sweep, so every citation written `Draft-NN Section X.Y`
— which is every one that opens a sentence, and that is the house style — fell
between the two and was read by neither. That was a quarter of them. Both rules
now take their split from one function, `citation_spans`, rather than from two
patterns that have to agree: rule 2 skips exactly what rule 1 matched, computed
on the same text, so there is no seam left to drift.

**The plural form is one citation per number.** `Sections 9.8 and 9.13` was one
citation to a pattern wanting a space right after the word and none at all to a
pattern that stopped after the first number. Ninety-five came into view when
that was fixed, and all ninety-five resolved.

**Both citation rules read a joined comment block, not a line.** The prose is
hard-wrapped, so a citation can arrive as `draft-14` at the end of one line and
`Section 9.7` at the start of the next. Read a line at a time that is two
things: an invisible citation, or — worse — a bare `Section 9.7` resolved
against the file's own draft instead of draft-14, which reports nothing at all
whenever that number happens to exist there. Joining first made 117 citations
visible to rule 2 that had never been read, and moved 34 into rule 1.

**Rule 1 reads string literals too, deliberately.** A per-draft test macro's
`$section` literal is a citation and one of the most considered in the tree. A
rewrite that read only comments would stop checking every one of them without
changing a single reported number.

**Rules 3 to 5 read prose only, and that is a different reader.** A JSON sample
inside a doc-test fence is full of quote marks, and pairing them produces spans
like `: 9 }] } }]` that are read as a draft's sentence and can never be found in
one. The fence is the author saying it is a sample. Two readers rather than one
is a considered split: rules 1 and 2 divide the citations between them and so
must share a reader, while rules 3 to 5 want prose and nothing else. What the
prose reader drops is counted and reported in two halves, because only one of
them is a defect: a quotation in a *trailing* comment got there by accident and
nothing reads it where it sits, while a quotation in a *fenced sample* is the
author saying it is not prose. The test trees are full of the second kind — a
recorded panic message is verbatim on purpose — and asking a checker to find one
in an Internet-Draft would report every one of them.

**Double quotes in prose mean the draft is speaking.** That is a convention
these rules can only enforce once they read the file, and twenty-five spans in
the test trees turned out to be the crate speaking instead: an assertion's
label, a claim being contrasted with a weaker one, an encoding mode being named.
None can be told from a misquotation by any checker there could be, so they were
rewritten without the marks rather than exempted.

**A claim about several drafts is a claim about each of them, and rule 3 passes
it on one.** The sweep that wrote rule 6 read 26 range claims and reported 12.
Nine were wrong, and every one of them sat where the drafts renamed something
and the tree quoted one side of the rename: draft-14 spelling `a Protocol
Violation` as `a PROTOCOL_VIOLATION`, draft-16 saying close where draft-15 says
terminate, draft-15 renaming an ordered N-tuple of bytes to a Track Namespace
Field, and the token rule naming its code in prose on drafts 12 through 14 and
as a constant from draft-15. Each quoted sentence is genuinely some named
draft's, so every one of the nine reads as checked. The other three reports were
the crate speaking inside the drafts' quote marks in a draft-neutral file, where
no rule had ever read them.

**A range was about half of what the tree writes.** `drafts 12 and 13` and
`drafts 11, 12 and 13` claim their members exactly as firmly, and reading them
too found two more of the same rename defect: one filing drafts 12 and 13's
wording under the `PROTOCOL_VIOLATION` draft-14 renamed it to, and one claiming
draft-17's list of the six message types that may open a request stream for
drafts 18 and 19, where the list is seven. The second is the sharper of the two,
because the file already said thirty lines earlier that the set is not stable
across drafts and named what draft-18 adds to it.

**Attributions govern as a run, not one at a time.** The ordinary shape here is
a paragraph that names a range for one claim and then attributes its quotation
to a single draft beside it — "Drafts 14 through 19 carried the Filter Type as a
field of SUBSCRIBE ... Section 5.1.2: '...'". Reading the range as the
attribution reported all of those, and reading the *nearest* thing before the
quotation instead — a draft, a bare citation in a file that has a draft to
resolve it against, a range or an enumeration — cut 22 reports to 12 without
losing one of the nine. But the nearest one alone is not the claim either:
`draft-17 Section 3.3.1, draft-18 Section 3.3.2 and draft-19 Section 3.3.3 all
say "..."` claims one sentence for three drafts and its nearest attribution
names one. So what governs is the run: walk back while nothing but a comma or a
conjunction stands between two attributions, and claim the union.

**A quotation that ends where the draft carries on is a different sentence.**
Rule 7 is the only rule here whose answer needs no judgement at all: it asks
nothing about which draft a neutral file's quotation belongs to, only whether
some draft has the sentence once the mark it was closed on is taken off. Nine
were found the day it was written, all in test files whose names carry no draft,
and the split between them was the whole of the reading. Draft-14's UNSUBSCRIBE
sentence had lost ", indicating that the Publisher stop sending Objects as soon
as possible" — the consequence the message exists for, and the same truncation
an earlier round had already fixed in the per-draft copies of it, left standing
here because nothing read this file. Its PUBLISH_NAMESPACE_DONE sentence had
lost "although it is not a protocol error for the subscriber to send a SUBSCRIBE
or FETCH message for a track in a namespace after receiving an
PUBLISH_NAMESPACE_DONE", which is the opposite of what stopping at the full stop
tells a reader. Its SERVER_SETUP sentence had a list of three ended after two.
Where the drafts ran on into something else — a cross-reference, the messages
that follow Setup on the control stream — the mark came off and the comment says
the sentence continues, which is the convention a sibling gate in one of the
same files had been using all along.

Six ablations, all run. Restoring the UNSUBSCRIBE truncation is reported as
`draft-14, draft-15, draft-16 have this sentence without the mark it is closed
on here, and run on`, with the draft's own continuation printed under it, and
restoring the PUBLISH_NAMESPACE_DONE one the same way. Giving this rule rule
5's two filters over a standing defect takes it from 940 quotations to **263**
and reports nothing at all, which is the measurement the whole rule rests on:
every one of the nine was outside both filters. Reading a full stop as the only
closing mark still reports both of those, because both close on one — so the
question mark was measured by writing a truncation that ends on one, which is
reported with `.!?` and not read at all with `.` alone. Stripping the drafts'
own quote marks as well reports nothing today, so leaving them out is an
argument rather than a measurement: a draft's `'Too Many Subscribes'` ends on
one, and taking it off would ask the drafts about half a name.

**The mark a quotation ends on is part of it.** An earlier round fixed two dozen
full stops the tree had supplied where the draft's sentence goes on, in the
per-draft files rule 3 reads. The neutral files kept theirs, because nothing
read them — eleven quotations there are exact except for the mark they close on,
and rule 6 reported two of the eleven the moment it started reading
enumerations. One closed draft-17's cancel sentence with a full stop where the
draft runs on with a semicolon into the same rule for receivers; the other
closed the Track Namespace definition where the draft runs on with a comma into
the field layout. Half a sentence presented as a whole one is a change to the
draft's words, and the other nine are worth a look rather than a floor.

Every half was ablated, and run rather than predicted. Putting a range back
across the draft-14 rename — the reason-phrase cap, claimed for drafts 11
through 19 — is reported as `the block claims this sentence for drafts 11-19 and
draft-11, draft-12, draft-13 have not got it`, and putting an enumeration back
across the same rename as `the block claims this sentence for drafts 12-14 and
draft-12, draft-13 have not got it`. Dropping the bare-citation clause takes the
rule from 47 claims and no reports to 57 and ten, and every one of the ten is a
paragraph that is right. Dropping the enumerated spelling leaves 28 claims and
the dash form of a range 43. Taking the nearest attribution alone rather than
its run leaves 40, and that is the one with a defect behind it: restoring the
full stop on the cancel sentence is reported as `the block claims this sentence
for drafts 17-19 and draft-17, draft-18, draft-19 have not got it` with the run,
and with the nearest attribution alone the block is not read at all.

**A quote mark inside a quotation is whichever mark the tree could write
there.** A comment's quotation is delimited by `"`, so a draft sentence
containing a `"` cannot be transcribed with one — the tree writes `\'Yes\'` where
draft-14 has `"Yes"`. Reading the marks as one retired four floor entries that
had been pinned as unquotable renderings and were nothing of the kind.

**A character the rendering escapes is a character no quotation could carry.**
The comparison is built per character so a quote mark can be softened, and every
other character went through `re.escape` — so a draft sentence written with `<`,
`>` or `&` reached the file as itself while the pattern went looking for it
where the rendering has `&lt;`, `&gt;` or `&amp;`. Nothing ever failed over it,
which is the shape of the defect rather than a defence of it: what this hits are
the drafts' most formal sentences — the comparisons, the bit masks written as
expressions, the structure diagrams — so a round that wanted one paraphrased it
instead and no report was ever made. 300 of the 21,287 sentences across drafts
07-20 carry one, and the count climbs with the draft number: 10 on draft-07, 35
on each of drafts 18 and 19, 40 on draft-20. A sentence here is the rendering
with its stylesheet dropped, tags stripped, entities unescaped and the text split
on `[.!?]` followed by whitespace; the method is stated because dropping the
stylesheet is worth 5 a draft and nothing else reproduces the count.

**The fix softens the comparison and not the input, and that is measured rather
than preferred.** The obvious alternative is to unescape each rendering once at
load, the way `toc_of` already does for a heading — but `toc_of` strips the tags
*first*, and these rules keep them on purpose so the separator can step over
markup. Unescape first and a literal `<` in the text is the start of a tag as
far as the separator can tell. Doing it loses text on every draft — 10
characters on draft-07, 100 on draft-11, 596 on draft-20 — and what it loses is
the point: on drafts 07 through 10 the first span swallowed is a bibliography
entry whose URL the rendering wraps in `&lt;` and `&gt;`, but from draft-11 on
it is the Location ordering comparison itself, which is exactly the kind of
sentence a quotation wants.

Ablated by taking the alternation back out, with the Location ordering rule
quoted in drafts 12 and 13: rule 3 goes from 5 unresolved to 7 and the run exits
1, reporting `crates/moqtap-client/src/draft12/endpoint.rs: not found in
draft-12` under the sentence it could not find. Every other count in every rule
is unchanged, which is what a widening should look like — it can give a match,
never take one away.

## Needs the rendered drafts, and fails closed without them

One rendering per draft the tree implements, read from the directory of
rendered drafts beside this checkout by default, and from anywhere else with
`--drafts DIR`. Which drafts those are
is derived rather than declared - see `implemented_drafts` - so the set grows
with the tree and a missing rendering stops the run instead of narrowing it. If
they are not where it looks, it says so and exits 1: an unverifiable citation is
not a verified one.

`--fetch` downloads whatever `--drafts` does not already hold, from the IETF
archive, where these are published and where anyone can read them. Only the
missing ones: a published draft's bytes do not change, and re-downloading one
would replace the rendering a citation was checked against with a re-render of
it for no gain. That is what lets this run in CI with no credential and no
sibling checkout.
"""

import argparse
import html
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# The rendered drafts are not part of this repository. `.drafts` at the checkout
# root is where `--fetch` writes them, what CI and the justfile pass, and a path
# git ignores — so the default resolves on a fresh clone with nothing set up.
DEFAULT_DRAFTS = os.environ.get("MOQT_SPEC_DIR", os.path.join(ROOT, ".drafts"))

SKIP_DIRS = (".git", "target", "test-vectors")

# Crates whose prose is not resolved against the MoQT drafts at all.
#
# `moqtap-trace` implements the `.moqtrace` recording format, not MoQT. Its
# normative sentences come from that format's own specification, which we
# control and which moves when our code moves. The drafts are the opposite
# case, and that difference is the whole reason these rules exist: the drafts
# are edited by other people on their own schedule, so a sentence quoted from
# one goes stale underneath us and nothing but a machine re-reading it will
# notice. A spec that cannot change without us changing it needs no such guard.
#
# Rule 5's answer for this crate was worse than no answer. It reads every long
# normative quotation in a draft-neutral file as a draft's sentence, resolves it
# against 07-20, and reports a true statement as "wrong whichever one was
# meant" - five of them, from the format's own encoding rules. Attribution
# cannot silence that, because the rule never asks who was cited; it asks only
# whether some draft has the span.
#
# Measured when this was added: the crate held no draft citation of any kind -
# no `draft-NN Section X.Y`, no bare `Section X.Y` - so nothing that was being
# checked stopped being checked. A crate added later is scanned by default and
# has to be named here to opt out.
NOT_DRAFT_SCANNED = ("moqtap-trace",)
PER_DRAFT_DIR = re.compile(r"/draft(\d\d)/")

# A test file carries its draft in its own name rather than in a directory, and
# a name that opens with two of them carries neither: `draft16_17_...` is a file
# about the pair, so a rule that read it as draft-16's would hold draft-17's
# half of every comparison against the wrong rendering. Those go to the neutral
# set, where the question asked is the one they can answer - that the sentence
# is *some* draft's.
PER_DRAFT_FILE = re.compile(r"^draft(\d\d)_(?!\d\d_)")

# The drafts to read, taken from the tree rather than written down.
#
# This was `list(range(7, 20))` until a fourteenth draft landed in the codec,
# and the shape of that mistake is worth keeping in view. Every guard below
# asks `in DRAFTS` and *drops* what it cannot place rather than reporting it,
# so a citation naming the new draft was not an unresolved citation - it was
# not a citation at all. Rules 1, 3, 4 and 6 went on printing the same counts
# over a tree that had grown a draft, an open-ended range resolved to one draft
# short of the end, and every `tests/draftNN_*.rs` for it was read by nothing.
# The one guard that did not fail silently is what made the rest visible:
# `rule_1_and_2` resolves a bare `Section X.Y` against `tocs[own]`, where `own`
# comes from the directory name and never from this list, so it died with a
# `KeyError` instead of under-reporting.
#
# Deriving it closes the gap by construction. The set loaded here is the set
# `owning_draft` can name, so a per-draft file cannot exist without a rendering
# to be read against, and a new draft module brings its citations into the
# sweep on the day it lands rather than on the day someone remembers this line.
# `load_drafts` is what makes the coupling hold - it exits 1 naming the
# rendering it could not open, so a draft the tree has and `--drafts` does not
# stops the run rather than quietly narrowing it.
#
# # The floor was the last written-down draft number, and it had already lapsed
#
# A derivation that can grow can also shrink, and shrinking is the silent
# direction: every guard above passes more, no count moves, and the rules that
# no longer reach a draft report nothing at all. So the derived set is held
# against a floor - and the floor was `frozenset(range(7, 20))`, a hand-written
# range that stopped at draft-19 while the tree had already moved past it. It was
# still doing its job, because a floor only has to be a *lower* bound, but it
# was doing it one draft behind, and the day somebody deleted `src/draft20/`
# nothing here would have said so. That is the same defect one paragraph up,
# written into the guard against it.
#
# `declared_drafts` is the fix and it is the same fix: read the floor off the
# tree too, from a place that is not the one the set above is read from. The
# manifests declare a `draftNN` cargo feature per draft; the modules and test
# files are what `implemented_drafts` walks. Two independent statements of one
# set, each of which has to account for the other, and no number to bump. A
# module deleted while its feature stands is reported here; a feature declared
# with no module behind it is reported here as well, which is the direction a
# half-finished draft arrives from.
#
# The other direction - a module or a `DraftVersion` variant with no feature -
# is `scripts/check-draft-parity.py` rule 1, which reads five statements of
# this same set and requires all of them to agree.

DRAFT_DIR_NAME = re.compile(r"^draft(\d\d)$")
DRAFT_FEATURE_KEY = re.compile(r'^\s*draft(\d\d)\s*=\s*\[', re.M)


def declared_drafts(root):
    """Every draft the crate manifests declare a cargo feature for."""
    found = set()
    crates = os.path.join(root, "crates")
    for crate in sorted(os.listdir(crates)):
        manifest = os.path.join(crates, crate, "Cargo.toml")
        if not os.path.isfile(manifest):
            continue
        text = io.open(manifest, encoding="utf-8", errors="replace").read()
        found.update(int(m.group(1)) for m in DRAFT_FEATURE_KEY.finditer(text))
    return found


def implemented_drafts(root):
    """Every draft this workspace files a module or a test file under."""
    found = set()
    crates = os.path.join(root, "crates")
    for crate in sorted(os.listdir(crates)):
        for sub in ("src", "tests"):
            for where, dirs, files in os.walk(os.path.join(crates, crate, sub)):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for name in dirs:
                    m = DRAFT_DIR_NAME.match(name)
                    if m:
                        found.add(int(m.group(1)))
                for name in files:
                    m = PER_DRAFT_FILE.match(name) if name.endswith(".rs") else None
                    if m:
                        found.add(int(m.group(1)))
    declared = declared_drafts(root)
    if not declared:
        print("::error::no crate manifest under crates/ declares a `draftNN` "
              "feature. The floor for the set read off the tree is read off the "
              "manifests, and there is nothing there to read - which is a moved "
              "layout rather than a workspace with no drafts.")
        sys.exit(1)
    missing = declared - found
    if missing:
        print("::error::no per-draft module or test file under crates/ for %s, "
              "which the crate manifests declare a feature for. This set is read "
              "off the tree, so a renamed or deleted directory narrows every rule "
              "below without moving a count. If a draft has really been dropped, "
              "drop its cargo feature in the same commit."
              % ", ".join("draft-%02d" % n for n in sorted(missing)))
        sys.exit(1)
    return sorted(found)


DRAFTS = implemented_drafts(ROOT)

# ---------------------------------------------------------------------------
# Comment text, joined
# ---------------------------------------------------------------------------

COMMENT_ONLY = re.compile(r"^\s*(///|//!|//)")


class Block(object):
    """Joined comment text, with the source line each character came from."""

    def __init__(self):
        self.text = ""
        self._marks = []

    def add(self, body, lineno):
        if self.text:
            self.text += " "
        self._marks.append((len(self.text), lineno))
        self.text += body

    def line_at(self, offset):
        found = self._marks[0][1] if self._marks else 0
        for start, lineno in self._marks:
            if start > offset:
                break
            found = lineno
        return found

    def __bool__(self):
        return bool(self.text)

    __nonzero__ = __bool__


def comment_start(line):
    """Index of the `//` that opens a comment on this line, or -1.

    Scanning for the first `//` is not enough: a URL in a string literal carries
    one, and giving up on it hides the real comment further along the line. Walk
    the line tracking whether we are inside a string.
    """
    quote, esc = chr(34), chr(92)
    in_string = False
    i = 0
    while i < len(line) - 1:
        c = line[i]
        if in_string:
            if c == esc:
                i += 2
                continue
            if c == quote:
                in_string = False
        elif c == quote:
            in_string = True
        elif c == "/" and line[i + 1] == "/":
            return i
        i += 1
    return -1


def body_of(line):
    """`(text, standalone)` for the comment on a line, or `None` if there is none."""
    m = COMMENT_ONLY.match(line)
    if m:
        return line[m.end():].strip(), True
    i = comment_start(line)
    if i == -1:
        return None
    return line[i + 2:].strip(), False


def blocks(text):
    """Every comment block in a source file, in order.

    A run is consecutive comment-only lines. A comment trailing a line of code
    is its own block: it cannot wrap, and joining it to the prose above would
    invent an adjacency that is not there.
    """
    out, current = [], Block()
    for lineno, line in enumerate(text.splitlines(), 1):
        got = body_of(line)
        if got is None:
            if current:
                out.append(current)
            current = Block()
            continue
        body, standalone = got
        if not standalone:
            if current:
                out.append(current)
            current = Block()
            trailing = Block()
            trailing.add(body, lineno)
            out.append(trailing)
            continue
        current.add(body, lineno)
    if current:
        out.append(current)
    return out


def code_chunks(text):
    """The non-comment part of every line, one `Block` each.

    Per line on purpose: a Rust string literal does not wrap the way prose does.
    """
    out = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if COMMENT_ONLY.match(line):
            continue
        i = comment_start(line)
        if i != -1:
            line = line[:i]
        if not line.strip():
            continue
        b = Block()
        b.add(line.strip(), lineno)
        out.append(b)
    return out


PROSE_LINE = re.compile(r"^\s*//[/!]? ?(.*)$")


def prose_blocks(path):
    """Contiguous comment runs as plain strings, with fenced samples dropped.

    The reader rules 3 to 5 use. It differs from `blocks` in two ways and both
    are deliberate: a fenced code sample inside a doc comment is not prose and
    its quote marks are not quotations, and a comment trailing a line of code is
    not part of the paragraph above it.
    """
    out, run, fenced = [], [], False
    for line in io.open(path, encoding="utf-8", errors="replace"):
        m = PROSE_LINE.match(line)
        if m:
            body = m.group(1)
            if body.lstrip().startswith("```"):
                fenced = not fenced
                continue
            if not fenced:
                run.append(body)
        elif run or fenced:
            if run:
                out.append(" ".join(run))
            run, fenced = [], False
    if run:
        out.append(" ".join(run))
    return out


def dropped_prose(path):
    """Comment text `prose_blocks` does not return, split by why it was dropped.

    Returns `(trailing, sampled)`. Counted rather than assumed: a quotation in
    either is a quotation no rule reads, and the only thing worse than a blind
    spot is an unmeasured one. They are separated because only one of them is a
    defect.

    A quotation in a **trailing** comment is one that got there by accident -
    the paragraph it belongs to is the one above, and nothing reads it where it
    sits. A quotation in a **fenced sample** is deliberate: the fence is the
    author saying this is not prose, and what these fences hold in the test
    trees is recorded ablation output, which is verbatim on purpose. Asking a
    checker to find a panic message in an Internet-Draft would report every one
    of them.
    """
    trailing, sampled, fenced = [], [], False
    for line in io.open(path, encoding="utf-8", errors="replace"):
        got = body_of(line)
        if got is None:
            continue
        body, standalone = got
        if standalone and body.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if fenced:
            sampled.append(body)
        elif not standalone:
            trailing.append(body)
    return trailing, sampled


def paragraphs(text):
    """Markdown paragraphs, joined the way a comment run is."""
    out, cur = [], Block()
    for lineno, line in enumerate(text.splitlines(), 1):
        if line.strip():
            cur.add(line.strip(), lineno)
        elif cur:
            out.append(cur)
            cur = Block()
    if cur:
        out.append(cur)
    return out


# ---------------------------------------------------------------------------
# The renderings
# ---------------------------------------------------------------------------

SECTION_ID = re.compile(r'id="section-(\d+(?:\.\d+)*)(?:-\d+)?"')
HEADING = re.compile(r"<h([1-6])[^>]*>(.*?)</h\1>", re.S)
NUMBERED = re.compile(r"^(\d+(?:\.\d+)*)\.\s+(.*)$")
SEP = r"(?:\s|<[^>]*>|&[a-z#0-9]+;)*"
TOKEN = re.compile(r"[\w'_-]+|[^\w\s]")


# Every mark a quotation could be carrying where the draft has one, as a class.
# A comment's quotation is delimited by `"`, so a draft sentence that contains a
# `"` cannot be transcribed with one: the tree writes `\'Yes\'` where draft-14
# has `"Yes"`, and a reader that told them apart would report a sentence quoted
# exactly right. The marks differ because of the delimiter, not because of the
# sentence.
QUOTE_MARK = "\"'\u2018\u2019\u201c\u201d"
ANY_MARK = "[%s]" % QUOTE_MARK


# Every character a rendering carries as an entity rather than as itself, with
# the entity it carries.
#
# A draft sentence written with one of these reaches the file escaped, so a
# pattern looking for the literal finds nothing and the sentence is reported as
# being in no draft at all. The sentences this hits are the drafts' most formal
# ones - the comparisons, the bit masks written as expressions, the structure
# diagrams - which is to say exactly the material that leaves the least room for
# paraphrase. 300 of the 21,287 sentences across drafts 07-20 carry one, and the
# count climbs with the draft number: 10 on draft-07, 35 on each of drafts 18 and
# 19, 40 on draft-20.
#
# Re-derived on 2026-09-02 rather than extended by a draft, because the figure it
# replaces could not be reproduced until its method was: sentences are the
# rendering with `<style>` and `<script>` contents dropped, tags stripped,
# entities unescaped, whitespace collapsed, split on `[.!?]` followed by
# whitespace. Dropping the stylesheet is the part that matters — four CSS blocks
# per draft otherwise count as sentences carrying an escape, which is 5 a draft
# and the whole of the difference between 300 and the 365 a naive count gives.
#
# # Why not unescape the rendering once and be done with it
#
# Because the separator above skips `<...>` to step over markup, and a literal
# `<` in the text is then the start of a tag as far as it can tell. Measured
# rather than supposed: `len(unescape(strip(r))) - len(strip(unescape(r)))` is
# the text the second order loses, and it is positive on every draft and grows
# with the draft number - 10 characters on draft-07, 100 on draft-11, 596 on
# draft-20.
#
# What is lost matters more than how much. On drafts 07 through 10 the first
# span swallowed is a bibliography entry, a URL the rendering wraps in `&lt;`
# and `&gt;`, which becomes a tag and is eaten whole. From draft-11 on it is the
# Location ordering comparison itself - `A.Group < B.Group || (A.Group ==
# B.Group && ...)` - and that is a sentence a quotation is far more likely to
# want than a bibliography entry. The cost of softening the input rises exactly
# where the drafts get more formal. Softening the comparison instead is safe.
ESCAPED_AS = {"<": "&lt;", ">": "&gt;", "&": "&amp;"}


def char_pattern(ch):
    """One character, as the rendering could be carrying it."""
    if ch in QUOTE_MARK:
        return ANY_MARK
    entity = ESCAPED_AS.get(ch)
    if entity is None:
        return re.escape(ch)
    return "(?:%s|%s)" % (re.escape(ch), entity)


def token_pattern(w):
    """One token, with every quote mark and escapable character softened.

    Per character rather than per token, because the tokeniser keeps an
    apostrophe inside the word: `'Yes'` is one token, and a rule that only
    softened a mark standing on its own would still refuse the sentence
    draft-14 renders as `"Yes"`.
    """
    return "".join(char_pattern(ch) for ch in w)


def phrase(t):
    """`t` as a pattern that tolerates tags, entities and whitespace between tokens."""
    return SEP.join(token_pattern(w) for w in TOKEN.findall(t))


# Where the renderings are published. These are Internet-Drafts at the IETF
# archive, readable by anyone and immutable once published, so `--fetch` needs
# no credential and no sibling checkout. The same URL and the same idea are in
# `crates/moqtap-codec/tools/extract-registries.py`, which is the other tool
# that reads these files; keeping the two spellings identical is deliberate.
SPEC_URL = "https://www.ietf.org/archive/id/draft-ietf-moq-transport-%02d.html"
USER_AGENT = "moqtap check-drafts"


def fetch_missing(where, numbers):
    """Download any draft in `numbers` that `where` does not already hold.

    Only what is missing, because a published draft's bytes do not change and
    re-downloading one would only risk replacing a rendering the tree's
    citations were checked against with a re-render of it.
    """
    import urllib.request

    if not os.path.isdir(where):
        os.makedirs(where)
    for n in numbers:
        path = os.path.join(where, "draft-%02d.html" % n)
        if os.path.isfile(path):
            continue
        url = SPEC_URL % n
        print("fetching %s" % url, file=sys.stderr)
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=60) as response:
            body = response.read()
        with io.open(path, "wb") as f:
            f.write(body)


def load_drafts(where, fetch=False):
    """`{draft number: rendering}`, or exit 1 saying what is missing."""
    if fetch:
        fetch_missing(where, DRAFTS)
    out = {}
    missing = []
    for n in DRAFTS:
        path = os.path.join(where, "draft-%02d.html" % n)
        try:
            out[n] = io.open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            missing.append(os.path.basename(path))
    if missing:
        print("::error::the rendered drafts are not in %s (missing %s). This "
              "cannot check a citation it cannot read, and an unverifiable "
              "citation is not a verified one. Pass --fetch to download them "
              "from the IETF archive, --drafts DIR to point it somewhere else, "
              "or set MOQT_SPEC_DIR." % (where, ", ".join(missing)))
        sys.exit(1)
    return out


def toc_of(rendering):
    """`{section number: title}` from the rendering's own numbered headings."""
    out = {}
    for m in HEADING.finditer(rendering):
        t = html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]*>", " ", m.group(2))))
        t = t.strip().replace("¶", "").strip()
        mm = NUMBERED.match(t)
        if mm:
            out[mm.group(1)] = mm.group(2)
    return out


def section_of(rendering, at):
    """The section the byte offset `at` falls in.

    Read from the rendering's own ids rather than from the text: every section
    is wrapped in `id="section-X.Y"` and every paragraph carries
    `id="section-X.Y-N"`, so the nearest one before a quotation names the
    section that quotation is in. Reading headings out of flattened text cannot
    do this — a sentence ending in a number reads as a heading, and the table of
    contents at the top lists every heading there is.
    """
    last = None
    for m in SECTION_ID.finditer(rendering, 0, at):
        last = m.group(1)
    return last


# ---------------------------------------------------------------------------
# Citations
# ---------------------------------------------------------------------------

NUM = r"\d+(?:\.\d+)*"
GROUP = r"%s(?:\s*(?:,|and)\s*%s)*" % (NUM, NUM)
# The prefix is capitalised wherever a citation opens a sentence, which is the
# house style, so this is case-insensitive by necessity rather than by taste.
PREFIXED = re.compile(r"[Dd]raft-(\d\d)\s+(?:[Ss]ections?|§)\s*(%s)" % GROUP)
BARE = re.compile(r"(?:[Ss]ections?|§)\s*(%s)" % GROUP)
EACH_NUM = re.compile(NUM)


def citation_spans(text):
    """`(prefixed, covered)` for one joined chunk.

    `prefixed` is every `draft-NN Section ...` match. `covered` is the set of
    character offsets those matches occupy, which is what makes a bare citation
    bare: rule 2 skips a `Section ...` that starts inside one of them, rather
    than trying to recognise the prefix again with a second pattern. One
    function decides the split, so the two rules cannot drift apart.
    """
    found = list(PREFIXED.finditer(text))
    covered = set()
    for m in found:
        covered.update(range(m.start(), m.end()))
    return found, covered


def rust_and_markdown(root):
    """Every `.rs` and `.md` under `crates/`, less the crates that cite no draft.

    {@link NOT_DRAFT_SCANNED} is filtered at the top level only, so it names a
    crate rather than any directory that happens to share the name.
    """
    crates = os.path.join(root, "crates")
    for base, dirs, files in os.walk(crates):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        if base == crates:
            dirs[:] = [d for d in dirs if d not in NOT_DRAFT_SCANNED]
        for f in sorted(files):
            if f.endswith((".rs", ".md")):
                yield os.path.join(base, f)


def rel(path):
    return os.path.relpath(path, ROOT).replace(os.sep, "/")


def draft_of_path(path):
    """The draft a file or directory belongs to, or `None` for a neutral one.

    The path is bracketed with separators before matching so that a directory
    named `draft08` matches as readily as a file inside one. Getting this wrong
    is silent in the worst way: an earlier cut appended `os.sep` to an
    already-normalised path, so on Windows only paths with a further
    subdirectory below `draftNN` matched, and the quotation sweep read 111
    quotations where there are 1,933 while reporting a clean run.
    """
    m = PER_DRAFT_DIR.search("/" + rel(path).replace(os.sep, "/") + "/")
    return int(m.group(1)) if m else None


# Rule 1's floor. A citation being *mentioned* rather than *used* reads the same
# to any checker there could be.
PREFIXED_FLOOR = {
    (18, "14.6.1", "crates/moqtap-client/CHANGELOG.md"):
        "the changelog records a fixed defect by quoting the wrong citation it "
        "replaced — draft-18 numbers its session termination codes 15.10.1 — "
        "and a checker cannot tell a citation being mentioned from one in use",
}

# Rule 2's floor. Each names a section of a *different* draft than the file it
# sits in, which is the one form a bare citation cannot express, and each was
# read by hand against the draft it actually names.
BARE_FLOOR = {
    (11, "8.3.2.4", "crates/moqtap-codec/src/draft11/message.rs"): "names another draft",
    (13, "13.1.3", "crates/moqtap-codec/src/draft13/error_codes.rs"): "names another draft",
    (13, "13.1.8", "crates/moqtap-codec/src/draft13/error_codes.rs"): "names another draft",
    (17, "11.4.2", "crates/moqtap-client/src/draft17/connection.rs"): "names another draft",
}


def rule_1_and_2(rendered, tocs, verbose):
    """Every citation resolves in the draft it names."""
    prefixed_total = bare_total = 0
    prefixed_bad, bare_bad = [], []

    for path in rust_and_markdown(ROOT):
        try:
            text = io.open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        if path.endswith(".rs"):
            chunks = blocks(text) + code_chunks(text)
        else:
            chunks = paragraphs(text)
        own = owning_draft(path)
        for chunk in chunks:
            found, covered = citation_spans(chunk.text)
            for m in found:
                n = int(m.group(1))
                if n not in tocs:
                    continue
                line = chunk.line_at(m.start())
                for sec in EACH_NUM.findall(m.group(2)):
                    prefixed_total += 1
                    if sec not in tocs[n]:
                        prefixed_bad.append((n, sec, rel(path), line))
            # Rule 2 only means anything in a file that names a draft, where a
            # bare citation has one to be resolved against, and only for Rust:
            # a crate's README or changelog is not filed under a draft.
            if own is None or not path.endswith(".rs"):
                continue
            for m in BARE.finditer(chunk.text):
                if m.start() in covered:
                    continue
                line = chunk.line_at(m.start())
                for sec in EACH_NUM.findall(m.group(1)):
                    bare_total += 1
                    if sec not in tocs[own]:
                        bare_bad.append((own, sec, rel(path), line))

    new_prefixed = [b for b in prefixed_bad if (b[0], b[1], b[2]) not in PREFIXED_FLOOR]
    new_bare = [b for b in bare_bad if (b[0], b[1], b[2]) not in BARE_FLOOR]

    # Said on every run, because a crate quietly outside the scan is exactly
    # the kind of gap these rules exist to make impossible. A reader comparing
    # totals should be told what was not counted before they read a count.
    if NOT_DRAFT_SCANNED:
        # ASCII, like every other line printed unconditionally here. A console
        # that cannot encode an em dash raises on the print rather than
        # dropping the character, which would take the whole run down over a
        # note. The verbose-only line below can afford one; this cannot.
        print("        not scanned: %s (implements a format of ours, cites no draft)"
              % ", ".join(NOT_DRAFT_SCANNED))
    print("rule 1  %5d prefixed citations, %d unresolved (floor %d)"
          % (prefixed_total, len(prefixed_bad), len(PREFIXED_FLOOR)))
    print("rule 2  %5d bare citations in per-draft files, %d unresolved (floor %d)"
          % (bare_total, len(bare_bad), len(BARE_FLOOR)))
    for n, sec, where, line in new_prefixed:
        print("::error::draft-%02d Section %s does not exist, cited at %s:%d"
              % (n, sec, where, line))
    for n, sec, where, line in new_bare:
        print("::error::Section %s does not exist in draft-%02d, cited at %s:%d"
              % (sec, n, where, line))
    if verbose:
        for key, why in sorted(PREFIXED_FLOOR.items()) + sorted(BARE_FLOOR.items()):
            print("        floor: draft-%02d Section %s in %s — %s" % (key + (why,)))
    return bool(new_prefixed or new_bare)


# ---------------------------------------------------------------------------
# Quotations
# ---------------------------------------------------------------------------

# Pair the marks in order and judge length afterwards. Baking a minimum into the
# pattern makes the scanner skip a short quoted term and then re-anchor on its
# closing mark, capturing the prose that follows it as though it were a
# quotation — 56 of one early reading's 269 hits were exactly that.
QUOTE = re.compile(r'"([^"]*)"')
SHORTEST = 20
LONGEST_WITHOUT_A_CLAIM = 60
NORMATIVE = re.compile(r"\b(MUST|SHOULD|MAY)\b")

# Rule 3's floor. None of the five is a defect the tree can fix: a rendering is
# not always quotable, and what is left after 2026-08-26 is one shape only - a
# cross-reference rendered as a bare link *inside* the sentence, so the sentence
# a reader sees is not the sentence the rendering holds. Four entries left that
# day: they were floored for the drafts' own quotation marks, which a quotation
# delimited by the same mark cannot carry, and `phrase` reads any mark as any
# other now.
QUOTE_FLOOR = [
    # drafts 08, 09 and 10 render the MAX_SUBSCRIBE_ID rule with a
    # cross-reference as a bare link inside the noun phrase, so the sentence a
    # reader sees is not the sentence the rendering holds
    ('crates/moqtap-client/src/draft08/endpoint.rs',
     "If a Subscribe ID equal or larger than this is received by the "
     "publisher that sent the MAX_SUBSCRIBE_ID, the publisher MUST close "
     "the session with an error of 'Too Many Subscribes'."
    ),
    # as draft-08
    ('crates/moqtap-client/src/draft09/endpoint.rs',
     "If a Subscribe ID equal or larger than this is received by the "
     "publisher that sent the MAX_SUBSCRIBE_ID, the publisher MUST close "
     "the session with an error of 'Too Many Subscribes'."
    ),
    # as draft-08
    ('crates/moqtap-client/src/draft10/endpoint.rs',
     "If a Subscribe ID equal or larger than this is received by the "
     "publisher that sent the MAX_SUBSCRIBE_ID, the publisher MUST close "
     "the session with an error of 'Too Many Subscribes'."
    ),
    # draft-19 does the same for the MAX_FILTER_RANGES option
    ('crates/moqtap-client/src/draft19/endpoint.rs',
     "The MAX_FILTER_RANGES option (Type 0x06) limits the peer's total "
     "number of Ranges (Start/End pairs) allowed concurrently in all "
     "Range filter parameters for a given subscription or fetch. The "
     "default value is 0, so if not specified, the peer MUST NOT send "
     "any such filter parameters."
    ),
    # as the option above, in the same sentence's second half
    ('crates/moqtap-client/src/draft19/endpoint.rs',
     "the total number of Ranges allowed concurrently in all Range "
     "filter parameters for a given subscription or fetch"
    ),
]


def floor_index(where, quotation):
    """Which floor entry this unfound quotation is, or `None`.

    Returned by index rather than as a yes-or-no so the caller can tell which
    entries were used. A floor that is only ever compared by size lets a new
    defect take a fixed one's place and report the same number.

    The whole quotation is compared, not its opening. An earlier cut matched on
    a prefix, and an ablation that changed `Length of 0` to `Length of 3` — six
    words past the end of the prefix — was absorbed by the floor entry and
    reported nothing at all. A floor pins a specific sentence or it pins
    whatever a defect leaves of it.
    """
    for i, (path, text) in enumerate(QUOTE_FLOOR):
        if where == path and quotation == text:
            return i
    return None


def quotations_in(block):
    """Every span in a joined comment worth asking a draft about.

    An elided quotation cannot be found verbatim and is not claiming to be; a
    span carrying a backtick is code the comment is naming, not prose; a span
    ending in a colon is a label. Each is skipped rather than reported, and each
    still counts towards the ambiguity rule 4 needs.
    """
    for q in QUOTE.findall(block):
        q = q.strip()
        if len(q) < SHORTEST or "..." in q or "`" in q or q.endswith(":"):
            continue
        yield q


# `PER_DRAFT_FILE` is defined beside `PER_DRAFT_DIR` at the top, because the
# two of them together are what `implemented_drafts` reads the draft set off.

ALL_CRATES = ("moqtap-client", "moqtap-codec", "moqtap-proxy", "moqtap-trace")

# Derived rather than written out, so a crate is scanned unless something says
# otherwise and the reason it is not lives in one place.
CRATES = tuple(c for c in ALL_CRATES if c not in NOT_DRAFT_SCANNED)


def draft_of_test(name):
    """The draft a test file's own name claims, or `None`."""
    m = PER_DRAFT_FILE.match(name)
    if not m:
        return None
    n = int(m.group(1))
    return n if n in DRAFTS else None


def owning_draft(path):
    """The draft a file answers to, whichever way it says so.

    A bare `Section X.Y` and a quotation are the same question about the same
    file - "which rendering is this to be read against" - so they are answered
    here rather than in each rule. Rule 2 asked it of the directory alone until
    2026-08-26, which meant a bare citation in `tests/draft14_wire_rules.rs`
    was read by nothing at all: rule 1 skips it because it is not prefixed, and
    rule 2 skipped it because its draft is in the file name.
    """
    n = draft_of_path(path)
    if n is not None:
        return n
    parts = rel(path).split("/")
    return draft_of_test(parts[-1]) if "tests" in parts[:-1] else None


def rust_under(root, crate, sub):
    """Every `.rs` under one crate's `src` or `tests`, with its own file name."""
    base = os.path.join(root, "crates", crate, sub)
    for where, dirs, files in os.walk(base):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in sorted(files):
            if f.endswith(".rs"):
                yield os.path.join(where, f), where, f


def per_draft_sources(root):
    """Every file whose quotations are one named draft's to answer for.

    Two ways a file names its draft and both are here: a `src/draftNN/`
    directory, and a `tests/draftNN_*.rs` file name. Leaving the second out is
    what this rule did until 2026-08-26, and it left 209 quotations in 67 files
    unread - including the ones written by the round that had just checked them
    by hand, which is the reading this rule exists to make unnecessary.
    """
    for crate in CRATES:
        for path, where, name in rust_under(root, crate, "src"):
            n = draft_of_path(where)
            if n is not None:
                yield path, n
        for path, _, name in rust_under(root, crate, "tests"):
            n = draft_of_test(name)
            if n is not None:
                yield path, n


def neutral_sources(root):
    """Every file whose quotations belong to no single draft.

    A test file covering a range is the common case here and the reason the
    two sets are drawn from the same walk: a file is per-draft or it is
    neutral, and nothing is in both or in neither.
    """
    for crate in CRATES:
        for path, where, name in rust_under(root, crate, "src"):
            if draft_of_path(where) is None:
                yield path
        for path, _, name in rust_under(root, crate, "tests"):
            if draft_of_test(name) is None:
                yield path


# A draft named in prose, with or without a section beside it. Rule 3 needs a
# looser reader than rule 1's: "drafts 08 through 16 say" attributes a sentence
# just as well as "draft-08 Section 2.4.1" does, and a paragraph comparing two
# wordings usually names the neighbour without citing it.
DRAFT_MENTION = re.compile(r"\bdrafts?[- ](\d\d)\b", re.I)
DRAFT_RANGE = re.compile(r"\bdrafts?[- ](\d\d)\s+(?:through|to)\s+(\d\d)\b", re.I)


def mentioned_drafts(block):
    """Every draft this block names, by number, however it names them."""
    out = set()
    for m in DRAFT_RANGE.finditer(block):
        lo, hi = int(m.group(1)), int(m.group(2))
        if lo <= hi:
            out.update(range(lo, hi + 1))
    out.update(int(m.group(1)) for m in DRAFT_MENTION.finditer(block))
    return {n for n in out if n in DRAFTS}


def rule_3_and_4(rendered, verbose):
    """Every quotation is its draft's own sentence, filed under its own section."""
    checked = missing = attributed = misattributed = coarse = wrong = 0
    unseen = in_samples = 0
    notes = []
    used_floor = set()

    for path, n in per_draft_sources(ROOT):
        where = rel(path)
        trailing, sampled = dropped_prose(path)
        for body in trailing:
            unseen += len(list(quotations_in(body)))
        for body in sampled:
            in_samples += len(list(quotations_in(body)))
        for block in prose_blocks(path):
            # Two sets, because the two rules ask different questions of them.
            # Rule 3 asks whose sentence this is, which any mention of a draft
            # answers. Rule 4 asks whether a bare `Section X.Y` is about this
            # file's draft, which is confused only by another draft being
            # *cited* beside it - a paragraph that merely mentions a neighbour
            # has not made its own citation ambiguous.
            named = mentioned_drafts(block) - {n}
            cited_elsewhere = {int(d) for d, _ in PREFIXED.findall(block)} - {n}
            cited = sorted({s for m in BARE.finditer(block)
                            for s in EACH_NUM.findall(m.group(1))}) \
                if not cited_elsewhere else []
            # Every qualifying span counts towards ambiguity, including ones
            # skipped below: a block carrying an elided quotation and a whole
            # one is not evidence that its single citation belongs to either.
            spans = len([q for q in QUOTE.findall(block) if len(q.strip()) >= SHORTEST])
            for q in quotations_in(block):
                checked += 1
                pattern = phrase(q)
                if not re.search(pattern, rendered[n], re.I):
                    # Absent from its own draft, in a block naming others, is a
                    # comparison with one of them — but only if the sentence is
                    # really in one of the drafts the block names. A block can
                    # name a neighbour and still misquote it.
                    #
                    # Any of them rather than all of them, because the ordinary
                    # shape of a comparison here is a paragraph that quotes one
                    # draft's wording and names the draft that changed it in the
                    # same breath. Requiring every named draft to carry the
                    # sentence would report twenty such paragraphs, all of them
                    # right. Which drafts a paragraph claims is rule 6's,
                    # and is exactly what this cannot ask without reporting
                    # them.
                    if named:
                        hit = [d for d in sorted(named)
                               if d in rendered and re.search(pattern, rendered[d], re.I)]
                        if hit:
                            attributed += 1
                            continue
                        elsewhere = [o for o in sorted(rendered)
                                     if o != n and re.search(pattern, rendered[o], re.I)]
                        if elsewhere:
                            misattributed += 1
                            notes.append(
                                ("::error::", where,
                                 "the block names %s and the sentence is in %s"
                                 % (", ".join("draft-%02d" % d for d in sorted(named)),
                                    ", ".join("draft-%02d" % o for o in elsewhere)), q))
                            continue
                    at = floor_index(where, q)
                    if at is None:
                        notes.append(("::error::", where,
                                      "not found in draft-%02d" % n, q))
                    else:
                        used_floor.add(at)
                    missing += 1
                    continue
                # One citation and one quotation is the only case where the two
                # are unambiguously about each other. A block citing two
                # sections, or quoting two sentences, is not evidence that any
                # particular pairing was intended.
                if len(cited) != 1 or spans != 1:
                    continue
                # A sentence can appear more than once in a rendering — in the
                # table of contents, or in prose that repeats it. The citation
                # is right if any occurrence is in the section it names, so
                # every occurrence is resolved before one is called wrong.
                owns = [section_of(rendered[n], hit.start())
                        for hit in re.finditer(pattern, rendered[n], re.I)]
                owns = [o for o in owns if o is not None]
                if not owns or cited[0] in owns:
                    continue
                own = next((o for o in owns if o.startswith(cited[0] + ".")), owns[0])
                if own.startswith(cited[0] + "."):
                    coarse += 1
                    notes.append(("::error::", where,
                                  "cites Section %s and sits in %s, its child"
                                  % (cited[0], own), q))
                else:
                    wrong += 1
                    notes.append(("::error::", where,
                                  "cites Section %s and sits in Section %s"
                                  % (cited[0], own), q))

    stale = [QUOTE_FLOOR[i] for i in range(len(QUOTE_FLOOR)) if i not in used_floor]
    new_missing = missing - len(used_floor)
    print("rule 3  %5d quotations in per-draft files, %d not in their draft "
          "(floor %d), %d attributed to a named neighbour, %d misattributed"
          % (checked, missing, len(QUOTE_FLOOR), attributed, misattributed))
    print("rule 4  %5d cite a parent of the section they sit in, %d cite a different one"
          % (coarse, wrong))
    print("        %5d quotations in trailing comments, %d in fenced samples"
          % (unseen, in_samples))
    for tag, where, why, q in notes:
        print("%s%s: %s" % (tag, where, why))
        print("          %s" % q[:150])
    if unseen:
        print("::error::%d quotation(s) sit in a trailing comment, where no rule "
              "reads them. Move the sentence into the paragraph above it." % unseen)
    for path, text in stale:
        # Not an error. A floor member that no longer reports is one the tree
        # found a way to quote, and the only thing wrong is that the floor still
        # claims it - which is worth saying out loud, because a floor nobody
        # shrinks is room a future defect can sit in unnoticed.
        print("        the floor entry for %s is no longer reported and can be "
              "dropped: %s" % (path, text[:60]))
    if verbose:
        for path, text in QUOTE_FLOOR:
            print("        floor: %s" % path)
            print("               %s" % text[:110])
    return bool(new_missing > 0 or misattributed or coarse or wrong or unseen)


# ---------------------------------------------------------------------------
# Multi-draft claims
# ---------------------------------------------------------------------------

# How this tree spells a contiguous run of drafts. `mentioned_drafts` reads only
# the first of these, which is all rule 3 needs — it wants any draft the block
# names — and not enough here, where the claim is about every draft in the run.
# The dash form is not a rarity to leave out: reading `through` and `to` alone
# leaves 43 of the 47 claims this finds, measured by doing it.
CLOSED_RANGE = re.compile(
    r"\bdrafts?[- ](\d\d)\s*(?:through|to|[-\u2013\u2014])\s*(\d\d)\b", re.I)
# An open-ended range ends at the newest draft there is, which is what the tree
# means by it and what a reader checks it against.
OPEN_RANGE = re.compile(
    r"\bdrafts?[- ](\d\d)\s+(?:onwards?|and later|and after)\b", re.I)
FROM_ON_RANGE = re.compile(r"\bfrom\s+drafts?[- ](\d\d)\s+on\b", re.I)
# `drafts 12 and 13`, `drafts 11, 12 and 13`, `drafts 12, 13`. A set spelled out
# claims its members as firmly as a range claims the run between them, and the
# tree has no reason to prefer either spelling — it uses whichever reads better
# where it stands. Dropping this spelling leaves the rule 28 of the 47 claims it
# finds, measured by doing it.
ENUMERATION = re.compile(
    r"\bdrafts[- ](\d\d)(?:\s*(?:,\s*and|,|\s+and)\s*(?:draft[- ])?\d\d)+",
    re.I)
# What may stand between two attributions that govern the same quotation: a
# comma, a conjunction, or nothing. Anything else is a sentence, and a sentence
# is where one claim stops and the next one starts.
LINK = re.compile(r"^[\s,;]*(?:and[\s,;]*)?$")


def attributions(block, own):
    """`[(start, end, drafts or None)]` for everything in a block that attributes.

    A range, an enumeration and a `draft-NN Section X.Y` carry the drafts they
    name. A bare draft mention and a bare `Section X.Y` carry `None`: what
    matters about those is that they stand between the quotation and whatever
    came before them, not which draft they name.

    A bare `Section X.Y` counts only in a file that has a draft to resolve it
    against, which is the same condition rule 2 puts on reading one at all.
    """
    out = []
    for m in CLOSED_RANGE.finditer(block):
        lo, hi = int(m.group(1)), int(m.group(2))
        if lo < hi and lo in DRAFTS and hi in DRAFTS:
            out.append((m.start(), m.end(), list(range(lo, hi + 1))))
    for pattern in (OPEN_RANGE, FROM_ON_RANGE):
        for m in pattern.finditer(block):
            lo = int(m.group(1))
            if lo in DRAFTS and lo < DRAFTS[-1]:
                out.append((m.start(), m.end(), list(range(lo, DRAFTS[-1] + 1))))
    for m in ENUMERATION.finditer(block):
        got = sorted({int(d) for d in re.findall(r"\d\d", m.group(0))})
        if len(got) > 1 and all(d in DRAFTS for d in got):
            out.append((m.start(), m.end(), got))
    for m in PREFIXED.finditer(block):
        if int(m.group(1)) in DRAFTS:
            out.append((m.start(), m.end(), [int(m.group(1))]))
    for m in DRAFT_MENTION.finditer(block):
        out.append((m.start(), m.end(), None))
    if own is not None:
        for m in BARE.finditer(block):
            out.append((m.start(), m.end(), None))
    return out


def attributed_drafts(block, at, own):
    """Every draft a quotation at offset `at` is claimed for, or `None`.

    Attributions govern a quotation as a **run** rather than one at a time.
    `draft-11 Section 9.1.1.2, drafts 12 and 13 Section 9.2.1.2, draft-14
    Section 10.2.1.2: "..."` claims one sentence for four drafts, and reading
    only the nearest would ask about draft-14 alone — which is how the tree came
    to file drafts 11 to 13's wording under a rename draft-14 had made. So walk
    back from the quotation taking attributions while nothing but a comma or a
    conjunction stands between them, and claim the union. A range on its own is
    that walk of length one.

    Where two attributions open in the same place the longer wins, which is what
    keeps `Drafts 15-19` from being read as a mention of draft-15.
    """
    spans = [s for s in attributions(block, own) if s[0] < at]
    if not spans:
        return None
    spans.sort(key=lambda s: (s[0], s[0] - s[1]))
    kept = []
    for s in spans:
        if kept and s[0] < kept[-1][1]:
            continue                          # inside one already taken
        kept.append(s)
    run = [kept[-1]]
    for s in reversed(kept[:-1]):
        if not LINK.match(block[s[1]:run[0][0]]):
            break
        run.insert(0, s)
    got = set()
    for _, _, drafts in run:
        if drafts:
            got.update(drafts)
    return sorted(got) if len(got) > 1 else None


def spell(drafts):
    """`11-19` where the drafts run on, `12, 14, 16` where they do not."""
    if len(drafts) > 2 and drafts == list(range(drafts[0], drafts[-1] + 1)):
        return "%02d-%02d" % (drafts[0], drafts[-1])
    return ", ".join("%02d" % d for d in drafts)


# Rule 6's floor is empty, and that is the finding rather than an oversight.
# Every claim this reported was one the tree could state correctly instead, so
# each was rewritten to name the drafts the quoted words are actually in. A
# floor entry here would be a set of drafts the renderings make unquotable
# together, and there is no such thing: which drafts a sentence is claimed for
# is the tree's own sentence, not a rendering's.
CLAIM_FLOOR = []


def rule_6(rendered, verbose):
    """A quotation a block claims for several drafts is in every one of them."""
    checked = 0
    bad = []
    seen = set()
    for path, own in list(per_draft_sources(ROOT)) + [(p, None) for p in
                                                      neutral_sources(ROOT)]:
        if path in seen:
            continue
        seen.add(path)
        for block in prose_blocks(path):
            # One quotation in the block, for the reason rule 4 wants one
            # citation: a paragraph quoting two sentences is not evidence that
            # the drafts beside it were claimed for either.
            spans = [m for m in QUOTE.finditer(block)
                     if len(m.group(1).strip()) >= SHORTEST]
            if len(spans) != 1:
                continue
            q = spans[0].group(1).strip()
            if list(quotations_in(block)) != [q]:
                continue
            drafts = attributed_drafts(block, spans[0].start(), own)
            if drafts is None:
                continue
            checked += 1
            pattern = phrase(q)
            missing = [d for d in drafts
                       if not re.search(pattern, rendered[d], re.I)]
            if missing:
                bad.append((rel(path), drafts, missing, q))

    new = [b for b in bad if (b[0], b[3]) not in CLAIM_FLOOR]
    print("rule 6  %5d quotations claimed for several drafts, %d not in every "
          "one of them (floor %d)" % (checked, len(bad), len(CLAIM_FLOOR)))
    for where, drafts, missing, q in new:
        print("::error::%s: the block claims this sentence for drafts %s "
              "and %s %s not got it"
              % (where, spell(drafts),
                 ", ".join("draft-%02d" % d for d in missing),
                 "has" if len(missing) == 1 else "have"))
        print("          %s" % q[:150])
    if verbose:
        for where, q in CLAIM_FLOOR:
            print("        floor: %s" % where)
            print("               %s" % q[:110])
    return bool(new)


def rule_5(rendered, verbose):
    """A long normative quotation in a draft-neutral file is some draft's sentence."""
    checked = 0
    bad = []
    for path in neutral_sources(ROOT):
        for block in prose_blocks(path):
            for q in quotations_in(block):
                if len(q) < LONGEST_WITHOUT_A_CLAIM or not NORMATIVE.search(q):
                    continue
                checked += 1
                if any(re.search(phrase(q), rendered[n], re.I) for n in DRAFTS):
                    continue
                bad.append((rel(path), q))
    print("rule 5  %5d normative quotations in draft-neutral files, %d in no draft (floor 0)"
          % (checked, len(bad)))
    for where, q in bad:
        print("::error::%s: this sentence is in none of drafts %02d-%02d, so it "
              "is wrong whichever one was meant" % (where, DRAFTS[0], DRAFTS[-1]))
        print("          %s" % q[:150])
    return bool(bad)


# ---------------------------------------------------------------------------
# The mark a quotation closes on
# ---------------------------------------------------------------------------

# The three marks that end a sentence, and deliberately not a quote mark: a
# draft's own `'Too Many Subscribes'` ends on one, and stripping it would ask
# the drafts a question about half a name. Counted rather than guessed at: of
# the 940 quotations in draft-neutral files, 613 close on no mark at all, 322 on
# a full stop and 5 on a question mark. A comma or a semicolon is not here
# because a quotation ending on one is a clause the tree left open on purpose,
# and a colon is not here because `quotations_in` drops a colon-terminated span
# before this rule ever sees it - that is a label, not a sentence.
SENTENCE_MARKS = ".!?"
# How much of the draft's own continuation to show. The report is only worth
# reading if it says what the quotation dropped, since that is the whole of the
# judgement about how to fix it.
CONTINUATION = 110

# Rule 7's floor is empty and cannot be otherwise. An entry here would be a
# sentence the renderings make impossible to end correctly, and there are two
# ways to end a quotation correctly - carry the draft's own mark, or carry none
# at all. A clause quoted with no mark on it is what the tree already writes
# where it means a clause, and this rule passes it without being asked to.
TRUNCATION_FLOOR = []


def continuation_of(rendering, at):
    """The draft's own words after `at`, flattened, for the report to show."""
    tail = re.sub(r"<[^>]*>", "", rendering[at:at + CONTINUATION * 3])
    tail = re.sub(r"&[a-z#0-9]+;", " ", tail)
    # The renderings mark a paragraph end with a literal pilcrow, which is
    # not part of any sentence and turns the report into something `grep`
    # reads as binary.
    tail = tail.replace("¶", " ")
    return re.sub(r"\s+", " ", tail).strip()[:CONTINUATION]


def rule_7(rendered, verbose):
    """A draft-neutral file's quotation does not close on a mark no draft has.

    Rule 3 asks this of a per-draft file by asking the wider question, and
    answers it whichever way the sentence is wrong. A draft-neutral file has no
    draft to be asked about, so rule 5 asks the wider question of the long
    normative quotations alone - and every truncation found here was outside
    that filter, which is what a filter for a question needing judgement does to
    a question needing none.
    """
    checked = 0
    bad = []
    for path in neutral_sources(ROOT):
        for block in prose_blocks(path):
            for q in quotations_in(block):
                checked += 1
                trimmed = q.rstrip(SENTENCE_MARKS)
                if trimmed == q:
                    continue                      # closed on no mark at all
                pattern = phrase(q)
                if any(re.search(pattern, rendered[n], re.I) for n in DRAFTS):
                    continue                      # the draft has it as written
                pattern = phrase(trimmed)
                got = []
                for n in DRAFTS:
                    m = re.search(pattern, rendered[n], re.I)
                    if m:
                        got.append((n, continuation_of(rendered[n], m.end())))
                if got:
                    bad.append((rel(path), q, got))
    new = [b for b in bad if (b[0], b[1]) not in TRUNCATION_FLOOR]
    print("rule 7  %5d quotations in draft-neutral files, %d closed on a mark "
          "no draft has (floor %d)" % (checked, len(bad), len(TRUNCATION_FLOOR)))
    for where, q, got in new:
        drafts = ", ".join("draft-%02d" % n for n, _ in got)
        print("::error::%s: %s %s this sentence without the mark it is closed "
              "on here, and %s on"
              % (where, drafts, "has" if len(got) == 1 else "have",
                 "runs" if len(got) == 1 else "run"))
        print("          %s" % q[:150])
        print("          ... %s" % got[0][1])
    if verbose:
        for where, q in TRUNCATION_FLOOR:
            print("floor  %s: %s" % (where, q[:110]))
    return bool(new)


# ---------------------------------------------------------------------------
# The citation table, which is a value rather than a comment
# ---------------------------------------------------------------------------

# Where the per-draft citations live. One path, hard-coded, and guarded below by
# a floor on how many rows have to parse - because a rule that reads one file is
# one rename away from reading nothing and reporting a clean run, which is the
# failure this whole script exists to make impossible.
CITATION_TABLE = os.path.join(
    ROOT, "crates", "moqtap-client", "src", "above_codec_rules.rs")

# The fewest rows that can be there without something having gone wrong. Not the
# exact count: this is a lower bound on a table that is expected to grow, and a
# gate that has to be edited every time a citation is added is a gate somebody
# edits without reading. The exact count is pinned on the Rust side, by
# `a_wording_shared_across_runs_is_written_once`, which is where it belongs -
# that test can say *which* sentence moved and this cannot.
CITATION_FLOOR = 60

# `const NAME: &str = "...";`, where the literal may run over several lines with
# a backslash at each break. One literal, not several concatenated: that is what
# the tree writes and what `rustfmt` leaves alone, and reading only this form
# means a table written some other way is reported as unparsed rather than
# quietly skipped.
CITATION_CONST = re.compile(
    r'const\s+(\w+)\s*:\s*&str\s*=\s*"((?:[^"\\]|\\.)*)"\s*;', re.S)
# `Self::RuleName => &[`, which opens one rule's runs.
CITATION_ARM = re.compile(r"Self::(\w+)\s*=>\s*&\[")
# One run. Written on one line by hand and exploded over five by `rustfmt`, so
# every separator here has to tolerate a newline.
CITATION_ROW = re.compile(
    r"RuleCitation\s*\{\s*"
    r"drafts:\s*\((\d+)\s*,\s*(\d+)\)\s*,\s*"
    r'section:\s*"([^"]*)"\s*,\s*'
    r"sentence:\s*(\w+)\s*,\s*"
    r'code_name:\s*(?:None|Some\("([^"]*)"\))\s*,?\s*\}',
    re.S)


def rust_string(literal):
    """A Rust string literal's body as the text it denotes.

    Only the escapes this table can contain, and it is a short list on purpose:
    a backslash before a newline swallows the break and the indentation that
    follows it, which is how a 200-character draft sentence is written inside a
    100-column file, and an escaped quote and an escaped backslash are the two
    characters that cannot be written raw. Anything else is left as it stands
    rather than guessed at - a
    table using an escape this does not know reports as a sentence no draft has,
    which is the safe direction.
    """
    out, i = [], 0
    while i < len(literal):
        c = literal[i]
        if c != "\\" or i + 1 >= len(literal):
            out.append(c)
            i += 1
            continue
        nxt = literal[i + 1]
        if nxt == "\n":
            i += 2
            while i < len(literal) and literal[i] in " \t\r":
                i += 1
            continue
        if nxt == '"' or nxt == "\\":
            out.append(nxt)
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def citation_rows():
    """`[(rule, lo, hi, section, sentence, code)]` read off the table."""
    try:
        text = io.open(CITATION_TABLE, encoding="utf-8").read()
    except OSError:
        print("::error::the per-draft citation table is not at %s. Rule 8 checks "
              "the sentences a consumer publishes per negotiated draft, and a "
              "table it cannot read is a table nothing checks - which is the "
              "state this rule was written to end. If the file moved, move this "
              "path with it." % rel(CITATION_TABLE))
        sys.exit(1)
    text = re.sub(r"(?m)^\s*//.*$", "", text)
    sentences = {m.group(1): rust_string(m.group(2))
                 for m in CITATION_CONST.finditer(text)}
    arms = [(m.start(), m.group(1)) for m in CITATION_ARM.finditer(text)]
    out = []
    for m in CITATION_ROW.finditer(text):
        rule = "?"
        for at, name in arms:
            if at < m.start():
                rule = name
            else:
                break
        key = m.group(4)
        if key not in sentences:
            print("::error::%s: the run for %s names a sentence constant %s that "
                  "this file does not define" % (rel(CITATION_TABLE), rule, key))
            sys.exit(1)
        out.append((rule, int(m.group(1)), int(m.group(2)),
                    m.group(3), sentences[key], m.group(5)))
    return out


def rule_8(rendered, tocs, verbose):
    """Every row of the citation table is its drafts' own sentence, where it says."""
    rows = citation_rows()
    if len(rows) < CITATION_FLOOR:
        print("::error::%s parsed as %d citation rows, and there were at least %d. "
              "A table this rule cannot read reports nothing, so too few rows is "
              "an error rather than a smaller table." % (rel(CITATION_TABLE), len(rows), CITATION_FLOOR))
        sys.exit(1)
    checked = 0
    bad = []
    for rule, lo, hi, section, sentence, code in rows:
        pattern = phrase(sentence)
        for n in range(lo, hi + 1):
            checked += 1
            if n not in rendered:
                bad.append((rule, n, section, "draft-%02d is not in this sweep" % n, sentence))
                continue
            if section not in tocs[n]:
                bad.append((rule, n, section, "that draft has no such section", sentence))
                continue
            owns = [section_of(rendered[n], hit.start())
                    for hit in re.finditer(pattern, rendered[n], re.I)]
            owns = [o for o in owns if o is not None]
            if not owns:
                bad.append((rule, n, section, "the sentence is not in that draft at all", sentence))
            elif section not in owns:
                bad.append((rule, n, section,
                            "the sentence sits in Section %s" % ", ".join(sorted(set(owns))), sentence))
        if code:
            flat = sentence.replace("_", " ").lower()
            if code.replace("_", " ").lower() not in flat:
                bad.append((rule, lo, section,
                            "names the code %s, which its own sentence does not use" % code,
                            sentence))
    print("rule 8  %5d per-draft citations in %s, %d wrong (floor 0)"
          % (checked, rel(CITATION_TABLE), len(bad)))
    for rule, n, section, why, sentence in bad:
        print("::error::%s: %s cites draft-%02d Section %s and %s"
              % (rel(CITATION_TABLE), rule, n, section, why))
        print("          %s" % sentence[:150])
    if verbose:
        print("        %d rows over %d drafts, from %s"
              % (len(rows), checked, rel(CITATION_TABLE)))
    return bool(bad)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--drafts", default=DEFAULT_DRAFTS,
                    help="directory holding draft-NN.html (default: %(default)s)")
    ap.add_argument("--fetch", action="store_true",
                    help="download any draft --drafts does not hold, from the "
                         "IETF archive")
    ap.add_argument("--verbose", action="store_true",
                    help="also print why each floor member is a floor member")
    args = ap.parse_args()

    rendered = load_drafts(args.drafts, args.fetch)
    tocs = {n: toc_of(rendered[n]) for n in rendered}

    failed = rule_1_and_2(rendered, tocs, args.verbose)
    failed |= rule_3_and_4(rendered, args.verbose)
    failed |= rule_5(rendered, args.verbose)
    failed |= rule_6(rendered, args.verbose)
    failed |= rule_7(rendered, args.verbose)
    failed |= rule_8(rendered, tocs, args.verbose)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
