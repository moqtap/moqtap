#!/usr/bin/env python3
"""The new-draft checklist, executable: every per-draft construct names every draft.

Adding a draft to this workspace is about forty files and five thousand lines,
and the bulk of it is mechanical and safe. The tail is not. Roughly a dozen edit
sites fail *silently* when they are missed - the code compiles, the tests pass,
and the new draft quietly gets some other draft's answer. This reads those sites
and says which ones have not been brought forward.

It compiles nothing and needs no toolchain.

## The one design rule: never write a draft number down

Every draft number here is read off the tree. That is not tidiness, it is the
defect this file exists to prevent, and the workspace has already been bitten by
it three times:

  * `scripts/check-drafts.py` carried `list(range(7, 20))`. A fourteenth draft
    landed and four of its rules went on printing the same counts over a tree
    that had grown a draft. Its own comment beside `implemented_drafts`
    argues for deriving the list, and does.
  * `crates/moqtap-proxy/src/shape/matcher.rs` declared
    `const DRAFTS: [DraftVersion; 13]` under a doc comment saying "All
    fourteen, so a claim about 'every draft' is one rather than a sample". It
    ended at `Draft19`, and every matcher unit test that swept it skipped
    draft-20. Fixed while this file was being written, which is the point: it
    took a person reading the array to find it, and rule 2 below would have.
  * Eleven `matches!(draft, ...)` predicates in `moqtap-proxy/src` desugar to
    `_ => false`, so a draft nobody added to the list is answered "no".

A gate that hard-codes the draft set has the same bug as the code it is
watching, so `axes()` below derives the set from every independent statement of
it the tree makes - fourteen of them today - and *requires them to agree*. There
is no constant to bump, and the day a `draft21` directory lands the whole file
starts asking about draft-21.

## What it checks

**Rule 1 - the draft set agrees on every axis.** Seven kinds of place state
which drafts exist:

  1. the per-draft source directories, per crate;
  2. the `mod draftNN` declarations in each `lib.rs`;
  3. each manifest's `draftNN = [...]` features;
  4. each manifest's `all-drafts` aggregator;
  5. the `DraftVersion` variants in `moqtap-codec/src/version.rs`;
  6. any literal draft range a sibling script in `scripts/` writes down;
  7. **the per-draft rows in `justfile` and `.github/workflows/*.yml`** - the
     lists that decide which drafts anything is *run against*, and therefore the
     one place where being short is silent in every other gate at once.

Any axis that differs from the union is reported, named, with the drafts it is
short of. This is where "a `draft21` directory landed and `lib.rs` /
`Cargo.toml` / `version.rs` were not touched" turns up, and where "the CI matrix
was not extended, so none of the per-draft rows ever compiled the new
draft" turns up. It is set equality rather than an N-1/N comparison, so it does
not care in which order the axes were edited.

**Rule 2 - a list that names draft N-1 and not draft N.** N is the newest draft
in the derived set. This is the review's formulation word for word, applied to
every list of drafts the tree writes: `matches!` patterns, the arm sets of a
`match`, `[DraftVersion; N]` and `&[DraftVersion]` literals, and
`cfg(any(feature = "draftNN", ...))` conditions. A list that stops one draft
short of the newest is the shape of a list somebody forgot, and
`shape/matcher.rs`'s `[DraftVersion; 13]` was exactly it.

For a `[DraftVersion; N]` it is the **initialiser** that is read and not the
type: the compiler already refuses a length that disagrees with the elements
beside it, so reading both would report one list twice and neither reading is
weaker. Ablated: changing the declared length alone is correctly not a finding;
removing the `DraftVersion::Draft20` element is.

**`#[cfg]` is gated under `src/` only.** It is the one class here that answers
"is this compiled for that draft" rather than "what does this answer for that
draft", and in a test tree that is the test-parity question this file
deliberately does not ask. The test-tree half is counted and named on every run
instead - 27 lists across 7 files the day this was written - so the residual has
a size without being an error. See `cfg_is_gated`, which carries the two
measurements that decided it.

**It deliberately does not ask that every list be complete**, and that
distinction is the whole of its false-positive rate. A draft set that stops
earlier than N-1 has drawn a boundary that a new draft falls outside of *by
design*, and the tree is full of those: `moqtap-codec/src/fields/params.rs` is
gated `any(draft07, draft08, draft09, draft10)` because draft-08 removed ROLE
and draft-11 keeps its own tables; `moqtap-client/src/lib.rs` compiles
`forwarding_preference` for drafts 07-15 because draft-16 made the preference a
property of the object rather than of the track. Demanding a draft-N
counterpart for every draft-N-1 construct reports both of those, and they are
the specification talking. Only a list that reaches N-1 is claiming to be
current.

**A baselined list answers to N from wherever it is.** The ladder is what a
list gets for not having been read yet, and it expires when somebody reads
it: an entry in `KNOWN` has been judged not to be one of the specification's
own boundaries. Without the exemption a judged list leaves this rule by
falling *further* behind - adding a draft turns every N-1 finding into an
N-2 one - and the baseline then retires it as fixed. Measured: five entries
did exactly that when draft-21 landed, and all five were still wrong.
Rule 3 carries the same exemption for the same reason. Ablated by putting
the newest draft into one of the baselined sweeps: that entry, and only that
entry, moves to "no longer reported".

**A file under `src/draftNN/` is skipped by rule 2 entirely.** The one
cross-draft list such a file writes is the rejection `cfg`, which names the
other drafts on purpose and has its own gate in
`scripts/check-draft-cfg.py` asking a stronger question than this could.
Reading them here reported a draft-17 module's test offering the ALPNs of
drafts 17, 18 and 19 - three of them, which is what "several" is for - as a list
that had not been brought forward.

Rules 2 and 3 both turn on "the newest draft", so neither runs while rule 1 is
failing: a half-added draft would otherwise report every list in the tree at
once. Measured - an empty `src/draft21/` and nothing else takes rule 2 from 0
findings to 97, which is a wall rather than a checklist. Settle rule 1 and rule
2 becomes the list of what is left to do.

**Rule 3 - a draft-enumerating `match` that reaches the newest draft must not
close with a quiet catch-all.** A `match` over one of the codec's `Any*` enums
or over `DraftVersion` that answers for every draft up to the newest and then
falls through to `_` is a construct a new draft's variant lands in silently. The
severity is in the body, so that is what is read: an arm that panics, returns an
`Err` or is `unreachable!` is loud and roughly correct - it exists for the
zero-draft build and it fails where somebody will see it. An arm that returns a
*plausible value* - `false`, `None`, an empty collection, some other draft's
wire byte - is a wrong answer that nothing distinguishes from a right one.

The count of draft arms is what separates this from the per-draft modules'
rejection guards, and the separation is clean rather than tuned: a guard in
`src/draft20/connection.rs` names **one** draft variant - its own - and rejects
everything else, which stays correct when a draft arrives, because the arm
matches a *variant* and a draft-21 header is draft-21's whatever its bytes look
like - and draft-21's look exactly like draft-20's. A dispatcher names **all of
them** and then guesses. Measured on this tree: 59 catch-alls sit in one-variant
matches and none of them is reported, while the one the rule finds in `src/`
names every draft.

## What it does not check, and what does check it

  * **What is inside a per-draft module.** That a `draft21/` directory exists
    says nothing about whether its code is right. `cargo` and the test suite own
    that, and the per-draft CI rows - one draft at a time, `--all-targets`,
    `-D warnings` - are what turn "this construct is reachable from only one
    draft" into a build failure.
  * **Completeness of a rejection `cfg(any(...))`.** `check-draft-cfg.py`.
  * **Citations and quotations against the draft texts.** `check-drafts.py`.
  * **Test-file parity.** `tests/draft20_*.rs` existing wherever
    `tests/draft19_*.rs` does is *not* asked, and deliberately: drafts delete
    features as well as adding them, and
    `moqtap-codec/tests/encode_discriminator_agreement.rs` excludes draft-20 in
    twelve lines of rationale because draft-20 deleted the FETCH discriminator.
    A gate over that would report the rationale.
  * **Anything a macro spells.** Where a per-draft item's name is assembled by
    token concatenation, the draft number is not in the text and nothing here
    can see it. `dispatch_enum!`'s and `dispatch_all!`'s invocations do write
    the numbers out, so rule 2 reads those lists like any other - but the
    *variants they generate* are not an axis rule 1 knows about, and an `Any*`
    enum silently short of a draft is between the invocation and the compiler.
  * **Runtime data.** Registry JSON, test vectors and the ALPN table on the wire
    are outside this file entirely.
  * **`required-features`, benches, examples and doc tests.** The
    target-accounting step in CI owns the first; nothing here reads the others.

## Known findings

`KNOWN` at the foot carries every finding on the tree the day this was written,
one entry each with the reason it is there and who owns the fix. They are
printed on every run rather than skipped silently, because a baseline nobody
reads is a disabled gate with extra steps. It may be shortened and not
lengthened: a new site is a new finding.
"""

from __future__ import annotations

import ast
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CRATES = os.path.join(ROOT, "crates")
SKIP_DIRS = (".git", "target", "test-vectors", "node_modules")

DRAFT_DIR = re.compile(r"^draft(\d\d)$")
MOD_DECL = re.compile(r"^\s*(?:pub\s+)?mod\s+draft(\d\d)\s*;", re.M)
FEATURE_KEY = re.compile(r"^\s*draft(\d\d)\s*=\s*\[", re.M)
ALL_DRAFTS_KEY = re.compile(r"^\s*all-drafts\s*=\s*\[(.*?)\]", re.M | re.S)
VERSION_VARIANT = re.compile(r"^\s*Draft(\d\d)\s*,", re.M)
DRAFT_TOKEN = re.compile(r"\bDraft(\d\d)\b")
FEATURE_DRAFT = re.compile(r'feature\s*=\s*"draft(\d\d)"')


def rel(path):
    return os.path.relpath(path, ROOT).replace(os.sep, "/")


def read(path):
    return io.open(path, encoding="utf-8", errors="replace").read()


def crates():
    return [c for c in sorted(os.listdir(CRATES))
            if os.path.isdir(os.path.join(CRATES, c))]


def rust_files():
    for base, dirs, files in os.walk(CRATES):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in sorted(files):
            if f.endswith(".rs"):
                yield os.path.join(base, f)


def owning_draft(path):
    """The draft whose module this file lives in, or `None`."""
    for part in rel(path).split("/"):
        m = DRAFT_DIR.match(part)
        if m:
            return int(m.group(1))
    return None


# ---------------------------------------------------------------------------
# Rule 1 - five statements of the draft set, which have to agree
# ---------------------------------------------------------------------------


LIST_TOKEN = re.compile(r"\bdraft[-_]?(\d\d)\b", re.I)
#: What may stand between two entries of one list and nothing else: whitespace,
#: a comma, a YAML dash, a quote. A letter between them is the next command.
LIST_GAP = re.compile(r"^[\s,\-\"']*$")


def list_runs(text):
    """Every run of `draftNN` tokens written as one list, as `{drafts}`.

    `for d in draft07 draft08 ... draft20; do` and a YAML
    `- draft07\\n - draft08\\n ...` are the same object in two spellings, and
    both are the enumeration that decides which drafts a gate is run against.
    A two-draft row like `--features draft07,draft20` is also a run and is left
    to the caller's length threshold: it is a deliberate pair, not a list that
    means "all of them".
    """
    found = [(m.start(), m.end(), int(m.group(1))) for m in LIST_TOKEN.finditer(text)]
    runs, current = [], []
    for i, (start, end, n) in enumerate(found):
        if current and not LIST_GAP.match(text[found[i - 1][1]:start]):
            runs.append({d for _, _, d in current})
            current = []
        current.append((start, end, n))
    if current:
        runs.append({d for _, _, d in current})
    return runs


def axes():
    """`[(name, {drafts})]` - every place the tree says which drafts exist.

    Each is read as its own sentence rather than derived from another, which is
    the point: a set stated once cannot disagree with itself, and disagreement
    is the whole signal. An axis a crate does not have at all is left out, not
    reported as empty - `moqtap-trace` has no drafts and is not a defect.
    """
    out = []
    for crate in crates():
        src = os.path.join(CRATES, crate, "src")
        if os.path.isdir(src):
            dirs = {int(m.group(1)) for name in os.listdir(src)
                    for m in [DRAFT_DIR.match(name)]
                    if m and os.path.isdir(os.path.join(src, name))}
            if dirs:
                out.append(("%s/src/draftNN/ directories" % crate, dirs))
            lib = os.path.join(src, "lib.rs")
            if os.path.isfile(lib):
                mods = {int(m.group(1)) for m in MOD_DECL.finditer(read(lib))}
                if mods:
                    out.append(("%s/src/lib.rs `mod draftNN`" % crate, mods))
        manifest = os.path.join(CRATES, crate, "Cargo.toml")
        if os.path.isfile(manifest):
            text = read(manifest)
            feats = {int(m.group(1)) for m in FEATURE_KEY.finditer(text)}
            if feats:
                out.append(("%s/Cargo.toml draftNN features" % crate, feats))
            agg = ALL_DRAFTS_KEY.search(text)
            if agg:
                named = {int(n) for n in re.findall(r'"draft(\d\d)"', agg.group(1))}
                if named:
                    out.append(("%s/Cargo.toml all-drafts" % crate, named))
    # A sibling gate that writes the draft set down as a python range is
    # stating the same set as everything above, in the one place where being
    # wrong is silent twice over: a checker short of a draft passes by asking
    # for too little, and a passing checker is the thing nobody looks at.
    #
    # This reports nothing today and is kept anyway, which is a judgement worth
    # writing down. It has had two subjects in this repository and both were
    # removed while this file was being written: `check-drafts.py`'s
    # `DRAFT_FLOOR = frozenset(range(7, 20))`, a floor sitting one draft behind
    # the tree, and `check-draft-cfg.py`'s `ALL_DRAFTS = [... for n in
    # range(7, 21)]` under a comment reading "Add a row here when a draft is
    # added, or this check passes by asking for too little" - a correct
    # description of a defect, filed as an instruction. An axis is what stops
    # it being an instruction. Ablated by putting a `range(7, 20)` back.
    for name in sorted(os.listdir(HERE)):
        if not name.endswith(".py"):
            continue
        # Parsed rather than matched, because both of these scripts *quote*
        # `range(7, 20)` in their prose - it is the historical defect they each
        # describe - and a text search reads the account of the bug as the bug.
        # An `ast` walk sees calls and not strings.
        try:
            tree = ast.parse(read(os.path.join(HERE, name)))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "range"
                    and len(node.args) == 2):
                continue
            lo, hi = node.args
            if not (isinstance(lo, ast.Constant) and isinstance(hi, ast.Constant)
                    and isinstance(lo.value, int) and isinstance(hi.value, int)):
                continue
            if 5 <= lo.value <= 10 and lo.value + 5 < hi.value < 100:
                out.append(("scripts/%s `range(%d, %d)` at line %d"
                            % (name, lo.value, hi.value, node.lineno),
                            set(range(lo.value, hi.value))))
    # From here on the crate axes are in hand, so "the oldest draft there is"
    # has an answer without anything below being consulted for it. That matters:
    # the tooling's own lists are the ones most likely to be short, and a
    # threshold read off them would move with the defect.
    oldest = min(min(s) for _, s in out) if out else None

    # The gates' own enumerations. `justfile` writes `for d in draft07 ...
    # draft20` twice and `.github/workflows/ci.yml` writes a one-row-per-draft
    # matrix, and those lists are what decide which drafts are *checked at all*.
    # A draft missing from them is the sharpest version of the defect in this
    # whole file: every other gate goes on passing, because nothing ran them
    # against the new draft.
    #
    # The union of every draft either file names, rather than each list
    # separately - both also carry two-draft rows (`draft07,draft20`,
    # `draft13,draft14`) and prose naming a draft or two, and those are subsets
    # on purpose. The union is the claim: a file that decides what gets checked
    # has to have heard of the newest draft somewhere.
    for where in [os.path.join(ROOT, "justfile")] + sorted(
            os.path.join(ROOT, ".github", "workflows", f)
            for f in (os.listdir(os.path.join(ROOT, ".github", "workflows"))
                      if os.path.isdir(os.path.join(ROOT, ".github", "workflows"))
                      else [])
            if f.endswith((".yml", ".yaml"))):
        if not os.path.isfile(where) or oldest is None:
            continue
        # Comment lines dropped, and that is not tidiness either: both files
        # explain this gate in prose that names a hypothetical `draft21/`, and
        # reading the prose put draft-21 into the union and reported eleven
        # axes for not having heard of it. What the axis is about is the part
        # that runs.
        body = "\n".join(l for l in read(where).splitlines()
                         if not l.lstrip().startswith("#"))
        # The *runs*, not the union of the file. Ablated both ways: taking the
        # union of every draft either file names, deleting the `- draft20`
        # matrix row from `ci.yml` and deleting `draft20` from the justfile's
        # `for d in ...` loops are both reported clean, because each file also
        # carries `draft07,draft20` and `draft19,draft20` two-draft rows
        # elsewhere that put draft-20 back into the union. The union is the
        # wrong question; the enumeration is.
        #
        # And a run only counts as an enumeration when it is **contiguous and
        # starts at the oldest draft there is**, which is what tells "every
        # draft" from a chosen few. `just draft-pairs` writes
        # `for pair in draft07,draft20 draft19,draft20; do`, which is one run
        # of three distinct drafts and means nothing of the kind - it reported
        # as an axis eleven drafts short until this condition was added. Same
        # argument `check-draft-cfg.py` makes about list lengths: a list that
        # opens at the beginning and runs on is claiming to be all of them.
        for run in list_runs(body):
            if len(run) >= 3 and min(run) == oldest \
                    and run == set(range(min(run), max(run) + 1)):
                out.append(("%s per-draft rows" % rel(where), run))
    version = os.path.join(CRATES, "moqtap-codec", "src", "version.rs")
    if os.path.isfile(version):
        text = read(version)
        # The enum body only; `Draft07,` appears nowhere else in that shape.
        m = re.search(r"pub enum DraftVersion\s*\{(.*?)\n\}", text, re.S)
        if m:
            got = {int(x.group(1)) for x in VERSION_VARIANT.finditer(m.group(1))}
            if got:
                out.append(("moqtap-codec/src/version.rs DraftVersion", got))
    return out


def drafts(found):
    return sorted(set().union(*[s for _, s in found])) if found else []


def spell(ds):
    return ", ".join("draft-%02d" % d for d in sorted(ds))


def rule_1(found, everything):
    bad = []
    for name, got in found:
        missing = set(everything) - got
        extra = got - set(everything)
        if missing or extra:
            bad.append((name, sorted(missing), sorted(extra)))
    print("rule 1  %d statements of the draft set, %d disagree with the union %s"
          % (len(found), len(bad), spell(everything)))
    for name, missing, extra in bad:
        parts = []
        if missing:
            parts.append("does not name %s" % spell(missing))
        if extra:
            parts.append("names %s, which nothing else does" % spell(extra))
        print("::error::%s: %s. Every other statement of this set has it, so "
              "either this one was not brought forward or the draft is being "
              "removed and they all have to move together." % (name, " and ".join(parts)))
    return bad


# ---------------------------------------------------------------------------
# Reading Rust without a parser
# ---------------------------------------------------------------------------


def strip_noncode(text, keep_strings=False):
    """Blank comments and literals, keeping every offset and newline in place.

    Line numbers are reported from the original text, so nothing here may
    change a length. A `//` inside a string literal and a `"` inside a comment
    both mislead a simpler reader, and both occur in this tree.

    `keep_strings` blanks the comments and leaves the literals, which one
    reader needs and the rest must not have. A draft `cfg` names its drafts
    *inside string literals* - `feature = "draft20"` - so blanking those makes
    every `cfg(any(...))` list read as empty. That is not a hypothetical: the
    cfg arm of rule 2 was written against the blanked text and reported nothing
    at all until an ablation that removed draft-20 from
    `moqtap-client/src/lib.rs`'s `malformed_tracks` gate came back clean. A
    rule that cannot fail is not a rule, and the only thing that found this was
    running it against a defect rather than against the tree.
    """
    out = list(text)
    i, n = 0, len(text)

    def blank(a, b):
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = text[i]
        if c == "/" and text[i + 1:i + 2] == "/":
            j = text.find("\n", i)
            j = n if j == -1 else j
            blank(i, j)
            i = j
            continue
        if c == "/" and text[i + 1:i + 2] == "*":
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            blank(i, j)
            i = j
            continue
        if c == "r":
            m = re.match(r'r(#*)"', text[i:])
            if m:
                close = '"' + m.group(1)
                j = text.find(close, i + m.end())
                j = n if j == -1 else j + len(close)
                blank(i, j)
                i = j
                continue
        if c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            if not keep_strings:
                blank(i, j)
            i = j
            continue
        if c == "'":
            # A char literal, and not a lifetime: `'a` is followed by no mark.
            m = re.match(r"'(?:\\.|[^\\'])'", text[i:])
            if m:
                blank(i, i + m.end())
                i += m.end()
                continue
        i += 1
    return "".join(out)


OPEN, CLOSE = "([{", ")]}"


def balanced(code, start):
    """The offset just past the bracket opened at `start`, or `len(code)`."""
    depth, i, n = 0, start, len(code)
    while i < n:
        if code[i] in OPEN:
            depth += 1
        elif code[i] in CLOSE:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def match_bodies(code):
    """`(body_start, body_end)` for every `match` expression in `code`."""
    for m in re.finditer(r"\bmatch\b", code):
        i, depth, n = m.end(), 0, len(code)
        while i < n:
            c = code[i]
            if c in "([":
                depth += 1
            elif c in ")]":
                depth -= 1
            elif c == "{" and depth == 0:
                break
            elif c == ";" and depth == 0:
                i = n
                break
            i += 1
        if i >= n:
            continue
        end = balanced(code, i)
        if end <= i:
            continue
        yield i, end - 1


ATTR = re.compile(r"#\s*\[[^\]]*\]", re.S)


def arms(code, start, end):
    """`[(pattern, body, pattern_offset)]` for one match body."""
    i, out = start + 1, []
    while i < end:
        while i < end and code[i] in " \t\r\n,":
            i += 1
        if i >= end:
            break
        pat_start, depth, arrow = i, 0, -1
        while i < end:
            c = code[i]
            if c in OPEN:
                depth += 1
            elif c in CLOSE:
                depth -= 1
            elif c == "=" and depth == 0 and code[i + 1:i + 2] == ">":
                arrow = i
                break
            i += 1
        if arrow == -1:
            break
        pattern = code[pat_start:arrow]
        i = arrow + 2
        while i < end and code[i] in " \t\r\n":
            i += 1
        body_start = i
        if i < end and code[i] == "{":
            i = balanced(code, i)
        else:
            depth = 0
            while i < end:
                c = code[i]
                if c in OPEN:
                    depth += 1
                elif c in CLOSE:
                    depth -= 1
                elif c == "," and depth == 0:
                    break
                i += 1
        out.append((pattern, code[body_start:i], pat_start))
    return out


def at(fn):
    """How to name where a site sits, when it may not sit in a function."""
    return "at module level" if fn == "<module level>" else "in `%s`" % fn


def lineno(text, offset):
    return text.count("\n", 0, offset) + 1


def enclosing_fn(code, offset):
    """The name of the `fn` a site sits in, for a baseline key that survives edits.

    A line number moves whenever anything above it does, and a draft set moves
    by definition, so neither can key a baseline. A function name is the one
    thing about a site that a new draft does not change.
    """
    last = None
    for m in re.finditer(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)", code, re.M):
        if m.start() > offset:
            break
        last = m.group(1)
    return last or "<module level>"


# ---------------------------------------------------------------------------
# Rule 2 - a list that names draft N-1 and not draft N
# ---------------------------------------------------------------------------


MATCHES_MACRO = re.compile(r"\bmatches!\s*\(")
DRAFT_ARRAY = re.compile(r"(?:\[|&\s*\[)\s*DraftVersion\s*::")
CFG_ANY = re.compile(r"#\s*\[\s*cfg\s*\(\s*any\s*\(")


def draft_lists(text, code):
    """Every list of drafts one file writes, as `(kind, drafts, offset)`.

    Four shapes, and the reason they are read together is that the defect is
    one defect: a run of drafts that somebody extended for the last draft and
    not for this one. Where it is written down does not change what it means.
    """
    out = []
    for m in MATCHES_MACRO.finditer(code):
        end = balanced(code, m.end() - 1)
        got = {int(x.group(1)) for x in DRAFT_TOKEN.finditer(code[m.end():end])}
        if len(got) >= 2:
            out.append(("a `matches!` predicate", got, m.start()))
    # The initialiser rather than the type. `const DRAFTS: [DraftVersion; 13]`
    # cannot disagree with the list beside it - the compiler counts those - so
    # reading both would report one list twice.
    for m in DRAFT_ARRAY.finditer(code):
        start = code.index("[", m.start())
        end = balanced(code, start)
        got = {int(x.group(1)) for x in DRAFT_TOKEN.finditer(code[start:end])}
        if len(got) >= 2:
            out.append(("a `DraftVersion` list literal", got, m.start()))
    # Over the text with its string literals intact: a draft `cfg` writes its
    # drafts as `feature = "draft20"`, and `code` has blanked those.
    spelled = strip_noncode(text, keep_strings=True)
    for m in CFG_ANY.finditer(spelled):
        start = spelled.index("(", m.start() + 2)
        end = balanced(spelled, start)
        inner = spelled[start:end]
        got = {int(x.group(1)) for x in FEATURE_DRAFT.finditer(inner)}
        # Only a condition made of draft features and nothing else. A `cfg`
        # mixing in a target or another feature is a different claim.
        if len(got) >= 2 and not re.search(r"feature\s*=\s*\"(?!draft\d\d)", inner):
            out.append(("a `cfg(any(...))` draft list", got, m.start()))
    # `#[cfg]` is the one class here that answers "is this compiled for that
    # draft" rather than "what does this do for that draft", and in a test tree
    # that is the test-parity question rather than the silent-answer one. See
    # `cfg_is_gated`.
    for start, end in match_bodies(code):
        got = set()
        for pattern, _, _ in arms(code, start, end):
            bare = ATTR.sub(" ", pattern)
            got.update(int(x.group(1)) for x in DRAFT_TOKEN.finditer(bare))
        if len(got) >= 2:
            out.append(("a `match` over drafts", got, start))
    return out


CFG_KIND = "a `cfg(any(...))` draft list"


def cfg_is_gated(where):
    """Whether a short `cfg(any(...))` draft list in this file is an error.

    Only under `src/`, and the reason is the one thing this gate is most at
    risk of getting wrong. Every other class here asks *what the code answers*
    for a draft, and a wrong answer is wrong wherever it is written. A `#[cfg]`
    asks whether the code is compiled for that draft at all - and in a test
    tree that is the test-parity question, which drafts delete features as
    readily as they add them and which this gate deliberately does not ask.

    Measured rather than assumed. On the tree the day this was written the
    class reports 27 lists that name draft-19 and stop, **every one of them in
    a test tree and none in `src/`** - and the two sharpest are exactly the
    ambiguous case: `moqtap-client/tests/uni_control_plane.rs` excludes
    draft-20 because draft-20 restructured FETCH and the file cannot yet
    express it, and
    `moqtap-client/tests/a_fetch_range_means_one_thing_on_every_draft.rs` for
    the same reason. Both are real gaps and neither is a defect in the list.
    Gating them would have shipped a red gate over a specification fact.

    So the test-tree half is counted and named on every run instead, under
    "not gated". A number nobody has to act on is a weaker thing than an
    error, and it is the honest strength of the evidence.
    """
    return "/src/" in where


def rule_2(everything, known, used):
    if len(everything) < 2:
        print("rule 2  fewer than two drafts in the tree; nothing to compare")
        return [], []
    newest, previous = everything[-1], everything[-2]
    checked, bad, ungated = 0, [], []
    for path in rust_files():
        # A file under `src/draftNN/` is that draft's own business: the one
        # cross-draft list it writes is the rejection `cfg`, and
        # `check-draft-cfg.py` asks a stronger question of those than this
        # could. Reading them here reported a draft-17 test offering the ALPNs
        # of drafts 17, 18 and 19 - three of them, which is what "several" is
        # for - as a list that had not been brought forward.
        if owning_draft(path) is not None:
            continue
        text = read(path)
        code = strip_noncode(text)
        for kind, got, off in draft_lists(text, code):
            where = rel(path)
            fn = enclosing_fn(code, off)
            key = (where, fn, kind)
            # The ladder - only a list reaching N-1 is asked about N - is what
            # keeps this rule off the boundaries the specification itself drew,
            # and it is the whole of the false-positive argument above. It also
            # means a list falls out of the rule by falling further behind: the
            # run that adds a draft turns every N-1 finding into an N-2 one and
            # reports it as gone. For an unjudged list that is the right trade.
            # For one in `KNOWN` it is not - a person has read that list and
            # found it is not a boundary - so a judged list answers to the
            # newest draft from wherever it has got to, and retiring means it
            # was fixed. Measured: five entries left the ladder when draft-21
            # landed, every one of them still wrong.
            on_the_ladder = previous in got
            if not on_the_ladder and key not in known:
                continue
            if on_the_ladder:
                checked += 1
            if newest in got:
                continue
            if kind == CFG_KIND and not cfg_is_gated(where):
                ungated.append(where)
                continue
            if key in known:
                used.add(key)
                continue
            bad.append((where, lineno(text, off), kind, sorted(got), fn))
    print("rule 2  %d list(s) reaching draft-%02d, %d of them stop there"
          % (checked, previous, len(bad)))
    for where, line, kind, got, fn in bad:
        print("::error::%s:%d: %s %s names draft-%02d and not draft-%02d. "
              "It lists %s. A list that reaches the second-newest draft is a "
              "list that was current when that draft landed, so this is the "
              "shape of one that was not brought forward."
              % (where, line, kind, at(fn), previous, newest, spell(got)))
    if ungated:
        by_file = {}
        for where in ungated:
            by_file[where] = by_file.get(where, 0) + 1
        print("        not gated: %d `cfg(any(...))` draft list(s) in test trees "
              "name draft-%02d and stop, across %d file(s). A `#[cfg]` in a test "
              "answers whether a draft is covered, and a draft is sometimes "
              "uncovered on purpose - see `cfg_is_gated`. Counted so the "
              "residual has a size:" % (len(ungated), previous, len(by_file)))
        for where in sorted(by_file):
            print("          %3d  %s" % (by_file[where], where))
    return bad


# ---------------------------------------------------------------------------
# Rule 3 - a dispatcher that guesses for a draft it does not know
# ---------------------------------------------------------------------------


# An arm that says "I do not know this" where somebody will see it. `Err` is
# here because a returned error is as loud as a panic to the caller and rather
# more useful; `unreachable!` is here because the zero-draft build needs it and
# it fails at the first call.
LOUD = re.compile(r"\b(?:unreachable|panic|todo|unimplemented|assert|debug_assert)\s*!"
                  r"|\bErr\s*\(|UnsupportedDraft")


def rule_3(everything, known, used):
    if not everything:
        print("rule 3  no drafts in the tree; nothing to check")
        return []
    newest = everything[-1]
    checked, bad = 0, []
    for path in rust_files():
        text = read(path)
        code = strip_noncode(text)
        for start, end in match_bodies(code):
            got, catchall = set(), None
            for pattern, body, off in arms(code, start, end):
                bare = ATTR.sub(" ", pattern).strip()
                got.update(int(x.group(1)) for x in DRAFT_TOKEN.finditer(bare))
                if bare.lstrip("|").strip() == "_":
                    catchall = (body, off)
            # One draft variant is a per-draft module's rejection guard, which
            # stays right when a draft is added: a draft-21 header really is
            # not draft-20's. Two or more is a construct answering *for* the
            # drafts, and the catch-all is then a draft it has not met.
            if len(got) < 2 or catchall is None:
                continue
            body, off = catchall
            where = rel(path)
            fn = enclosing_fn(code, off)
            key = (where, fn, "quiet catch-all")
            # A match that has not met the newest draft is rule 2's finding and
            # not this one, so it is skipped here - unless it is already in
            # `KNOWN`, where skipping it would retire a judged defect for
            # having fallen further behind. Same exemption as rule 2, same
            # reason.
            if newest not in got and key not in known:
                continue
            if newest in got:
                checked += 1
            if LOUD.search(body):
                continue
            if key in known:
                used.add(key)
                continue
            bad.append((where, lineno(text, off), sorted(got), fn,
                        " ".join(body.split())[:60]))
    print("rule 3  %d draft-enumerating match(es) reaching draft-%02d with a "
          "catch-all, %d of them answer quietly" % (checked, newest, len(bad)))
    for where, line, got, fn, body in bad:
        print("::error::%s:%d: the match %s answers for %s and then falls "
              "through to `_ => %s`. That is a plausible value, not a refusal, "
              "so the next draft's variant would be answered wrongly and "
              "nothing would say so. Make the arm loud, or name every draft."
              % (where, line, at(fn), spell(got), body))
    return bad


# ---------------------------------------------------------------------------
# The known findings
# ---------------------------------------------------------------------------

# Keyed by `(file, enclosing fn, kind)` - never by line number, which moves
# whenever anything above it does, and never by the draft set, which moves by
# definition. Each entry carries why it is here and who owns the fix. Printed on
# every run: a finding that is skipped silently is a finding nobody fixes.
KNOWN = {
    ("crates/moqtap-proxy/tests/control_undecodable.rs", "alpn", "a `match` over drafts"):
        "REAL DEFECT, owned by moqtap-proxy. `alpn()` maps Draft15..Draft19 to "
        "`moqt-NN` and everything else to `moq-00`, so the draft-20 row takes "
        "the drafts-07-to-14 route through the fixture instead of the "
        "ALPN-resolved one the comment above it describes. Both routes pass, "
        "which is why nothing has reported it. Drop this entry when Draft20 is "
        "in the match.",

    # `message_type_name` and `setup_option_name` are not baselined here, and
    # this rule does not see them at all. They share
    # `moqtap_codec::draft_table::by_draft`, which writes an arm per draft under
    # `#[cfg(feature)]` and another under `#[cfg(not(feature))]` and so leaves no
    # `_` to fall into: a sixteenth `DraftVersion` variant stops that crate
    # compiling instead of being answered quietly. The macro invocation writes
    # `Draft07` rather than `DraftVersion::Draft07`, which is the "anything a
    # macro spells by token concatenation" this file's own summary already excludes.
    #
    # `AnyControlMessage::is_setup`, `::fields` and `::fetch_group_order` reach
    # the same guarantee from the other end and are invisible here for a
    # different reason: they match the cfg-gated `AnyControlMessage` rather than
    # `DraftVersion`, so a draft with no feature has no variant to answer for and
    # the arms are exactly the variants under every feature set. Nothing is left
    # for a `_` to catch, so the rule finds no catch-all to read, and a draft
    # added to the enum without an arm is a compile error rather than a plausible
    # value.

    ("crates/moqtap-proxy/src/session.rs", "datagram_is_status", "quiet catch-all"):
        "REAL DEFECT, owned by moqtap-proxy, and the sharpest of the set "
        "because the seam analysis holds this exact site up as the *correct* "
        "pattern at 2.3 - `#[allow(unreachable_patterns)] _ => false` is total "
        "under every feature set, which is what that section is about. It "
        "is still a quiet answer for a draft the match has not met. Both "
        "readings are true; the fix is an arm that is total AND loud.",

    ("crates/moqtap-codec/tests/dispatch_tests.rs", "put_varint_for", "quiet catch-all"):
        "Test helper. An arm per draft from 17 on and `_ => put_varint(v, out)`, "
        "so a new draft silently gets the pre-delta encoding. Owned by the "
        "codec test suite; harmless today and wrong the day it is not.",

    ("crates/moqtap-proxy/tests/action_matrix.rs", "fetch_frame", "quiet catch-all"):
        "Test helper. An arm per draft from 18 on and `_ => return None`, so a "
        "new draft is silently skipped by the rows that use it rather than "
        "covered by them. Owned by the proxy test suite.",

    # Rule 2. Four sweeps in one file, all of them sampling the drafts rather
    # than listing them, and all of them stopping where draft-19 was the newest
    # there was. The first is the sharpest: it is named for every draft.
    ("crates/moqtap-proxy/tests/matcher_keyability.rs",
     "a_fetch_key_is_carried_on_every_draft", "a `DraftVersion` list literal"):
        "REAL FINDING, owned by the proxy test suite. The test is named "
        "`..._on_every_draft` and sweeps drafts 14, 18 and 19. Draft-20 is not "
        "in it, so the claim in the name is not the claim in the loop.",

    ("crates/moqtap-proxy/tests/matcher_keyability.rs",
     "every_key_the_predicate_admits_claims_a_real_object",
     "a `DraftVersion` list literal"):
        "REAL FINDING, owned by the proxy test suite. Sweeps drafts 14 and 19 "
        "as one-from-each-era representatives; draft-19 was the newest era "
        "when it was written and no longer is.",

    ("crates/moqtap-proxy/tests/matcher_keyability.rs",
     "a_datagram_aimed_subgroup_id_rule_is_refused",
     "a `DraftVersion` list literal"):
        "REAL FINDING, owned by the proxy test suite. As above - drafts 14 and "
        "19 as representatives of the two eras, with the newer one stale.",

    ("crates/moqtap-proxy/tests/matcher_keyability.rs",
     "a_rule_that_can_still_fire_somewhere_is_admitted",
     "a `DraftVersion` list literal"):
        "REAL FINDING, owned by the proxy test suite. As above - drafts 14 and "
        "19 as representatives of the two eras, with the newer one stale.",
}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    ignore_known = "--ignore-known" in argv
    for arg in argv:
        if arg not in ("--ignore-known",):
            print("usage: check-draft-parity.py [--ignore-known]")
            print("  --ignore-known  report the baselined findings as findings, "
                  "which is how the entries below were written and how a fix to "
                  "one of them is confirmed")
            return 2
    print("check-draft-parity: the per-draft constructs, read off the tree")
    print("  checks   every statement of the draft set - source directories, "
          "`mod draftNN`, cargo features, `all-drafts`, `DraftVersion`, a "
          "literal range in any scripts/*.py, and the per-draft rows in the "
          "justfile and in CI - and requires them to agree; a list naming "
          "draft N-1 and not draft N (matches!, match arms, DraftVersion list "
          "literals, and cfg(any(...)) under src/); a draft-enumerating match "
          "with a quiet catch-all")
    print("  does not check what is inside a per-draft module (cargo and the "
          "per-draft CI rows), rejection cfg completeness (check-draft-cfg.py), "
          "citations (check-drafts.py), test-file parity or whether a draft is "
          "covered by the tests at all (deliberately - counted, not gated), or "
          "anything a macro spells by token concatenation")
    print()

    found = axes()
    if not found:
        print("::error::no per-draft directory, `mod draftNN`, draft feature or "
              "`DraftVersion` variant anywhere under crates/. This gate reads "
              "the draft set off the tree and has just read an empty one, which "
              "is a broken checkout or a moved layout, not a workspace with no "
              "drafts.")
        return 1
    everything = drafts(found)

    known = {} if ignore_known else dict(KNOWN)
    used = set()
    failed = bool(rule_1(found, everything))
    ran_the_rest = not failed
    if failed:
        # Rules 2 and 3 both turn on "the newest draft", and while the five
        # statements of the set disagree there is no single answer to that. Run
        # them anyway and a half-added draft reports every list in the tree at
        # once - measured: an empty `src/draft21/` directory and nothing else
        # takes rule 2 from 0 findings to 97, which is not a checklist, it is a
        # wall. Fix rule 1 first and rule 2 becomes the list of what is left.
        print("rule 2  not run: the draft set does not agree, so \"the newest "
              "draft\" has no single answer yet")
        print("rule 3  not run: same reason")
    else:
        failed |= bool(rule_2(everything, known, used))
        failed |= bool(rule_3(everything, known, used))

    print()
    print("known findings (%d), printed rather than skipped:" % len(known))
    for key in sorted(known):
        mark = " " if key in used else "*"
        print("  %s %s  %s  [%s]" % (mark, key[0], key[2], key[1]))
        for line in re.findall(r".{1,72}(?:\s|$)", known[key]):
            print("      %s" % line.strip())
    stale = [k for k in known if k not in used] if ran_the_rest else []
    if stale:
        print()
        print("  * no longer reported. Delete the entry - a baseline that does "
              "not shrink is room for the next defect to sit in:")
        for key in sorted(stale):
            print("      %s  %s  [%s]" % (key[0], key[2], key[1]))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
