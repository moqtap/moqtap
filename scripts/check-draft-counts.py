#!/usr/bin/env python3
"""No comment may count the draft set in words.

`ARCHITECTURE.md` section 4 calls prose the fourth silent construct: "a doc
comment saying 'all thirteen drafts' or 'drafts 15-19' compiles, passes, and
gets quoted by the next person who greps for it". This reads the first half of
that sentence. The second half — a range ending at the previous draft — stays a
judgement call, because a draft really can end an era; a count of *all* the
drafts cannot be anything but the draft set, and the draft set is on disk.

## What it asks

A count word — `eleven` through `eighteen` — sitting within a few words of
`draft`, `variant`, `row`, `module`, `place`, `arm` or `text`, whose value is
the number of drafts this tree has or that number less one. A per-draft match
is the draft set as surely as a list of drafts is, and `arms` was the noun
that let a baseline in `check-draft-parity.py` describe a fifteen-arm match as
a fourteen-arm one.

And the same count as a numeral where it is unmistakable: `2^N feature sets`,
which is a statement about how many draft features there are. Two of the
three places that wrote that down disagreed with the third.

## The bare form

The commonest shape in this tree has no noun at all, because the noun is in the
sentence before: "all fourteen", "whichever of the fourteen", "live on all
fourteen", "restating all fourteen", "a mismatch on all fifteen for no reason".
A count word followed by punctuation, by the end of the line, or by a
closed-class word is one of these.

It cannot be judged by its shape - about one in five counts something that is
not the draft set - so the ones that are not are named in `NOT_THE_DRAFT_SET` with
the reason, and everything else is an error. The list is short and each entry
says what the number counts: a sixteen-bit ceiling, sixteen reddened gates,
modules rather than drafts, and the two design documents that have to keep
quoting the defective comment they are written about.

Naming them rather than counting them is the difference between a gate and a
statistic. A residual with a number in front of it is one nobody finishes.

Both numbers are read off the per-draft source directories, so neither is
written down here and neither needs editing when a draft lands. The day
draft-22 arrives this file starts asking about "sixteen" and "fifteen" without
being touched, which is the whole point: the phrases it is looking for are
exactly the ones that just became wrong.

## Why those values and no others

A phrase of the form "all N drafts" is the whole set, and "the other N drafts"
is the set less the one the sentence is about. Every other count near the word
draft is a *subset* — the era of drafts that carry a joining fetch, the drafts
that have a peer completing a session — bounded by something other than how
many drafts exist, and it does not move when one is added. Reporting those too
would report the sentences that are right along with the ones that are wrong,
and a gate nobody can act on is a gate that gets switched off.

The cost of the narrow rule is that a subset count *can* go stale on its own,
and nothing here will say so. That is the residual, it is about sixty
sentences, and it is the same residual `check-draft-parity.py` leaves for a
range that stops one draft short.

## Another tree

Given a directory, it reads that one instead of this workspace - the draft set
still comes from this workspace's per-draft source directories, because that is
where a draft is defined. `testlab` is the case it was added for: a separate
repository that takes the crates by path, gains a draft the moment this
workspace has one, and has no gate of its own to notice. Its CI checks this
repository out next door and runs this file against itself.

## What it does not read

**History.** A changelog entry recording that a claim was made about one number
of drafts is correct about the day it was written, and `docs/archive/` is a set
of contracts that were closed. Rewriting either would make the record say
something that did not happen. `docs/task-list.md` is a work log and is read
the same way.

**Its own docstring**, which has to quote the phrases it refuses.

## What to write instead

Drop the numeral. The phrase already says *all*, so the number was never
carrying anything, and leaving the plural keeps every verb as it was. Where the
numeral is load-bearing grammar rather than a modifier — a sentence built on
"which of N drafts was negotiated" — say it without counting: "which draft was
negotiated".
"""

from __future__ import annotations

import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CRATES = os.path.join(ROOT, "crates")
SKIP = (".git", "target", "test-vectors", "test-traces", ".drafts", "vendor",
        "node_modules", "archive")
EXT = (".rs", ".md", ".py", ".yml", ".yaml", ".toml")
#: Read as a record of a moment rather than a claim about now — see the
#: docstring. `check-draft-counts.py` is here because it quotes what it refuses.
HISTORY = ("CHANGELOG.md", "task-list.md", "check-draft-counts.py")

DRAFT_DIR = re.compile(r"^draft(\d\d)$")
WORD = {11: "eleven", 12: "twelve", 13: "thirteen", 14: "fourteen",
        15: "fifteen", 16: "sixteen", 17: "seventeen", 18: "eighteen"}

#: What the count has to be counting for this to be the draft set. `rows` is
#: here because the CI matrix and the justfile sweep are one row per draft;
#: `versions`, `wire formats`, `session state machines` and `implementations`
#: because the architecture notes count drafts by what each one holds rather
#: than by the word draft, and those went stale the same way and were invisible
#: to a narrower list.
NOUNS = (r"drafts?|variants?|texts?|rows?|modules?|places?|versions?"
         r"|wire formats?|session state machines?|implementations?"
         r"|state machines?|arms?|match arms?|-armed|-draft")

#: The same count with a different notation on it. A workspace of N draft
#: features has 2^N builds, so "2^15 feature sets" states the draft set as
#: exactly as "fifteen drafts" does - and a rule that looks for count *words*
#: cannot see a numeral. Three places wrote this down and two of them
#: disagreed with the third, which is the failure the word rule is for.
POWER_NOUNS = r"feature sets?|combinations?|builds?|configurations?"

#: Closed-class words. A count word followed by one of these has no noun behind
#: it either - the noun was in the sentence before, and the phrase is as bare as
#: one that ends a line. "all fifteen for no reason", "one of the fourteen is",
#: "all fourteen at once". Without them the census sees only the count that ends
#: a clause, which is about half of them.
FUNCTION = (r"of|at|is|are|was|were|and|or|that|for|in|on|to|with|but|so"
            r"|than|as|if|when|because|which|who|it|its|they|them|from|each")


NOT_THE_DRAFT_SET = {
    ("ARCHITECTURE.md", '"All fourteen". All three have been derived'):
        "quotes the doc comment that shipped over a short array - the phrase is "
        "the evidence, and paraphrasing it would make the record say something "
        "that did not happen",
    ("ARCHITECTURE.md", 'reading "All fourteen" is this defect'):
        "the same quotation, in the section that names the defect",
    ("ARCHITECTURE.md", "which have fourteen and twelve distinct"):
        "distinct variants in two files, not drafts",
    ("ARCHITECTURE.md", 'grep -rn "twelve drafts'):
        "a grep recipe: it has to contain the phrases it hunts for",
    ("ARCHITECTURE.md", "for f in $(grep -rl"):
        "the same recipe, second half",
    ("scripts/check-draft-parity.py", "so a claim about 'every draft' is one"):
        "quotes the same shipped comment, for the same reason",
    ("scripts/check-draft-parity.py", "fourteen of them today"):
        "counts the axes that gate reads and prints on every run, which does "
        "not move when a draft is added",
    ("crates/moqtap-client/tests/a_publish_this_endpoint_makes_has_a_lifecycle.rs",
     "It reddens sixteen, on drafts 12 and 13"):
        "counts the gates this ablation reddens, not drafts",
    ("crates/moqtap-codec/src/draft18/data_stream.rs", "and the sixteen"):
        "Type values inside one section, not drafts",
    ("crates/moqtap-codec/src/draft19/data_stream.rs", "and the sixteen"):
        "Type values inside one section, not drafts",
    ("crates/moqtap-codec/src/draft19/message.rs", "this one admits fourteen"):
        "parameter types admitted by one message, not drafts",
    ("crates/moqtap-codec/tests/dispatch_tests.rs", "header form and so list sixteen"):
        "entries in a draft's reserved-Type list, not drafts",
    ("crates/moqtap-codec/tests/draft14_wire_rules.rs", "unchecked ceiling was sixteen"):
        "a ratio between two byte ceilings",
    ("crates/moqtap-codec/tests/track_namespace_rules.rs", "a peer spends sixteen"):
        "the same ratio",
    ("crates/moqtap-proxy/src/types.rs", "`use` edges from fourteen"):
        "modules reaching for these types, not drafts",
    ("crates/moqtap-proxy/tests/leaf_modules.rs", "`types` from fourteen"):
        "modules again",
    ("crates/quinn-netem/src/control.rs", "every third of fifteen"):
        "a loss counter's period, not drafts",
    ("crates/quinn-netem/tests/socket.rs", "datagram in sixteen and reporting sixteen"):
        "datagrams in a transmit run, not drafts",

    # `testlab`, read with `check-draft-counts.py ../testlab`. Paths are
    # relative to whichever tree is being read, so these sit beside the
    # workspace's own; the fragments are distinctive enough that neither tree
    # excuses the other's lines by accident.
    ("README.md", "Fifteen arms across the"):
        "arms in one file that shared a bug, not drafts (testlab)",
    ("container_src/src/main.rs", "declared capacity — fifteen"):
        "minutes of backoff, not drafts",
    ("container_src/src/pace.rs", "`-j` default of sixteen"):
        "parallel jobs, not drafts",
    ("container_src/src/setup.rs", "let sixteen = widths("):
        "a local named for draft-16, not a count",
    ("container_src/src/setup.rs", "assert_eq!(sixteen.stage"):
        "the same local",
    ("docs/findings.md", "fifteen, into nothing at all"):
        "two of the fifteen read stops in `delivery.rs`, named a sentence earlier",
    ("docs/findings.md", "Two of the sixteen stop a draft short"):
        "rules in the catalogue, not drafts",
    ("docs/findings.md", "have fired on the fourteen"):
        "the fourteen relay rows with a delivery section, named a sentence earlier",
    ("docs/findings.md", "the sixteen that have"):
        "catalogue entries that have had the sweep, not drafts",
}

BARE_IS = ("counts the draft set with the noun in the sentence before, which is "
           "wrong the day a draft lands. Say it without counting - or, if the "
           "number counts something else, name it in NOT_THE_DRAFT_SET with the reason.")

WORDS_ARE = ("counts the draft set in words, which is wrong the day a draft "
             "lands. Drop the numeral.")
POWERS_ARE = ("counts the draft set as an exponent - 2^N feature sets is N "
              "draft features - which is wrong the day a draft lands. Say it "
              "without counting.")


def draft_count() -> int:
    """How many drafts the tree has, from the per-draft source directories.

    The same derivation `check-draft-parity.py` and `check-draft-cfg.py` make,
    and for the same reason: a gate that writes the draft set down has the bug
    it is watching for.
    """
    found = set()
    for crate in sorted(os.listdir(CRATES)):
        src = os.path.join(CRATES, crate, "src")
        if not os.path.isdir(src):
            continue
        for child in os.listdir(src):
            if DRAFT_DIR.match(child) and os.path.isdir(os.path.join(src, child)):
                found.add(child)
    return len(found)


def files():
    for base, dirs, fs in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP]
        for f in sorted(fs):
            if f in HISTORY:
                continue
            if f.endswith(EXT) or f == "justfile":
                yield os.path.join(base, f)


def rel(path: str) -> str:
    return os.path.relpath(path, ROOT).replace(os.sep, "/")


def main() -> int:
    global ROOT
    # A tree to read, if one is named. Everything else - the draft set, the
    # words to refuse, the exemptions - is unchanged: a count of the drafts is
    # wrong in the same way wherever it is written.
    for arg in sys.argv[1:]:
        if not arg.startswith("-"):
            ROOT = os.path.abspath(arg)
            if not os.path.isdir(ROOT):
                sys.exit("no such tree: %s" % ROOT)
            break
    n = draft_count()
    if n < 2 or n + 1 not in WORD:
        sys.exit("derived a draft set of %d, which is not a number this file "
                 "has a word for. Extend WORD." % n)

    # The set, the set less one, and the set plus one — the last because the
    # per-draft sweeps carry a zero-draft row on the end and count it in.
    watched = {WORD[n]: n, WORD[n - 1]: n - 1, WORD[n + 1]: n + 1}
    pattern = re.compile(
        r"\b(%s)\b(?=(?:[\s-]+\w+){0,2}?[\s-]*(?:%s)\b)"
        % ("|".join(watched), NOUNS), re.I)
    #: The same three values as digits, behind a `2^` or `2**`.
    power = re.compile(
        r"\b2\s*(?:\^|\*\*)\s*(%s)\b(?=(?:[\s-]+\w+){0,2}?[\s-]*(?:%s)\b)"
        % ("|".join(str(v) for v in sorted(watched.values())), POWER_NOUNS),
        re.I)

    findings = []
    scanned = 0
    for path in files():
        try:
            text = io.open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        scanned += 1
        for pat, why in ((pattern, WORDS_ARE), (power, POWERS_ARE)):
            for m in pat.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                start = text.rfind("\n", 0, m.start()) + 1
                end = text.find("\n", m.end())
                findings.append(
                    (rel(path), line, why,
                     " ".join(text[start:end if end > 0 else None].split())))
    findings.sort()

    # The bare form: a watched count word with no noun behind it at all. Not a
    # finding - see the docstring - but counted out loud, because a residual
    # with a size is one somebody can finish and an unmeasured one is one
    # nobody starts.
    census = []
    bare = re.compile(
        r"\b(%s)\b(?:(?![\s-]*[A-Za-z`])|(?=[\s-]+(?:%s)\b))"
        % ("|".join(watched), FUNCTION), re.I)
    for path in files():
        try:
            text = io.open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for m in bare.finditer(text):
            # "two hundred and fourteen" is a number, not a count of drafts.
            if re.search(r"hundred\s+and\s+$", text[max(0, m.start() - 20):m.start()], re.I):
                continue
            start = text.rfind("\n", 0, m.start()) + 1
            end = text.find("\n", m.end())
            census.append((rel(path),
                           text.count("\n", 0, m.start()) + 1,
                           " ".join(text[start:end if end > 0 else None].split())))

    print("check-draft-counts: the draft set counted in words")
    print("  reading %s" % ROOT)
    print("  derived %d drafts from the tree, so the words to refuse are "
          "%s, %s and %s" % (n, WORD[n - 1], WORD[n], WORD[n + 1]))
    print("  scanned %d files" % scanned)
    for where, line_no, text in census:
        findings.append((where, line_no, BARE_IS, text))

    # One exemption list over both rules. A numeral that counts something else
    # can trip either, and the reason it is excused does not depend on which.
    kept, allowed = [], 0
    for finding in findings:
        where, _, _, text = finding
        if any(path == where and fragment in text
               for (path, fragment) in NOT_THE_DRAFT_SET):
            allowed += 1
            continue
        kept.append(finding)
    findings = kept
    findings.sort()
    print("  %d count word(s) excused by name in NOT_THE_DRAFT_SET" % allowed)

    if not findings:
        print("  no comment counts the draft set")
        return 0
    for where, line, why, text in findings:
        print("::error::%s:%d: %s %s" % (where, line, why, text[:140]))
    print("  %d phrase(s)" % len(findings))
    return 1


if __name__ == "__main__":
    sys.exit(main())
