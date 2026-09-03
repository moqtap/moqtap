#!/usr/bin/env python3
"""Check that a module's documentation lives in one place.

A module can be documented twice over: with an outer `///` comment above its
`mod x;` declaration, and with inner `//!` comments at the top of `x.rs`. Rust
concatenates the two into one doc string, and rustdoc then resolves the
*whole* of it in the scope of the declaration — the parent module — rather
than in the module's own. Every relative intra-doc link in the file quietly
starts looking one level up.

The failure is invisible three times over. It compiles. The prose still reads
correctly, because a human resolves `[`FieldValue`]` against the file it is
written in. And rustdoc's own diagnostic loses the span — a doc string built
from fragments in two files has no single location — so instead of
`--> src/fields/mod.rs:15` you get "the link appears in this line" and a
snippet, which names no file at all. That is what a `-D warnings` doc job
reports when this is the cause, and it is why the eight of these that had
accumulated in this tree were read as eight separate broken links in four
files rather than as one mechanism in two.

What made it worth a checker rather than eight edits is that the eight were
not the extent of it. 114 declarations carried a doubled doc; the other 106
were latent, waiting for someone to write a relative link in a file that had
one. Several had already been worked around at the call site, with the link
target spelled out in full — `[`SessionErrorCode`](crate::draft08::error_codes::SessionErrorCode)` —
which fixes the one link and leaves the mechanism in place for the next.

The rule is therefore about the declaration, not about the links: **if a
module's file documents itself, its declaration must not also document it.**
That is checkable without resolving anything, it has no false negatives, and
the fix is always to delete the outer comment — in this tree every one of the
114 restated the file's own first line, and several restated it wrongly,
naming registries the draft has not got.

Modules with no inner docs are not this rule's business. Their declaration is
the only documentation they have, `#![deny(missing_docs)]` is what requires it,
and an outer comment there resolves in the parent scope because the parent
scope is where it was written.
"""
import argparse
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SKIP_DIRS = (".git", "target", "test-vectors")

# An outer doc block, then anything Rust lets sit between it and the item it
# documents, then the declaration.
#
# The attributes matter: a `mod` behind a `#[cfg]` is the common shape here, and
# a pattern demanding the doc sit directly above the `mod` would miss every
# draft module in the codec. Blank lines matter for a different reason — there
# are none of them in this shape today, and a doc comment attaches across one
# anyway, so a check that required adjacency would go quietly wrong the first
# time somebody spaced a declaration out.
DECL = re.compile(
    r'(?P<block>(?:^[ \t]*///.*\n)+)'
    r'(?:^[ \t]*(?:#\[[^\n]*\])?[ \t]*\n)*'
    r'^[ \t]*(?:pub(?:\([^)]*\))?[ ]+)?mod[ ]+(?P<name>\w+);',
    re.M)

# Inner docs need not be the first thing in the file: an inner attribute may
# come first, and `#![allow(missing_docs)]` does on four of the endpoints here.
# A check that demanded `//!` at byte zero would pass those four while they
# were broken, which is how they survived the first sweep of this.
INNER = re.compile(r'\A(?:\s*#!\[[^\n]*\]\s*\n)*\s*//!', re.M)

# Every module declaration, documented or not. This is what the reach floor
# counts, and it has to be this rather than the documented ones: deleting an
# outer doc comment is exactly what fixing a finding does, so a floor measured
# on documented declarations would fall every time the check was obeyed and
# would have to be lowered to stay green. A floor that the fix erodes is not a
# floor.
ANY_DECL = re.compile(
    r'^[ \t]*(?:pub(?:\([^)]*\))?[ ]+)?mod[ ]+\w+;', re.M)

# A floor on how much of the tree the walk reached. Both halves of this check
# are "a thing was not found", so a walk that reaches nothing reports a clean
# tree. That is the direction a checker fails silently in, and the count is the
# only thing that can see it.
MIN_DECLARATIONS = 250


def module_file(where, name):
    """The file a `mod name;` in `where` refers to, or None."""
    for cand in (os.path.join(where, name + ".rs"),
                 os.path.join(where, name, "mod.rs")):
        if os.path.isfile(cand):
            return cand
    return None


def read(path):
    return io.open(path, encoding="utf-8", newline="").read().replace("\r\n", "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--root", default=ROOT, help="workspace root")
    args = parser.parse_args()

    seen = 0
    findings = []
    crates = os.path.join(args.root, "crates")
    for crate in sorted(os.listdir(crates)):
        src = os.path.join(crates, crate, "src")
        if not os.path.isdir(src):
            continue
        for where, dirs, files in os.walk(src):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for name in sorted(files):
                if not name.endswith(".rs"):
                    continue
                path = os.path.join(where, name)
                text = read(path)
                seen += len(ANY_DECL.findall(text))
                for m in DECL.finditer(text):
                    target = module_file(where, m.group("name"))
                    if target is None:
                        continue
                    if not INNER.match(read(target)):
                        continue
                    line = text.count("\n", 0, m.start("block")) + 1
                    findings.append((
                        os.path.relpath(path, args.root).replace("\\", "/"),
                        line,
                        m.group("name"),
                        os.path.relpath(target, args.root).replace("\\", "/"),
                        m.group("block").strip().split("\n")[0].strip()))

    if seen < MIN_DECLARATIONS:
        print("::error::this check reached %d module declarations and expected "
              "at least %d. Both of its halves are the absence of something, so "
              "a walk that reaches nothing reports a clean tree. Either the "
              "layout under crates/*/src moved, or the walk is broken; lower "
              "MIN_DECLARATIONS in the same commit if the tree really shrank."
              % (seen, MIN_DECLARATIONS))
        return 1

    for path, line, name, target, first in findings:
        print("::error file=%s,line=%d::`mod %s;` is documented here and %s "
              "documents itself. Rust joins the two, and rustdoc then resolves "
              "every intra-doc link in %s against this file's module instead of "
              "%s's own — so a relative link there breaks, or worse, silently "
              "resolves to the wrong item. Delete this comment; the module's "
              "own docs are the ones that keep their scope. (%s)"
              % (path, line, name, target, target, name, first))

    if findings:
        print("::error::%d module(s) documented twice over. See above."
              % len(findings))
        return 1

    print("module docs: %d declarations, none doubled" % seen)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
