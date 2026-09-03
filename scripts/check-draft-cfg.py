#!/usr/bin/env python3
"""Check the cross-draft rejection arms: the surviving `cfg` lists, and the
per-draft construct that replaced most of them.

A per-draft module matches on one of the codec's `Any*` enums, handles its own
variant, and rejects the rest with a wildcard arm. That arm is unreachable when
this draft is the only one enabled — the enum then has a single variant and the
first arm is already exhaustive — so it has to be either compiled out or have
the lint allowed. The workspace used both shapes and now overwhelmingly uses
the second:

```rust
match header {
    AnySubgroupHeader::Draft20(ref header) => { ... }
    #[allow(unreachable_patterns)]
    _ => {}
}
```

## Why the `cfg` shape had to go, and what went with it

The compiled-out shape wrote the *complement* of the owning draft:

```rust
    #[cfg(any(feature = "draft07", ..., feature = "draft19"))]
    _ => {}
```

**That list was written by copying the previous draft's module**, and a copy
names one draft too few: the predecessor, whose name the new module took.
`draft20`'s lists were copied from `draft19`'s and ran `draft07` through
`draft18`, so a build enabling draft19 and draft20 and not draft18 compiled the
wildcard out and the match went non-exhaustive. Five sites in `draft20`, plus
three in `draft11` through `draft13` that never gained `draft20`.

**Nothing in a single-draft build could see that.** The failure needs two
drafts, one of them missing from the list, and the CI sweep compiles one draft
at a time. The two-draft row it runs is `draft07,draft20`, and `draft07` is the
first entry of every defective list. Adding rows does not scale either: there
are 91 pairs of fourteen drafts and the defect can hide in any of them. So this
script read the lists instead — it compiles nothing, needs no toolchain, and
covered every pair at once.

The forty-one lists in `moqtap-client/src/draftNN/connection.rs` have since
been replaced by the `#[allow(unreachable_patterns)]` form, which is total
under all 2^14 feature sets and needs no edit when a draft is added. **That
conversion also deleted a signal**, and rule 2 below is what replaces it: the
old list, wrong as it usually was, at least had to be looked at once per draft.
The new form never has to be looked at at all, which is the point and also the
risk — a fifteenth draft's module that simply *lacks* one of these arms, because
whoever copied it dropped a function, is now invisible to the compiler under
every feature set including `all-drafts`.

## Rule 1 — the `cfg` lists that remain

Every `#[cfg(any(...))]` under `crates/` whose condition is **only**
`feature = "draftNN"` terms. A `cfg` that mixes in anything else — a target,
another crate feature, a `not(...)` — is a different thing and is left alone.

The owning draft comes from the path when there is one: a file under
`src/draftNN/` rejects the other thirteen, and which thirteen is not a guess.

**A draft-neutral file can hold one too**, and one did: a `moqtap-proxy` test
asserts a draft-19 header inside a `#[cfg(feature = "draft19")]` block and
rejects the rest with the same kind of arm, whose list ran to draft-18. The path
says nothing there, so the count does. A complete rejection list names thirteen
of the fourteen drafts; a list naming **twelve** is a rejection list with a
draft missing, because no deliberate subset stops one short of all-but-one. The
workspace bears that out — of the lists naming eleven or more, the elevens are a
real feature boundary (the authorization token, which exists from draft-10), the
fourteens are "any draft at all", the thirteens are rejection lists, and the
only twelve was the defect. So twelve is reported wherever it appears, and the
message names both omissions rather than guessing which was the owner.

**A crate that holds none of these is said so out loud.** Reporting `checked 0`
and passing is how a gate goes blind when the construct it watches is renamed
or moved, so the per-crate tally is printed whether or not it is zero.

## Rule 2 — the replacement, and the arithmetic that guards it

For every per-draft module the tree actually contains, count the
`#[allow(unreachable_patterns)]` arms. The population is **derived from the
directory names**, never written down here, for the reason
`scripts/check-drafts.py:274-289` sets out at length: a hardcoded draft list
narrows silently when a fourteenth draft lands, and the guards that ask
`in DRAFTS` then drop what they cannot place rather than reporting it.

Then require the count to be **non-decreasing from one draft to the next**
inside each crate. Today, in `moqtap-client/src`:

    07-10: 1    11-13: 2    14-15: 3    16: 5    17-20: 6

Each step up is a real one — draft-11 gated extension headers on the stream
type, draft-14 moved the subgroup object reader into the header, draft-16 added
request streams, draft-17 split the control plane. None of them ever goes back
down, because a draft's module is copied from its predecessor's and then
extended. **A drop is therefore a lost arm, not a simplified draft**, and it is
exactly the omission the old `cfg` list existed to catch.

A draft that genuinely retires a construct is possible and would fail here.
That is intended: add the draft to `ACKNOWLEDGED_DROPS` with the reason, so the
next reader sees a decision rather than a hole. The table is empty today.

Rule 2 is arithmetic over shapes, not semantics — it cannot tell a *correct*
arm from an incorrect one. The compile-side gate for that is one matrix row per
draft, built alone, `--all-targets` under `RUSTFLAGS="-D warnings"`, which is
what rustc reports when a construct is reachable from only one draft.

Exit status is 1 if any list is short, if any draft module has lost an arm, or
if a converted module has grown a new `cfg` rejection list.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRATES = ROOT / "crates"

#: Drafts that legitimately hold fewer rejection arms than their predecessor,
#: as `("crate-name", "draftNN"): "why"`. Empty, and it should stay that way
#: until a draft removes a construct on purpose.
ACKNOWLEDGED_DROPS: dict[tuple[str, str], str] = {}

#: The fewest drafts the tree may contain before this script is asked to
#: believe its own derivation. Below this the directory scan has gone wrong —
#: a bad root, a partial checkout — and passing would be a false pass.
MINIMUM_DRAFTS = 10

#: A `cfg(any(...))` whose whole condition is `feature = "draftNN"` terms.
CFG = re.compile(r'#\[cfg\(any\(((?:\s*feature\s*=\s*"draft\d\d"\s*,?)+)\s*\)\)\]')
FEATURE = re.compile(r'feature\s*=\s*"(draft\d\d)"')
DRAFT_DIR = re.compile(r"draft\d\d")
ALLOW = re.compile(r"#\[allow\(unreachable_patterns\)\]")


def owning_draft(path: Path) -> str | None:
    """The draft whose module `path` lives in, or `None` for a neutral file."""
    for part in path.parts:
        if DRAFT_DIR.fullmatch(part):
            return part
    return None


def implemented_drafts() -> list[str]:
    """Every draft the tree has a module for, derived from the directories.

    Deliberately not a constant: see the module docstring, and
    `scripts/check-drafts.py:274-289` for the failure this avoids.
    """
    found = set()
    for crate in sorted(CRATES.iterdir()):
        src = crate / "src"
        if not src.is_dir():
            continue
        for child in src.iterdir():
            if child.is_dir() and DRAFT_DIR.fullmatch(child.name):
                found.add(child.name)
    return sorted(found)


def rule_1_cfg_lists(all_drafts: list[str]) -> tuple[dict[str, int], list[str]]:
    """The surviving `cfg` rejection lists, per crate."""
    per_crate: dict[str, int] = {c.name: 0 for c in sorted(CRATES.iterdir()) if c.is_dir()}
    failures: list[str] = []

    for path in sorted(CRATES.glob("**/*.rs")):
        if "target" in path.parts:
            continue
        rel = path.relative_to(CRATES)
        crate = rel.parts[0]
        owner = owning_draft(rel)
        text = path.read_text(encoding="utf-8")
        for match in CFG.finditer(text):
            named = FEATURE.findall(match.group(1))
            line = text.count("\n", 0, match.start()) + 1
            where = f"{path.relative_to(ROOT).as_posix()}:{line}"

            if owner is not None:
                per_crate[crate] += 1
                expected = [d for d in all_drafts if d != owner]
                missing = [d for d in expected if d not in named]
                if missing:
                    failures.append(
                        f"{where}: the {owner} rejection list omits "
                        f"{', '.join(missing)}: a build enabling {owner} and "
                        f"{missing[0]} compiles this arm out and the match is "
                        f"non-exhaustive"
                    )
                if owner in named:
                    failures.append(
                        f"{where}: the {owner} rejection list names {owner} "
                        f"itself, so the arm is compiled in when this draft is "
                        f"the only one enabled and is then unreachable"
                    )
                failures.append(
                    f"{where}: a per-draft module has grown a `cfg` rejection "
                    f"list again. These were replaced by "
                    f"`#[allow(unreachable_patterns)]`, which is total under "
                    f"every feature set; a `cfg` here has to be maintained in "
                    f"all {len(all_drafts)} modules and is silent when it is not"
                )
                continue

            # A draft-neutral file. The path names no owner, so the count is
            # what says this is a rejection list: thirteen is complete, twelve
            # is one short. See the module docstring for why nothing else
            # lands on twelve.
            if len(named) == len(all_drafts) - 1:
                per_crate[crate] += 1
            elif len(named) == len(all_drafts) - 2:
                per_crate[crate] += 1
                missing = [d for d in all_drafts if d not in named]
                failures.append(
                    f"{where}: this list names {len(named)} drafts, one short "
                    f"of a rejection list. It omits {' and '.join(missing)}; "
                    f"one of those is the draft the arm rejects *for*, and the "
                    f"other is missing, so a build enabling both leaves the "
                    f"match non-exhaustive"
                )

    return per_crate, failures


def rule_2_allow_arms(all_drafts: list[str]) -> tuple[dict[str, dict[str, int]], list[str]]:
    """The always-compiled arms, counted per crate and draft."""
    counts: dict[str, dict[str, int]] = {}
    failures: list[str] = []

    for crate in sorted(CRATES.iterdir()):
        src = crate / "src"
        if not src.is_dir():
            continue
        present = {d: src / d for d in all_drafts if (src / d).is_dir()}
        if not present:
            continue
        counts[crate.name] = {}
        for draft, directory in present.items():
            n = 0
            for path in sorted(directory.glob("**/*.rs")):
                n += len(ALLOW.findall(path.read_text(encoding="utf-8")))
            counts[crate.name][draft] = n

        ordered = [d for d in all_drafts if d in present]
        for previous, draft in zip(ordered, ordered[1:]):
            before, after = counts[crate.name][previous], counts[crate.name][draft]
            if after >= before:
                continue
            if (crate.name, draft) in ACKNOWLEDGED_DROPS:
                continue
            failures.append(
                f"{crate.name}/src/{draft}: {after} always-compiled rejection "
                f"arm(s) against {previous}'s {before}. A draft module is "
                f"copied from its predecessor and extended, so an arm that "
                f"exists for {previous} and not for {draft} is one that was "
                f"dropped in the copy, and nothing else in the tree reports "
                f"it, because the arm is not required to compile. Restore it, "
                f"or record why {draft} does not need it in "
                f"ACKNOWLEDGED_DROPS in this script"
            )

    return counts, failures


def main() -> int:
    if not CRATES.is_dir():
        print(f"no crates directory at {CRATES}", file=sys.stderr)
        return 2

    all_drafts = implemented_drafts()
    if len(all_drafts) < MINIMUM_DRAFTS:
        print(
            f"derived only {len(all_drafts)} draft module(s) from {CRATES} "
            f"({', '.join(all_drafts) or 'none'}); expected at least "
            f"{MINIMUM_DRAFTS}. Refusing to pass on a derivation this small.",
            file=sys.stderr,
        )
        return 2
    print(f"{len(all_drafts)} drafts derived from the tree: {all_drafts[0]}..{all_drafts[-1]}")

    per_crate, cfg_failures = rule_1_cfg_lists(all_drafts)
    allow_counts, allow_failures = rule_2_allow_arms(all_drafts)

    print("\nrule 1 - `cfg` rejection lists, per crate")
    for crate, n in sorted(per_crate.items()):
        if n:
            print(f"  {crate}: {n} list(s), each required to name {len(all_drafts) - 1} drafts")
        else:
            print(f"  {crate}: none - the construct is not present in this crate")

    print("\nrule 2 - always-compiled rejection arms, per draft module")
    if not allow_counts:
        print("  no crate has per-draft modules; nothing to compare")
    for crate, drafts in sorted(allow_counts.items()):
        row = "  ".join(f"{d[-2:]}:{n}" for d, n in drafts.items())
        print(f"  {crate}: {row}")

    failures = cfg_failures + allow_failures
    for failure in failures:
        print(f"\n  {failure}")
    if failures:
        print(f"\n{len(failures)} problem(s)")
        return 1
    print("\nevery surviving list is complete, and no draft module has lost an arm")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
