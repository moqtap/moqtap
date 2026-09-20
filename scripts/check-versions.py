#!/usr/bin/env python3
"""Check this workspace's release numbers against crates.io.

Three facts about version numbers that no compiler, linter or test suite in this
repository can observe, because none of them changes an exit code until
`cargo publish` runs — by which point the number is in the registry forever.

1. **A `[workspace.dependencies]` pin must equal the member's own version.**
   Inside the workspace a path dependency resolves by path and the `version`
   field is never consulted, so a wrong number builds, tests and lints
   perfectly. `cargo publish` then writes it into the published manifest as a
   requirement on a version that may not exist. `moqtap-trace` was pinned at
   `0.2.0` against a `0.1.0` crate for the whole of this project's history
   without a single gate noticing, because nothing declared
   `moqtap-trace = { workspace = true }`.

2. **A crate sitting at an already-published version must have nothing under
   `## [Unreleased]`.** Equalling the published version is the correct state
   for a crate with no new work in it, and the wrong one for a crate carrying
   changes: those changes then have no number, and whoever assigns one later is
   guessing which release they belong to. `moqtap-client` sat at `0.3.0` —
   live on crates.io — while carrying three breaking changes.

   The heading itself is part of the rule. A changelog with no
   `## [Unreleased]` at all cannot answer the question either way, so it is an
   error rather than a pass — otherwise deleting one line silences this rule
   for good, and the state it leaves behind is a *green* line asserting
   something nothing checked.

3. **A crate sitting at an already-published version must have the same `src/`
   and the same `Cargo.toml` as the published one.** Rule 2 asks the changelog
   whether there is unreleased work, so a change nobody wrote down answers *no*
   and passes.
   That is not a hypothetical: `moqtap-trace` sat at `0.1.0` — live on
   crates.io — having gained a public field on a public enum variant, with an
   empty `## [Unreleased]`, and rules 1 and 2 were both green. The check was
   asking the record rather than the code, and the record was silent.

   So rule 3 asks the code. It downloads the published `.crate` for the
   version the tree claims and compares every `src/**/*.rs` against the
   working tree — and the manifest with them, against the tarball's
   `Cargo.toml.orig`, because a feature added at a published version is a
   change to the public API that no file under `src/` records.

   **It is a source comparison, not a semantic one, and it is deliberately the
   blunter instrument.** It flags a comment fix as loudly as a renamed
   function, and that is the intended behaviour rather than a limitation
   tolerated: a crate at a published version should have *nothing* uncommitted
   to a release, and asking "did anything change" needs no parser to get
   wrong. A tool that diffs the public API — `cargo public-api` — answers the
   narrower question more precisely, at the cost of a nightly toolchain and an
   installed binary this script otherwise does not need. If the noise ever
   becomes the problem, that is the upgrade path; today the noise *is* the
   signal, because every one of these crates is meant to be quiet at a
   published version.

   Rules 2 and 3 are a pair and neither subsumes the other: rule 3 catches a
   change with no changelog entry, rule 2 catches a changelog entry with no
   number.

The failure these rules exist to prevent has already happened here in a
fourth form. `moqtap-proxy`'s changelog had no `0.3.0` section while `0.3.0` was
the published version, later work read the missing section as a missing
release, and the next version was numbered `0.5.0` on that basis. Hence the
error text: take the next number from the registry, not from the changelog.

**Rules 2 and 3 go red immediately after a release, and that is the design.** The
moment `proxy-v0.4.0` reaches crates.io, the tree still says `0.4.0` with the
release's notes still sitting under `## [Unreleased]` — which is exactly the
state rule 2 describes, and the tree's sources are the ones just published only
until the next commit touches them. Clearing rule 2 is one edit: move that
section under `## [0.4.0] - <date>`. Clearing rule 3 is the next version bump.
The alternative is a window in which the next change is silently attributed to a
release that already shipped, so the red is the reminder, not a false positive.

Needs the network, and fails closed if crates.io is unreachable. An
unverifiable version is not a verified one.
"""

import io
import json
import re
import subprocess
import sys
import tarfile
import urllib.error
import urllib.request

USER_AGENT = "moqtap-ci (github.com/moqtap/moqtap)"


def members():
    """Every publishable workspace member, as `(name, version)`."""
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [
        (p["name"], p["version"])
        for p in json.loads(out)["packages"]
        # `publish = false` in a member manifest shows up here as an empty
        # list. Such a crate can hold any version it likes.
        if p.get("publish") != []
    ]


def workspace_pin(root_manifest, name):
    """The `version` in this crate's `[workspace.dependencies]` entry, if any."""
    tail = root_manifest.split("[workspace.dependencies]", 1)
    if len(tail) < 2:
        return None
    body = re.split(r"\n\[", tail[1])[0]
    entry = re.search(r'^\s*%s\s*=\s*\{([^}]*)\}' % re.escape(name), body, re.M)
    if not entry:
        return None
    version = re.search(r'version\s*=\s*"([^"]+)"', entry.group(1))
    return version.group(1) if version else None


NO_CHANGELOG = object()
NO_SECTION = object()


def unreleased_body(name):
    """Whatever sits under `## [Unreleased]` in this crate's changelog.

    Three failure states, and they were once one. `NO_CHANGELOG` means the file
    is missing; `NO_SECTION` means the file has no `## [Unreleased]` heading at
    all. Both are cases where rule 2 *cannot be answered*, and collapsing either
    into `""` makes this function report "nothing unreleased" about a crate it
    never examined — which is a worse failure than the one rule 2 catches,
    because it is a green line rather than a missing one. `moqtap-client` and
    `moqtap-proxy` were both in the second state while carrying hundreds of
    lines of unreleased work.

    The empty string keeps its meaning: the heading is there and nothing is
    under it, which is the one state that genuinely passes.
    """
    path = "crates/%s/CHANGELOG.md" % name
    try:
        text = open(path, encoding="utf-8").read()
    except OSError:
        return NO_CHANGELOG
    # `\Z` as well as the next heading: `## [Unreleased]` is often the *last*
    # `##` in a changelog — a crate with no released sections yet, or one whose
    # link references sit under a different heading level. Without it the
    # lookahead fails, the search returns nothing, and a section full of
    # unreleased work reads as an absent one.
    section = re.search(
        r"^## \[Unreleased\][^\n]*\n(.*?)(?=^## |\Z)", text, re.M | re.S
    )
    return section.group(1).strip() if section else NO_SECTION


def published_versions(name):
    """Every version of `name` on crates.io, or `None` if the crate is new.

    Raises on anything that is not a clean answer, so the caller fails closed.
    """
    req = urllib.request.Request(
        "https://crates.io/api/v1/crates/%s" % name,
        headers={"User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return [v["num"] for v in json.load(response).get("versions", [])]
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def normalize(text):
    """Strip the differences that are about storage rather than about code.

    Line endings, because this repository is checked out with CRLF on Windows
    while a `.crate` tarball always carries LF, and a whole-file mismatch on
    every line would make rule 3 useless on half the machines that run it.
    Trailing whitespace, for the same reason at the end of a line. A final
    newline, because `cargo package` adds one and an editor may not.
    """
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    return "\n".join(line.rstrip() for line in lines).rstrip("\n")


def published_files(name, version):
    """The published `.crate`'s comparable files, as `{path: normalized text}`.

    `src/**/*.rs`, plus `Cargo.toml` — taken from the tarball's
    `Cargo.toml.orig`, which is the manifest as written. The tarball's own
    `Cargo.toml` is cargo's normalized rewrite of it (path dependencies
    resolved to versions, workspace inheritance flattened, keys reordered) and
    would never match a working tree verbatim.

    **The manifest is compared because a published feature list is as much
    public API as a `pub fn`.** Rule 3 read only `src/` for its whole history,
    so `moqtap-client` could gain a `wt-protocol` feature at an already-published
    `0.5.0` and every rule here stay green on that account. It happened.

    Raises on anything that is not a clean answer, so the caller fails closed —
    an unreadable tarball is not evidence that the sources match.
    """
    req = urllib.request.Request(
        "https://crates.io/api/v1/crates/%s/%s/download" % (name, version),
        headers={"User-Agent": USER_AGENT},
    )
    with urllib.request.urlopen(req, timeout=60) as response:
        payload = response.read()

    out = {}
    # The tarball's single top-level directory is `<name>-<version>/`; strip it
    # so the keys match the working tree's `src/...` relative paths.
    prefix = "%s-%s/" % (name, version)
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            path = member.name
            if not path.startswith(prefix):
                continue
            path = path[len(prefix):]
            if path == "Cargo.toml.orig":
                path = "Cargo.toml"
            elif not path.startswith("src/") or not path.endswith(".rs"):
                continue
            handle = tar.extractfile(member)
            if handle is None:
                continue
            out[path] = normalize(handle.read().decode("utf-8"))
    return out


def tree_files(name):
    """The same shape, read from `crates/<name>`."""
    import os

    base = os.path.join("crates", name)
    out = {}
    for dirpath, _dirnames, filenames in os.walk(os.path.join(base, "src")):
        for filename in filenames:
            if not filename.endswith(".rs"):
                continue
            full = os.path.join(dirpath, filename)
            key = os.path.relpath(full, base).replace(os.sep, "/")
            out[key] = normalize(open(full, encoding="utf-8").read())
    manifest = os.path.join(base, "Cargo.toml")
    if os.path.exists(manifest):
        out["Cargo.toml"] = normalize(open(manifest, encoding="utf-8").read())
    return out


def source_drift(name, version):
    """Files that differ between the published crate and the working tree.

    Returns a sorted list of `(path, why)`. Empty means the tree is the
    published crate. `None` means the published tarball carried no `src/*.rs`
    at all, which is a fact about that crate's packaging rather than a pass —
    the caller reports it rather than counting it as agreement.
    """
    published = published_files(name, version)
    # Deliberately `src/`, not `published`: a tarball always carries a manifest,
    # so counting it here would turn the "nothing to compare" case into a
    # comparison of one file and report agreement the sources never showed.
    if not any(path.startswith("src/") for path in published):
        return None
    tree = tree_files(name)

    drift = []
    for path in sorted(set(published) | set(tree)):
        if path not in tree:
            drift.append((path, "published, absent from the tree"))
        elif path not in published:
            drift.append((path, "in the tree, not in the published crate"))
        elif published[path] != tree[path]:
            drift.append((path, "differs"))
    return drift


def main():
    root = open("Cargo.toml", encoding="utf-8").read()
    crates = members()
    failed = False

    for name, version in crates:
        pin = workspace_pin(root, name)
        if pin is not None and pin != version:
            print(
                "::error::[workspace.dependencies] pins %s at %s; the crate "
                "itself is %s. Nothing but `cargo publish` reads that number, "
                "so no build, test or lint here will ever disagree with it."
                % (name, pin, version)
            )
            failed = True
        else:
            print("%-16s %-8s pin: %s" % (name, version, pin or "none"))

    print()

    for name, version in crates:
        try:
            published = published_versions(name)
        except Exception as e:  # noqa: BLE001 — network, DNS, TLS, malformed JSON
            print("::error::%s: could not reach crates.io (%s)" % (name, e))
            failed = True
            continue

        if published is None:
            print("%-16s %-8s not on crates.io yet" % (name, version))
            continue

        if version not in published:
            print(
                "%-16s %-8s unpublished (registry has %s)"
                % (name, version, ", ".join(published))
            )
            continue

        unreleased = unreleased_body(name)
        if unreleased is NO_CHANGELOG:
            print(
                "::error::%s is publishable and has no crates/%s/CHANGELOG.md, "
                "so whether %s carries unreleased work cannot be answered."
                % (name, name, version)
            )
            failed = True
        elif unreleased is NO_SECTION:
            print(
                "::error::%s is at %s, which is already on crates.io, and its "
                "changelog has no `## [Unreleased]` heading — so whether it "
                "carries unreleased work cannot be answered. Add the heading. "
                "An absent section and an empty one are the same green line "
                "otherwise, and deleting the heading at release time is the "
                "one edit that would silence this rule permanently."
                % (name, version)
            )
            failed = True
        elif unreleased:
            print(
                "::error::%s is at %s, which is already on crates.io, and its "
                "changelog has unreleased content under it: %r... Those changes "
                "have no version number. Take the next one from the registry "
                "rather than from the changelog — a published release with no "
                "section in CHANGELOG.md reads exactly like a release that "
                "never happened."
                % (name, version, unreleased.splitlines()[0][:70])
            )
            failed = True
        else:
            print(
                "%-16s %-8s published, nothing unreleased under it"
                % (name, version)
            )

        # Rule 3. Run whatever rule 2 concluded: a crate can perfectly well
        # have an empty `## [Unreleased]` *and* changed sources, and that pair
        # is the exact state this rule exists to catch. Skipping it after a
        # rule 2 failure would hide the more serious of the two.
        try:
            drift = source_drift(name, version)
        except Exception as e:  # noqa: BLE001 — network, TLS, tarfile, encoding
            print(
                "::error::%s: could not read the published %s sources (%s). "
                "An unverifiable source comparison is not a passing one."
                % (name, version, e)
            )
            failed = True
            continue

        if drift is None:
            print(
                "%-16s %-8s the published crate carries no src/*.rs to compare"
                % (name, version)
            )
        elif drift:
            listing = "; ".join("%s (%s)" % (p, why) for p, why in drift[:6])
            more = "" if len(drift) <= 6 else " and %d more" % (len(drift) - 6)
            print(
                "::error::%s is at %s, which is already on crates.io, and its "
                "sources are not the published ones: %s%s. Either those changes "
                "belong to the next version — bump it and write the changelog "
                "entry — or they should not be here. A crate at a published "
                "version whose code has moved is a release nobody can reproduce "
                "from the registry."
                % (name, version, listing, more)
            )
            failed = True
        else:
            print(
                "%-16s %-8s and its sources are the published ones"
                % (name, version)
            )

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
