#!/usr/bin/env bash
# The listener-charter gate (design docs/design/yara-sensor.md sections 3.2, 9).
#
# hitomi is a LISTENER, never an enforcer: a dead, slow, or full sensor must never delay an exec by
# a nanosecond, because the kernel is never waiting for it to answer. fanotify offers that power --
# the permission event classes and the permission ("_PERM") masks let a listener VETO an open, which
# is what a blocking antivirus uses. This sensor must never reach for them. This gate is the written,
# mechanical counterpart of mimi's ban on bpf_send_signal: it greps the Rust sources for the tokens
# that would make hitomi an enforcer and FAILS THE BUILD if any appears in code.
#
# The tokens are allowed to appear in COMMENTS (the module docs in src/fanotify.rs explain exactly
# why they are banned, and must be free to name them), so this strips // line comments before
# grepping. A match in real code -- a `use`, a constant, a call -- fails.
#
# Run by `just charter` and by CI. Exit 0 = clean (listener-only); exit 1 = a banned token in code.
set -euo pipefail

# Resolve the repo root from this script's location, so it runs the same from any cwd (justfile, CI).
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# The banned tokens. `_PERM` catches every permission mask (FAN_OPEN_EXEC_PERM, FAN_ACCESS_PERM,
# FAN_OPEN_PERM, ...); the two class names catch the permission (blocking) notification classes.
banned_regex='_PERM|FAN_CLASS_CONTENT|FAN_CLASS_PRE_CONTENT'

# Every Rust source (crate code, tests, fuzz targets). fuzz/ is a separate workspace but is still
# hitomi's source and held to the same charter. Prefer `git ls-files` (tracked files only), but fall
# back to `find` when the tree is not a git checkout -- e.g. an rsync'd build copy on the build host,
# where a `git ls-files` that silently listed nothing would be a false pass. A while-read loop (not
# `mapfile`) so the gate runs under the old bash 3.2 on a dev Mac as well as bash 5 in CI.
list_rs_files() {
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        git ls-files '*.rs'
    else
        find . -type f -name '*.rs' -not -path './target/*' | sed 's;^\./;;'
    fi
}

scanned=0
fail=0
while IFS= read -r f; do
    [ -n "$f" ] || continue
    scanned=$((scanned + 1))
    # Strip from the first // to end of line (covers //, ///, //!), then look for a banned token in
    # what remains -- i.e. in code, not in the comments that explain the ban.
    if sed 's;//.*$;;' "$f" | grep -nE "$banned_regex" >/dev/null; then
        echo "LISTENER-CHARTER VIOLATION: a permission/enforcer token appears in code in $f:" >&2
        sed 's;//.*$;;' "$f" | grep -nE "$banned_regex" | sed "s;^;  $f: ;" >&2
        fail=1
    fi
done < <(list_rs_files)

# A gate that scanned nothing is not a pass: refuse rather than wave the build through.
if [ "$scanned" -eq 0 ]; then
    echo "listener-charter gate: found no .rs files to scan (wrong directory?)" >&2
    exit 1
fi

if [ "$fail" -ne 0 ]; then
    echo "" >&2
    echo "hitomi is listener-only: FAN_CLASS_NOTIF and non-permission masks only (design 3.2)." >&2
    echo "If you genuinely need one of these, you are building an enforcer -- that is a different" >&2
    echo "sensor behind its own option, not this one. The gate stands." >&2
    exit 1
fi

echo "listener-charter gate: OK ($scanned .rs files, no permission classes or _PERM masks in code)"
