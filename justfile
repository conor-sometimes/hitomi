# The yara sensor's gate -- the banken bar, mimi's shape. `just` lists targets; `just default` runs
# the whole thing. Runs on the stable toolchain (rust-toolchain.toml); in the lane this is run
# inside `nix develop` on hokkaido (there is no nix on the Mac).

default: fmt-check clippy charter test deny

# Format (write locally; check in CI).
fmt:
    cargo fmt
fmt-check:
    cargo fmt --check

# Lints as errors across the workspace: the wire schema and the engine. Unlike mimi there is no
# eBPF/flake toolchain barrier, so the engine crate is linted in the default gate, not a separate
# job.
clippy:
    cargo clippy --workspace --all-targets -- -D warnings

# Unit tests of the whole workspace: the shared schema's render/parse logic and the engine's
# load/scan/event path (no kernel, no fanotify).
test:
    cargo test --workspace

# The listener charter, mechanically enforced (design 3.2): fail the build if a permission class or
# an `_PERM` mask appears in code (outside the comments that explain the ban). hitomi is a listener,
# never an enforcer -- a dead sensor must never delay an exec. This is the counterpart of mimi's
# `bpf_send_signal` ban.
charter:
    bash ci/listener-charter-gate.sh

# Supply-chain gate: advisories, licenses, sources (deny.toml). The fuzz crate is its own workspace
# (cargo-fuzz builds it with special flags), so gate it explicitly too -- the instrumented build
# must not be the one place with a floating dependency.
deny:
    cargo deny check
    cargo deny --manifest-path fuzz/Cargo.toml check

# The sensor<->brain contract: render(sample) must still equal the shared golden that banken parses
# from its side (`just contract` there). The two repos' testdata/yara_event.golden.jsonl must stay
# byte-identical, so a schema change has to move both halves of the family.
contract:
    cargo test -p yara-types golden

# The dependency tree -- the audit surface, in one place.
tree:
    cargo tree -e normal

# Fuzz a target (`fuzz_scan` or `fuzz_parse`) for a bounded time. Needs cargo-fuzz and a nightly
# rustc on PATH (the sanitizer and coverage instrumentation are nightly-only); in the lane this is
# an `agent-job` on hokkaido, not a CI gate. The live corpus grows under fuzz/corpus/<target>
# (gitignored); the committed seeds under fuzz/seeds/<target> prime it. A crash writes a
# reproducer to fuzz/artifacts/<target> (gitignored) and stops.
fuzz target='fuzz_scan' seconds='60':
    cargo fuzz run {{target}} fuzz/corpus/{{target}} fuzz/seeds/{{target}} -- -max_total_time={{seconds}}

# Point git at the repo's tracked hooks (core.hooksPath): no AI attribution in commit messages,
# no em/en dashes in messages or staged content. Run once after cloning.
install-hooks:
    git config core.hooksPath .githooks
    @echo "core.hooksPath -> .githooks"
