# The yara sensor's gate -- the banken bar, mimi's shape. `just` lists targets; `just default` runs
# the whole thing. Runs on the stable toolchain (rust-toolchain.toml); in the lane this is run
# inside `nix develop` on hokkaido (there is no nix on the Mac).

default: fmt-check clippy test deny

# Format (write locally; check in CI).
fmt:
    cargo fmt
fmt-check:
    cargo fmt --check

# Lints as errors over the wire schema.
clippy:
    cargo clippy -p yara-types --all-targets -- -D warnings

# Unit tests of the shared schema + the render/parse logic (no engine, no kernel).
test:
    cargo test -p yara-types

# Supply-chain gate: advisories, licenses, sources (deny.toml).
deny:
    cargo deny check

# The sensor<->brain contract: render(sample) must still equal the shared golden that banken parses
# from its side (`just contract` there). The two repos' testdata/yara_event.golden.jsonl must stay
# byte-identical, so a schema change has to move both halves of the family.
contract:
    cargo test -p yara-types golden

# The dependency tree -- the audit surface, in one place.
tree:
    cargo tree -e normal

# Point git at the repo's tracked hooks (core.hooksPath): no AI attribution in commit messages,
# no em/en dashes in messages or staged content. Run once after cloning.
install-hooks:
    git config core.hooksPath .githooks
    @echo "core.hooksPath -> .githooks"
