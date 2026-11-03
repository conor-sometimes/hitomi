# the yara sensor (name TBD)

A **listener-only YARA content scanner**, the sibling of [mimi](https://github.com/conor-sometimes/mimi):
where mimi says *what a process did* over eBPF, this sensor says *what a file is* over YARA. It
subscribes to the kernel (fanotify) for "a file was executed" and "a file under a drop zone was
written", scans the exact inode the kernel hands it with [yara-x](https://github.com/VirusTotal/yara-x)
(pure Rust, interpreter mode, no JIT), hashes it, and emits one `yara/1` event per rule hit on a
stream [banken](https://github.com/conor-sometimes/banken) tails. It **never blocks an exec, never
acts, and never takes input from banken** -- the kernel is the only thing that drives it. Detection
and response are banken's job; this sensor reports a signature on an inode with the pid that touched
it, and stops.

The working name is "the yara sensor" throughout; the real name is deferred.

**Design:** [`../banken/docs/design/yara-sensor.md`](../banken/docs/design/yara-sensor.md) is the
authoritative spec (viability, the fanotify triggers, the engine decision, the Event mapping, the
unit, the matrix). Read it first.

## Status: step 1 of the build sequence

This repo is being built in the order of the design's section 12. **Only step 1 is here:** the wire
contract. The daemon, fanotify, the engine, the CLI and the NixOS module land in later steps.

| step | what | here? |
| --- | --- | --- |
| 1 | the `yara/1` wire contract + the shared golden | **yes** |
| 2 | the engine spike (yara-x + pulley, the canary, `scan --fd`) | no |
| 3 | the CLI and the quarantine verdict | no |
| 4 | the daemon: fanotify, cache, queue, sink | no |
| 5 | the one switch and the distro matrix stage | no |
| 6 | response wiring (`FileRef.SHA256`, `enforceSources`) | no |
| 7 | bench and the rule-set recipe | no |

### `yara-types` -- the wire schema

The one crate step 1 needs. It defines the Rust type for the `yara/1` match line (design section
5.1), renders it (`render`) and parses it (`parse`) with serde, and freezes the format against a
shared golden:

- `testdata/yara_event.golden.jsonl` is **byte-for-byte identical** to banken's copy at
  `internal/parser/testdata/yara_event.golden.jsonl`. That is the contract: this crate asserts
  `render(sample)` equals the golden, and banken asserts its parser reads exactly it, so the two
  repos cannot drift. `just contract` checks it on both sides; a schema change has to move both
  halves of the family.

## Build and test

There is no nix on the Mac; this is built and tested on a Linux host (hokkaido in the lane) like
mimi. `nix develop` gives a stable-Rust shell:

```sh
nix develop -c just          # fmt-check, clippy, test, deny
nix develop -c just contract # the shared-golden render test
nix build .#yara-types       # hermetic build + unit tests
```

## Dependencies

The mimi policy verbatim: every dep is audit surface, justified against the cost of auditing its
whole tree. Step 1 needs only `serde` + `serde_json` to render and parse the line. Exact pins
(`=x.y.z`), `Cargo.lock` committed, `cargo-deny` gates the tree (`just deny`), Dependabot proposes
bumps as PRs. The engine step adds `yara-x`, `sha2`, `libc`, `anyhow` and nothing else (design
section 8.1).

## Hooks

`just install-hooks` points `core.hooksPath` at `.githooks` (match style): no AI-attribution footer
in commit messages, no em/en dashes in messages or staged content.

## License

MIT (`LICENSE`). The engine (yara-x, BSD-3-Clause) and its wasmtime runtime (Apache-2.0 WITH
LLVM-exception) arrive in a later step; community rule sets are an operator opt-in, pinned by Nix,
never embedded (design section 6.3).
