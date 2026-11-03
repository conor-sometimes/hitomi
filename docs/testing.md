# hitomi testing

What we test, and how. Safe inputs only. Never real malware.

## Test corpus

- **EICAR** - the standard 68-byte antivirus test string. Every scanner matches it. We generate it at runtime and never commit it.
- **`test:eicar`** - a YARA rule, shipped with the tests, that matches EICAR.
- **Clean files** - real binaries plus a benign canary. These must NOT match. They are the true-negative check.

## Three levels

The harness runs at three levels, fast to slow.

1. **Engine** (unit, runs anywhere). The scan engine matches EICAR and misses the clean file. It also records per-scan time.
2. **Contract** (unit, runs anywhere). A scan of EICAR emits one `yara/1` line. banken's parser reads it. Both sides are pinned to the shared golden, so the wire format cannot drift.
3. **End-to-end** (VM). The daemon watches a directory. You drop EICAR. It scans, hashes, and emits. banken fires `yara_match`. If enforcement is armed, banken quarantines.

## Detection proof

The core claim: a real file hitting the watched path produces a real banken alert.

- Drop EICAR in a watched dir. `FAN_CLOSE_WRITE` fires.
- hitomi scans it, matches `test:eicar`, emits a `yara/1` line with the path, pid and SHA256.
- banken reads the line, fires `yara_match` (high).
- A clean file dropped the same way produces nothing.

## Enforcement proof

This is the one that matters. It is a NixOS VM test, the same shape as banken's `tests/response-enforce.nix`.

**Default (enforcement off):**

- Drop EICAR. banken alerts. The file is left untouched.

**Armed (enforcement on, hitomi in `enforceSources`, a policy on `test:eicar`):**

- Drop EICAR. banken quarantines it. `respond thaw` restores it.
- Execute an EICAR-matched file. banken kills the process on exec.

**Safety:**

- A benign file sitting beside EICAR is never touched. Zero collateral.

## In the distro matrix

hitomi gets its own column, like mimi's and Sysmon's: the sensor loads on the distro's own kernel, scans a dropped EICAR, and banken detects off its stream.

The exact shape is on hold. The VM matrix's attribution method is under review, so this column waits for that outcome rather than copying a method that may change.

## Fuzzing

hitomi meets the family's never-die bar (banken: 73.6M executions, zero crashes).

- **fuzz_scan** - compile a fixed ruleset once, then scan arbitrary bytes. The scanner must never panic on any file content. This is the main untrusted-input surface.
- **fuzz_parse** - feed arbitrary bytes to the `yara/1` parser. Never panic. A valid line round-trips.

Both run an obscene campaign, as a contract, not a one-off.
