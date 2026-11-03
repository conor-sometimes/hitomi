#!/usr/bin/env bash
# mksuite.sh - generate hitomi's detection-accuracy suite.
#
#   should-pass/ : N files that MUST be detected (random data with EICAR embedded
#                  at a varying offset, so a match is found wherever it sits)
#   should-fail/ : N files that MUST NOT be detected (random data, no signature)
#
# run-suite.sh then asserts the invariant: 100% of should-pass detected, 0% of
# should-fail. Generated at runtime and gitignored - these files contain EICAR,
# so they are never committed.
#
# Usage: mksuite.sh [N] [outdir]   (default: N=1000, outdir=./out beside this script)
set -euo pipefail
n="${1:-1000}"
out="${2:-$(cd "$(dirname "$0")" && pwd)/out}"
pass="$out/should-pass"
fail="$out/should-fail"
rm -rf "$pass" "$fail"
mkdir -p "$pass" "$fail"

# EICAR split so this script file is not itself a hit.
a='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STAND'
b='ARD-ANTIVIRUS-TEST-FILE!$H+H*'
eicar="$a$b"

for i in $(seq 1 "$n"); do
	# should-pass: random prefix + EICAR + random suffix. The signature lands at a
	# different offset each time, so the scanner must find it anywhere, not just at 0.
	{ head -c "$((RANDOM % 4096))" /dev/urandom; printf '%s' "$eicar"; head -c "$((RANDOM % 4096))" /dev/urandom; } > "$pass/pass-$i.bin"
	# should-fail: random only. A 34-char exact EICAR substring never occurs by chance.
	head -c "$((256 + RANDOM % 8192))" /dev/urandom > "$fail/fail-$i.bin"
done

echo "generated $n should-pass + $n should-fail files in $out"
