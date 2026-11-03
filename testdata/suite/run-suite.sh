#!/usr/bin/env bash
# run-suite.sh - run hitomi over the accuracy suite and assert the invariant:
# every should-pass file is detected, no should-fail file is. Exit 0 only if both
# hold (100% true positives, 0% false positives).
#
# hitomi's scan CLI emits a yara/1 line on a match and nothing on a clean file,
# so "produced output" means "detected". This is the designed interface; when the
# scan binary is built it runs here and in CI/the matrix unchanged.
#
# Usage: run-suite.sh <hitomi-binary> <rules-dir> [suite-outdir]
set -uo pipefail
hitomi="${1:?usage: run-suite.sh <hitomi-binary> <rules-dir> [outdir]}"
rules="${2:?usage: run-suite.sh <hitomi-binary> <rules-dir> [outdir]}"
out="${3:-$(cd "$(dirname "$0")" && pwd)/out}"

miss=0 fp=0 np=0 nf=0

for f in "$out/should-pass"/*; do
	np=$((np + 1))
	if ! "$hitomi" scan --rules "$rules" "$f" | grep -q .; then
		echo "MISS (should-pass not detected): $f"
		miss=$((miss + 1))
	fi
done

for f in "$out/should-fail"/*; do
	nf=$((nf + 1))
	if "$hitomi" scan --rules "$rules" "$f" | grep -q .; then
		echo "FALSE POSITIVE (should-fail detected): $f"
		fp=$((fp + 1))
	fi
done

echo "should-pass: $((np - miss))/$np detected ($miss missed)"
echo "should-fail: $((nf - fp))/$nf clean ($fp false positives)"
if [ "$miss" -eq 0 ] && [ "$fp" -eq 0 ]; then
	echo "SUITE PASS"
	exit 0
fi
echo "SUITE FAIL"
exit 1
