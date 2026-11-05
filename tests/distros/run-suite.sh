#!/usr/bin/env bash
# The hitomi accuracy suite on this distro: scan every sample with the shipped
# binary and rules, and require 100% true positives and 0% false positives.
# Malicious samples live under /opt/suite/malicious, clean ones under
# /opt/suite/clean (hitomi's own testdata/suite layout). Exit 0 only on a clean
# sweep; any missed detection or any false positive fails the distro.
set -uo pipefail

RULES=/etc/hitomi/rules
mal=/opt/suite/malicious
clean=/opt/suite/clean

scan() { hitomi scan --rules "$RULES" "$1" >/dev/null 2>&1; }  # exit 0 = matched

fn=0 # false negatives (missed malicious)
fp=0 # false positives (flagged clean)

for f in "$mal"/*; do
  [ -e "$f" ] || continue
  if ! scan "$f"; then echo "MISS (false negative): $f"; fn=$((fn+1)); fi
done
for f in "$clean"/*; do
  [ -e "$f" ] || continue
  if scan "$f"; then echo "FALSE POSITIVE: $f"; fp=$((fp+1)); fi
done

. /etc/os-release
echo "hitomi suite on ${PRETTY_NAME}: false negatives=$fn, false positives=$fp"
[ "$fn" -eq 0 ] && [ "$fp" -eq 0 ]
