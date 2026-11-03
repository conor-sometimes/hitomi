#!/usr/bin/env bash
# mkcorpus.sh - generate hitomi's YARA test corpus at runtime. Safe inputs only.
#
# We do NOT commit a live EICAR file. It trips antivirus on the committer's
# machine, in CI, and on the git host. So the EICAR string lives here SPLIT in
# two: this script file does not contain the contiguous signature, and the full
# string only exists on disk after you run this, in a gitignored output dir.
#
# Usage: mkcorpus.sh [outdir]   (default: ./out beside this script)
set -euo pipefail
out="${1:-$(cd "$(dirname "$0")" && pwd)/out}"
mkdir -p "$out"

# EICAR standard antivirus test string (68 bytes), split so this file is not a hit.
a='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STAND'
b='ARD-ANTIVIRUS-TEST-FILE!$H+H*'
eicar="$a$b"

# 1. the plain EICAR file: the canonical positive
printf '%s' "$eicar" > "$out/eicar.com"

# 2. extension/content mismatch: EICAR bytes behind a .pdf name (masquerade test)
printf '%s' "$eicar" > "$out/invoice.pdf"

# 3. EICAR appended to a larger real binary: scan coverage past the first bytes
if [ -r /bin/true ]; then cp /bin/true "$out/big.bin"; else head -c 1048576 /dev/urandom > "$out/big.bin"; fi
printf '%s' "$eicar" >> "$out/big.bin"

# 4. EICAR inside a zip: archive handling (skipped if zip is absent)
if command -v zip >/dev/null 2>&1; then ( cd "$out" && zip -q eicar.zip eicar.com ); fi

# 5. clean true-negatives: these must NEVER match
printf 'just a harmless text file, nothing to see here\n' > "$out/clean.txt"
if [ -r /bin/true ]; then cp /bin/true "$out/clean.bin"; fi

echo "corpus written to $out:"
ls -la "$out"
