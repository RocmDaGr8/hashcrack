#!/usr/bin/env bash
# HashCrack demo — generate a few hashes, then identify and crack them.
set -e

WL="wordlists/common.txt"

PLAIN=$(python3 -c "import hashlib; print(hashlib.md5(b'dragon').hexdigest())")
RULES=$(python3 -c "import hashlib; print(hashlib.sha256(b'Dragon123').hexdigest())")

echo ">>> Identifying an MD5 hash"
python3 -m hashcrack identify "$PLAIN"

echo ">>> Plain dictionary attack (MD5 of 'dragon')"
python3 -m hashcrack crack "$PLAIN" -w "$WL" --quiet || true

echo ">>> Rule-based attack (SHA-256 of 'Dragon123', derived from base word 'dragon')"
python3 -m hashcrack crack "$RULES" -w "$WL" --rules --quiet || true
