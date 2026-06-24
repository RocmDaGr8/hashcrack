"""The dictionary / rule-based cracking engine."""

import hashlib
import sys
import time

from .rules import candidates


def hash_string(text, algo):
    """Hash a UTF-8 string with the named hashlib algorithm, return hex digest."""
    h = hashlib.new(algo)
    h.update(text.encode("utf-8"))
    return h.hexdigest()


def crack(target_hash, algo, words, use_rules=False, progress=True,
          progress_every=50000, out=sys.stderr):
    """Try candidates until one hashes to ``target_hash``.

    Returns a result dict: {found, password, attempts, seconds, rate}.
    ``words`` is any iterable of base words (e.g., an open file).
    """
    target = target_hash.strip().lower()
    start = time.time()
    attempts = 0
    last_candidate = None

    for candidate in candidates(words, use_rules):
        attempts += 1
        last_candidate = candidate
        if hash_string(candidate, algo) == target:
            elapsed = time.time() - start
            return _result(True, candidate, attempts, elapsed)

        if progress and attempts % progress_every == 0:
            elapsed = time.time() - start or 1e-9
            print(f"\r  ...{attempts:,} tried ({attempts / elapsed:,.0f}/s) "
                  f"latest: {candidate[:24]:<24}", end="", file=out, flush=True)

    elapsed = time.time() - start
    if progress and attempts >= progress_every:
        print("", file=out)  # finish the progress line
    return _result(False, None, attempts, elapsed, last_candidate)


def _result(found, password, attempts, elapsed, last=None):
    return {
        "found": found,
        "password": password,
        "attempts": attempts,
        "seconds": round(elapsed, 3),
        "rate": round(attempts / elapsed) if elapsed > 0 else attempts,
        "last_tried": last,
    }
