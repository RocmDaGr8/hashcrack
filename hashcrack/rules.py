"""Rule-based candidate mangling.

Given a base word from a wordlist, generate the common variations real users
apply to passwords — capitalization, appended digits/symbols, leetspeak, and
reversal. This dramatically widens coverage without needing a bigger wordlist.
"""

# Common suffixes people tack onto a base word.
_SUFFIXES = ["", "1", "12", "123", "1234", "!", "@", "#", "?",
             "2023", "2024", "2025", "2026", "01", "00", "69", "007"]

# Common leetspeak substitutions (applied all-at-once).
_LEET = str.maketrans({"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"})


def mangle(word):
    """Yield unique candidate variants for a base word."""
    word = word.rstrip("\r\n")
    if not word:
        return

    seen = set()
    bases = {word, word.lower(), word.upper(), word.capitalize(), word[::-1]}
    # add a leetspeak version of the lowercase word
    bases.add(word.lower().translate(_LEET))

    for base in bases:
        for suffix in _SUFFIXES:
            candidate = base + suffix
            if candidate not in seen:
                seen.add(candidate)
                yield candidate


def candidates(words, use_rules):
    """Stream candidates from an iterable of words, with or without mangling."""
    if use_rules:
        for word in words:
            yield from mangle(word)
    else:
        for word in words:
            w = word.rstrip("\r\n")
            if w:
                yield w
