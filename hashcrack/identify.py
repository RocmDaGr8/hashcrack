"""Hash type identification by format and length."""

import re

# Cracking-capable algorithms map to a hashlib name; identify-only ones map to None.
_HEX_BY_LENGTH = {
    32: [("MD5", "md5"), ("NTLM", None)],   # same length — ambiguous, report both
    40: [("SHA-1", "sha1")],
    56: [("SHA-224", "sha224")],
    64: [("SHA-256", "sha256")],
    96: [("SHA-384", "sha384")],
    128: [("SHA-512", "sha512")],
}

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_BCRYPT_RE = re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$")
_SHA512_CRYPT_RE = re.compile(r"^\$6\$")
_SHA256_CRYPT_RE = re.compile(r"^\$5\$")
_MD5_CRYPT_RE = re.compile(r"^\$1\$")


def identify(hash_str):
    """Return a list of candidate types: [{"name", "algo", "crackable"}].

    ``algo`` is the hashlib algorithm name when this tool can crack it, else None.
    """
    h = hash_str.strip()

    # Prefixed (crypt-style) hashes first — unambiguous.
    if _BCRYPT_RE.match(h):
        return [_t("bcrypt", None)]
    if _SHA512_CRYPT_RE.match(h):
        return [_t("sha512crypt ($6$)", None)]
    if _SHA256_CRYPT_RE.match(h):
        return [_t("sha256crypt ($5$)", None)]
    if _MD5_CRYPT_RE.match(h):
        return [_t("md5crypt ($1$)", None)]

    # Plain hex digests, keyed by length.
    if _HEX_RE.match(h) and len(h) in _HEX_BY_LENGTH:
        return [_t(name, algo) for name, algo in _HEX_BY_LENGTH[len(h)]]

    return []


def _t(name, algo):
    return {"name": name, "algo": algo, "crackable": algo is not None}


def best_crackable_algo(hash_str):
    """Pick the most likely crackable hashlib algo for a hash, or None."""
    for cand in identify(hash_str):
        if cand["crackable"]:
            return cand["algo"]
    return None
