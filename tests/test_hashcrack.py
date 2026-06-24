"""Unit tests for HashCrack. Run with: python -m unittest discover tests"""

import hashlib
import unittest

from hashcrack.identify import identify, best_crackable_algo
from hashcrack.rules import mangle, candidates
from hashcrack.cracker import crack, hash_string


def md5(s):
    return hashlib.md5(s.encode()).hexdigest()


class TestIdentify(unittest.TestCase):
    def test_md5_length(self):
        names = [c["name"] for c in identify(md5("hello"))]
        self.assertIn("MD5", names)

    def test_sha256_length(self):
        h = hashlib.sha256(b"x").hexdigest()
        self.assertEqual(identify(h)[0]["name"], "SHA-256")

    def test_bcrypt_prefix(self):
        h = "$2b$12$" + "a" * 53
        self.assertEqual(identify(h)[0]["name"], "bcrypt")
        self.assertFalse(identify(h)[0]["crackable"])

    def test_garbage(self):
        self.assertEqual(identify("nothing-like-a-hash"), [])

    def test_best_crackable_picks_md5_over_ntlm(self):
        self.assertEqual(best_crackable_algo(md5("hi")), "md5")


class TestRules(unittest.TestCase):
    def test_mangle_includes_capitalize_and_suffix(self):
        out = set(mangle("letmein"))
        self.assertIn("letmein", out)
        self.assertIn("Letmein", out)
        self.assertIn("letmein123", out)

    def test_mangle_includes_leet(self):
        self.assertIn("p@$$w0rd", set(mangle("password")))

    def test_candidates_without_rules_is_passthrough(self):
        self.assertEqual(list(candidates(["a\n", "b\n", ""], use_rules=False)), ["a", "b"])


class TestCracker(unittest.TestCase):
    def test_hash_string_matches_hashlib(self):
        self.assertEqual(hash_string("abc", "sha1"), hashlib.sha1(b"abc").hexdigest())

    def test_plain_dictionary_hit(self):
        target = md5("password")
        result = crack(target, "md5", iter(["nope", "password", "later"]), progress=False)
        self.assertTrue(result["found"])
        self.assertEqual(result["password"], "password")

    def test_miss_returns_not_found(self):
        result = crack(md5("zzz-not-here"), "md5", iter(["a", "b"]), progress=False)
        self.assertFalse(result["found"])
        self.assertEqual(result["attempts"], 2)

    def test_rules_crack_word_plus_suffix(self):
        # "letmein123" is not in the list, but rules derive it from "letmein".
        target = md5("letmein123")
        result = crack(target, "md5", iter(["letmein"]), use_rules=True, progress=False)
        self.assertTrue(result["found"])
        self.assertEqual(result["password"], "letmein123")

    def test_rules_crack_capitalized_leet(self):
        target = md5("p@$$w0rd")
        result = crack(target, "md5", iter(["password"]), use_rules=True, progress=False)
        self.assertTrue(result["found"])


if __name__ == "__main__":
    unittest.main()
