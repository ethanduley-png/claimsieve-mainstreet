from __future__ import annotations

import unittest

from claimsieve_ref.canonical import CanonicalizationError, canonical_bytes, digest, loads_strict


class CanonicalTests(unittest.TestCase):
    def test_key_order_does_not_change_digest(self) -> None:
        self.assertEqual(digest({"b": 2, "a": 1}), digest({"a": 1, "b": 2}))

    def test_float_rejected(self) -> None:
        with self.assertRaises(CanonicalizationError):
            canonical_bytes({"x": 1.5})

    def test_duplicate_key_rejected(self) -> None:
        with self.assertRaises(CanonicalizationError):
            loads_strict('{"x":1,"x":2}')

    def test_unsafe_integer_rejected(self) -> None:
        with self.assertRaises(CanonicalizationError):
            canonical_bytes({"x": 9_007_199_254_740_992})
        with self.assertRaises(CanonicalizationError):
            loads_strict('{"x":9007199254740992}')

    def test_non_nfc_string_rejected(self) -> None:
        with self.assertRaises(CanonicalizationError):
            canonical_bytes({"x": "e\u0301"})

    def test_control_character_rejected(self) -> None:
        with self.assertRaises(CanonicalizationError):
            canonical_bytes({"x": "line\nfeed"})

    def test_utf16_property_order_matches_jcs(self) -> None:
        encoded = canonical_bytes({"\ue000": 1, "\U00010000": 2}).decode("utf-8")
        self.assertEqual(encoded, '{"\U00010000":2,"\ue000":1}')

    def test_normalized_unicode_value_is_accepted(self) -> None:
        self.assertEqual(canonical_bytes({"message": "Café"}), b'{"message":"Caf\xc3\xa9"}')


if __name__ == "__main__":
    unittest.main()
