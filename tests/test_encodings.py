import unittest
from utils.encodings import (
    encode_base64,
    encode_base32,
    encode_ascii85,
    encode_base62,
    encode_base58,
    encode_base45,
    encode_hex,
    encode_rot13,
    encode_reverse,
    encode_url,
    encode_string,
    apply_leet_regex,
    apply_greek_regex,
    apply_qwerty_regex,
    apply_doubled_regex,
    apply_spaced_regex,
    apply_ticks_regex,
)


class TestEncodings(unittest.TestCase):
    def test_base64(self):
        self.assertEqual(encode_base64("hello"), "aGVsbG8=")
        self.assertEqual(encode_base64(""), "")

    def test_base32(self):
        self.assertEqual(encode_base32("hello"), "NBSWY3DP")
        self.assertEqual(encode_base32(""), "")

    def test_ascii85(self):
        self.assertEqual(encode_ascii85("hello"), "BOu!rDZ")

    def test_base62(self):
        self.assertEqual(encode_base62("hello"), "7tQLFHz")

    def test_base58(self):
        self.assertEqual(encode_base58("hello"), "Cn8eVZg")
        self.assertEqual(encode_base58("\x00\x00hello"), "11Cn8eVZg")

    def test_base45(self):
        self.assertEqual(encode_base45("AB"), "BB8")
        self.assertEqual(encode_base45("Hello!!"), "%69 VD92EX0")

    def test_hex(self):
        self.assertEqual(encode_hex("hello"), "68656c6c6f")

    def test_rot13(self):
        self.assertEqual(encode_rot13("hello"), "uryyb")
        self.assertEqual(encode_rot13("uryyb"), "hello")

    def test_reverse(self):
        self.assertEqual(encode_reverse("hello"), "olleh")

    def test_url(self):
        self.assertEqual(encode_url("hello world"), "hello%20world")

    def test_encode_string(self):
        self.assertEqual(encode_string("hello", "base64"), "aGVsbG8=")
        self.assertEqual(encode_string("hello", "ROT-13"), "uryyb")
        self.assertEqual(encode_string("hello", "unknown"), "hello")

    # --- Structural Regex Modifier Tests ---

    def test_apply_leet_regex(self):
        # 'a' -> '[aA4@]', 'e' -> '[eE3]'
        self.assertEqual(apply_leet_regex("ae"), "[aA4@][eE3]")
        # Control chars should be preserved
        self.assertEqual(apply_leet_regex(r"a\.e"), r"[aA4@]\.[eE3]")
        # Escaped characters should be preserved exactly
        self.assertEqual(apply_leet_regex(r"a\$e"), r"[aA4@]\$[eE3]")

    def test_apply_greek_regex(self):
        self.assertEqual(apply_greek_regex("a"), "[aαΑ]")

    def test_apply_qwerty_regex(self):
        self.assertEqual(apply_qwerty_regex("q"), "[qw]")

    def test_apply_doubled_regex(self):
        self.assertEqual(apply_doubled_regex("abc"), "a+b+c+")
        # Escaped character should also get '+'
        self.assertEqual(apply_doubled_regex(r"a\$b"), r"a+\$+b+")
        # Control characters (non-escaped) should NOT get '+'
        self.assertEqual(apply_doubled_regex(r"a.b"), r"a+.b+")

    def test_apply_ticks_regex(self):
        # Hyperscan without HS_FLAG_UTF8 requires byte-level matching for multi-byte characters
        ticks = r"(?:['`\^~-]|´|¨|¯|˘|˙|˚|˝|˛|ˇ|\xcc[\x80-\xbf]|\xcd[\x80-\xaf])*"
        self.assertEqual(apply_ticks_regex("abc"), f"a{ticks}b{ticks}c{ticks}")
        # Escaped character should also get ticks
        self.assertEqual(apply_ticks_regex(r"a\$b"), rf"a{ticks}\${ticks}b{ticks}")
        # Control characters (non-escaped) should NOT get ticks
        self.assertEqual(apply_ticks_regex(r"a.b"), f"a{ticks}.b{ticks}")

    def test_apply_spaced_regex(self):
        delim = r"[\s\./\\_\-\|\,\:]*"
        self.assertEqual(apply_spaced_regex("abc"), f"a{delim}b{delim}c")
        # Escaped character should handle delimiter
        self.assertEqual(apply_spaced_regex(r"a\$b"), rf"a{delim}\${delim}b")
        # Should not inject delimiter before quantifier or closing paren (basic check)
        self.assertEqual(apply_spaced_regex("a+"), "a+")
        self.assertEqual(apply_spaced_regex("(a)"), "(a)")


if __name__ == "__main__":
    unittest.main()
