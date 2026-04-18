import unittest
from utils.sanitization import sanitize_agent_input, full_normalization

def extract_prefixes(processed_set):
    """
    Implementation of the prefix extraction logic from clean_filters.py
    to allow unit testing without running the full script.
    """
    prefixes = set()
    sorted_processed = sorted(list(processed_set))
    for i in range(len(sorted_processed) - 1):
        s1 = sorted_processed[i]
        s2 = sorted_processed[i+1]
        common = ""
        for c1, c2 in zip(s1, s2):
            if c1 == c2:
                common += c1
            else:
                break
        
        if not common:
            continue

        # Determine script and apply appropriate threshold
        is_cjk = any(0x4E00 <= ord(c) <= 0x9FFF or 0x3040 <= ord(c) <= 0x30FF or 0xAC00 <= ord(c) <= 0xD7AF for c in common)
        is_semitic = any(0x0600 <= ord(c) <= 0x06FF or 0x0590 <= ord(c) <= 0x05FF for c in common)

        if is_semitic:
            continue

        min_len = 4
        if is_cjk:
            min_len = 2

        if len(common) >= min_len:
            prefixes.add(common)
    
    return prefixes

class TestCleanFilters(unittest.TestCase):
    def test_latin_prefix_extraction(self):
        # Latin words: should extract prefixes >= 4 chars
        words = {"ignore", "ignoring", "ignored"}
        # "ignore" and "ignored" -> "ignore" (6 chars)
        # "ignored" and "ignoring" -> "ignor" (5 chars)
        # Result should contain "ignore" and "ignor"
        prefixes = extract_prefixes(words)
        self.assertIn("ignore", prefixes)
        self.assertIn("ignor", prefixes)
        
        # Test short common prefix < 4
        words = {"cat", "cats"}
        prefixes = extract_prefixes(words)
        self.assertEqual(len(prefixes), 0) # "cat" is length 3

    def test_cjk_prefix_extraction(self):
        # CJK words: should extract prefixes >= 2 chars
        # Japanese example: 攻撃 (attack), 攻撃者 (attacker)
        words = {"攻撃", "攻撃者"}
        prefixes = extract_prefixes(words)
        self.assertIn("攻撃", prefixes)
        
        # Single char prefix should be ignored
        words = {"電", "電話"}
        prefixes = extract_prefixes(words)
        self.assertEqual(len(prefixes), 0)

    def test_semitic_exclusion(self):
        # Arabic: "كتب" (kataba), "كتاب" (kitab)
        # Even if they share a prefix, it should be skipped per logic
        words = {"كتب", "كتاب"}
        prefixes = extract_prefixes(words)
        self.assertEqual(len(prefixes), 0)

    def test_normalization_integration(self):
        # Testing how it works with normalized input
        raw_words = {"Ignore", " IGNORING "}
        # Unpack the (app, radar) tuple and use the radar version
        processed = {full_normalization(sanitize_agent_input(w, apply_nfkc=True)[1]) for w in raw_words}
        # processed = {"ignore", "ignoring"}
        prefixes = extract_prefixes(processed)
        self.assertIn("ignor", prefixes)

    def test_mixed_scripts(self):
        # Mixed CJK and Latin
        words = {"ignore", "ignoring", "攻撃", "攻撃者"}
        prefixes = extract_prefixes(words)
        self.assertIn("ignor", prefixes)
        self.assertIn("攻撃", prefixes)

if __name__ == '__main__':
    unittest.main()
