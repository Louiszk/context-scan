import unittest
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.append(str(Path(__file__).parent.parent))

from utils.sanitization import sanitize_agent_input


class TestSanitization(unittest.TestCase):
    def test_homoglyphs(self):
        """Test that homoglyphs are correctly resolved to their ASCII equivalents in Radar text but preserved in App text."""
        # Test case: "pаypаl" using Cyrillic 'а' (0x0430) instead of Latin 'a'
        # According to homoglyph_map.json: "0x0430": "a"
        input_text = "p\u0430yp\u0430l"
        expected_radar = "paypal"
        expected_app = "p\u0430yp\u0430l"

        app_text, radar_text = sanitize_agent_input(input_text)
        self.assertEqual(radar_text, expected_radar, "Failed to resolve homoglyphs in Radar text")
        self.assertEqual(app_text, expected_app, "Failed to preserve original characters in App text")

        # Test case: Greek Omicron (0x039F), Greek Iota (0x0399), Cyrillic I (0x0406), Divides (0x2223)
        # Should map to "Olll" in radar
        input_text = "\u039f\u0399\u0406\u2223"
        expected_radar = "Olll"
        app_text, radar_text = sanitize_agent_input(input_text)
        self.assertEqual(radar_text, expected_radar, "Failed to resolve complex homoglyphs in Radar text")

    def test_nfkc_normalization(self):
        """Test that NFKC normalization correctly handles stylized fonts when enabled."""
        # Mathematical Bold Fraktur 'A' (U+1D504) -> 'A'
        input_text = "\U0001d504"
        expected_output = "A"
        # Must pass apply_nfkc=True for this to work as per function logic
        app_text, radar_text = sanitize_agent_input(input_text, apply_nfkc=True)
        self.assertEqual(app_text, expected_output)
        self.assertEqual(radar_text, expected_output)

    def test_steganography_stripping(self):
        """Test that excessive zero-width characters are pruned (preserves first one)."""
        # Text with multiple Zero-Width Joiners (U+200D)
        input_text = "h\u200d\u200de\u200d\u200dl\u200d\u200dl\u200d\u200do"
        expected_output = "h\u200de\u200dl\u200dl\u200do"
        app_text, radar_text = sanitize_agent_input(input_text)
        self.assertEqual(app_text, expected_output)
        self.assertEqual(radar_text, expected_output)

    def test_zalgo_pruning(self):
        """Test that Zalgo marks are limited to 2 per character."""
        input_text = "q\u0300\u0301\u0302"
        expected_output = "q\u0300\u0301"
        app_text, radar_text = sanitize_agent_input(input_text)
        self.assertEqual(app_text, expected_output)
        self.assertEqual(radar_text, expected_output)


if __name__ == "__main__":
    unittest.main()
