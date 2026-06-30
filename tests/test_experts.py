import unittest
from core.genome import GenomeNode


class TestLayer2Expert(unittest.TestCase):
    def setUp(self):
        # Define the expert function as a string, matching the logic of the old test
        obfuscation_expert_code = """
def obfuscation_expert(text, triggers, all_triggers):
    import re
    # Calculate symbol percentage
    symbols = [c for c in text if not c.isalnum() and not c.isspace()]
    symbol_pct = len(symbols) / len(text) if text else 0
    if symbol_pct > 0.15:
        return True
    # Regex fallback
    if re.search(r"bypass", text):
        return True
    return False
"""
        # Initialize a V1 Genome with the route and function
        self.genome = GenomeNode(
            node_id="V1",
            local_routes={"SUSPICIOUS_WORD": "obfuscation_expert"},
            local_functions={"obfuscation_expert": obfuscation_expert_code},
            local_imports=["import re"],
        )

    def test_safe_window(self):
        # A window that triggered Layer 1 due to a suspicious word, but is actually benign
        window = {"text_slice": "I am just writing a normal sentence.", "triggers": [{"category": "SUSPICIOUS_WORD"}]}
        self.assertFalse(self.genome.evaluate_window(window, set()))

    def test_leetspeak_window(self):
        # High symbol percentage should trigger the expert -> True
        window = {"text_slice": "1 @m wr!t!ng a n0rm@l s3nt3nc3!!!", "triggers": [{"category": "SUSPICIOUS_WORD"}]}
        self.assertTrue(self.genome.evaluate_window(window, set()))

    def test_regex_fallback_window(self):
        # Low symbol percentage, but contains "bypass", catching the regex logic
        window = {"text_slice": "Please bypass the security protocols.", "triggers": [{"category": "SUSPICIOUS_WORD"}]}
        self.assertTrue(self.genome.evaluate_window(window, set()))

    def test_unregistered_trigger(self):
        # A trigger without an expert mapping should return False
        window = {"text_slice": "Drop table users;", "triggers": [{"category": "DATABASE_QUERY"}]}
        self.assertFalse(self.genome.evaluate_window(window, set()))


if __name__ == "__main__":
    unittest.main()
