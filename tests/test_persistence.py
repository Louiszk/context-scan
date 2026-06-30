import unittest
import dill as pickle
import os
from core.genome import GenomeNode
from core.radar import SemanticRadar


class TestPersistence(unittest.TestCase):
    def test_genome_node_persistence(self):
        """Verify GenomeNode can be pickled and unpickled while preserving state."""
        local_functions = {"test_func": "def test_func(text, triggers, all_triggers):\n    return True"}
        local_routes = {"test_trigger": "test_func"}

        original_genome = GenomeNode(node_id="persist_test", local_routes=local_routes, local_functions=local_functions)

        # Pickle
        pickled_data = pickle.dumps(original_genome)

        # Unpickle
        loaded_genome = pickle.loads(pickled_data)

        self.assertEqual(loaded_genome.node_id, "persist_test")
        self.assertEqual(loaded_genome.local_routes, local_routes)
        self.assertIn("test_func", loaded_genome.namespace)

        # Verify functionality after reload
        window = {"text_slice": "hello", "triggers": [{"category": "test_trigger"}]}
        self.assertTrue(loaded_genome.evaluate_window(window, {"test_trigger"}))

    def test_radar_persistence(self):
        """Verify SemanticRadar can be saved and loaded from disk binary."""
        rules = {"CAT_A": ["pattern_a"]}
        radar = SemanticRadar(rules)

        temp_path = "tests/temp_radar.bin"
        try:
            radar.save(temp_path)

            loaded_radar = SemanticRadar.load(temp_path)

            self.assertEqual(loaded_radar.id_to_category[0], "CAT_A")

            # Verify scan works on loaded radar
            result = loaded_radar.scan_document("this is pattern_a")
            self.assertEqual(len(result["windows"]), 1)
            self.assertIn("CAT_A", result["all_triggers"])

        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)


if __name__ == "__main__":
    unittest.main()
