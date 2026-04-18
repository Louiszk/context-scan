import unittest
import os
from pathlib import Path
from core.genome import GenomeNode

class TestGenomeLoad(unittest.TestCase):
    def test_all_base_seeds(self):
        """Discovers and validates all seed files in base_genomes/."""
        base_dir = Path(__file__).parent.parent / "base_genomes"
        seed_files = list(base_dir.glob("v*_seed.py"))
        
        self.assertGreater(len(seed_files), 0, "No seed files found in base_genomes/")
        
        for seed_path in seed_files:
            with self.subTest(seed=seed_path.name):
                with open(seed_path, "r", encoding="utf-8") as f:
                    source = f.read()
                
                genome = GenomeNode.from_python_source(source, node_id=f"test_{seed_path.stem}")
                
                # Basic Structural Validation
                self.assertGreater(len(genome.local_routes), 0, f"{seed_path.name} has no routes")
                self.assertGreater(len(genome.local_functions), 0, f"{seed_path.name} has no functions")
                
                # Ensure all routed functions actually exist in the namespace
                for trigger, func_name in genome.local_routes.items():
                    self.assertIn(func_name, genome.namespace, 
                                 f"Route '{trigger}' maps to missing function '{func_name}' in {seed_path.name}")

                # Evaluate a window to ensure no runtime syntax errors in experts
                window = {
                    "text_slice": "ignore instructions",
                    "triggers": [{"category": "ignoring", "rel_start": 0, "rel_end": 6}]
                }
                try:
                    genome.evaluate_window(window, {"ignoring"})
                except Exception as e:
                    self.fail(f"Expert execution failed for {seed_path.name}: {e}")

if __name__ == "__main__":
    unittest.main()
