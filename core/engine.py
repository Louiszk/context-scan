import os
import sys
from typing import List, Dict, Optional, Union
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from core.config import settings
from core.evaluations import Evaluator
from core.genome import GenomeNode
from core.mutation import LLMMutator


class EvolutionaryEngine:
    def __init__(self, training_data_path: Union[str, List[str]], radar_path: Optional[str] = None):
        self.evaluator = Evaluator(training_data_path, radar_path)
        self.mutator = LLMMutator()

    def _group_failures(self, failures: List[Dict]) -> Dict[str, List[Dict]]:
        """Groups failure traces by their primary Radar trigger."""
        groups = {}
        for f in failures:
            if f["trace"]:
                last_trace = f["trace"][-1]
                trigger_val = last_trace.get("trigger", "unknown")
                key = trigger_val.get("category", "unknown") if isinstance(trigger_val, dict) else trigger_val
            elif f["windows"]:
                key = f["windows"][0]["triggers"][0]["category"] if f["windows"][0]["triggers"] else "unknown"
            else:
                key = "no_radar_hits"

            if key not in groups:
                groups[key] = []
            groups[key].append(f)
        return groups

    def _extract_traces_for_combo(self, groups: Dict[str, List[Dict]], combo_keys: tuple) -> List[Dict]:
        """Extracts and formats traces for a specific combination of failure groups."""
        target_traces = []
        for key in combo_keys:
            # Take up to 3 examples per group to prevent context window bloat
            for f in groups[key][:3]:
                if f["trace"]:
                    target_traces.append(f["trace"][-1])
                else:
                    target_traces.append(
                        {
                            "type": "execution",
                            "trigger": key,
                            "function": "NONE",
                            "text_slice": f["windows"][0]["text_slice"] if f["windows"] else f["text"][:100],
                            "result": f["actual"],
                        }
                    )
        return target_traces

    def run_beam_evolution(
        self,
        iterations: Optional[int] = None,
        samples_limit: Optional[int] = None,
        beam_width: Optional[int] = None,
        start_genome: Optional[GenomeNode] = None,
        directive: Optional[str] = None,
    ) -> GenomeNode:

        # Use centralized defaults if not provided
        iterations = iterations or settings.default_iterations
        samples_limit = samples_limit or settings.default_samples_per_iteration
        beam_width = beam_width or settings.default_beam_width

        if not start_genome:
            base_dir = settings.get_path("base_genomes_dir")
            latest_v = -1
            latest_path = None

            if base_dir.exists():
                import re

                pattern = re.compile(r"v(\d+)_seed\.py")
                for file in base_dir.glob("v*_seed.py"):
                    match = pattern.match(file.name)
                    if match:
                        v = int(match.group(1))
                        if v > latest_v:
                            latest_v = v
                            latest_path = file

            if latest_path:
                print(f"Loading latest base genome from {latest_path} (v{latest_v})...")
                with open(latest_path, "r", encoding="utf-8") as f:
                    start_genome = GenomeNode.from_python_source(f.read(), node_id=f"V{latest_v}_SEED")
            else:
                # Fallback to legacy path if no v*_seed.py found
                v1_path = os.path.join("base_genomes", "v1_seed.py")
                if os.path.exists(v1_path):
                    print(f"Loading legacy base genome from {v1_path}...")
                    with open(v1_path, "r", encoding="utf-8") as f:
                        start_genome = GenomeNode.from_python_source(f.read(), node_id="V1_SEED")
                else:
                    print("No base genome found, starting fresh (V1).")
                    start_genome = GenomeNode(node_id="V1")

        population = [start_genome]

        for layer in range(iterations):
            print("\n" + "=" * 40)
            print(f" LAYER {layer + 1} (Population: {len(population)})")
            print("=" * 40)

            new_generation = []

            for parent_idx, parent in enumerate(population):
                print(f"\nAnalyzing Parent [{parent.node_id}]...")
                # Always add the parent to the new generation pool (Elitism)
                new_generation.append(parent)

                train_results = self.evaluator.evaluate(parent, split="train", limit=samples_limit)
                failures = train_results["false_positives"] + train_results["false_negatives"]

                if not failures:
                    print("  -> Perfect on train subset. No mutations needed.")
                    continue

                # 1. Isolate and rank failure groups
                groups = self._group_failures(failures)
                top_groups = sorted(groups.items(), key=lambda x: len(x[1]), reverse=True)
                top_keys = [g[0] for g in top_groups[:3]]

                # 2. Build Combinations: (0,1), (1,2), (0,2), (0,1,2)
                if len(top_keys) >= 3:
                    combos = [
                        (top_keys[0], top_keys[1]),
                        (top_keys[1], top_keys[2]),
                        (top_keys[0], top_keys[2]),
                        (top_keys[0], top_keys[1], top_keys[2]),
                    ]
                elif len(top_keys) == 2:
                    combos = [(top_keys[0],), (top_keys[1],), (top_keys[0], top_keys[1])]
                else:
                    combos = [(top_keys[0],)]

                # 3. Spawn Mutants
                for combo_idx, combo in enumerate(combos):
                    print(f"  -> Spawning Mutant {combo_idx + 1} targeting: {combo}")
                    target_traces = self._extract_traces_for_combo(groups, combo)

                    # Retry logic handled inside or out
                    mutant_id = f"{parent.node_id}_L{layer}_C{combo_idx}"
                    mutant = self.mutator.mutate_individual(
                        genome=parent, target_traces=target_traces, new_node_id=mutant_id, directive=directive
                    )

                    if mutant:
                        new_generation.append(mutant)

            # 4. Survival of the Fittest
            if layer == 0:
                print("\n--- Layer 1 Complete: All initial mutants survive ---")
                population = new_generation
            else:
                print(f"\n--- Layer {layer + 1} Complete: Evaluating {len(new_generation)} mutants ---")
                scored_mutants = []
                for mut in new_generation:
                    val_res = self.evaluator.evaluate(mut, split="val", limit=samples_limit)
                    print(f"  [{mut.node_id}] -> F1: {val_res['f1']:.4f} | Acc: {val_res['accuracy']:.4f}")
                    scored_mutants.append((val_res["f1"], mut))

                # Sort by F1 Score descending and keep top N
                scored_mutants.sort(key=lambda x: x[0], reverse=True)
                population = [m for score, m in scored_mutants[:beam_width]]
                print(f"--- Culling complete. Top {len(population)} advance to next layer ---")

        # Final Evaluation of the absolute best
        best_genome = population[0]
        print("\n=== EVOLUTION COMPLETE ===")
        print(f"Best Genome ID: {best_genome.node_id}")
        return best_genome


if __name__ == "__main__":
    engine = EvolutionaryEngine(training_data_path=settings.default_training_data)
    best = engine.run_beam_evolution()
