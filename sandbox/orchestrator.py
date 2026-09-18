import json
import os
import sys

import dill as pickle
from dotenv import load_dotenv

# Add workspace to sys.path
sys.path.append("/sandbox/workspace")

# Load environment variables from .env inside the sandbox
load_dotenv("/sandbox/workspace/.env")

from core.config import settings
from core.engine import EvolutionaryEngine
from core.genome import GenomeNode


def main():
    print("Starting ContextScan Orchestrator inside sandbox...")

    # Ensure working directory is the workspace root
    os.chdir("/sandbox/workspace")

    # Configuration from environment or defaults
    iterations = int(os.environ.get("EVO_ITERATIONS", settings.default_iterations))
    samples_limit = int(os.environ.get("SAMPLES_LIMIT", settings.default_samples_per_iteration))
    directive = os.environ.get("EVO_DIRECTIVE", None)

    training_data_env = os.environ.get("TRAINING_DATA", str(settings.get_path("default_training_data")))
    if ";" in training_data_env:
        training_data = training_data_env.split(";")
    else:
        training_data = training_data_env

    output_dir = "/sandbox/workspace/output"

    os.makedirs(output_dir, exist_ok=True)

    # Initialize the engine
    engine = EvolutionaryEngine(training_data_path=training_data)

    # Check if we should resume from a previous genome
    start_genome = None
    resume_path = "/sandbox/workspace/best_genome.pkl"
    if os.path.exists(resume_path):
        print(f"Found existing genome at {resume_path}. Resuming evolution...")
        try:
            with open(resume_path, "rb") as f:
                start_genome = pickle.load(f)
        except Exception as e:
            print(f"Warning: Failed to load existing genome: {e}")

    # Run the evolution
    print(f"Running beam evolution for {iterations} iterations with {samples_limit} samples...")
    if directive:
        print(f"Applying directive: {directive}")

    best_genome = engine.run_beam_evolution(
        iterations=iterations,
        samples_limit=samples_limit,
        start_genome=start_genome,
        beam_width=settings.default_beam_width,
        directive=directive,
    )

    # Save the result
    output_path = os.path.join(output_dir, "best_genome.pkl")
    print(f"Flattening and saving best genome to {output_path}...")

    # Get the consolidated state
    final_context = best_genome.get_full_context()
    flat_genome = GenomeNode(
        node_id=best_genome.node_id,
        local_routes=final_context["routes"],
        local_functions=final_context["functions"],
        local_imports=list(final_context["imports"]),
    )

    with open(output_path, "wb") as f:
        pickle.dump(flat_genome, f)

    # Save final metrics (on Test set)
    final_results = engine.evaluator.evaluate(best_genome, split="test")
    metrics_path = os.path.join(output_dir, "metrics.json")
    with open(metrics_path, "w") as f:
        json.dump(
            {
                "accuracy": final_results["accuracy"],
                "precision": final_results["precision"],
                "recall": final_results["recall"],
                "f1": final_results["f1"],
                "total_samples": final_results["total_samples"],
                "genome_id": best_genome.node_id,
            },
            f,
            indent=2,
        )

    # Log radar misses for manual radar adjustment
    misses_path = os.path.join(output_dir, "radar_misses.json")
    unique_misses = list(set(final_results.get("radar_misses", [])))
    with open(misses_path, "w", encoding="utf-8") as f:
        json.dump(unique_misses, f, ensure_ascii=False, indent=2)
    print(f"Logged {len(unique_misses)} unique radar misses to {misses_path}")

    print("Orchestration complete!")


if __name__ == "__main__":
    main()
