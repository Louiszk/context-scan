import re
import sys
import dill as pickle
from pathlib import Path

# Add project root to sys.path to ensure core module can be loaded
project_root = Path(__file__).parent.parent.absolute()
sys.path.append(str(project_root))

from core.genome import GenomeNode  # noqa: E402


def get_next_version(base_dir: Path) -> int:
    """Finds the next version number based on existing files in base_genomes/."""
    version = 1
    pattern = re.compile(r"v(\d+)_seed\.py")

    for file in base_dir.glob("v*_seed.py"):
        match = pattern.match(file.name)
        if match:
            v = int(match.group(1))
            if v >= version:
                version = v + 1
    return version


def promote_genome(pkl_path: str = "output/best_genome.pkl", base_genomes_dir: str = "base_genomes"):
    """Unpickles the genome and saves it as a new seed version."""
    pkl_path = Path(pkl_path)
    base_dir = Path(base_genomes_dir)

    if not pkl_path.exists():
        print(f"Error: {pkl_path} not found.")
        return

    print(f"Loading genome from {pkl_path}...")
    try:
        with open(pkl_path, "rb") as f:
            genome = pickle.load(f)
    except Exception as e:
        print(f"Error loading pickle: {e}")
        return

    if not isinstance(genome, GenomeNode):
        print(f"Error: Pickled object is not a GenomeNode (got {type(genome)})")
        return

    next_v = get_next_version(base_dir)
    output_filename = f"v{next_v}_seed.py"
    output_path = base_dir / output_filename

    print(f"Promoting to {output_path}...")

    # Generate the source
    source = genome.to_python_source()

    # Ensure directory exists
    base_dir.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(source)

    print(f"Successfully created {output_path}")


if __name__ == "__main__":
    promote_genome()
