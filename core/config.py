import os
from pydantic import BaseModel, Field
from pathlib import Path
from typing import Tuple

class Settings(BaseModel):
    """
    Centralized configuration for ContextScan.
    Uses Pydantic for validation and easy access.
    """
    # --- LLM & Mutation Settings ---
    llm_model: str = "gpt-5.4-mini"
    max_failures_in_prompt: int = 5
    temperature: float = 0.0

    # --- Evolution Engine Defaults ---
    default_iterations: int = 3
    default_samples_per_iteration: int = 50
    default_beam_width: int = 4
    data_splits: Tuple[float, float, float] = (0.7, 0.15, 0.15) # Train, Val, Test

    # --- System Paths (Resolved relative to project root) ---
    root_path: Path = Path(__file__).parent.parent.resolve()
    
    radar_bin_path: str = "data/radar.bin"
    homoglyph_map_path: str = "utils/homoglyph_map.json"
    base_genomes_dir: str = "base_genomes"
    output_dir: str = "output"
    default_training_data: str = "data/training_data.json"

    # --- Semantic Radar Constants ---
    default_window_padding: int = 100

    def get_path(self, attribute_name: str) -> Path:
        """Helper to get an absolute path for a relative path setting."""
        rel_path = getattr(self, attribute_name)
        return (self.root_path / rel_path).resolve()

# Global settings instance
settings = Settings()
