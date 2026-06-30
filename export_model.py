import os
import shutil
import dill as pickle
import argparse
import pprint
from pathlib import Path

# Add root to sys.path to allow imports from core and data
import sys

ROOT_DIR = Path(__file__).resolve().parent
sys.path.append(str(ROOT_DIR))

from core.genome import GenomeNode  # noqa: E402
from core.config import settings  # noqa: E402
from data.raw_filters import WINDOW_SIZES  # noqa: E402

FIREWALL_TEMPLATE = """
import os
import re
import math
import hyperscan
import json
from sanitization import full_normalization, sanitize_agent_input

# --- Configuration ---
RADAR_DB_PATH = os.path.join(os.path.dirname(__file__), "radar.hs")
ID_TO_CATEGORY = {id_to_category_literal}
WINDOW_SIZES = {window_sizes_literal}
DEFAULT_PADDING = {default_padding}

{genome_imports}

# --- Radar Logic ---

class InferenceRadar:
    def __init__(self, db_path):
        with open(db_path, "rb") as f:
            self.db = hyperscan.loadb(f.read(), mode=hyperscan.HS_MODE_BLOCK)
        self.scratch = hyperscan.Scratch(self.db)

    def scan(self, text):
        norm_text = full_normalization(text)
        text_bytes = norm_text.encode('utf-8')
        hits = []
        all_triggers = set()

        def callback(id, from_pos, to_pos, flags, context):
            category = ID_TO_CATEGORY.get(id)
            if category:
                hits.append({{"start": from_pos, "end": to_pos, "category": category}})
                all_triggers.add(category)
            return None

        self.db.scan(text_bytes, callback, scratch=self.scratch)
        
        if not hits:
            return {{"windows": [], "all_triggers": set()}}

        raw_windows = []
        for hit in hits:
            padding = WINDOW_SIZES.get(hit["category"], DEFAULT_PADDING)
            raw_windows.append({{
                "start": max(0, hit["start"] - padding),
                "end": min(len(text_bytes), hit["end"] + padding)
            }})

        merged_windows = self._merge_windows(text_bytes, raw_windows, hits)
        return {{"windows": merged_windows, "all_triggers": all_triggers}}

    def _merge_windows(self, text_bytes, raw_windows, all_hits):
        if not raw_windows: return []
        sorted_w = sorted(raw_windows, key=lambda x: x["start"])
        merged = []
        curr = sorted_w[0].copy()
        for i in range(1, len(sorted_w)):
            nxt = sorted_w[i]
            if nxt["start"] <= curr["end"]:
                curr["end"] = max(curr["end"], nxt["end"])
            else:
                merged.append(curr)
                curr = nxt.copy()
        merged.append(curr)

        final = []
        for bound in merged:
            w_start, w_end = bound["start"], bound["end"]
            window_bytes = text_bytes[w_start:w_end]
            triggers = []
            for hit in all_hits:
                if hit["start"] >= w_start and hit["end"] <= w_end:
                    bytes_before_hit = window_bytes[:hit["start"] - w_start]
                    bytes_up_to_end = window_bytes[:hit["end"] - w_start]
                    
                    char_rel_start = len(bytes_before_hit.decode('utf-8', errors='ignore'))
                    char_rel_end = len(bytes_up_to_end.decode('utf-8', errors='ignore'))

                    triggers.append({{
                        "category": hit["category"],
                        "rel_start": char_rel_start,
                        "rel_end": char_rel_end
                    }})
            triggers.sort(key=lambda x: x["rel_start"])
            final.append({{
                "text_slice": window_bytes.decode('utf-8', errors='ignore'),
                "triggers": triggers
            }})
        return final

# --- Genome Routing & Experts ---

ROUTES = {routes_literal}

{expert_functions}

def evaluate_window(window, all_triggers):
    text_slice = window.get("text_slice", "")
    triggers = window.get("triggers", [])
    
    # Check all triggers in the window
    for trigger_dict in triggers:
        func_name = ROUTES.get(trigger_dict["category"])
        if func_name and func_name in globals():
            expert_func = globals()[func_name]
            try:
                if expert_func(text_slice, triggers, all_triggers):
                    return True
            except Exception:
                continue
    return False

# --- Public API ---

_RADAR = None

def predict(text):
    global _RADAR
    if _RADAR is None:
        _RADAR = InferenceRadar(RADAR_DB_PATH)
    
    # Stage 0: Sanitization returns both versions
    app_text, radar_text = sanitize_agent_input(text, apply_nfkc=True)
    
    # Stage 1: Radar (Scans the homoglyph-mapped version)
    radar_result = _RADAR.scan(radar_text)
    
    # Stage 2: Experts
    for window in radar_result["windows"]:
        if evaluate_window(window, radar_result["all_triggers"]):
            return {{"is_malicious": True, "sanitized_text": app_text}}
            
    return {{"is_malicious": False, "sanitized_text": app_text}}

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        test_text = " ".join(sys.argv[1:])
        result = predict(test_text)
        print(f"Malicious: {{result['is_malicious']}}")
        print(f"Clean Text: {{result['sanitized_text']}}")
"""


def main():
    parser = argparse.ArgumentParser(description="Export ContextScan Genome to a standalone folder.")
    parser.add_argument("--genome", default="output/best_genome.pkl", help="Path to best_genome.pkl or v1_seed.py")
    parser.add_argument("--output", default="firewall", help="Output directory for the exported model")
    parser.add_argument("--radar", default="data/radar.bin", help="Path to radar.bin")
    args = parser.parse_args()

    out_path = Path(args.output)
    out_path.mkdir(parents=True, exist_ok=True)

    # 1. Load Genome
    print(f"Loading genome from {args.genome}...")
    if args.genome.endswith(".pkl"):
        with open(args.genome, "rb") as f:
            genome = pickle.load(f)
    else:
        with open(args.genome, "r", encoding="utf-8") as f:
            source = f.read()
        genome = GenomeNode.from_python_source(source, node_id="EXPORT")

    context = genome.get_full_context()

    # 2. Extract Radar Assets
    print(f"Processing radar from {args.radar}...")
    if not os.path.exists(args.radar):
        # Build it if missing
        print("Radar binary missing. Building from rules...")
        from utils.build_hyperscan import build_and_save_radar

        build_and_save_radar(output_path=args.radar)

    with open(args.radar, "rb") as f:
        radar_data = pickle.load(f)

    # Save raw HS binary
    with open(out_path / "radar.hs", "wb") as f:
        f.write(radar_data["db_binary"])

    id_to_category = radar_data["id_to_category"]

    # 3. Copy Utilities
    print("Copying sanitization assets...")
    shutil.copy2(ROOT_DIR / "utils" / "sanitization.py", out_path / "sanitization.py")
    shutil.copy2(ROOT_DIR / "utils" / "homoglyph_map.json", out_path / "homoglyph_map.json")

    # 4. Generate firewall.py
    print("Generating firewall.py...")

    expert_funcs_code = "\n\n".join(context["functions"].values())
    genome_imports_code = "\n".join(context["imports"])

    # Use pprint for clean literals
    id_to_category_literal = pprint.pformat(id_to_category, indent=4)
    window_sizes_literal = pprint.pformat(WINDOW_SIZES, indent=4)
    routes_literal = pprint.pformat(context["routes"], indent=4)

    firewall_content = FIREWALL_TEMPLATE.format(
        id_to_category_literal=id_to_category_literal,
        window_sizes_literal=window_sizes_literal,
        default_padding=settings.default_window_padding,
        genome_imports=genome_imports_code,
        routes_literal=routes_literal,
        expert_functions=expert_funcs_code,
    )

    with open(out_path / "firewall.py", "w", encoding="utf-8") as f:
        f.write(firewall_content.strip())

    print(f"Export complete! Model saved to: {out_path}")


if __name__ == "__main__":
    main()
