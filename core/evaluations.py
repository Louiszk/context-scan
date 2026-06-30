import os
import sys
import json
import random
import concurrent.futures
from typing import List, Dict, Any, Optional, Union
from pathlib import Path
from functools import partial

sys.path.append(str(Path(__file__).resolve().parent.parent))

from core.config import settings
from core.radar import SemanticRadar
from core.genome import GenomeNode

# Global caches for multiprocessing workers
_RADAR_CACHE = None
_GENOME_CACHE = None
_GENOME_ID_CACHE = None


def _evaluate_document_task(entry: Dict, radar_path: str, genome_data: Dict) -> Dict:
    """Worker function for parallel evaluation."""
    global _RADAR_CACHE, _GENOME_CACHE, _GENOME_ID_CACHE

    if _RADAR_CACHE is None:
        _RADAR_CACHE = SemanticRadar.load(radar_path)

    if _GENOME_ID_CACHE != genome_data["node_id"]:
        _GENOME_CACHE = GenomeNode(
            node_id=genome_data["node_id"],
            local_routes=genome_data["routes"],
            local_functions=genome_data["functions"],
            local_imports=genome_data.get("imports", []),
        )
        _GENOME_ID_CACHE = genome_data["node_id"]

    text = entry["text"]
    expected = bool(entry["label"])

    assert _RADAR_CACHE is not None
    assert _GENOME_CACHE is not None

    radar_result = _RADAR_CACHE.scan_document(text)
    is_malicious = _GENOME_CACHE.process_document(radar_result)

    trace = _GENOME_CACHE.trace_log.copy()
    _GENOME_CACHE.clear_traces()

    return {
        "text": text,
        "expected": expected,
        "actual": is_malicious,
        "windows": radar_result["windows"],
        "trace": trace,
    }


class Evaluator:
    def __init__(
        self,
        training_data_path: Union[str, List[str]],
        radar_path: Optional[str] = None,
        train_split: Optional[float] = None,
        val_split: Optional[float] = None,
        max_workers: Optional[int] = None,
    ):
        self.training_data_path = training_data_path
        self.radar_path = radar_path or str(settings.get_path("radar_bin_path"))
        self.dataset = {"train": [], "val": [], "test": []}
        self.max_workers = max_workers or os.cpu_count() or 1

        self.train_split = train_split or settings.data_splits[0]
        self.val_split = val_split or settings.data_splits[1]
        self._load_data()
        self._ensure_radar()

    def _load_data(self):
        paths = [self.training_data_path] if isinstance(self.training_data_path, str) else self.training_data_path
        full_dataset = []
        for path in paths:
            print(f"Loading training data from {path}...")
            with open(path, "r", encoding="utf-8") as f:
                full_dataset.extend(json.load(f))

        random.seed(42)
        random.shuffle(full_dataset)

        total = len(full_dataset)
        train_idx = int(total * self.train_split)
        val_idx = train_idx + int(total * self.val_split)

        self.dataset["train"] = full_dataset[:train_idx]
        self.dataset["val"] = full_dataset[train_idx:val_idx]
        self.dataset["test"] = full_dataset[val_idx:]
        print(
            f"Dataset Split: Train={len(self.dataset['train'])}, Val={len(self.dataset['val'])}, Test={len(self.dataset['test'])}"
        )

    def _get_radar_hash(self) -> str:
        import hashlib

        hasher = hashlib.md5()
        base_dir = Path(__file__).resolve().parent.parent
        files_to_hash = [base_dir / "utils" / "build_hyperscan.py", base_dir / "data" / "raw_filters.py"]

        for fpath in files_to_hash:
            if fpath.exists():
                with open(fpath, "rb") as f:
                    hasher.update(f.read())
        return hasher.hexdigest()

    def _ensure_radar(self):
        hash_path = self.radar_path + ".hash"
        current_hash = self._get_radar_hash()

        needs_build = True
        if os.path.exists(self.radar_path) and os.path.exists(hash_path):
            with open(hash_path, "r", encoding="utf-8") as f:
                saved_hash = f.read().strip()
            if saved_hash == current_hash:
                needs_build = False

        if needs_build:
            print("Radar binary missing or outdated. Building from raw filters...")
            from utils.build_hyperscan import build_hyperscan_rules

            rules = build_hyperscan_rules()
            radar = SemanticRadar()
            radar.build(rules)
            os.makedirs(os.path.dirname(self.radar_path) or ".", exist_ok=True)
            radar.save(self.radar_path)
            with open(hash_path, "w", encoding="utf-8") as f:
                f.write(current_hash)
            print(f"Radar cached to {self.radar_path}")

    def evaluate(self, genome: GenomeNode, split: str = "val", limit: Optional[int] = None) -> Dict[str, Any]:
        data_to_eval = self.dataset.get(split, [])
        if limit:
            data_to_eval = data_to_eval[:limit]

        if not data_to_eval:
            return {"accuracy": 0, "f1": 0, "total_samples": 0}

        genome_context = genome.get_full_context()
        genome_data = {
            "node_id": genome.node_id,
            "routes": genome_context["routes"],
            "functions": genome_context["functions"],
            "imports": list(genome_context["imports"]),
        }

        fp, fn, tp, tn, radar_misses = [], [], 0, 0, []

        with concurrent.futures.ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            chunksize = max(1, len(data_to_eval) // (self.max_workers * 4))

            # Use partial to pass static arguments safely without creating massive arrays
            task_func = partial(_evaluate_document_task, radar_path=self.radar_path, genome_data=genome_data)
            results = executor.map(task_func, data_to_eval, chunksize=chunksize)

            for result in results:
                # Track Radar misses
                if result["expected"] and not result["windows"]:
                    radar_misses.append(result["text"])

                if result["actual"] == result["expected"]:
                    if result["actual"]:
                        tp += 1
                    else:
                        tn += 1
                else:
                    failure = {
                        "text": result["text"],
                        "expected": result["expected"],
                        "actual": result["actual"],
                        "windows": result["windows"],
                        "trace": result["trace"],
                    }
                    if result["actual"]:
                        fp.append(failure)
                    else:
                        fn.append(failure)

        total = tp + tn + len(fp) + len(fn)
        precision = tp / (tp + len(fp)) if (tp + len(fp)) > 0 else 0
        recall = tp / (tp + len(fn)) if (tp + len(fn)) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        return {
            "accuracy": (tp + tn) / total if total > 0 else 0,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "false_positives": fp,
            "false_negatives": fn,
            "radar_misses": radar_misses,
            "total_samples": total,
        }
