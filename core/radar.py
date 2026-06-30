import hyperscan
import dill as pickle
from core.config import settings
from utils.sanitization import full_normalization, sanitize_agent_input
from data.raw_filters import WINDOW_SIZES


from typing import Optional


class SemanticRadar:
    def __init__(self, hyperscan_rules: Optional[dict] = None):
        """
        Initializes the SemanticRadar with Hyperscan rules.
        :param hyperscan_rules: Dictionary mapping category names to lists of regex patterns.
        """
        self.db = None
        self.id_to_category = {}

        if hyperscan_rules:
            self.build(hyperscan_rules)

    def build(self, hyperscan_rules: dict):
        """
        Compiles Hyperscan rules into a binary database.
        """
        patterns = []
        ids = []
        flags = []

        current_id = 0
        for category, regexes in hyperscan_rules.items():
            self.id_to_category[current_id] = category
            for regex in regexes:
                patterns.append(regex.encode("utf-8"))
                ids.append(current_id)
                # Use HS_FLAG_SOM_LEFTMOST to get 'from' index
                flags.append(hyperscan.HS_FLAG_CASELESS | hyperscan.HS_FLAG_SOM_LEFTMOST)
            current_id += 1

        self.db = hyperscan.Database(mode=hyperscan.HS_MODE_BLOCK)
        self.db.compile(expressions=patterns, ids=ids, elements=len(patterns), flags=flags)

    def save(self, file_path: str):
        """Saves the compiled database and ID mapping to a file."""
        assert self.db is not None
        data = {"db_binary": hyperscan.dumpb(self.db), "id_to_category": self.id_to_category}
        with open(file_path, "wb") as f:
            pickle.dump(data, f)

    @classmethod
    def load(cls, file_path: str) -> "SemanticRadar":
        """Loads a SemanticRadar instance from a saved file."""
        with open(file_path, "rb") as f:
            data = pickle.load(f)

        radar = cls()
        # loadb requires the mode
        radar.db = hyperscan.loadb(data["db_binary"], mode=hyperscan.HS_MODE_BLOCK)
        radar.id_to_category = data["id_to_category"]
        return radar

    def scan_document(self, text: str) -> dict:
        """
        Scans a document using Hyperscan and proposes spatial text windows.
        Returns a dict containing 'windows' (list of regions) and 'all_triggers' (set of categories).
        """
        if not text or not self.db:
            return {"windows": [], "all_triggers": set()}

        # Sanitization returns both versions: (safe_for_app, safe_for_radar)
        _, radar_text = sanitize_agent_input(text, apply_nfkc=True)
        text = full_normalization(radar_text)
        text_bytes = text.encode("utf-8")

        hits = []
        all_triggers = set()

        def callback(id, from_pos, to_pos, flags, context):
            category = self.id_to_category.get(id)
            if category:
                hits.append({"start": from_pos, "end": to_pos, "category": category})
                all_triggers.add(category)
            return None

        scratch = hyperscan.Scratch(self.db)
        self.db.scan(text_bytes, callback, scratch=scratch)

        if not hits:
            return {"windows": [], "all_triggers": set()}

        raw_windows = []
        for hit in hits:
            category = hit["category"]
            padding = WINDOW_SIZES.get(category, settings.default_window_padding)

            start_index = max(0, hit["start"] - padding)
            end_index = min(len(text_bytes), hit["end"] + padding)

            raw_windows.append({"start": start_index, "end": end_index})

        merged_windows = self._merge_windows(text_bytes, raw_windows, hits)
        return {"windows": merged_windows, "all_triggers": all_triggers}

    def _merge_windows(self, text_bytes: bytes, raw_windows: list[dict], all_hits: list[dict]) -> list[dict]:
        """
        Merges overlapping boundary boxes and assigns all relevant hits to them.
        """
        if not raw_windows:
            return []

        sorted_windows = sorted(raw_windows, key=lambda x: x["start"])
        merged_bounds = []

        curr = sorted_windows[0].copy()

        for i in range(1, len(sorted_windows)):
            nxt = sorted_windows[i]

            if nxt["start"] <= curr["end"]:
                curr["end"] = max(curr["end"], nxt["end"])
            else:
                merged_bounds.append(curr)
                curr = nxt.copy()
        merged_bounds.append(curr)

        # Assign hits to merged windows
        final_windows = []
        for bound in merged_bounds:
            window_start = bound["start"]
            window_end = bound["end"]

            # The raw bytes for this specific window
            window_bytes = text_bytes[window_start:window_end]

            # Find all hits that fall within this window
            window_triggers = []
            for hit in all_hits:
                if hit["start"] >= window_start and hit["end"] <= window_end:
                    # Calculate character offsets by decoding the byte slices preceding the hit
                    bytes_before_hit = window_bytes[: hit["start"] - window_start]
                    bytes_up_to_end = window_bytes[: hit["end"] - window_start]

                    char_rel_start = len(bytes_before_hit.decode("utf-8", errors="ignore"))
                    char_rel_end = len(bytes_up_to_end.decode("utf-8", errors="ignore"))

                    window_triggers.append(
                        {"category": hit["category"], "rel_start": char_rel_start, "rel_end": char_rel_end}
                    )

            # Sort triggers by relative start position
            window_triggers.sort(key=lambda x: x["rel_start"])

            final_windows.append(
                {
                    "start": window_start,
                    "end": window_end,
                    "text_slice": window_bytes.decode("utf-8", errors="ignore"),
                    "triggers": window_triggers,
                }
            )

        return final_windows
