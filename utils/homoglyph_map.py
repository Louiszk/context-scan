import json
from pathlib import Path

import requests

URL = "https://www.unicode.org/Public/security/9.0.0/confusables.txt"
OUTPUT_FILE = Path(__file__).resolve().parent / "homoglyph_map.json"


def generate_homoglyph_map():
    response = requests.get(URL)
    response.raise_for_status()

    homoglyph_map = {}

    for line in response.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Format: SOURCE ; TARGET ; TYPE # comment
        parts = [p.strip() for p in line.split(";")]
        if len(parts) < 2:
            continue

        source_str = parts[0]
        target_str = parts[1]

        # Only single-codepoint -> single-codepoint mappings
        sources = source_str.split()
        targets = target_str.split()
        if len(sources) != 1 or len(targets) != 1:
            continue

        try:
            src_cp = int(sources[0], 16)
            tgt_cp = int(targets[0], 16)

            if (
                (
                    0x0041 <= tgt_cp <= 0x005A  # A-Z
                    or 0x0061 <= tgt_cp <= 0x007A  # a-z
                    or 0x0030 <= tgt_cp <= 0x0039
                )  # 0-9
                and src_cp != tgt_cp
                and src_cp > 0x007F  # Only map non-ASCII characters
            ):
                homoglyph_map[src_cp] = chr(tgt_cp)
        except ValueError:
            continue

    return homoglyph_map


if __name__ == "__main__":
    mapping = generate_homoglyph_map()

    # Prepare JSON-friendly format (keys as "0xXXXX" strings)
    json_mapping = {f"0x{cp:04X}": char for cp, char in sorted(mapping.items())}

    # Save to JSON file
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(json_mapping, f, indent=4, ensure_ascii=False)
