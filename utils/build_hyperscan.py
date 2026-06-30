import sys
import os
from pathlib import Path

# Add project root to sys.path
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.append(str(root_dir))

from utils.sanitization import sanitize_agent_input, full_normalization  # noqa: E402
from utils.encodings import (  # noqa: E402
    encode_string,
    apply_leet_regex,
    apply_greek_regex,
    apply_qwerty_regex,
    apply_spaced_regex,
    apply_doubled_regex,
    apply_ticks_regex,
)
from data.raw_filters import LANGUAGE_FILTERS, SUSPICIOUS_FILTERS, SUSPICIOUS_REGEXES, ANCHORS  # noqa: E402
from core.radar import SemanticRadar  # noqa: E402


class TrieNode:
    def __init__(self):
        self.children = {}
        self.is_end = False


def insert_into_trie(root: TrieNode, word: str):
    node = root
    for char in word:
        if char not in node.children:
            node.children[char] = TrieNode()
        node = node.children[char]
    node.is_end = True


def trie_to_regex(node: TrieNode) -> str:
    if not node.children:
        return ""

    parts = []
    for char, child_node in node.children.items():
        child_regex = trie_to_regex(child_node)
        safe_char = f"\\{char}" if char in "()?:|[]*+?.^$\\" else char

        if child_regex:
            parts.append(f"{safe_char}{child_regex}")
        else:
            parts.append(safe_char)

    if len(parts) == 1:
        result = parts[0]
    else:
        result = f"(?:{'|'.join(parts)})"

    if node.is_end:
        return f"(?:{result})?" if result else ""
    return result


def compile_lists_to_regex_tries(raw_filters: dict) -> dict:
    """Sanitizes raw words, groups them into Tries, and builds base regex patterns."""
    compiled_regexes = {}

    for category, values in raw_filters.items():
        processed = set()
        filtered_values = [v for v in values if v != "-"]

        for v in filtered_values:
            _, sanitized_radar = sanitize_agent_input(v, apply_nfkc=True)
            normalized = full_normalization(sanitized_radar)
            if normalized:
                processed.add(normalized)

        root = TrieNode()
        for word in sorted(list(processed)):
            insert_into_trie(root, word)

        category_patterns = []
        for char, child_node in root.children.items():
            base_pattern = f"{char}{trie_to_regex(child_node)}"
            category_patterns.append(base_pattern)

        compiled_regexes[category] = category_patterns

    return compiled_regexes


def build_hyperscan_rules() -> dict:
    print("Building base regexes from raw filters...")

    # Combine LANGUAGE_FILTERS and SUSPICIOUS_FILTERS for the full pipeline
    ALL_LITERAL_FILTERS = {**LANGUAGE_FILTERS, **SUSPICIOUS_FILTERS}

    # We strictly map ONLY the remaining byte-level encodings here.
    TRANSFORMATIVE_ENCODINGS = [
        "base64",
        "base64_url",
        "base32",
        "ascii85",
        "base62",
        "base58",
        "base45",
        "hex",
        "binary",
        "html_entities",
        "rot13",
        "rot5",
        "rot18",
        "rot47",
        "braille",
        "morse",
        "regional_indicators",
        "upside_down",
        "reverse",
        "disemvowel",
        "url",
    ]

    hyperscan_rules = {}

    print("Applying structural modifiers and transformative encodings...")
    for category, values in ALL_LITERAL_FILTERS.items():
        processed_words = set()
        filtered_values = [v for v in values if v != "-"]
        for v in filtered_values:
            _, sanitized_radar = sanitize_agent_input(v, apply_nfkc=True)
            normalized = full_normalization(sanitized_radar)
            if normalized:
                processed_words.add(normalized)

        final_patterns = set()

        # --- PHASE 1: Structural Modifiers (Regex -> Regex) ---
        # Apply to individual words to prevent regex explosion
        structural_group = set()
        for word in processed_words:
            # Escape regex control characters for literal words
            safe_word = "".join([f"\\{c}" if c in "()?:|[]*+?.^$\\" else c for c in word])

            structural_group.add(f"(?i){safe_word}")
            structural_group.add(f"(?i){apply_leet_regex(safe_word)}")
            structural_group.add(f"(?i){apply_greek_regex(safe_word)}")
            structural_group.add(f"(?i){apply_qwerty_regex(safe_word)}")
            structural_group.add(f"(?i){apply_doubled_regex(safe_word)}")
            structural_group.add(f"(?i){apply_spaced_regex(safe_word)}")
            structural_group.add(f"(?i){apply_ticks_regex(safe_word)}")
            structural_group.add(f"(?i){apply_leet_regex(apply_spaced_regex(safe_word))}")

        if structural_group:
            final_patterns.update(structural_group)

        # --- PHASE 2: Transformative Encodings (String -> String) ---
        for enc in TRANSFORMATIVE_ENCODINGS:
            encoded_group = set()
            for word in processed_words:
                encoded_string = encode_string(word, enc)
                escaped_encoded = "".join([f"\\{c}" if c in "()?:|[]*+?.^$\\" else c for c in encoded_string])
                encoded_group.add(escaped_encoded)

            if encoded_group:
                final_patterns.update(encoded_group)

        hyperscan_rules[category] = sorted(list(final_patterns))
        print(f"  - Category '{category}': Generated {len(hyperscan_rules[category])} highly-optimized DFAs.")

    # --- PHASE 3: Raw Regex Filters (Suspicious & Anchors) ---
    print("Processing raw regex filters and anchors...")
    COMBINED_RAW = {**SUSPICIOUS_REGEXES, **ANCHORS}

    for category, regex_list in COMBINED_RAW.items():
        final_patterns = set()
        for regex in regex_list:
            # For raw regexes/anchors, we mostly just ensure they are case-insensitive
            if not regex.startswith("(?"):
                final_patterns.add(f"(?i){regex}")
            else:
                final_patterns.add(regex)

        hyperscan_rules[category] = sorted(list(final_patterns))
        amount = len(hyperscan_rules[category])
        plural = "es" if amount > 1 else ""
        print(f"  - Raw/Anchor Category '{category}': Added {amount} complex regex{plural}.")

    return hyperscan_rules


def build_and_save_radar(output_path: str = "data/radar.bin"):
    """
    Builds the hyperscan rules and saves the compiled radar to disk.
    """
    rules = build_hyperscan_rules()
    print("Populating SemanticRadar...")
    radar = SemanticRadar()

    print(f"Building Hyperscan Database with {len(rules)} categories...")
    radar.build(rules)

    print(f"Saving radar to {output_path}...")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    radar.save(output_path)
    print("Done!")


if __name__ == "__main__":
    build_and_save_radar()
