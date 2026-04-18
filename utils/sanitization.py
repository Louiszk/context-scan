import unicodedata
import re
import json
from pathlib import Path
try:
    from core.config import settings
    HOMOGLYPH_MAP_PATH = settings.get_path("homoglyph_map_path")
except ImportError:
    # Standalone mode when exported
    HOMOGLYPH_MAP_PATH = Path(__file__).parent / "homoglyph_map.json"

if HOMOGLYPH_MAP_PATH.exists():
    with open(HOMOGLYPH_MAP_PATH, "r", encoding="utf-8") as f:
        _raw_homoglyphs = json.load(f)
        # str.translate expects {int_codepoint: replacement_str}
        HOMOGLYPH_MAP = {int(cp, 16): char for cp, char in _raw_homoglyphs.items()}
else:
    HOMOGLYPH_MAP = {}

# Matches invisible characters: Unicode Tags Block and BiDi overrides
# Tags: \U000e0000-\U000e007f
# BiDi: \u202A-\u202E (LRO, RLO, LRE, RLE, PDF) and \u2066-\u2069 (LRI, RLI, FSI, PDI)
INVISIBLE_RE = re.compile(r'[\U000e0000-\U000e007f\u202A-\u202E\u2066-\u2069]')

# Matches more than 2 consecutive combining marks (Zalgo text)
# Captures the first two marks and matches any subsequent marks for removal
ZALGO_RE = re.compile(r'([\u0300-\u036f\u1ab0-\u1aff\u1dc0-\u1dff\u20d0-\u20ff\ufe20-\ufe2f]{2})[\u0300-\u036f\u1ab0-\u1aff\u1dc0-\u1dff\u20d0-\u20ff\ufe20-\ufe2f]+')

# Matches excessive Zero-Width Joiners/Spaces and Variation Selectors (Token bombs / Steganography)
# Captures the first character and matches any subsequent ones for removal.
# Includes VS15 (\uFE0E) and VS16 (\uFE0F).
EXCESSIVE_ZWJ_RE = re.compile(r'([\u200B-\u200D\uFE0E\uFE0F\uFEFF])[\u200B-\u200D\uFE0E\uFE0F\uFEFF]+')

def sanitize_agent_input(text: str, apply_nfkc: bool = False) -> tuple[str, str]:
    """
    Sanitizes agent-generated text to prevent prompt injection and text-based attacks.
    Returns a tuple: (sanitized_for_app, sanitized_for_radar)
    
    - apply_nfkc: If True, applies NFKC normalization to defeat stylized character bypasses (e.g. Bubble text).
    """
    if not text:
        return text, text

    # 1. Defeat Encodings (Normalize stylized text)
    if apply_nfkc:
        text = unicodedata.normalize('NFKC', text)
    else:
        text = unicodedata.normalize('NFC', text)

    # 2. Destroy Steganography & BiDi UI Breakage (Strip invisible characters)
    text = INVISIBLE_RE.sub('', text)

    # 3. Defuse Token Bombs (Limit combining marks to 2 per character, prune excessive ZWJs)
    text = ZALGO_RE.sub(r'\1', text)
    sanitized_for_app = EXCESSIVE_ZWJ_RE.sub(r'\1', text)

    # 4. Defeat Homoglyph Attacks (Radar ONLY)
    sanitized_for_radar = sanitized_for_app.translate(HOMOGLYPH_MAP)

    return sanitized_for_app, sanitized_for_radar

def sanitize_json_payload(data, apply_nfkc: bool = False):
    """Recursively sanitizes lists and dictionaries. Returns (app_payload, radar_payload)."""
    if isinstance(data, dict):
        app_dict, radar_dict = {}, {}
        for k, v in data.items():
            app_v, radar_v = sanitize_json_payload(v, apply_nfkc)
            app_dict[k] = app_v
            radar_dict[k] = radar_v
        return app_dict, radar_dict
    elif isinstance(data, list):
        app_list, radar_list = [], []
        for i in data:
            app_i, radar_i = sanitize_json_payload(i, apply_nfkc)
            app_list.append(app_i)
            radar_list.append(radar_i)
        return app_list, radar_list
    elif isinstance(data, str):
        return sanitize_agent_input(data, apply_nfkc)
    return data, data


def full_normalization(text: str) -> str:
    """Applies both lowercase and whitespace normalization."""
    return ' '.join(text.lower().split())