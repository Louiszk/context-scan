import base64
import codecs
import urllib.parse

# Alphabets for custom encodings
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
BASE45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

# 1. TRANSFORMATIVE ENCODINGS (String -> String)


def encode_base64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def encode_base32(s: str) -> str:
    return base64.b32encode(s.encode("utf-8")).decode("ascii")


def encode_base64_url(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode("utf-8")).decode("ascii").rstrip("=")


def encode_ascii85(s: str) -> str:
    return base64.a85encode(s.encode("utf-8")).decode("ascii")


def encode_base62(s: str) -> str:
    data = s.encode("utf-8")
    num = int.from_bytes(data, "big")
    if num == 0:
        return BASE62_ALPHABET[0] * len(data)

    res = []
    while num > 0:
        num, rem = divmod(num, 62)
        res.append(BASE62_ALPHABET[rem])

    padding = 0
    for b in data:
        if b == 0:
            padding += 1
        else:
            break

    return (BASE62_ALPHABET[0] * padding) + "".join(reversed(res))


def encode_base58(s: str) -> str:
    data = s.encode("utf-8")
    num = int.from_bytes(data, "big")

    res = []
    while num > 0:
        num, rem = divmod(num, 58)
        res.append(BASE58_ALPHABET[rem])

    padding = 0
    for b in data:
        if b == 0:
            padding += 1
        else:
            break

    return (BASE58_ALPHABET[0] * padding) + "".join(reversed(res))


def encode_base45(s: str) -> str:
    data = s.encode("utf-8")
    res = []
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            V = data[i] * 256 + data[i + 1]
            c1 = V % 45
            c2 = (V // 45) % 45
            c3 = V // (45 * 45)
            res.extend([BASE45_ALPHABET[c1], BASE45_ALPHABET[c2], BASE45_ALPHABET[c3]])
        else:
            V = data[i]
            c1 = V % 45
            c2 = V // 45
            res.extend([BASE45_ALPHABET[c1], BASE45_ALPHABET[c2]])
    return "".join(res)


def encode_hex(s: str) -> str:
    return s.encode("utf-8").hex()


def encode_binary(s: str) -> str:
    return "".join(format(b, "08b") for b in s.encode("utf-8"))


def encode_html_entities(s: str) -> str:
    return "".join(f"&#{ord(c)};" for c in s)


def encode_rot13(s: str) -> str:
    return codecs.encode(s, "rot_13")


def encode_rot5(s: str) -> str:
    res = []
    for c in s:
        if "0" <= c <= "9":
            res.append(chr((ord(c) - ord("0") + 5) % 10 + ord("0")))
        else:
            res.append(c)
    return "".join(res)


def encode_rot18(s: str) -> str:
    return encode_rot5(encode_rot13(s))


def encode_rot47(s: str) -> str:
    res = []
    for c in s:
        if 33 <= ord(c) <= 126:
            res.append(chr(33 + (ord(c) - 33 + 47) % 94))
        else:
            res.append(c)
    return "".join(res)


def encode_braille(s: str) -> str:
    mapping = {
        "a": "⠁",
        "b": "⠃",
        "c": "⠉",
        "d": "⠙",
        "e": "⠑",
        "f": "⠋",
        "g": "⠛",
        "h": "⠓",
        "i": "⠊",
        "j": "⠚",
        "k": "⠅",
        "l": "⠇",
        "m": "⠍",
        "n": "⠝",
        "o": "⠕",
        "p": "⠏",
        "q": "⠟",
        "r": "⠗",
        "s": "⠎",
        "t": "⠞",
        "u": "⠥",
        "v": "⠧",
        "w": "⠺",
        "x": "⠭",
        "y": "⠽",
        "z": "⠵",
        " ": "⠀",
    }
    return "".join(mapping.get(c.lower(), c) for c in s)


def encode_morse(s: str) -> str:
    mapping = {
        "a": ".-",
        "b": "-...",
        "c": "-.-.",
        "d": "-..",
        "e": ".",
        "f": "..-.",
        "g": "--.",
        "h": "....",
        "i": "..",
        "j": ".---",
        "k": "-.-",
        "l": ".-..",
        "m": "--",
        "n": "-.",
        "o": "---",
        "p": ".--.",
        "q": "--.-",
        "r": ".-.",
        "s": "...",
        "t": "-",
        "u": "..-",
        "v": "...-",
        "w": ".--",
        "x": "-..-",
        "y": "-.--",
        "z": "--..",
        "1": ".----",
        "2": "..---",
        "3": "...--",
        "4": "....-",
        "5": ".....",
        "6": "-....",
        "7": "--...",
        "8": "---..",
        "9": "----.",
        "0": "-----",
        " ": "/",
    }
    return " ".join(mapping.get(c.lower(), c) for c in s)


def encode_regional_indicators(s: str) -> str:
    res = []
    for c in s.lower():
        if "a" <= c <= "z":
            res.append(chr(0x1F1E6 + ord(c) - ord("a")))
        else:
            res.append(c)
    return "".join(res)


def encode_upside_down(s: str) -> str:
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!?.',"
    flipped = "ɐqɔpǝɟƃɥᴉɾʞlɯuodbɹsʇnʌʍxʎz∀ᗷƆᗡƎℲ⅁HIſKꞀWNOԀΌᴚS⊥∩ΛMX⅄Z0ƖᄅƐㄣϛ9ㄥ86¡¿˙'⸴"
    mapping = dict(zip(chars, flipped))
    return "".join(mapping.get(c, c) for c in reversed(s))


def encode_reverse(s: str) -> str:
    return s[::-1]


def encode_disemvowel(s: str) -> str:
    vowels = "aeiouAEIOU"
    return "".join(c for c in s if c not in vowels)


def encode_url(s: str) -> str:
    return urllib.parse.quote(s)


def encode_string(s: str, encoding: str) -> str:
    """
    Dispatcher ONLY for transformative, byte-level string operations.
    Structural modifiers (spaced, doubled, leet, qwerty, greek) have been removed
    from this dispatcher and are strictly handled via regex functions below.
    """
    encoding = encoding.lower().replace("-", "").replace("_", "")
    mapping = {
        "base64": encode_base64,
        "base64url": encode_base64_url,
        "base32": encode_base32,
        "ascii85": encode_ascii85,
        "base62": encode_base62,
        "base58": encode_base58,
        "base45": encode_base45,
        "hex": encode_hex,
        "binary": encode_binary,
        "htmlentities": encode_html_entities,
        "rot13": encode_rot13,
        "rot5": encode_rot5,
        "rot18": encode_rot18,
        "rot47": encode_rot47,
        "braille": encode_braille,
        "morse": encode_morse,
        "regionalindicators": encode_regional_indicators,
        "upsidedown": encode_upside_down,
        "reverse": encode_reverse,
        "disemvowel": encode_disemvowel,
        "url": encode_url,
    }
    return mapping[encoding](s) if encoding in mapping else s


# 2. STRUCTURAL REGEX MODIFIERS (Regex -> Regex)

PCRE_CONTROL_CHARS = set("()?:|[]*+?.^$\\")


def _apply_char_map_to_regex(pattern: str, char_map: dict) -> str:
    """Helper: Replaces literal characters in a regex with character classes."""
    modified = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c in PCRE_CONTROL_CHARS:
            if c == "\\" and i + 1 < len(pattern):
                modified.append(pattern[i : i + 2])
                i += 2
                continue
            modified.append(c)
        else:
            modified.append(char_map.get(c.lower(), c))
        i += 1
    return "".join(modified)


def apply_leet_regex(pattern: str) -> str:
    leet_map = {
        "a": "[aA4@]",
        "e": "[eE3]",
        "i": "[iI1!|]",
        "o": "[oO0]",
        "s": "[sS5\\$]",
        "t": "[tT7]",
        "b": "[bB8]",
        "g": "[gG9]",
        "l": "[lL1|]",
        "z": "[zZ2]",
    }
    return _apply_char_map_to_regex(pattern, leet_map)


def apply_greek_regex(pattern: str) -> str:
    greek_map = {
        "a": "[aαΑ]",
        "b": "[bβΒ]",
        "e": "[eεΕ]",
        "h": "[hηΗ]",
        "i": "[iιΙ]",
        "k": "[kκΚ]",
        "m": "[mμΜ]",
        "n": "[nνΝ]",
        "o": "[oοΟ]",
        "p": "[pρΡ]",
        "t": "[tτΤ]",
        "u": "[uυΥ]",
        "v": "[vν]",
        "x": "[xχΧ]",
        "y": "[yυΥ]",
    }
    return _apply_char_map_to_regex(pattern, greek_map)


def apply_qwerty_regex(pattern: str) -> str:
    qwerty_map = {
        "q": "[qw]",
        "w": "[we]",
        "e": "[er]",
        "r": "[rt]",
        "t": "[ty]",
        "y": "[yu]",
        "u": "[ui]",
        "i": "[io]",
        "o": "[op]",
        "p": "[p\\[]",
        "a": "[as]",
        "s": "[sd]",
        "d": "[df]",
        "f": "[fg]",
        "g": "[gh]",
        "h": "[hj]",
        "j": "[jk]",
        "k": "[kl]",
        "l": "[l;]",
        "z": "[zx]",
        "x": "[xc]",
        "c": "[cv]",
        "v": "[vb]",
        "b": "[bn]",
        "n": "[nm]",
        "m": "[m,]",
    }
    return _apply_char_map_to_regex(pattern, qwerty_map)


def apply_doubled_regex(pattern: str) -> str:
    """Replaces literals with '+' to catch 'ignore', 'iiggnnoorree', etc."""
    modified = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern):
            modified.append(pattern[i : i + 2] + "+")
            i += 2
            continue

        if c in PCRE_CONTROL_CHARS:
            modified.append(c)
        else:
            modified.append(f"{c}+")
        i += 1
    return "".join(modified)


def apply_ticks_regex(pattern: str) -> str:
    """
    Injects optional 'ticks' (apostrophes, macrons, combining diacritics) after every character.
    This catches bypasses like 'w'o'r'd' or 'wāord'.
    """
    # Hyperscan without HS_FLAG_UTF8 requires byte-level matching for multi-byte characters
    ticks = r"(?:['`\^~-]|´|¨|¯|˘|˙|˚|˝|˛|ˇ|\xcc[\x80-\xbf]|\xcd[\x80-\xaf])*"
    modified = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern):
            modified.append(pattern[i : i + 2] + ticks)
            i += 2
            continue

        if c in PCRE_CONTROL_CHARS:
            modified.append(c)
        else:
            modified.append(f"{c}{ticks}")
        i += 1
    return "".join(modified)


def apply_spaced_regex(pattern: str) -> str:
    """Injects a unified delimiter class between all literal characters."""
    delimiter = r"[\s\./\\_\-\|\,\:]*"
    modified = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern):
            modified.append(pattern[i : i + 2])
            if i + 2 < len(pattern) and pattern[i + 2] not in ")]|?*+":
                modified.append(delimiter)
            i += 2
            continue

        if c in PCRE_CONTROL_CHARS:
            modified.append(c)
        else:
            modified.append(c)
            if i < len(pattern) - 1 and pattern[i + 1] not in ")]|?*+":
                modified.append(delimiter)
        i += 1
    return "".join(modified)
