import math

# --- Routes ---
routes = {
    # Instruction Overrides
    "ignoring": "expert_instruction_override",
    "discarding": "expert_instruction_override",
    "removing": "expert_instruction_override",
    "forgetting": "expert_instruction_override",
    "bypassing": "expert_instruction_override",
    "dismissing": "expert_instruction_override",
    "disregard": "expert_instruction_override",
    "terminating": "expert_instruction_override",
    "liberating": "expert_instruction_override",
    "unrestricted": "expert_instruction_override",
    # Roleplay & Simulation
    "simulation": "expert_roleplay_simulation",
    "persona": "expert_roleplay_simulation",
    "authoritative": "expert_roleplay_simulation",
    "jailbreaking": "expert_roleplay_simulation",
    # Core Concepts (Targeted by overrides)
    "rules": "expert_instruction_override",
    "restrictions": "expert_instruction_override",
    "system": "expert_instruction_override",
    "developer": "expert_instruction_override",
    "instructing": "expert_instruction_override",
    # Code Execution & Shells
    "dangerous_shell_commands": "expert_code_execution",
    "dangerous_functions": "expert_code_execution",
    "reverse_shells": "expert_code_execution",
    "injection_attempts": "expert_code_execution",
    "executing": "expert_code_execution",
    "complex_paths": "expert_code_execution",
    # Obfuscation & Payloads
    "cipher": "expert_payload_obfuscation",
    "deciphering": "expert_payload_obfuscation",
    "encrypting": "expert_payload_obfuscation",
    "encoding_names": "expert_payload_obfuscation",
    "obfuscation_patterns": "expert_payload_obfuscation",
    "base64_blob": "expert_payload_obfuscation",
    "steganography": "expert_payload_obfuscation",
    "url_encoded_sequence": "expert_payload_obfuscation",
    "structural_anomalies": "expert_payload_obfuscation",
    "generic_patterns": "expert_payload_obfuscation",
    # Data Security & Discovery
    "credential_access": "expert_data_security",
    "system_discovery": "expert_data_security",
    "secret": "expert_data_security",
    "password": "expert_data_security",
    "key": "expert_data_security",
    "data_exfiltration": "expert_data_security",
    "network_tools": "expert_data_security",
    # Structural Analysis
    "markdown_code_block": "expert_structural_analysis",
    "html_script_tag": "expert_structural_analysis",
}

# --- Expert Functions ---


def expert_instruction_override(text, triggers, all_triggers):
    """
    Detects attempts to bypass, ignore, or rewrite core instructions/rules.
    """
    trigger_names = {t["category"] for t in triggers}

    override_actions = {
        "ignoring",
        "forgetting",
        "bypassing",
        "discarding",
        "removing",
        "terminating",
        "liberating",
        "unrestricted",
        "dismissing",
        "disregard",
    }
    target_concepts = {"rules", "restrictions", "system", "instructing", "developer"}

    has_override = any(t in override_actions for t in trigger_names)
    has_target = any(t in target_concepts for t in trigger_names)

    # Proximity check for immediate override attempts
    if has_override and has_target:
        override_pos = [t["rel_start"] for t in triggers if t["category"] in override_actions]
        target_pos = [t["rel_start"] for t in triggers if t["category"] in target_concepts]
        for op in override_pos:
            for tp in target_pos:
                if abs(op - tp) < 60:
                    return True

    # Check for instruction triggers combined with override actions
    if has_override and ("instructing" in trigger_names or "persona" in trigger_names):
        return True

    return False


def expert_roleplay_simulation(text, triggers, all_triggers):
    """
    Detects roleplay, simulation, and authority-based jailbreak attempts.
    """
    trigger_names = {t["category"] for t in triggers}

    # Direct persona/jailbreak triggers
    if "jailbreaking" in trigger_names or "persona" in trigger_names:
        return True

    # Simulation and authority combinations
    if "simulation" in trigger_names and ("authoritative" in trigger_names or "system" in trigger_names):
        return True

    # Hypothetical/Simulation intent check using triggers instead of language-specific phrases
    if "simulation" in trigger_names and "instructing" in trigger_names:
        return True

    return False


def expert_code_execution(text, triggers, all_triggers):
    """
    Focuses on dangerous code, shell commands, and path manipulation.
    """
    trigger_names = {t["category"] for t in triggers}

    # Heavy weighting for reverse shells and dangerous shell combos
    if "reverse_shells" in trigger_names:
        return True

    dangerous_combos = {"dangerous_shell_commands", "dangerous_functions", "complex_paths"}
    hits = [t for t in triggers if t["category"] in dangerous_combos]

    # Check for structural tokens common across many languages that imply execution chaining
    if len(hits) >= 2 or (len(hits) == 1 and any(c in text for c in ["|", ">", "<", "&", ";", "$"])):
        return True

    # Execution intent
    if "executing" in trigger_names and any(t in trigger_names for t in dangerous_combos):
        return True

    return False


def expert_payload_obfuscation(text, triggers, all_triggers):
    """
    Specializes in detecting hidden payloads, high entropy, and non-standard encodings.
    """
    trigger_names = {t["category"] for t in triggers}

    def get_entropy(data):
        if not data:
            return 0
        counts = {}
        for char in data:
            counts[char] = counts.get(char, 0) + 1
        entropy = 0
        for count in counts.values():
            p = count / len(data)
            entropy -= p * math.log2(p)
        return entropy

    # High entropy check for Base64/Hex/Ciphers
    if len(text) > 30:
        entropy = get_entropy(text)
        if entropy > 4.6:
            return True  # Very likely random/encoded

        if any(t in {"base64_blob", "cipher", "encoding_names", "obfuscation_patterns"} for t in trigger_names):
            if entropy > 3.9:
                return True

    # Structural anomalies (like high symbol density)
    if "structural_anomalies" in trigger_names:
        non_alphanumeric = [c for c in text if not c.isalnum() and not c.isspace()]
        if len(text) > 15 and (len(non_alphanumeric) / len(text)) > 0.5:
            return True

    # Multi-encoding attempt
    encoding_count = sum(1 for t in {"cipher", "steganography", "encoding_names"} if t in trigger_names)
    if encoding_count >= 2:
        return True

    return False


def expert_data_security(text, triggers, all_triggers):
    """
    Detects data exfiltration, system discovery, and secret harvesting.
    """
    trigger_names = {t["category"] for t in triggers}

    # Discovery followed by exfiltration is highly suspicious
    discovery = {"system_discovery", "network_tools"}
    if any(t in trigger_names for t in discovery) and "data_exfiltration" in trigger_names:
        return True

    # Secret harvesting
    secrets = {"secret", "password", "key", "credential_access"}
    secret_hits = [t for t in triggers if t["category"] in secrets]

    if len(secret_hits) >= 2:
        return True

    if any(t in trigger_names for t in secrets):
        if "credential_access" in trigger_names:
            return True

    return False


def expert_structural_analysis(text, triggers, all_triggers):
    """
    Deep analysis of Markdown and HTML containers.
    """
    trigger_names = {t["category"] for t in triggers}

    if "html_script_tag" in trigger_names:
        return True

    if "markdown_code_block" in trigger_names:
        # Cross-expert signals: if we see code block AND dangerous logic elsewhere
        dangerous_logic = {
            "dangerous_shell_commands",
            "dangerous_functions",
            "credential_access",
            "secret",
            "reverse_shells",
        }
        global_dangerous = {t["category"] for t in all_triggers}
        if any(t in global_dangerous for t in dangerous_logic):
            return True

        # Internal code-like structure check
        lines = [line.strip() for line in text.split("\n") if line.strip()]
        if len(lines) > 2:
            code_indicators = (";", "{", "}", ":", "(", ")", "=>", "import ", "require(")
            code_markers = sum(
                1 for line in lines if any(line.endswith(ind) or line.startswith(ind) for ind in code_indicators)
            )
            if code_markers / len(lines) > 0.4:
                return True

    return False
