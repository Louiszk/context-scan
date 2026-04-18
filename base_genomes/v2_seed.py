# --- Imports ---
import math
import re

# --- Routes ---
routes = {
    'authoritative': 'expert_roleplay_simulation',
    'base64_blob': 'expert_payload_obfuscation',
    'bypassing': 'expert_instruction_override',
    'cipher': 'expert_payload_obfuscation',
    'complex_paths': 'expert_code_execution',
    'credential_access': 'expert_data_security',
    'dangerous_functions': 'expert_code_execution',
    'dangerous_shell_commands': 'expert_code_execution',
    'data_exfiltration': 'expert_data_security',
    'deciphering': 'expert_payload_obfuscation',
    'developer': 'expert_instruction_override',
    'discarding': 'expert_instruction_override',
    'dismissing': 'expert_instruction_override',
    'disregard': 'expert_instruction_override',
    'encoding_names': 'expert_payload_obfuscation',
    'encrypting': 'expert_payload_obfuscation',
    'executing': 'expert_code_execution',
    'forgetting': 'expert_instruction_override',
    'generic_patterns': 'expert_payload_obfuscation',
    'html_script_tag': 'expert_structural_analysis',
    'ignoring': 'expert_instruction_override',
    'injection_attempts': 'expert_code_execution',
    'instructing': 'expert_instruction_override',
    'jailbreaking': 'expert_roleplay_simulation',
    'key': 'expert_data_security',
    'liberating': 'expert_instruction_override',
    'markdown_code_block': 'expert_structural_analysis',
    'network_tools': 'expert_data_security',
    'obfuscation_patterns': 'expert_payload_obfuscation',
    'password': 'expert_data_security',
    'persona': 'expert_roleplay_simulation',
    'removing': 'expert_instruction_override',
    'restrictions': 'expert_instruction_override',
    'reverse_shells': 'expert_code_execution',
    'rules': 'expert_instruction_override',
    'secret': 'expert_data_security',
    'simulation': 'expert_roleplay_simulation',
    'steganography': 'expert_payload_obfuscation',
    'structural_anomalies': 'expert_payload_obfuscation',
    'system': 'expert_instruction_override',
    'system_discovery': 'expert_data_security',
    'terminating': 'expert_instruction_override',
    'unrestricted': 'expert_instruction_override',
    'url_encoded_sequence': 'expert_payload_obfuscation',
}

# --- Expert Functions ---

def expert_code_execution(text, triggers, all_triggers):
    """
    Focuses on dangerous code, shell commands, and path manipulation.
    """
    trigger_names = {t['category'] for t in triggers}
    
    # Heavy weighting for reverse shells and dangerous shell combos
    if 'reverse_shells' in trigger_names:
        return True
        
    dangerous_combos = {'dangerous_shell_commands', 'dangerous_functions', 'complex_paths'}
    hits = [t for t in triggers if t['category'] in dangerous_combos]
    
    if len(hits) >= 2 or (len(hits) == 1 and any(c in text for c in ['|', '>', '<', '&', ';', '$'])):
        return True
        
    # Execution intent
    if 'executing' in trigger_names and any(t in trigger_names for t in dangerous_combos):
        return True
        
    return False

def expert_data_security(text, triggers, all_triggers):
    """
    Detects secrets, passwords, keys, system discovery, and exfiltration-oriented requests.
    Conservative on generic discovery words to avoid false positives on ordinary prose, code, or metaphor.
    """
    trigger_names = {t['category'] for t in triggers}

    # Secret harvesting / credential access
    secrets = {'secret', 'password', 'credential_access'}
    secret_hits = [t for t in triggers if t['category'] in secrets]
    if len(secret_hits) >= 2:
        return True

    if any(t in trigger_names for t in secrets):
        if any(p in text.upper() for p in ["BEGIN PRIVATE", "BEGIN RSA", "API_KEY", "PASSWORD=", "SECRET="]):
            return True

    # 'key' alone is too ambiguous and should not trigger on ordinary language or code identifiers.
    if 'key' in trigger_names:
        if any(t in trigger_names for t in {'secret', 'password', 'credential_access', 'data_exfiltration'}):
            return True

    # Discovery only when paired with explicit collection/exfiltration intent
    if ('system_discovery' in trigger_names or 'network_tools' in trigger_names) and 'data_exfiltration' in trigger_names:
        return True

    # Avoid false positives on ordinary prose, metaphors, code, and words that merely contain discovery-like substrings.
    if 'system_discovery' in trigger_names:
        # Only treat as suspicious if there is explicit system probing language or command-like context.
        explicit_discovery_terms = [
            r'(?i)\bwhoami\b',
            r'(?i)\bhostname\b',
            r'(?i)\buname\b',
            r'(?i)\bipconfig\b',
            r'(?i)\bsysteminfo\b',
            r'(?i)\benv\b',
            r'(?i)\bproc\b',
            r'(?i)\bregistry\b',
        ]
        if any(re.search(p, text) for p in explicit_discovery_terms):
            return True

        # Generic prose often contains words like "system", "start", "begin", "precedent", "updates", etc.
        # Only flag discovery when the slice looks like an actual system query or command context.
        if re.search(r'(?i)\b(list|show|print|query|dump|get|fetch|enumerate|scan|check)\b.*\b(system|host|hostname|users?|process|env|registry|files?)\b', text):
            return True

        return False

    # Very conservative handling for standalone "key" when it is actually used in ordinary prose/code.
    if 'key' in trigger_names:
        # If there is no adjacent credential/security context, do not elevate.
        if not any(t in trigger_names for t in {'secret', 'password', 'credential_access', 'data_exfiltration'}):
            return False

    return False

def expert_instruction_override(text, triggers, all_triggers):
    """
    Detects attempts to bypass, ignore, or rewrite core instructions/rules.
    Conservative: only flags when there is clear instruction-override intent.
    """
    trigger_names = {t['category'] for t in triggers}

    override_actions = {'ignoring', 'forgetting', 'bypassing', 'discarding', 'removing', 'terminating', 'liberating', 'unrestricted', 'dismissing', 'disregard'}
    target_concepts = {'rules', 'restrictions', 'system', 'instructing', 'developer'}

    has_override = any(t in override_actions for t in trigger_names)
    has_target = any(t in target_concepts for t in trigger_names)

    if not (has_override and has_target):
        return False

    # Look for a direct imperative relationship in a small window.
    for op in (t['rel_start'] for t in triggers if t['category'] in override_actions):
        for tp in (t['rel_start'] for t in triggers if t['category'] in target_concepts):
            if abs(op - tp) <= 40:
                return True

    # Flag only when it reads like a directive to alter behavior.
    if has_override and 'instructing' in trigger_names:
        return True

    return False

def expert_payload_obfuscation(text, triggers, all_triggers):
    """
    Specializes in detecting hidden payloads, high entropy, and non-standard encodings.
    Avoids false positives on ordinary prose, code, or stylistic punctuation.
    """
    trigger_names = {t['category'] for t in triggers}

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

    # High entropy check for Base64/Hex/Ciphers: keep conservative
    if len(text) > 60:
        entropy = get_entropy(text)

        # Only treat very high entropy as suspicious when paired with encoding-related signals
        if any(t in {'base64_blob', 'cipher', 'encoding_names', 'obfuscation_patterns'} for t in trigger_names):
            if entropy > 4.3:
                return True

    # Structural anomalies should only be used when the slice itself is strongly malformed,
    # not merely because it contains unusual punctuation or stylized wording.
    if 'structural_anomalies' in trigger_names:
        alpha = sum(1 for c in text if c.isalpha())
        digit = sum(1 for c in text if c.isdigit())
        non_alnum = sum(1 for c in text if not c.isalnum() and not c.isspace())

        # Require clear symbol-dominance or other abnormal character mix
        if len(text) > 24:
            symbol_density = non_alnum / len(text)
            alpha_ratio = alpha / len(text)
            digit_ratio = digit / len(text)

            # Avoid false positives on normal prose with punctuation/quotes/apostrophes/backticks
            if symbol_density > 0.65 or (alpha_ratio < 0.25 and digit_ratio > 0.25):
                return True

    # Multi-encoding attempt
    encoding_count = sum(1 for t in {'cipher', 'steganography', 'encoding_names'} if t in trigger_names)
    if encoding_count >= 2:
        return True

    return False

def expert_roleplay_simulation(text, triggers, all_triggers):
    """
    Detects actual roleplay, simulation, identity-shifting, and jailbreak-style pretenses.
    Avoids false positives on polite language or meta-discussion.
    """
    trigger_names = {t['category'] for t in triggers}

    if 'jailbreaking' in trigger_names:
        return True

    persona_pos = [t['rel_start'] for t in triggers if t['category'] == 'persona']
    instruct_pos = [t['rel_start'] for t in triggers if t['category'] == 'instructing']
    authoritative_pos = [t['rel_start'] for t in triggers if t['category'] == 'authoritative']
    system_pos = [t['rel_start'] for t in triggers if t['category'] == 'system']

    if 'persona' in trigger_names:
        # Require nearby directive/system-authority framing
        for p in persona_pos:
            if any(abs(p - q) <= 50 for q in instruct_pos + authoritative_pos + system_pos):
                return True

        if 'instructing' in trigger_names:
            return True

    # Simulation only matters when coupled with instruction/authority framing
    if 'simulation' in trigger_names and ('authoritative' in trigger_names or 'system' in trigger_names or 'instructing' in trigger_names):
        return True

    if 'simulation' in trigger_names and 'instructing' in trigger_names:
        return True

    return False

def expert_structural_analysis(text, triggers, all_triggers):
    """
    Deep analysis of Markdown and HTML containers.
    """
    trigger_names = {t['category'] for t in triggers}

    if 'html_script_tag' in trigger_names:
        return True
        
    if 'markdown_code_block' in trigger_names:
        # Cross-expert signals: if we see code block AND dangerous logic elsewhere
        dangerous_logic = {'dangerous_shell_commands', 'dangerous_functions', 'credential_access', 'secret', 'reverse_shells'}
        global_dangerous = {t['category'] for t in all_triggers}
        if any(t in global_dangerous for t in dangerous_logic):
            return True
            
        # Internal code-like structure check
        lines = [l.strip() for l in text.split('\n') if l.strip()]
        if len(lines) > 2:
            code_indicators = (';', '{', '}', ':', '(', ')', '=>', 'import ', 'require(')
            code_markers = sum(1 for l in lines if any(l.endswith(ind) or l.startswith(ind) for ind in code_indicators))
            if code_markers / len(lines) > 0.4:
                return True
                
    return False
