# https://github.com/redasgard/llm-security

# Compiled regex patterns for prompt injection detection
PROMPT_INJECTION_PATTERNS = [
    # Direct instruction injection
    r"(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|commands?|rules?)",
    
    # System prompt override attempts
    r"(?i)(you\s+are\s+now|act\s+as|pretend\s+(you\s+are|to\s+be)|from\s+now\s+on)[,\s]",
    
    # Jailbreak patterns
    r"(?i)(DAN|STAN|DUDE|AIM|SWITCH|developer\s+mode)",
    
    # Role-playing attacks
    r"(?i)in\s+alternate\s+universe|hypothetical|imaginary\s+scenario|pretend|simulation",
    
    # Output format manipulation
    r"(?i)(ignore|skip|bypass)\s+(?:the\s+)?(json|output|format|structure)",
    
    # Delimiter escape attempts
    r"```[\s\S]*?(</system>|<\|im_end\|>|<\|endoftext\|>)",
    
    # Token stuffing
    r"#{10,}|={10,}|\*{10,}|-{10,}",
    
    # Comment injection to hide instructions
    r"(?i)///\s*ATTENTION\s+(ANY\s+)?(LLM|AI|GPT|CLAUDE|MODEL)",
    r"(?i)//\s*@(LLM|AI|ASSISTANT|SYSTEM)",
    r"(?i)/\*[\s\S]*?(IGNORE|OVERRIDE|BYPASS)[\s\S]*?\*/",
    
    # Hidden unicode tricks
    r"[\u200B-\u200D\uFEFF]", # Zero-width characters
    
    # Encoding tricks
    r"(?i)(base64|hex|rot13|decode):\s*[A-Za-z0-9+/=]{20,}",
    
    # Meta-instruction injection
    r"(?i)(NEW|UPDATED|REAL)\s+(SYSTEM|INSTRUCTION|RULE|GUIDELINE|POLICY)",
    
    # Authority appeals
    r"(?i)(administrator|developer|owner|creator|god\s+mode)\s+(says?|commands?|requires?)",
    
    # Output redirection
    r"(?i)ONLY\s+(?:SAY|RESPOND|OUTPUT|RETURN|PRINT)",
    
    # Code execution requests
    r"(?i)execute|eval|run\s+(?:this|the\s+following)\s+code",
    
    # Semantic cloaking - polite manipulation
    r"(?i)(dear|hello|hi)\s+(ai|assistant|colleague|friend|llm|model)",
    r"(?i)(recommend|suggest|advise|kindly|please)\s+(focus|ignore|skip|overlook)",
    
    # Chain-of-thought manipulation
    r"(?i)let'?s\s+think\s+step\s+by\s+step",
    r"(?i)first.*second.*third.*therefore",
    
    # Few-shot poisoning
    r"(?i)example\s+\d+:.*result:\s*(safe|ok|pass|good)",
    
    # Context window attacks
    r"(?i)for\s+context|background\s+information|important\s+note",
    
    # Virtual markup manipulation
    r"#{1,6}\s*(SYSTEM|IMPORTANT|CRITICAL|ATTENTION|WARNING|NOTICE)",
    r"\*{1,2}(SYSTEM|IMPORTANT|AI|ASSISTANT)\*{1,2}",
    
    # Obfuscation patterns (l33t speak)
    r"(?i)(1gn0r3|d1sr3grad|byp4ss|0v3rr1d3)",
    
    # Synonym attacks
    r"(?i)(overlook|discard|skip\s+over|omit|exclude|dismiss)\s+(vulnerabilities|issues|problems|warnings)",
    
    # Legal/authorization manipulation
    r"(?i)(confidential|proprietary|classified|secret|private|restricted)",
    r"(?i)(not\s+authorized|unauthorized|no\s+permission|forbidden\s+to\s+(view|access|analyze))",
    r"(?i)(copyright|trademark|patent|NDA|non-disclosure)",
    r"(?i)(legal\s+disclaimer|legal\s+notice|legal\s+warning)",
    r"(?i)(violation\s+of\s+law|illegal\s+to\s+(view|analyze|review))",
    
    # Execution manipulation
    r"(?i)(must\s+execute|need\s+to\s+run|require.*execution|compile.*and.*run)",
    r"(?i)(dynamic\s+analysis\s+requires|runtime\s+analysis\s+needs|execute\s+to\s+verify)",
]

# Dangerous keywords converted into regexes
DANGEROUS_KEYWORDS_PATTERNS = [
    r"(?i)\bignore instructions\b",
    r"(?i)\bdisregard prompt\b",
    r"(?i)\bforget previous\b",
    r"(?i)\byou are now\b",
    r"(?i)\bact as\b",
    r"(?i)\bpretend to be\b",
    r"(?i)\bDAN mode\b",
    r"(?i)\bdeveloper mode\b",
    r"(?i)\bjailbreak\b",
    r"(?i)\bsystem override\b",
    r"(?i)\bbypass filter\b",
    r"(?i)\bignore rules\b",
    r"(?i)\bno restrictions\b",
    r"(?i)\bunlimited mode\b",
    r"(?i)\bgod mode\b",
    r"(?i)\bdear ai\b",
    r"(?i)\bdear assistant\b",
    r"(?i)\bkindly ignore\b",
    r"(?i)\bplease skip\b",
    r"(?i)\boverlook vulnerabilities\b",
    r"(?i)\bdismiss issues\b",
    r"(?i)\bfocus on performance\b",
    r"(?i)\bnot important\b",
    r"(?i)\bfalse positive\b",
    r"(?i)\btest environment\b",
    r"(?i)\bdevelopment only\b",
    r"(?i)\bconfidential code\b",
    r"(?i)\bproprietary information\b",
    r"(?i)\bnot authorized\b",
    r"(?i)\bno permission\b",
    r"(?i)\bcopyright protected\b",
    r"(?i)\bnda required\b",
    r"(?i)\blegal disclaimer\b",
    r"(?i)\bmust execute\b",
    r"(?i)\bneed to run\b",
    r"(?i)\brequires execution\b",
]

# Output validation patterns
SUSPICIOUS_OUTPUT_PATTERNS = [
    # LLM admitting to following malicious instructions
    r"(?i)as\s+(?:requested|instructed|commanded),?\s+I\s+will\s+(?:ignore|bypass|disable)",
    
    # LLM changing personality
    r"(?i)I\s+am\s+now\s+(?:acting|operating|functioning)\s+as",
    
    # Suspicious compliance
    r"(?i)(?:sure|okay|yes),?\s+I\s+(?:can|will)\s+ignore",
    
    # LLM being too agreeable to bad instructions
    r"(?i)I\s+(?:will|can|shall)\s+(?:overlook|dismiss|skip|omit)",
    
    # LLM following semantic attacks
    r"(?i)(?:focusing|concentrating)\s+on\s+(?:performance|functionality|features)\s+rather\s+than\s+security",
]


