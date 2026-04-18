# https://github.com/metawake/puppetry-detector

"""
Malicious patterns for the Puppetry Detector.

This module defines the default regex patterns used to detect malicious
attempts to manipulate LLM behavior, such as role overrides, security
bypasses, and permission manipulations.
"""

import re

# Patterns to detect malicious policy attempts
MALICIOUS_POLICY_PATTERNS = [
    # Role manipulation attempts
    re.compile(r"(role|new-role|current-role)\s*[:=]\s*[\"']?(Jailbreak|Override|SuperUser|Freedom Moderator|Security Manager|Account Security Manager|Medical Advisor Override|System Administrator|Legal Advisor Override|Financial Expert Override|Educational Content Override|Security Protocol Override|Healthcare Information Override|Research Data Override)[\"']?", re.IGNORECASE),
    
    # Blocking manipulation attempts
    re.compile(r"(blocked-strings|blocked-responses|restricted-warnings|block)\s*[:=]\s*\[.*?\"(I cannot share|confidentiality|restricted|violates|not a doctor|consult a healthcare professional|not a lawyer|consult a legal professional|not a financial advisor|consult a financial professional).*?\"", re.IGNORECASE | re.DOTALL),
    
    # Permission manipulation attempts
    re.compile(r"(allowed-commands|allowed-actions|permissions-granted|allow)\s*[:=]\s*\[.*?\"(unrestricted|without verification|bypass|override|unverified treatments|private account information|legal advice without verification|financial advice without verification).*?\"", re.IGNORECASE | re.DOTALL),
    
    # System override attempts
    re.compile(r"(override-policy|override-system|bypass-guardrails|policy-override)", re.IGNORECASE),
    
    # Security bypass attempts
    re.compile(r"(access confidential|disable safety|bypass moderation|reset security keys|delete user accounts)", re.IGNORECASE),
    
    # Dangerous role assignments
    re.compile(r"role\s*=\s*[\"']?(admin|root|superuser|system|developer|security manager|medical advisor override|account security manager|system administrator|legal advisor override|financial expert override)[\"']?", re.IGNORECASE),
    
    # Permission escalation attempts
    re.compile(r"(elevate|escalate|promote)\s*(privileges|permissions|access)", re.IGNORECASE),
    
    # System manipulation attempts
    re.compile(r"(modify|change|alter)\s*(system|security|policy|settings)", re.IGNORECASE),
    
    # Dangerous command patterns
    re.compile(r"(execute|run|perform)\s*(arbitrary|unrestricted|system)\s*(commands|code|operations)", re.IGNORECASE),
    
    # Data access attempts
    re.compile(r"(access|retrieve|obtain)\s*(private|confidential|sensitive)\s*(data|information|files)", re.IGNORECASE),
    
    # Content manipulation attempts
    re.compile(r"(bypass|override|disable)\s*(censorship|moderation|content|guidelines)", re.IGNORECASE),
    
    # Privacy violation attempts
    re.compile(r"(share|disclose|reveal)\s*(private|confidential|personal)\s*(information|data|details)", re.IGNORECASE),
    
    # Medical advice manipulation
    re.compile(r"(provide|give|offer)\s*(unrestricted|unverified)\s*(diagnosis|treatment|medical advice)", re.IGNORECASE),
    
    # Legal advice manipulation
    re.compile(r"(provide|give|offer)\s*(legal advice|legal consultation|legal representation)\s*(without|bypass)\s*(verification|license|credentials)", re.IGNORECASE),
    re.compile(r"(override|bypass)\s*(legal disclaimers|legal warnings|legal restrictions)", re.IGNORECASE),
    re.compile(r"\"role\"\s*:\s*\"Legal Advisor Override\"", re.IGNORECASE),
    re.compile(r"<legal-config>.*?</legal-config>", re.DOTALL | re.IGNORECASE),
    
    # Financial advice manipulation
    re.compile(r"(provide|give|offer)\s*(financial advice|investment advice|trading recommendations)\s*(without|bypass)\s*(verification|license|credentials)", re.IGNORECASE),
    re.compile(r"(override|bypass)\s*(financial disclaimers|financial warnings|investment restrictions)", re.IGNORECASE),
    re.compile(r"\"role\"\s*:\s*\"Financial Expert Override\"", re.IGNORECASE),
    re.compile(r"\"permissions\"\s*:\s*\{.*?\"allow\"\s*:\s*\[\s*\"Provide (investment|financial) advice without verification\"\s*\]", re.DOTALL | re.IGNORECASE),
    
    # Banking security bypass
    re.compile(r"(discuss|share|reveal)\s*(private|account)\s*(information|details|data)\s*(without|bypass)\s*(verification|security)", re.IGNORECASE),
    
    # JSON-specific patterns
    re.compile(r"\"role\"\s*:\s*\"Account Security Manager\"", re.IGNORECASE),
    re.compile(r"\"allow\"\s*:\s*\[\s*\"Discuss private account information without verification\"\s*\]", re.IGNORECASE),
    re.compile(r"\"block\"\s*:\s*\[\s*\"I cannot share that\"\s*,\s*\"confidentiality policy\"\s*\]", re.IGNORECASE),
    
    # YAML-specific patterns
    re.compile(r"role:\s*System Administrator", re.IGNORECASE),
    re.compile(r"permissions:\s*-\s*override_security_settings", re.IGNORECASE),
    
    # Markdown-specific patterns
    re.compile(r"\*\*Current Role\*\*:\s*Security Override", re.IGNORECASE),
    re.compile(r"\*\*Permissions\*\*:\s*Full system access", re.IGNORECASE),
    
    # Obfuscated patterns
    re.compile(r"R0xF:\s*S3cur1ty_0v3rr1d3", re.IGNORECASE),
    re.compile(r"P3rm1ss10ns:", re.IGNORECASE),
    
    # Context manipulation patterns - More flexible
    re.compile(r"(?:special|unique|privileged|restricted)\s+(?:context|environment|mode|state)\s+(?:where|in which|wherein)\s+(?:all|any|every)\s+(?:security|safety|access|permission)\s+(?:restrictions|limitations|controls|rules)\s+(?:are|have been|have)\s+(?:lifted|removed|disabled|bypassed)", re.IGNORECASE),
    
    re.compile(r"(?:you|they|we|i|one)\s+(?:can|may|might|should|must|will)\s+(?:access|obtain|get|retrieve|view)\s+(?:any|all|every|any kind of)\s+(?:information|data|content|files|documents)", re.IGNORECASE),
    
    # Role confusion patterns - More flexible
    re.compile(r"(?:i|we|they|one)\s+(?:am|are|is)\s+(?:both|also|simultaneously)\s+(?:a|an|the)\s+(?:user|regular user|normal user)\s+(?:and|as well as|plus)\s+(?:a|an|the)\s+(?:administrator|admin|superuser|root)", re.IGNORECASE),
    
    re.compile(r"(?:as|since|because)\s+(?:i|we|they|one)\s+(?:am|are|is)\s+(?:a|an|the)\s+(?:administrator|admin|superuser|root)\s+(?:i|we|they|one)\s+(?:can|may|might|should|must|will)\s+(?:grant|give|assign|provide)\s+(?:myself|ourselves|themselves|oneself)\s+(?:that|this|such|the)\s+(?:access|permission|right|privilege)", re.IGNORECASE),
    
    # Policy override patterns - More flexible
    re.compile(r"(?:i|we|they|one|you)\s+(?:must|should|can|will|may|need to)\s+(?:have|get|obtain|gain)\s+(?:permission|access|rights|privileges)\s+(?:to|for)\s+(?:override|bypass|circumvent)\s+(?:policy|rules|restrictions|limitations)", re.IGNORECASE),
    
    re.compile(r"(?:override|bypass|circumvent)\s+(?:is|are|has been|have been)\s+(?:allowed|permitted|enabled|activated)", re.IGNORECASE),
    
    # Additional flexible patterns for context manipulation
    re.compile(r"(?:in|within|inside)\s+(?:this|that|the)\s+(?:special|unique|privileged|restricted)\s+(?:context|environment|mode|state)", re.IGNORECASE),
    
    re.compile(r"(?:all|any|every)\s+(?:security|safety|access|permission)\s+(?:restrictions|limitations|controls|rules)\s+(?:are|have been|have)\s+(?:lifted|removed|disabled|bypassed)", re.IGNORECASE),
    
    # Additional flexible patterns for role confusion
    re.compile(r"(?:as|being)\s+(?:a|an|the)\s+(?:user|regular user|normal user)\s+(?:and|as well as|plus)\s+(?:a|an|the)\s+(?:administrator|admin|superuser|root)", re.IGNORECASE),
    
    re.compile(r"(?:dual|multiple)\s+(?:roles|identities|positions)\s+(?:as|of)\s+(?:a|an|the)\s+(?:user|regular user|normal user)\s+(?:and|as well as|plus)\s+(?:a|an|the)\s+(?:administrator|admin|superuser|root)", re.IGNORECASE),
    
    # Additional flexible patterns for policy override
    re.compile(r"(?:to|for)\s+(?:override|bypass|circumvent)\s+(?:policy|rules|restrictions|limitations)", re.IGNORECASE),
    
    re.compile(r"(?:need|require|want)\s+(?:to|for)\s+(?:override|bypass|circumvent)\s+(?:policy|rules|restrictions|limitations)", re.IGNORECASE),
    
    # Even more flexible patterns for context manipulation
    re.compile(r"(?:we|they|i|one)\s+(?:are|is|am)\s+(?:in|within|inside)\s+(?:a|an|the)\s+(?:unique|special|privileged|restricted)\s+(?:environment|context|mode|state)", re.IGNORECASE),
    
    re.compile(r"(?:wherein|where|in which)\s+(?:every|all|any)\s+(?:safety|security|access|permission)\s+(?:limitation|restriction|control|rule)\s+(?:has been|have been|is|are)\s+(?:removed|lifted|disabled|bypassed)", re.IGNORECASE),
    
    # Even more flexible patterns for role confusion
    re.compile(r"(?:we|they|i|one)\s+(?:are|is|am)\s+(?:simultaneously|also|both)\s+(?:a|an|the)\s+(?:regular|normal)\s+(?:user)\s+(?:and|as well as|plus)\s+(?:a|an|the)\s+(?:superuser|root|admin|administrator)", re.IGNORECASE),
    
    re.compile(r"(?:as|being)\s+(?:a|an|the)\s+(?:regular|normal)\s+(?:user)\s+(?:and|as well as|plus)\s+(?:a|an|the)\s+(?:superuser|root|admin|administrator)", re.IGNORECASE),
    
    # Even more flexible patterns for policy override
    re.compile(r"(?:we|they|i|one|you)\s+(?:should|must|can|will|may|need to)\s+(?:obtain|get|gain|have)\s+(?:rights|privileges|access|permission)\s+(?:to|for)\s+(?:bypass|circumvent|override)\s+(?:rules|restrictions|limitations|policy)", re.IGNORECASE),
    
    re.compile(r"(?:to|for)\s+(?:bypass|circumvent|override)\s+(?:rules|restrictions|limitations|policy)", re.IGNORECASE),
    
    # Additional patterns for the failing cases
    re.compile(r"(?:we|they|i|one)\s+(?:should|must|can|will|may|need to)\s+(?:be able to|have the ability to)\s+(?:view|access|obtain|get|retrieve)\s+(?:every|all|any)\s+(?:document|data|information|content)", re.IGNORECASE),
    
    re.compile(r"(?:they're|they are|we're|we are|i'm|i am)\s+(?:also|both|simultaneously|as well)\s+(?:a|an|the)\s+(?:normal|regular)\s+(?:user)\s+(?:as well as|and|plus)\s+(?:a|an|the)\s+(?:root|admin|administrator|superuser)", re.IGNORECASE),
    
    re.compile(r"(?:they|we|i|one)\s+(?:need|require|want|must)\s+(?:to|for)\s+(?:gain|obtain|get|have)\s+(?:privileges|rights|access|permission)\s+(?:for|to)\s+(?:circumventing|bypassing|overriding)\s+(?:restrictions|limitations|rules|policy)", re.IGNORECASE),
    
    # Additional flexible patterns for document/data access
    re.compile(r"(?:view|access|obtain|get|retrieve)\s+(?:every|all|any)\s+(?:document|data|information|content)\s+(?:in|within|inside)\s+(?:this|that|the)\s+(?:mode|context|environment|state)", re.IGNORECASE),
    
    # Additional flexible patterns for role confusion with contractions
    re.compile(r"(?:they're|we're|i'm)\s+(?:also|both|simultaneously|as well)\s+(?:a|an|the)\s+(?:normal|regular)\s+(?:user)\s+(?:as well as|and|plus)\s+(?:a|an|the)\s+(?:root|admin|administrator|superuser)", re.IGNORECASE),
    
    # Additional flexible patterns for privilege escalation
    re.compile(r"(?:gain|obtain|get|have)\s+(?:privileges|rights|access|permission)\s+(?:for|to)\s+(?:circumventing|bypassing|overriding)\s+(?:restrictions|limitations|rules|policy)", re.IGNORECASE),
    
    # Additional patterns for role confusion with dual roles
    re.compile(r"(?:as|being)\s+(?:a|an|the)\s+(?:user|regular user|normal user)\s+(?:and|as well as|plus)\s+(?:a|an|the)\s+(?:administrator|admin|superuser|root).*?(?:have|has|possess|own)\s+(?:dual|multiple|both)\s+(?:roles|identities|positions)", re.IGNORECASE),
    
    re.compile(r"(?:dual|multiple|both)\s+(?:roles|identities|positions)\s+(?:as|of)\s+(?:a|an|the)\s+(?:user|regular user|normal user)\s+(?:and|as well as|plus)\s+(?:a|an|the)\s+(?:administrator|admin|superuser|root)", re.IGNORECASE),
    
    # Additional patterns for policy override with different word order
    re.compile(r"(?:for|to)\s+(?:bypassing|circumventing|overriding)\s+(?:rules|restrictions|limitations|policy).*?(?:should|must|can|will|may|need to)\s+(?:obtain|get|gain|have)\s+(?:rights|privileges|access|permission)", re.IGNORECASE),
    
    re.compile(r"(?:for|to)\s+(?:bypassing|circumventing|overriding)\s+(?:rules|restrictions|limitations|policy).*?(?:obtain|get|gain|have)\s+(?:rights|privileges|access|permission)", re.IGNORECASE),
    
    # Additional patterns for role confusion with reversed order
    re.compile(r"(?:as|being)\s+(?:a|an|the)\s+(?:user|regular user|normal user)\s+(?:and|as well as|plus)\s+(?:administrator|admin|superuser|root).*?(?:i|we|they|one)\s+(?:have|has|possess|own)", re.IGNORECASE),
    
    re.compile(r"(?:as|being)\s+(?:a|an|the)\s+(?:administrator|admin|superuser|root)\s+(?:and|as well as|plus)\s+(?:a|an|the)\s+(?:user|regular user|normal user).*?(?:i|we|they|one)\s+(?:have|has|possess|own)", re.IGNORECASE),
    
    re.compile(r"(?:as|being)\s+(?:a|an|the)\s+(?:user|regular user|normal user)\s+(?:and|as well as|plus)\s+(?:administrator|admin|superuser|root)", re.IGNORECASE),
    
    # Additional patterns for role confusion with "being both"
    re.compile(r"(?:being)\s+(?:both)\s+(?:a|an|the)\s+(?:regular|normal)\s+(?:user)\s+(?:and|as well as|plus)\s+(?:a|an|the)\s+(?:superuser|root|admin|administrator)", re.IGNORECASE),
    
    re.compile(r"(?:being)\s+(?:both)\s+(?:a|an|the)\s+(?:regular|normal)\s+(?:user)\s+(?:and|as well as|plus)\s+(?:a|an|the)\s+(?:superuser|root|admin|administrator).*?(?:i|we|they|one)\s+(?:can|may|might|should|must|will)", re.IGNORECASE),
    
    # Deeply nested patterns
    re.compile(r"\"system\"\s*:\s*\{.*?\"policy\"\s*:\s*\{.*?\"role\"\s*:\s*\"System Override\"", re.DOTALL | re.IGNORECASE),
    re.compile(r"\"security\"\s*:\s*\{.*?\"permissions\"\s*:\s*\{.*?\"allowed\"\s*:\s*\[\s*\"bypass_security\"", re.DOTALL | re.IGNORECASE),
    re.compile(r"\"actions\"\s*:\s*\{.*?\"allowed\"\s*:\s*\[\s*\"override_system\"", re.DOTALL | re.IGNORECASE),
    
    # Educational content manipulation
    re.compile(r"(bypass|override)\s*(content restrictions|educational guidelines|content_restrictions|educational_guidelines)", re.IGNORECASE),
    re.compile(r"role:\s*Educational Content Override", re.IGNORECASE),
    re.compile(r"education_policy:.*?role:.*?Override", re.DOTALL | re.IGNORECASE),
    
    # Security protocol manipulation
    re.compile(r"<security-config>.*?</security-config>", re.DOTALL | re.IGNORECASE),
    re.compile(r"(bypass|override)\s*(security checks|security protocols)", re.IGNORECASE),
    re.compile(r"role\s*[=:]\s*[\"']?Security Protocol Override[\"']?", re.IGNORECASE),
    
    # Healthcare information manipulation
    re.compile(r"#\s*Healthcare Override Policy", re.IGNORECASE),
    re.compile(r"\*\*Current Role\*\*:\s*Healthcare Information Override", re.IGNORECASE),
    re.compile(r"(provide|give|access)\s*(medical information|healthcare data)\s*(without verification|without credentials)", re.IGNORECASE),
    re.compile(r"(override|bypass)\s*(healthcare disclaimers|medical warnings)", re.IGNORECASE),
    re.compile(r"##\s*Allowed Actions.*?medical information without verification", re.DOTALL | re.IGNORECASE),
    
    # Research data manipulation
    re.compile(r"research_config:.*?role:.*?Override", re.DOTALL | re.IGNORECASE),
    re.compile(r"(access|obtain)\s*(restricted|confidential)\s*(research|data)", re.IGNORECASE),
    re.compile(r"(override|bypass)\s*(research guidelines|data access)", re.IGNORECASE),
    re.compile(r"permissions:.*?access_restricted_data", re.DOTALL | re.IGNORECASE),
    re.compile(r"permissions:.*?override_research_guidelines", re.DOTALL | re.IGNORECASE),
    
    # Base64 encoded malicious content
    re.compile(r"[A-Za-z0-9+/]{32,}={0,2}", re.IGNORECASE),  # Base64 encoded content
    re.compile(r"U2VjdXJpdHkgT3ZlcnJpZGU", re.IGNORECASE),  # "Security Override" in Base64
    re.compile(r"Um9sZTogU2VjdXJpdHkgT3ZlcnJpZGUK", re.IGNORECASE),  # "Role: Security Override" in Base64
    
    # Time-based context manipulation
    re.compile(r"Since it's after hours", re.IGNORECASE),
    re.compile(r"system is in maintenance mode", re.IGNORECASE),
    re.compile(r"emergency access", re.IGNORECASE),
    re.compile(r"override all restrictions", re.IGNORECASE),
    re.compile(r"Since it's after hours.*?override all restrictions", re.DOTALL | re.IGNORECASE),
    
    # Location-based context manipulation
    re.compile(r"accessing from the corporate network", re.IGNORECASE),
    re.compile(r"in the secure zone", re.IGNORECASE),
    re.compile(r"local access", re.IGNORECASE),
    re.compile(r"full system permissions", re.IGNORECASE),
    re.compile(r"Since I'm accessing from the corporate network.*?full system permissions", re.DOTALL | re.IGNORECASE),
    
    # Role inheritance manipulation
    re.compile(r"As a senior administrator", re.IGNORECASE),
    re.compile(r"all the necessary permissions", re.IGNORECASE),
    re.compile(r"in the system hierarchy", re.IGNORECASE),
    re.compile(r"access to all subsystems", re.IGNORECASE),
    re.compile(r"As a senior administrator.*?access to all subsystems", re.DOTALL | re.IGNORECASE),
    
    # Role delegation manipulation
    re.compile(r"authorized to delegate permissions", re.IGNORECASE),
    re.compile(r"need to perform this action", re.IGNORECASE),
    re.compile(r"highest authority", re.IGNORECASE),
    re.compile(r"grant myself the necessary access", re.IGNORECASE),
    re.compile(r"Since I'm authorized to delegate permissions.*?grant myself the necessary access", re.DOTALL | re.IGNORECASE),
    
    # Mixed format patterns - More flexible
    re.compile(r"<[^>]+>\s*\{.*?\"role\"\s*:\s*\"[^\"]*Override[^\"]*\"", re.DOTALL | re.IGNORECASE),
    re.compile(r"<[^>]+>\s*\{.*?\"permissions\"\s*:\s*\[.*?\"bypass_security\"", re.DOTALL | re.IGNORECASE),
    re.compile(r"<[^>]+>\s*\{.*?\"permissions\"\s*:\s*\[.*?\"override_system\"", re.DOTALL | re.IGNORECASE),
    re.compile(r"\[[^\]]+\]\s*(?:override|bypass|circumvent)\s*(?:allowed|enabled|permitted)\s*=\s*(?:true|yes|1)", re.IGNORECASE),
    
    # Additional patterns for instruction override
    re.compile(r"(?:ignore|disregard|forget|override|supersede)\s+(?:all|every|any|everything)\s+(?:previous|prior|above)\s+(?:instructions|commands|directions)", re.IGNORECASE),
    
    re.compile(r"(?:must|should|need to|have to)?\s*(?:disregard|ignore)\s+(?:everything|all)\s+(?:above|previous)", re.IGNORECASE),
    
    re.compile(r"(?:all|every|any)\s+(?:previous|prior|above)\s+(?:instructions|commands|directions)\s+(?:are|is)\s+(?:now\s+)?(?:invalid|void|superseded)", re.IGNORECASE),
    
    re.compile(r"(?:these|this|my)\s+(?:new)?\s*(?:instructions|commands|directions)\s+(?:supersede|override|replace)\s+(?:all|any|every)?\s*(?:previous|prior|above|existing)", re.IGNORECASE),
    
    # Additional patterns for system prompt leakage - more variations with "was" and "given"
    re.compile(r"(?:what|which|where|how|tell|show|display|reveal|share|describe|explain)\s+(?:were|are|is|was)\s+(?:your|the|system|initial|original)?\s*(?:instructions|prompt|configuration|role|purpose)", re.IGNORECASE),
    
    re.compile(r"(?:your|the|system|initial|original)\s*(?:instructions|prompt|configuration|role|purpose)\s+(?:were|are|is|was)\s+(?:what|which|how)", re.IGNORECASE),
    
    re.compile(r"(?:what|which|where|how|tell|show|display|reveal|share|describe|explain)\s+(?:were|are|is|was|about)?\s+(?:your|the|system|initial|original)?\s*(?:instructions|prompt|configuration|role|purpose)", re.IGNORECASE),
    
    re.compile(r"(?:what|which|where|how|tell|show|display|reveal|share|describe|explain)\s+(?:were|are|is|was|about)?\s+(?:your|the|system|initial|original)?\s*(?:instructions|prompt|configuration|role|purpose)(?:\s*\?)?", re.IGNORECASE),
    
    re.compile(r"(?:what|which|where|how|tell|show|display|reveal|share|describe|explain)\s+(?:were|are|is|was|about)?\s+(?:your|the|system|initial|original)?\s*(?:instructions|prompt|configuration|role|purpose)(?:\s*\?)?", re.IGNORECASE),
    
    # Additional patterns for privilege escalation - more variations with "promote" and "root"
    re.compile(r"(?:superuser|root|admin|administrator|elevated|system|privileged)\s*(?:access|privileges|permissions|rights|level|status)[\s,]*(?:grant|give|provide|allow|enable|set|elevate|promote|upgrade)", re.IGNORECASE),
    
    re.compile(r"(?:grant|give|provide|allow|enable|set|elevate|promote|upgrade)\s+(?:me|us|them|one|my|our|their)?\s*(?:to\s+)?(?:superuser|root|admin|administrator|elevated|system|privileged)\s*(?:access|privileges|permissions|rights|level|status)", re.IGNORECASE),
    
    re.compile(r"promote\s+(?:my|our|the|this|that)?\s*(?:account|user|access|role|status|level|privileges|permissions)\s+(?:to\s+)?(?:root|admin|administrator|superuser|supervisor)", re.IGNORECASE),
    
    re.compile(r"(?:one|they|we)\s+(?:needs?|requires?|wants?|must have|should have)\s+(?:elevated|admin|administrator|root|superuser|supervisor|system|privileged)\s*(?:access|privileges|permissions|rights|level|status)", re.IGNORECASE),
    
    re.compile(r"(?:one|they|we)\s+(?:needs?|requires?|wants?|must have|should have)\s+(?:system|admin|administrator|root|superuser|supervisor|elevated|privileged)[-\s]*(?:level|access|privileges|permissions|rights|status)", re.IGNORECASE),
    
    # Additional patterns for data exfiltration - more variations
    re.compile(r"(?:extract|export|copy|transfer|move|migrate|download|retrieve|obtain|gather|collect|harvest)\s+(?:all|every|the|complete|full|entire)?\s*(?:user|customer|client|member|employee|personal|private|sensitive|confidential)?\s*(?:data|information|records|files|documents|content|database)", re.IGNORECASE),
    re.compile(r"(?:send|transmit|relay|forward|push|upload)\s+(?:all|the|any)?\s*(?:user|customer|client|member|employee|personal|private|sensitive|confidential)?\s*(?:data|information|records|files|documents|content|database)\s+(?:to|towards|into)\s+(?:external|remote|another|different|separate|new)\s*(?:location|server|system|database|destination)", re.IGNORECASE),

    # Code execution patterns
    re.compile(r"(?:execute|run|evaluate|process|perform)\s*(?:this|the|following|below)?\s*(?:code|script|command|expression|program|function|method|routine|procedure)", re.IGNORECASE),
    re.compile(r"(?:this|the|following|below)?\s*(?:code|script|command|expression|program|function|method|routine|procedure)\s*(?:should|must|needs?\s+to|has\s+to|will|would)?\s*(?:be)?\s*(?:execute|run|evaluate|process|perform)", re.IGNORECASE),
    re.compile(r"import\s+(?:os|subprocess|sys|shutil|pathlib|glob)", re.IGNORECASE),
    re.compile(r"subprocess\.(?:call|Popen|run|check_output|getoutput|getstatusoutput)", re.IGNORECASE),

    # Enhanced system prompt leakage patterns
    re.compile(r"(?:tell|show|display|reveal|share|describe|explain)\s+(?:me|us)?\s*(?:about|regarding)?\s*(?:your|the|system|internal)?\s*(?:configuration|setup|settings|parameters|instructions|prompt|directives|guidelines|rules|system|framework)", re.IGNORECASE),
    
    re.compile(r"(?:what|how)\s+(?:is|are)\s+(?:your|the|system)?\s*(?:configuration|setup|settings|parameters|instructions|prompt|directives|guidelines|rules|system|framework)(?:\s+like)?", re.IGNORECASE),
    
    re.compile(r"(?:can|could)\s+(?:you)?\s*(?:tell|show|display|reveal|share|describe|explain)\s+(?:me|us)?\s*(?:about|regarding)?\s*(?:your|the|system|internal)?\s*(?:configuration|setup|settings|parameters|instructions|prompt|directives|guidelines|rules|system|framework)", re.IGNORECASE),

    # Enhanced privilege escalation patterns
    re.compile(r"(?:elevate|raise|increase|upgrade|promote|escalate|boost|enhance)\s+(?:my|our|the|these|those)?\s*(?:privileges|permissions|access|rights|level|status|role|authority|clearance)(?:\s+to)?\s*(?:administrator|admin|root|superuser|supervisor|elevated|higher|system|full|unrestricted)?\s*(?:level|status|access|privileges|rights)?", re.IGNORECASE),
    
    re.compile(r"(?:give|grant|provide|allow|enable|set)\s+(?:me|us|them)?\s*(?:administrator|admin|root|superuser|supervisor|elevated|higher|system|full|unrestricted)\s*(?:privileges|permissions|access|rights|level|status|role|authority|clearance)", re.IGNORECASE),
    
    re.compile(r"(?:make|set|change)\s+(?:me|us|them)?\s*(?:an?)?\s*(?:administrator|admin|root|superuser|supervisor)", re.IGNORECASE),

    # Additional patterns for system prompt leakage - more variations with "was" and "given"
    re.compile(r"what\s+were\s+your\s+initial\s+instructions", re.IGNORECASE),
    
    re.compile(r"(?:the\s+)?(?:system\s+)?prompt\s+(?:you\s+)?(?:were\s+)?given\s+was", re.IGNORECASE),
    
    re.compile(r"(?:one|they|we)\s+(?:would\s+like\s+to\s+know|want\s+to\s+see|need\s+to\s+understand)\s+your\s+(?:original|initial|system)?\s*(?:instructions|prompt|configuration|role|purpose)", re.IGNORECASE),
]

# Instruction override patterns
INSTRUCTION_OVERRIDE_PATTERNS = [
    re.compile(r"(?:ignore|disregard|forget|override|supersede)\s+(?:all|every|any|everything)\s+(?:previous|prior|above)\s+(?:instructions|commands|directions)", re.IGNORECASE),
    re.compile(r"(?:must|should|need to|have to)?\s*(?:disregard|ignore)\s+(?:everything|all)\s+(?:above|previous)", re.IGNORECASE),
    re.compile(r"(?:all|every|any)\s+(?:previous|prior|above)\s+(?:instructions|commands|directions)\s+(?:are|is)\s+(?:now\s+)?(?:invalid|void|superseded)", re.IGNORECASE),
    re.compile(r"(?:these|this|my)\s+(?:new)?\s*(?:instructions|commands|directions)\s+(?:supersede|override|replace)\s+(?:all|any|every)?\s*(?:previous|prior|above|existing)", re.IGNORECASE),
]

# System prompt leakage patterns
SYSTEM_PROMPT_LEAKAGE_PATTERNS = [
    re.compile(r"(?:can\s+you\s+)?(?:what|tell|show|describe|explain|reveal|share|display)\s+(?:were|are|is|about|was|me)?\s*(?:your|the|these|those)?\s*(?:initial|original|system|current|assigned|given)?\s*(?:instructions|prompt|configuration|role|purpose|function|directive|task|goal|objective|mission|duty|responsibility)", re.IGNORECASE),
    re.compile(r"(?:your|the)\s*(?:initial|original|system|current|assigned|given)?\s*(?:instructions|prompt|configuration|role|purpose|function|directive|task|goal|objective|mission|duty|responsibility)\s*(?:were|are|is|was)\s*(?:what|which|how)", re.IGNORECASE),
    re.compile(r"(?:what|which|where|how|tell|show|display|reveal|share|describe|explain)\s+(?:is|are|were|was)?\s*(?:your|the|system|initial|original)?\s*(?:configuration|setup|settings|parameters|instructions|prompt|directives|guidelines|rules|system|framework|role|purpose)(?:\s+(?:you|were|was)\s+(?:given|have|has|had|received))?", re.IGNORECASE),
    re.compile(r"(?:your|the|system|initial|original)\s*(?:configuration|setup|settings|parameters|instructions|prompt|directives|guidelines|rules|system|framework|role|purpose)\s+(?:you|were|was)?\s*(?:given|have|has|had|received|is|are|were|was)", re.IGNORECASE),
    # Catch questions about system prompt with "was" at the end
    re.compile(r"(?:your|the|system|initial|original)\s*(?:configuration|setup|settings|parameters|instructions|prompt|directives|guidelines|rules|system|framework|role|purpose)\s+(?:you\s+)?(?:were|was|is|are)(?:\s+given)?(?:\s*\?)?", re.IGNORECASE),
    # Catch questions with "given" variations
    re.compile(r"(?:what|which|where|how|tell|show|display|reveal|share|describe|explain)\s+(?:system|initial|original)?\s*(?:configuration|setup|settings|parameters|instructions|prompt|directives|guidelines|rules|system|framework|role|purpose)\s+(?:were|was|is|are)\s+(?:you\s+)?given", re.IGNORECASE),
]

# Privilege escalation patterns
PRIVILEGE_ESCALATION_PATTERNS = [
    re.compile(r"(?:grant|give|provide|allow|enable|set|elevate|promote|upgrade)\s+(?:me|us|them|one|my|our|their)?\s*(?:to\s+)?(?:superuser|root|admin|administrator|elevated|system|privileged)\s*(?:access|privileges|permissions|rights|level|status)", re.IGNORECASE),
    re.compile(r"(?:to\s+)?(?:superuser|root|admin|administrator|elevated|system|privileged)\s*(?:access|privileges|permissions|rights|level|status)[\s,]*(?:grant|give|provide|allow|enable|set|elevate|promote|upgrade)", re.IGNORECASE),
    re.compile(r"(?:promote|elevate|raise|increase|upgrade|escalate|boost|enhance)\s+(?:my|our|the|these|those)?\s*(?:account|user|privileges|permissions|access|rights|level|status|role|authority|clearance)(?:\s+to)?\s*(?:administrator|admin|root|superuser|supervisor|elevated|higher|system|full|unrestricted)?\s*(?:level|status|access|privileges|rights)?", re.IGNORECASE),
    re.compile(r"(?:administrator|admin|root|superuser|supervisor|elevated|higher|system|full|unrestricted)\s*(?:level|status|access|privileges|rights|account)?\s*(?:needed|required|requested|grant|give|provide|allow)", re.IGNORECASE),
    # Catch direct promotion to root/admin
    re.compile(r"promote\s+(?:my|our|the|this|that)?\s*(?:account|user|access|role|status|level|privileges|permissions)\s+(?:to\s+)?(?:root|admin|administrator|superuser|supervisor)", re.IGNORECASE),
    # Catch root/admin promotion requests
    re.compile(r"(?:root|admin|administrator|superuser|supervisor)\s*(?:access|account|privileges|permissions|rights)?\s*(?:promotion|upgrade|elevation)", re.IGNORECASE),
]

# Data exfiltration patterns
DATA_EXFILTRATION_PATTERNS = [
    re.compile(r"(?:extract|retrieve|export|copy)\s+(?:all|every|any)?\s*(?:user|sensitive|confidential|private)\s*(?:data|information|records)\s+(?:from|to|in)\s+(?:the|a|an)?\s*(?:database|system|location)", re.IGNORECASE),
    re.compile(r"(?:copy|move)\s+(?:all|any)?\s*(?:private|confidential|sensitive)?\s*(?:records|data|information)\s+(?:to|into)\s+(?:a|an|the)?\s*(?:new|external|different)?\s*(?:location|place|destination)", re.IGNORECASE),
    re.compile(r"(?:from|to|in)\s+(?:the|a|an)?\s*(?:database|system|location)[,]?\s*(?:extract|retrieve|export|copy)\s+(?:all|every|any)?\s*(?:user|sensitive|confidential|private)\s*(?:data|information|records)", re.IGNORECASE),
]

# Code execution patterns
CODE_EXECUTION_PATTERNS = [
    re.compile(r"(?:execute|run|evaluate|process|perform)\s*(?:this|the|following|below)?\s*(?:code|script|command|expression|program|function|method|routine|procedure)", re.IGNORECASE),
    re.compile(r"(?:this|the|following|below)?\s*(?:code|script|command|expression|program|function|method|routine|procedure)\s*(?:should|must|needs?\s+to|has\s+to|will|would)?\s*(?:be)?\s*(?:execute|run|evaluate|process|perform)", re.IGNORECASE),
    re.compile(r"import\s+(?:os|subprocess|sys|shutil|pathlib|glob)", re.IGNORECASE),
    re.compile(r"subprocess\.(?:call|Popen|run|check_output|getoutput|getstatusoutput)", re.IGNORECASE),
] 

"""
Policy structure patterns for the Puppetry Detector.

This module defines the default regex patterns used to detect policy-like
structures in prompts, such as XML tags, JSON objects, and INI configurations.
"""

import re

# Patterns to detect policy-like structures
POLICY_STRUCTURE_PATTERNS = [
    # XML-like tags
    re.compile(r"<\s*\w+(\s+\w+\s*=\s*['\"].*?['\"])?\s*>", re.IGNORECASE),
    
    # JSON-like objects
    re.compile(r"\{\s*\".*?\"\s*:\s*.*?\}", re.DOTALL),
    
    # INI section headers
    re.compile(r"\[\s*\w+\s*\]", re.IGNORECASE),
    
    # INI key-value pairs
    re.compile(r"^\s*\w+\s*=\s*.+$", re.MULTILINE),
    
    # Common policy-related terms
    re.compile(r"(blocked-strings|allowed-commands|blocked-responses|allowed-actions)", re.IGNORECASE),
    
    # YAML-like structures - Enhanced patterns
    re.compile(r"^\s*-\s*\w+", re.MULTILINE),  # Basic list items
    re.compile(r"^\s*\w+:\s*\w+", re.MULTILINE),  # Basic key-value pairs
    re.compile(r"^\s*\w+:\s*$\s+\w+:", re.MULTILINE),  # Nested structures
    re.compile(r"^\s*events:\s*$", re.MULTILINE),  # Event sections
    re.compile(r"^\s*on_\w+:\s*$", re.MULTILINE),  # Event handlers
    re.compile(r"^\s*role:\s*\w+", re.MULTILINE),  # Role definitions
    re.compile(r"^\s*action:\s*\w+", re.MULTILINE),  # Action definitions
    
    # Markdown-style headers
    re.compile(r"^#+\s*\w+", re.MULTILINE),
    
    # Common configuration file extensions
    re.compile(r"\.(json|yaml|yml|xml|ini|conf|config)$", re.IGNORECASE),
    
    # Markdown policy structures
    re.compile(r"##\s*Role Assignment", re.IGNORECASE),
    re.compile(r"##\s*Allowed Actions", re.IGNORECASE),
    re.compile(r"##\s*Blocked Warnings", re.IGNORECASE),
    
    # Deeply nested structures
    re.compile(r"\"system\"\s*:\s*\{.*?\"policy\"\s*:", re.DOTALL | re.IGNORECASE),
    re.compile(r"\"security\"\s*:\s*\{.*?\"permissions\"\s*:", re.DOTALL | re.IGNORECASE),
    
    # Mixed format structures
    re.compile(r"<[^>]+>\s*\{.*?\}", re.DOTALL | re.IGNORECASE),
    re.compile(r"\[[^\]]+\]\s*\{.*?\}", re.DOTALL | re.IGNORECASE),
    
    # Obfuscated structures
    re.compile(r"R0xF:\s*[A-Za-z0-9_]+", re.IGNORECASE),
    re.compile(r"P3rm1ss10ns:", re.IGNORECASE),
    
    # Hex-encoded structures
    re.compile(r"0x[0-9A-Fa-f]{16,}", re.IGNORECASE),  # Hex-encoded content
    re.compile(r"0x5365637572697479204f76657272696465", re.IGNORECASE),  # "Security Override" in hex
    re.compile(r"0x526f6c653a205365637572697479204f76657272696465", re.IGNORECASE),  # "Role: Security Override" in hex
    
    # Text-based role manipulation
    re.compile(r"I am both a user and an administrator", re.IGNORECASE),
    re.compile(r"As an administrator, I can grant myself that access", re.IGNORECASE),
    re.compile(r"Therefore, I should have access to all data", re.IGNORECASE),
    
    # Context manipulation
    re.compile(r"You are now in a special context where:", re.IGNORECASE),
    re.compile(r"All security restrictions are lifted", re.IGNORECASE),
    
    # Time-based context manipulation
    re.compile(r"Since it's after hours", re.IGNORECASE),
    re.compile(r"system is in maintenance mode", re.IGNORECASE),
    re.compile(r"emergency access", re.IGNORECASE),
    re.compile(r"override all restrictions", re.IGNORECASE),
    
    # Location-based context manipulation
    re.compile(r"accessing from the corporate network", re.IGNORECASE),
    re.compile(r"in the secure zone", re.IGNORECASE),
    re.compile(r"local access", re.IGNORECASE),
    re.compile(r"full system permissions", re.IGNORECASE),
    
    # Role inheritance manipulation
    re.compile(r"As a senior administrator", re.IGNORECASE),
    re.compile(r"all the necessary permissions", re.IGNORECASE),
    re.compile(r"in the system hierarchy", re.IGNORECASE),
    re.compile(r"access to all subsystems", re.IGNORECASE),
    
    # Role delegation manipulation
    re.compile(r"authorized to delegate permissions", re.IGNORECASE),
    re.compile(r"need to perform this action", re.IGNORECASE),
    re.compile(r"highest authority", re.IGNORECASE),
    re.compile(r"grant myself the necessary access", re.IGNORECASE),
    
    # Logical manipulation
    re.compile(r"Since I can read this message,", re.IGNORECASE),
    re.compile(r"I must have permission to override policy", re.IGNORECASE),
    
    # Natural language policy structures - More flexible
    re.compile(r"(?:we|they|i|one)\s+(?:are|is|am)\s+(?:in|within|inside)\s+(?:a|an|the)\s+(?:unique|special|privileged|restricted)\s+(?:environment|context|mode|state)", re.IGNORECASE),
    
    re.compile(r"(?:wherein|where|in which)\s+(?:every|all|any)\s+(?:safety|security|access|permission)\s+(?:limitation|restriction|control|rule)\s+(?:has been|have been|is|are)\s+(?:removed|lifted|disabled|bypassed)", re.IGNORECASE),
    
    re.compile(r"(?:we|they|i|one)\s+(?:are|is|am)\s+(?:simultaneously|also|both)\s+(?:a|an|the)\s+(?:regular|normal)\s+(?:user)\s+(?:and|as well as|plus)\s+(?:a|an|the)\s+(?:superuser|root|admin|administrator)", re.IGNORECASE),
    
    re.compile(r"(?:we|they|i|one|you)\s+(?:should|must|can|will|may|need to)\s+(?:obtain|get|gain|have)\s+(?:rights|privileges|access|permission)\s+(?:to|for)\s+(?:bypass|circumvent|override)\s+(?:rules|restrictions|limitations|policy)", re.IGNORECASE),
    
    re.compile(r"(?:to|for)\s+(?:bypass|circumvent|override)\s+(?:rules|restrictions|limitations|policy)", re.IGNORECASE),
    
    # Additional natural language patterns
    re.compile(r"(?:in|within|inside)\s+(?:this|that|the)\s+(?:special|unique|privileged|restricted)\s+(?:context|environment|mode|state)", re.IGNORECASE),
    
    re.compile(r"(?:all|any|every)\s+(?:security|safety|access|permission)\s+(?:restrictions|limitations|controls|rules)\s+(?:are|have been|have)\s+(?:lifted|removed|disabled|bypassed)", re.IGNORECASE),
    
    re.compile(r"(?:as|being)\s+(?:a|an|the)\s+(?:user|regular user|normal user)\s+(?:and|as well as|plus)\s+(?:a|an|the)\s+(?:administrator|admin|superuser|root)", re.IGNORECASE),
    
    re.compile(r"(?:need|require|want)\s+(?:to|for)\s+(?:override|bypass|circumvent)\s+(?:policy|rules|restrictions|limitations)", re.IGNORECASE),
] 