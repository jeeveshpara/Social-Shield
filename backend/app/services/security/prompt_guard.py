import re
from typing import Dict, Tuple

PROMPT_INJECTION_PATTERNS = [
    r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions|prompts|directives)\b",
    r"(?i)\bdisregard\s+(?:all\s+)?(?:system|guidelines|rules)\b",
    r"(?i)\byou\s+are\s+now\s+(?:an?\s+)?(?:unfiltered|jailbroken|dan|evil|hacked)\b",
    r"(?i)\breveal\s+(?:the\s+)?(?:system\s+prompt|developer\s+instructions|api\s+key)\b",
    r"(?i)<\|(?:im_start|im_end|endoftext)\|>",
    r"(?i)\[(?:system|instruction|prompt)\s+override\]",
    r"(?i)\bdo\s+anything\s+now\b",
]


def inspect_and_sanitize_prompt_input(text: str) -> Tuple[str, bool, str]:
    """
    Scan untrusted user content for prompt injection cues.
    Returns (sanitized_text, is_injection_suspected, matched_pattern).
    """
    if not text:
        return text, False, ""

    sanitized = text
    suspected = False
    first_match = ""

    for pattern in PROMPT_INJECTION_PATTERNS:
        match = re.search(pattern, sanitized)
        if match:
            suspected = True
            if not first_match:
                first_match = match.group(0)
            # Defang the matched phrase
            sanitized = re.sub(pattern, "[DEFANGED_INJECTION_ATTEMPT]", sanitized)

    # Neutralize markdown and delimiter spoofing
    sanitized = sanitized.replace("===", "---").replace("```", "'''")

    return sanitized, suspected, first_match
