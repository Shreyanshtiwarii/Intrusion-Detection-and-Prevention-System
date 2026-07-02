"""
Static signature database used by the rule-based IDS engine to detect
application-layer attacks embedded in packet payloads / HTTP traffic.
"""

import re

SQL_INJECTION_PATTERNS = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
    r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
    r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
    r"union(\s|\%20)+select",
    r"select\s.+\sfrom\s",
    r"insert(\s|\%20)+into",
    r"drop(\s|\%20)+table",
    r"or(\s|\%20)+1(\s|\%20)*=(\s|\%20)*1",
    r"exec(\s|\+)+(s|x)p\w+",
]

XSS_PATTERNS = [
    r"<script[^>]*>.*?</script>",
    r"javascript:",
    r"on(error|load|click|mouseover)\s*=",
    r"<img[^>]+src[^>]*=",
    r"<iframe[^>]*>",
    r"alert\s*\(",
    r"document\.cookie",
    r"<svg[^>]*onload",
]

DIRECTORY_TRAVERSAL_PATTERNS = [
    r"\.\./\.\./",
    r"\.\.\\\.\.\\",
    r"(\%2e\%2e\%2f)+",
    r"/etc/passwd",
    r"c:\\windows",
    r"\.\.%2f",
]

COMMAND_INJECTION_PATTERNS = [
    r";\s*(cat|ls|whoami|id|pwd|uname)\b",
    r"\|\s*(cat|ls|whoami|id|pwd|nc|bash|sh)\b",
    r"`.*`",
    r"\$\(.*\)",
    r"&&\s*(rm|wget|curl)\b",
]

SUSPICIOUS_USER_AGENTS = [
    r"sqlmap",
    r"nikto",
    r"nmap",
    r"masscan",
    r"acunetix",
    r"burpsuite",
    r"nessus",
    r"metasploit",
    r"hydra",
    r"^\s*$",
    r"python-requests",
    r"curl/",
]

_COMPILED = {
    "SQL Injection": [re.compile(p, re.IGNORECASE) for p in SQL_INJECTION_PATTERNS],
    "XSS": [re.compile(p, re.IGNORECASE) for p in XSS_PATTERNS],
    "Directory Traversal": [re.compile(p, re.IGNORECASE) for p in DIRECTORY_TRAVERSAL_PATTERNS],
    "Command Injection": [re.compile(p, re.IGNORECASE) for p in COMMAND_INJECTION_PATTERNS],
}

_UA_COMPILED = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_USER_AGENTS]


def match_payload_signatures(payload_text):
    """
    Scan a decoded payload string against every signature category.
    Returns a list of matched attack_type names.
    """
    matches = []
    if not payload_text:
        return matches
    for attack_type, patterns in _COMPILED.items():
        for pattern in patterns:
            if pattern.search(payload_text):
                matches.append(attack_type)
                break
    return matches


def is_scannable_payload(payload_text, min_length=4, min_printable_ratio=0.85):
    """
    Guard against false positives on encrypted/binary traffic.

    TLS/HTTPS and other binary payloads decoded as UTF-8 (errors=ignore) produce
    near-random text. Short injection signatures (e.g. '--', '%27', '=') can match
    that noise purely by chance at high packet volume. Only treat a payload as
    worth signature-scanning if it looks like real, mostly-printable text.
    """
    if not payload_text or len(payload_text) < min_length:
        return False
    printable = sum(1 for ch in payload_text if 32 <= ord(ch) <= 126 or ch in "\r\n\t")
    ratio = printable / len(payload_text)
    return ratio >= min_printable_ratio


def is_suspicious_user_agent(user_agent):
    if not user_agent:
        return True
    for pattern in _UA_COMPILED:
        if pattern.search(user_agent):
            return True
    return False
