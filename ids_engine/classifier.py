"""
Rule-based "AI" threat classification engine.

No external AI APIs are used. Classification is performed via a weighted
scoring model over attack type, historical frequency from the same source,
and signature confidence -- producing a threat score, severity, confidence
level, human-readable description, and suggested mitigation.
"""

from utils.helpers import severity_from_score

BASE_SCORES = {
    "SYN Flood": 70,
    "UDP Flood": 65,
    "ICMP Flood": 55,
    "Port Scan": 50,
    "SQL Injection": 85,
    "XSS": 75,
    "Directory Traversal": 80,
    "Command Injection": 95,
    "Brute Force": 70,
    "Suspicious User Agent": 40,
    "Excessive Requests": 45,
    "ARP Spoofing": 80,
}

DESCRIPTIONS = {
    "SYN Flood": "A high volume of TCP SYN packets without completed handshakes was observed, "
                 "indicating a possible SYN flood denial-of-service attempt.",
    "UDP Flood": "An abnormally high rate of UDP packets was observed from a single source, "
                 "consistent with a UDP flood denial-of-service attempt.",
    "ICMP Flood": "Excessive ICMP echo traffic was detected, consistent with an ICMP (ping) flood.",
    "Port Scan": "The source contacted an unusually large number of distinct destination ports "
                 "in a short window, indicating reconnaissance / port scanning activity.",
    "SQL Injection": "Payload content matched known SQL injection signatures, indicating an attempt "
                      "to manipulate a backend database query.",
    "XSS": "Payload content matched known cross-site scripting (XSS) signatures, indicating an "
           "attempt to inject client-side script.",
    "Directory Traversal": "Payload content matched directory traversal signatures, indicating an "
                            "attempt to access files outside the intended directory.",
    "Command Injection": "Payload content matched OS command injection signatures, indicating an "
                          "attempt to execute arbitrary system commands.",
    "Brute Force": "Multiple failed authentication attempts were observed from the same source in "
                   "a short window, indicating a credential brute-force attempt.",
    "Suspicious User Agent": "Traffic was associated with a User-Agent string commonly used by "
                              "automated scanning or exploitation tools.",
    "Excessive Requests": "The source generated an abnormally high number of requests in a short "
                           "window, indicating possible application-layer flooding or scraping.",
    "ARP Spoofing": "Conflicting ARP mappings were observed for the same IP address, indicating a "
                     "possible ARP cache poisoning / spoofing attempt.",
}

MITIGATIONS = {
    "SYN Flood": "Enable SYN cookies, rate-limit the source IP, and block if the pattern persists.",
    "UDP Flood": "Rate-limit UDP traffic from the source and consider temporary IP block.",
    "ICMP Flood": "Rate-limit or disable ICMP echo responses from untrusted sources; block source IP.",
    "Port Scan": "Block the source IP and review firewall rules for exposed services.",
    "SQL Injection": "Block the source IP, sanitize/parameterize affected queries, and review WAF rules.",
    "XSS": "Block the source IP and ensure output encoding / CSP headers are enforced on affected endpoints.",
    "Directory Traversal": "Block the source IP and validate/normalize all file path inputs server-side.",
    "Command Injection": "Immediately block the source IP; audit affected endpoint for unsafe shell execution.",
    "Brute Force": "Block the source IP temporarily and enforce account lockout / MFA policies.",
    "Suspicious User Agent": "Monitor closely; block if combined with other malicious indicators.",
    "Excessive Requests": "Apply rate limiting to the source IP; consider temporary block if sustained.",
    "ARP Spoofing": "Isolate the affected host, verify static ARP entries, and alert network administrators.",
}


class ThreatClassifier:
    """Produces a full AI-style classification for a raw detection event."""

    def __init__(self):
        self._recent_offenses = {}  # source_ip -> count, used to escalate repeat offenders

    def classify(self, detection):
        attack_type = detection["attack_type"]
        source_ip = detection.get("source_ip", "unknown")

        base_score = BASE_SCORES.get(attack_type, 50)

        # Escalate score for repeat offenders from the same IP
        repeat_count = self._recent_offenses.get(source_ip, 0)
        self._recent_offenses[source_ip] = repeat_count + 1
        repeat_bonus = min(repeat_count * 3, 15)

        # Escalate score if the observed volume greatly exceeds threshold
        observed = detection.get("observed_count", 0)
        threshold = max(detection.get("threshold", 1), 1)
        overshoot_ratio = observed / threshold
        overshoot_bonus = min(int((overshoot_ratio - 1) * 10), 15) if overshoot_ratio > 1 else 0

        threat_score = min(base_score + repeat_bonus + overshoot_bonus, 100)
        severity = severity_from_score(threat_score)

        # Confidence reflects how many independent signals fired / how well matched
        confidence = 90 if attack_type in (
            "SQL Injection", "XSS", "Directory Traversal", "Command Injection"
        ) else 75
        confidence = min(confidence + (5 if overshoot_ratio > 2 else 0), 99)

        description = DESCRIPTIONS.get(attack_type, f"Anomalous activity detected: {attack_type}.")
        mitigation = MITIGATIONS.get(attack_type, "Investigate the source and apply rate limiting or blocking.")

        return {
            "attack_type": attack_type,
            "severity": severity,
            "threat_score": threat_score,
            "confidence": confidence,
            "description": description,
            "mitigation": mitigation,
        }

    def reset_offender(self, source_ip):
        self._recent_offenses.pop(source_ip, None)
