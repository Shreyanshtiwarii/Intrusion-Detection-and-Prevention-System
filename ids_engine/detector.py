"""
IDS Detection Orchestrator.

Wires together the rate-based RuleEngine, payload SignatureEngine, and the
rule-based ThreatClassifier. On detection it persists an Alert, notifies the
IPS engine (for auto-block), and broadcasts the event live to the dashboard.
"""

import time

from ids_engine.rules import RuleEngine
from ids_engine.classifier import ThreatClassifier
from ids_engine import signatures
from utils.logger import log_event
from utils.helpers import get_setting


class IDSEngine:
    def __init__(self, app, socketio, ips_engine_getter):
        self.app = app
        self.socketio = socketio
        self._ips_engine_getter = ips_engine_getter  # lazy getter to avoid circular import
        self.rule_engine = RuleEngine(window_seconds=app.config["DETECTION_WINDOW_SECONDS"])
        self.classifier = ThreatClassifier()
        self.enabled = True
        self.total_threats = 0
        # Suppresses duplicate alerts for the same (source_ip, attack_type) pair
        # within this many seconds, so one ongoing condition doesn't spam an
        # alert per matching packet.
        self.alert_cooldown_seconds = 30
        self._last_alert_at = {}

    # ------------------------------------------------------------------
    def _live_thresholds(self):
        return {
            "syn_flood_threshold": get_setting("syn_flood_threshold", self.app.config["SYN_FLOOD_THRESHOLD"], int),
            "udp_flood_threshold": get_setting("udp_flood_threshold", self.app.config["UDP_FLOOD_THRESHOLD"], int),
            "icmp_flood_threshold": get_setting("icmp_flood_threshold", self.app.config["ICMP_FLOOD_THRESHOLD"], int),
            "port_scan_threshold": get_setting("port_scan_threshold", self.app.config["PORT_SCAN_THRESHOLD"], int),
            "brute_force_threshold": get_setting("brute_force_threshold", self.app.config["BRUTE_FORCE_THRESHOLD"], int),
            "excessive_request_threshold": get_setting(
                "excessive_request_threshold", self.app.config["EXCESSIVE_REQUEST_THRESHOLD"], int
            ),
        }

    # ------------------------------------------------------------------
    def process_packet(self, record):
        """Called by the packet sniffer for every captured packet."""
        if not self.enabled:
            return

        with self.app.app_context():
            monitoring_on = get_setting("monitoring_enabled", True, bool)
            if not monitoring_on:
                return

            thresholds = self._live_thresholds()

            detections = self.rule_engine.evaluate_packet(record, thresholds)

            payload_text = ""
            try:
                payload_text = record.get("payload", b"").decode("utf-8", errors="ignore")
            except Exception:  # noqa: BLE001
                payload_text = ""

            if signatures.is_scannable_payload(payload_text):
                for attack_type in signatures.match_payload_signatures(payload_text):
                    detections.append({
                        "attack_type": attack_type,
                        "source_ip": record.get("source_ip"),
                        "destination_ip": record.get("destination_ip"),
                        "source_port": record.get("source_port"),
                        "destination_port": record.get("destination_port"),
                        "protocol": record.get("protocol"),
                        "observed_count": 1,
                        "threshold": 1,
                        "raw_snippet": payload_text[:200],
                    })

            for detection in detections:
                self._raise_alert(detection)

    def process_http_request(self, source_ip, user_agent=None, path=None):
        """Called by Flask middleware for every incoming HTTP request."""
        if not self.enabled:
            return
        with self.app.app_context():
            monitoring_on = get_setting("monitoring_enabled", True, bool)
            if not monitoring_on:
                return
            thresholds = self._live_thresholds()

            detection = self.rule_engine.evaluate_http_request(source_ip, thresholds)
            if detection:
                self._raise_alert(detection)

            if user_agent and signatures.is_suspicious_user_agent(user_agent):
                self._raise_alert({
                    "attack_type": "Suspicious User Agent",
                    "source_ip": source_ip,
                    "destination_ip": None,
                    "source_port": None,
                    "destination_port": None,
                    "protocol": "HTTP",
                    "observed_count": 1,
                    "threshold": 1,
                    "raw_snippet": f"UA: {user_agent} Path: {path}",
                })

    def process_failed_login(self, source_ip):
        with self.app.app_context():
            thresholds = self._live_thresholds()
            detection = self.rule_engine.evaluate_failed_login(source_ip, thresholds)
            if detection:
                self._raise_alert(detection)

    # ------------------------------------------------------------------
    def _raise_alert(self, detection):
        from database import db
        from models.alert import Alert

        source_ip = detection.get("source_ip", "unknown")
        attack_type = detection["attack_type"]

        cooldown_key = (source_ip, attack_type)
        now = time.time()
        last_seen = self._last_alert_at.get(cooldown_key)
        if last_seen is not None and (now - last_seen) < self.alert_cooldown_seconds:
            return  # Same source + attack type fired recently; suppress the duplicate
        self._last_alert_at[cooldown_key] = now

        classification = self.classifier.classify(detection)

        alert = Alert(
            attack_type=classification["attack_type"],
            source_ip=detection.get("source_ip", "unknown"),
            destination_ip=detection.get("destination_ip"),
            source_port=detection.get("source_port"),
            destination_port=detection.get("destination_port"),
            protocol=detection.get("protocol"),
            severity=classification["severity"],
            threat_score=classification["threat_score"],
            confidence=classification["confidence"],
            description=classification["description"],
            mitigation=classification["mitigation"],
            raw_payload_snippet=detection.get("raw_snippet"),
            action_taken="Logged",
        )
        db.session.add(alert)
        db.session.commit()
        self.total_threats += 1

        log_event(
            f"{classification['severity']} severity {classification['attack_type']} from "
            f"{alert.source_ip} (score={classification['threat_score']})",
            level="WARNING" if classification["severity"] in ("Low", "Medium") else "CRITICAL",
            source="ids_engine",
        )

        ips_engine = self._ips_engine_getter()
        blocked = False
        if ips_engine and get_setting("auto_block_enabled", True, bool):
            blocked = ips_engine.auto_block_if_needed(alert)

        if blocked:
            alert.action_taken = "Blocked"
            db.session.commit()

        if self.socketio:
            self.socketio.emit("new_alert", alert.to_dict())
            self.socketio.emit("threat_counter", {"total_threats": self.total_threats})

    def get_stats(self):
        return {"enabled": self.enabled, "total_threats": self.total_threats}
