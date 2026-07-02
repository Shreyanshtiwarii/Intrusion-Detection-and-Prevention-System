"""
Stateful, in-memory rule engine for rate/behavior-based attack detection.

Each rule tracks a sliding time window of activity per source IP and fires
when a configurable threshold is crossed. Thresholds are read live from the
Settings table so the UI's Settings page changes take effect immediately.
"""

import time
import threading
from collections import defaultdict, deque


class SlidingWindowCounter:
    """Thread-safe per-key sliding-window event counter."""

    def __init__(self, window_seconds):
        self.window_seconds = window_seconds
        self._events = defaultdict(deque)
        self._lock = threading.Lock()

    def add(self, key, value=None, timestamp=None):
        timestamp = timestamp or time.time()
        with self._lock:
            dq = self._events[key]
            dq.append((timestamp, value))
            self._trim(dq, timestamp)
            return len(dq), {v for _, v in dq if v is not None}

    def _trim(self, dq, now):
        cutoff = now - self.window_seconds
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def count(self, key):
        with self._lock:
            dq = self._events.get(key, deque())
            self._trim(dq, time.time())
            return len(dq)

    def reset(self, key):
        with self._lock:
            self._events.pop(key, None)


class RuleEngine:
    """
    Aggregates all rate-based detection rules. Call `evaluate_packet(record)`
    for every parsed packet; returns a list of detection dicts.
    """

    def __init__(self, window_seconds=10):
        self.window_seconds = window_seconds
        self.syn_counter = SlidingWindowCounter(window_seconds)
        self.udp_counter = SlidingWindowCounter(window_seconds)
        self.icmp_counter = SlidingWindowCounter(window_seconds)
        self.port_scan_counter = SlidingWindowCounter(window_seconds)
        self.request_counter = SlidingWindowCounter(window_seconds)
        self.brute_force_counter = SlidingWindowCounter(60)
        self.arp_table = {}  # ip -> mac, to detect spoofing (mac flips)
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    def evaluate_packet(self, record, thresholds):
        detections = []
        proto = record.get("protocol")
        src_ip = record.get("source_ip")
        if not src_ip:
            return detections

        if proto == "TCP" and record.get("flags") and "S" in str(record["flags"]) and "A" not in str(record["flags"]):
            count, _ = self.syn_counter.add(src_ip)
            if count >= thresholds.get("syn_flood_threshold", 100):
                detections.append(self._build("SYN Flood", src_ip, record, count, thresholds.get("syn_flood_threshold", 100)))

        if proto == "UDP":
            count, _ = self.udp_counter.add(src_ip)
            if count >= thresholds.get("udp_flood_threshold", 150):
                detections.append(self._build("UDP Flood", src_ip, record, count, thresholds.get("udp_flood_threshold", 150)))

        if proto == "ICMP":
            count, _ = self.icmp_counter.add(src_ip)
            if count >= thresholds.get("icmp_flood_threshold", 100):
                detections.append(self._build("ICMP Flood", src_ip, record, count, thresholds.get("icmp_flood_threshold", 100)))

        if proto in ("TCP", "UDP") and record.get("destination_port") is not None:
            count, ports = self.port_scan_counter.add(src_ip, value=record["destination_port"])
            if len(ports) >= thresholds.get("port_scan_threshold", 15):
                detections.append(self._build("Port Scan", src_ip, record, len(ports), thresholds.get("port_scan_threshold", 15)))

        if proto == "ARP":
            spoof = self._check_arp_spoof(record)
            if spoof:
                detections.append(self._build("ARP Spoofing", src_ip, record, 1, 1))

        return detections

    def evaluate_http_request(self, source_ip, thresholds):
        """Called by the excessive-request middleware for web-layer traffic."""
        count, _ = self.request_counter.add(source_ip)
        if count >= thresholds.get("excessive_request_threshold", 200):
            return self._build("Excessive Requests", source_ip, {"protocol": "HTTP"}, count,
                                thresholds.get("excessive_request_threshold", 200))
        return None

    def evaluate_failed_login(self, source_ip, thresholds):
        count, _ = self.brute_force_counter.add(source_ip)
        if count >= thresholds.get("brute_force_threshold", 5):
            return self._build("Brute Force", source_ip, {"protocol": "AUTH"}, count,
                                thresholds.get("brute_force_threshold", 5))
        return None

    # ------------------------------------------------------------------
    def _check_arp_spoof(self, record):
        # ARP record: source_ip = psrc; flags carries request/reply; MAC not parsed here
        # so we approximate using destination_ip field misuse guard -- real MAC captured upstream if needed.
        return False  # Reserved hook; MAC-level check performed in sniffer extension if enabled

    def _build(self, attack_type, src_ip, record, observed, threshold):
        return {
            "attack_type": attack_type,
            "source_ip": src_ip,
            "destination_ip": record.get("destination_ip"),
            "source_port": record.get("source_port"),
            "destination_port": record.get("destination_port"),
            "protocol": record.get("protocol"),
            "observed_count": observed,
            "threshold": threshold,
        }
