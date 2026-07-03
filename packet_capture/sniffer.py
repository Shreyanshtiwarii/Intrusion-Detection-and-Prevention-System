"""
Packet Sniffer with cloud-safe fallback.

On cloud/PaaS environments where raw socket access is not available,
automatically falls back to a realistic traffic simulator that generates
live packet data, feeds the IDS engine, and pushes real-time SocketIO
events — so the entire dashboard works without root privileges.
"""

import threading
import queue
import time
import random
import ipaddress
from datetime import datetime

from utils.logger import log_event


def _can_sniff():
    """Return True only if raw socket capture is actually available."""
    try:
        import socket
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        s.close()
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Realistic traffic simulator
# ---------------------------------------------------------------------------
_INTERNAL_IPS = [f"192.168.1.{i}" for i in range(2, 30)]
_EXTERNAL_IPS = [
    "8.8.8.8", "1.1.1.1", "185.220.101.47", "45.33.32.156",
    "104.21.14.95", "172.67.68.228", "54.239.28.85", "13.107.42.14",
    "91.108.4.1", "162.159.133.1", "203.0.113.5", "198.51.100.42",
]
_PROTOCOLS = ["TCP", "TCP", "TCP", "UDP", "UDP", "ICMP", "DNS", "ARP"]
_COMMON_PORTS = {
    "TCP": [80, 443, 22, 21, 25, 3306, 8080, 8443, 3389, 445],
    "UDP": [53, 67, 68, 123, 161, 500, 514],
    "ICMP": [0],
    "DNS": [53],
    "ARP": [0],
}
_ATTACK_PATTERNS = [
    # (probability, src_ip, dst_port, protocol, flags, label)
    (0.02, "185.220.101.47", 22, "TCP", "S", "SSH Brute Force"),
    (0.01, "45.33.32.156", 3306, "TCP", "S", "Port Scan"),
    (0.01, "203.0.113.5", 80, "TCP", "S", "SYN Flood"),
    (0.005, "198.51.100.42", 443, "TCP", "PA", "SQL Injection Attempt"),
]


class SimulatedPacketSniffer:
    """Generates realistic network traffic simulation for cloud environments."""

    def __init__(self, app, socketio, ids_engine):
        self.app = app
        self.socketio = socketio
        self.ids_engine = ids_engine

        self._stop_event = threading.Event()
        self._thread = None

        self.running = False
        self.total_packets = 0
        self.protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "DNS": 0, "OTHER": 0}
        self.interface = "eth0 (simulated)"

    def start(self):
        if self.running:
            return False, "Sniffer already running"
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._simulate_loop, daemon=True)
        self.running = True
        self._thread.start()
        log_event("Packet capture started (cloud simulation mode — raw sockets unavailable)",
                  level="INFO", source="packet_capture")
        return True, "Sniffer started (simulation mode)"

    def stop(self):
        if not self.running:
            return False, "Sniffer is not running"
        self._stop_event.set()
        self.running = False
        log_event("Packet sniffer stopped", level="INFO", source="packet_capture")
        return True, "Sniffer stopped"

    def _simulate_loop(self):
        from database import db
        from models.packet_log import PacketLog

        with self.app.app_context():
            while not self._stop_event.is_set():
                # Generate 1-5 packets per tick
                count = random.randint(1, 5)
                for _ in range(count):
                    if self._stop_event.is_set():
                        break
                    record = self._generate_packet()
                    self._process(db, PacketLog, record)
                time.sleep(random.uniform(0.3, 0.8))

    def _generate_packet(self):
        now = datetime.utcnow()

        # Occasionally inject attack patterns
        for prob, src, dport, proto, flags, _ in _ATTACK_PATTERNS:
            if random.random() < prob:
                return {
                    "timestamp": now,
                    "source_ip": src,
                    "destination_ip": random.choice(_INTERNAL_IPS),
                    "protocol": proto,
                    "source_port": random.randint(1024, 65535),
                    "destination_port": dport,
                    "packet_size": random.randint(40, 200),
                    "flags": flags,
                    "summary": f"{proto} {src}:{random.randint(1024,65535)} → {dport}",
                    "payload": None,
                }

        # Normal traffic
        proto = random.choice(_PROTOCOLS)
        src_internal = random.random() < 0.6
        src_ip = random.choice(_INTERNAL_IPS) if src_internal else random.choice(_EXTERNAL_IPS)
        dst_ip = random.choice(_EXTERNAL_IPS) if src_internal else random.choice(_INTERNAL_IPS)
        ports = _COMMON_PORTS.get(proto, [0])
        sport = random.randint(1024, 65535)
        dport = random.choice(ports)
        size = random.randint(40, 1500)

        return {
            "timestamp": now,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "protocol": proto,
            "source_port": sport if proto not in ("ICMP", "ARP") else None,
            "destination_port": dport if proto not in ("ICMP", "ARP") else None,
            "packet_size": size,
            "flags": random.choice(["S", "SA", "A", "PA", "F"]) if proto == "TCP" else "",
            "summary": f"{proto} {src_ip}:{sport} → {dst_ip}:{dport}",
            "payload": None,
        }

    def _process(self, db, PacketLog, record):
        self.total_packets += 1
        proto = record["protocol"] if record["protocol"] in self.protocol_counts else "OTHER"
        self.protocol_counts[proto] = self.protocol_counts.get(proto, 0) + 1

        # Persist to DB (every 10th packet to avoid hammering SQLite)
        if self.total_packets % 10 == 0:
            try:
                entry = PacketLog(
                    timestamp=record["timestamp"],
                    source_ip=record["source_ip"],
                    destination_ip=record["destination_ip"],
                    protocol=record["protocol"],
                    source_port=record["source_port"],
                    destination_port=record["destination_port"],
                    packet_size=record["packet_size"],
                    flags=record.get("flags", ""),
                    summary=record["summary"],
                )
                db.session.add(entry)
                db.session.commit()
            except Exception as exc:
                db.session.rollback()
                log_event(f"Packet persist error: {exc}", level="ERROR", source="packet_capture")

        # Forward to IDS engine
        try:
            self.ids_engine.process_packet(record)
        except Exception:
            pass

        # Emit to dashboard in real time
        if self.socketio:
            payload = dict(record)
            payload["timestamp"] = record["timestamp"].isoformat()
            payload.pop("payload", None)
            self.socketio.emit("new_packet", payload)
            self.socketio.emit("packet_counter", {
                "total_packets": self.total_packets,
                "protocol_counts": self.protocol_counts,
            })

    def get_stats(self):
        return {
            "running": self.running,
            "total_packets": self.total_packets,
            "protocol_counts": self.protocol_counts,
            "interface": self.interface,
            "mode": "simulation",
        }


# ---------------------------------------------------------------------------
# Real Scapy sniffer (used only when raw sockets are available)
# ---------------------------------------------------------------------------
class RealPacketSniffer:
    def __init__(self, app, socketio, ids_engine, interface=None, bpf_filter=""):
        self.app = app
        self.socketio = socketio
        self.ids_engine = ids_engine
        self.interface = interface
        self.bpf_filter = bpf_filter

        self._thread = None
        self._stop_event = threading.Event()
        self._packet_queue = queue.Queue(maxsize=5000)
        self._writer_thread = None

        self.running = False
        self.total_packets = 0
        self.protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "DNS": 0, "OTHER": 0}

    def start(self):
        if self.running:
            return False, "Sniffer already running"
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._writer_thread = threading.Thread(target=self._writer_loop, daemon=True)
        self.running = True
        self._thread.start()
        self._writer_thread.start()
        log_event("Packet sniffer started", level="INFO", source="packet_capture")
        return True, "Sniffer started"

    def stop(self):
        if not self.running:
            return False, "Sniffer is not running"
        self._stop_event.set()
        self.running = False
        log_event("Packet sniffer stopped", level="INFO", source="packet_capture")
        return True, "Sniffer stopped"

    def _sniff_loop(self):
        try:
            from scapy.all import sniff, conf
            sniff(
                iface=self.interface,
                filter=self.bpf_filter or None,
                prn=self._on_packet,
                store=False,
                stop_filter=lambda pkt: self._stop_event.is_set(),
            )
        except Exception as exc:
            log_event(f"Packet capture error: {exc}", level="ERROR", source="packet_capture")
            self.running = False

    def _on_packet(self, pkt):
        if self._stop_event.is_set():
            return
        try:
            from packet_capture.parser import parse_packet
            record = parse_packet(pkt)
            if record is None:
                return
            self.total_packets += 1
            proto = record["protocol"] if record["protocol"] in self.protocol_counts else "OTHER"
            self.protocol_counts[proto] = self.protocol_counts.get(proto, 0) + 1
            try:
                self._packet_queue.put_nowait(record)
            except queue.Full:
                pass
        except Exception:
            pass

    def _writer_loop(self):
        from database import db
        from models.packet_log import PacketLog
        with self.app.app_context():
            batch = []
            last_flush = time.time()
            while not self._stop_event.is_set() or not self._packet_queue.empty():
                try:
                    record = self._packet_queue.get(timeout=0.5)
                except queue.Empty:
                    record = None
                if record:
                    batch.append(record)
                    self._dispatch_realtime(record)
                    self.ids_engine.process_packet(record)
                if batch and (len(batch) >= 50 or time.time() - last_flush > 2):
                    try:
                        for r in batch:
                            db.session.add(PacketLog(
                                timestamp=r["timestamp"], source_ip=r["source_ip"],
                                destination_ip=r["destination_ip"], protocol=r["protocol"],
                                source_port=r["source_port"], destination_port=r["destination_port"],
                                packet_size=r["packet_size"], flags=r.get("flags", ""),
                                summary=r["summary"],
                            ))
                        db.session.commit()
                    except Exception as exc:
                        db.session.rollback()
                        log_event(f"Packet persist error: {exc}", level="ERROR", source="packet_capture")
                    batch = []
                    last_flush = time.time()

    def _dispatch_realtime(self, record):
        if not self.socketio:
            return
        payload = dict(record)
        payload["timestamp"] = record["timestamp"].isoformat()
        payload.pop("payload", None)
        self.socketio.emit("new_packet", payload)
        self.socketio.emit("packet_counter", {
            "total_packets": self.total_packets,
            "protocol_counts": self.protocol_counts,
        })

    def get_stats(self):
        from scapy.all import conf
        return {
            "running": self.running,
            "total_packets": self.total_packets,
            "protocol_counts": self.protocol_counts,
            "interface": self.interface or str(conf.iface),
            "mode": "live",
        }


# ---------------------------------------------------------------------------
# Factory: auto-detect environment and return the right implementation
# ---------------------------------------------------------------------------
class PacketSniffer:
    """
    Transparent factory. Instantiates RealPacketSniffer when raw sockets are
    available (local / root), SimulatedPacketSniffer on cloud/PaaS.
    Callers use the same API regardless.
    """

    def __new__(cls, app, socketio, ids_engine, interface=None, bpf_filter=""):
        if _can_sniff():
            log_event("Raw socket access confirmed — using live packet capture",
                      level="INFO", source="packet_capture")
            inst = RealPacketSniffer(app, socketio, ids_engine, interface, bpf_filter)
        else:
            log_event("Raw socket access unavailable — using traffic simulation mode",
                      level="WARNING", source="packet_capture")
            inst = SimulatedPacketSniffer(app, socketio, ids_engine)
        return inst
