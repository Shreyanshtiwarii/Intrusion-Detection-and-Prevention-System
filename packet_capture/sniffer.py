"""
Background packet sniffer built on Scapy.

Runs in its own daemon thread so it never blocks the Flask/SocketIO event loop.
Each captured packet is parsed, persisted, forwarded to the IDS engine, and
broadcast to connected dashboard clients in real time.
"""

import threading
import queue
import time

from scapy.all import sniff, conf

from packet_capture.parser import parse_packet
from utils.logger import log_event


class PacketSniffer:
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

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
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

    # ------------------------------------------------------------------
    # Capture loop (Scapy)
    # ------------------------------------------------------------------
    def _sniff_loop(self):
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter or None,
                prn=self._on_packet,
                store=False,
                stop_filter=lambda pkt: self._stop_event.is_set(),
            )
        except PermissionError:
            log_event(
                "Packet capture requires elevated privileges (run with sudo/administrator).",
                level="ERROR", source="packet_capture",
            )
            self.running = False
        except OSError as exc:
            log_event(f"Packet capture failed to start: {exc}", level="ERROR", source="packet_capture")
            self.running = False
        except Exception as exc:  # noqa: BLE001
            log_event(f"Unexpected sniffer error: {exc}", level="ERROR", source="packet_capture")
            self.running = False

    def _on_packet(self, pkt):
        if self._stop_event.is_set():
            return
        record = parse_packet(pkt)
        if record is None:
            return
        self.total_packets += 1
        proto = record["protocol"] if record["protocol"] in self.protocol_counts else "OTHER"
        self.protocol_counts[proto] = self.protocol_counts.get(proto, 0) + 1
        try:
            self._packet_queue.put_nowait(record)
        except queue.Full:
            pass  # Drop under extreme load rather than block capture

    # ------------------------------------------------------------------
    # DB writer / IDS dispatch loop (runs with Flask app context)
    # ------------------------------------------------------------------
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
                    self._flush_batch(db, PacketLog, batch)
                    batch = []
                    last_flush = time.time()

            if batch:
                self._flush_batch(db, PacketLog, batch)

    def _flush_batch(self, db, PacketLog, batch):
        try:
            for record in batch:
                entry = PacketLog(
                    timestamp=record["timestamp"],
                    source_ip=record["source_ip"],
                    destination_ip=record["destination_ip"],
                    protocol=record["protocol"],
                    source_port=record["source_port"],
                    destination_port=record["destination_port"],
                    packet_size=record["packet_size"],
                    flags=record["flags"],
                    summary=record["summary"],
                )
                db.session.add(entry)
            db.session.commit()
        except Exception as exc:  # noqa: BLE001
            db.session.rollback()
            log_event(f"Failed to persist packet batch: {exc}", level="ERROR", source="packet_capture")

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
        return {
            "running": self.running,
            "total_packets": self.total_packets,
            "protocol_counts": self.protocol_counts,
            "interface": self.interface or (conf.iface and str(conf.iface)),
        }
