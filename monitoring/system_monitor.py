"""
Background system resource monitor. Polls CPU / RAM / Disk usage with psutil
and broadcasts snapshots to the dashboard over SocketIO on a fixed interval.
"""

import threading
import time
import psutil

from utils.logger import log_event


class SystemMonitor:
    def __init__(self, app, socketio, interval_seconds=3):
        self.app = app
        self.socketio = socketio
        self.interval_seconds = interval_seconds
        self._thread = None
        self._stop_event = threading.Event()
        self.running = False
        self.latest_snapshot = {}

    def start(self):
        if self.running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self.running = True
        self._thread.start()
        log_event("System monitor started", level="INFO", source="system_monitor")

    def stop(self):
        self._stop_event.set()
        self.running = False
        log_event("System monitor stopped", level="INFO", source="system_monitor")

    def _loop(self):
        # Prime psutil's internal CPU sample window
        psutil.cpu_percent(interval=None)
        while not self._stop_event.is_set():
            try:
                snapshot = self._collect()
                self.latest_snapshot = snapshot
                if self.socketio:
                    self.socketio.emit("system_stats", snapshot)
            except Exception as exc:  # noqa: BLE001
                log_event(f"System monitor error: {exc}", level="ERROR", source="system_monitor")
            time.sleep(self.interval_seconds)

    def _collect(self):
        cpu_percent = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        net = psutil.net_io_counters()

        return {
            "cpu_percent": cpu_percent,
            "memory_percent": mem.percent,
            "memory_used_gb": round(mem.used / (1024 ** 3), 2),
            "memory_total_gb": round(mem.total / (1024 ** 3), 2),
            "disk_percent": disk.percent,
            "disk_used_gb": round(disk.used / (1024 ** 3), 2),
            "disk_total_gb": round(disk.total / (1024 ** 3), 2),
            "bytes_sent": net.bytes_sent,
            "bytes_recv": net.bytes_recv,
            "timestamp": time.time(),
        }

    def get_snapshot(self):
        return self.latest_snapshot or self._collect()
