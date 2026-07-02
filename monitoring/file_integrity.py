"""
File Integrity Monitoring (FIM).

Computes SHA-256 hashes of configured critical files on a timer, compares
against the last known-good hash stored in the database, and raises an
alert (plus SystemLog + SocketIO broadcast) whenever a change or removal
is detected.
"""

import os
import threading
import time
from datetime import datetime

from utils.helpers import sha256_of_file
from utils.logger import log_event


class FileIntegrityMonitor:
    def __init__(self, app, socketio, watch_paths, interval_seconds=30):
        self.app = app
        self.socketio = socketio
        self.watch_paths = watch_paths
        self.interval_seconds = interval_seconds
        self._thread = None
        self._stop_event = threading.Event()
        self.running = False

    def start(self):
        if self.running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self.running = True
        self._thread.start()
        log_event("File integrity monitor started", level="INFO", source="file_integrity")

    def stop(self):
        self._stop_event.set()
        self.running = False
        log_event("File integrity monitor stopped", level="INFO", source="file_integrity")

    def _loop(self):
        with self.app.app_context():
            self._seed_baseline()
        while not self._stop_event.is_set():
            with self.app.app_context():
                self.scan_once()
            time.sleep(self.interval_seconds)

    def _seed_baseline(self):
        from database import db
        from models.file_hash import FileHash

        for path in self.watch_paths:
            if not os.path.isfile(path):
                continue
            existing = FileHash.query.filter_by(file_path=path).first()
            if existing:
                continue
            try:
                digest = sha256_of_file(path)
                db.session.add(FileHash(file_path=path, sha256_hash=digest, status="OK"))
            except Exception as exc:  # noqa: BLE001
                log_event(f"Failed to baseline {path}: {exc}", level="ERROR", source="file_integrity")
        db.session.commit()

    def scan_once(self):
        from database import db
        from models.file_hash import FileHash
        from models.alert import Alert

        for path in self.watch_paths:
            record = FileHash.query.filter_by(file_path=path).first()

            if not os.path.isfile(path):
                if record and record.status != "MISSING":
                    record.status = "MISSING"
                    record.last_checked = datetime.utcnow()
                    record.last_modified_alert = datetime.utcnow()
                    db.session.commit()
                    self._raise_fim_alert(path, "File Missing", "The monitored file could not be found.")
                continue

            try:
                current_hash = sha256_of_file(path)
            except Exception as exc:  # noqa: BLE001
                log_event(f"FIM read error for {path}: {exc}", level="ERROR", source="file_integrity")
                continue

            if record is None:
                db.session.add(FileHash(file_path=path, sha256_hash=current_hash, status="OK"))
                db.session.commit()
                continue

            if record.sha256_hash != current_hash:
                record.status = "MODIFIED"
                record.sha256_hash = current_hash
                record.last_checked = datetime.utcnow()
                record.last_modified_alert = datetime.utcnow()
                db.session.commit()
                self._raise_fim_alert(path, "File Modified", "The SHA-256 hash of this monitored file changed.")
            else:
                if record.status != "OK":
                    record.status = "OK"
                record.last_checked = datetime.utcnow()
                db.session.commit()

    def _raise_fim_alert(self, path, attack_type, description):
        from database import db
        from models.alert import Alert

        alert = Alert(
            attack_type="File Integrity Violation",
            source_ip="localhost",
            destination_ip=None,
            protocol="FIM",
            severity="High",
            threat_score=75,
            confidence=95,
            description=f"{description} Path: {path}",
            mitigation="Verify the change was authorized. Restore from backup if unauthorized.",
            action_taken="Logged",
        )
        db.session.add(alert)
        db.session.commit()

        log_event(f"FIM: {attack_type} - {path}", level="CRITICAL", source="file_integrity")

        if self.socketio:
            self.socketio.emit("new_alert", alert.to_dict())
            self.socketio.emit("fim_event", {"path": path, "type": attack_type})

    def add_watch_path(self, path):
        if path not in self.watch_paths:
            self.watch_paths.append(path)

    def remove_watch_path(self, path):
        if path in self.watch_paths:
            self.watch_paths.remove(path)
