"""
Intrusion Prevention System engine.

Maintains the IP blacklist/whitelist, decides when a detected alert warrants
an automatic block, applies the block at both the application layer (checked
on every request via middleware) and best-effort OS firewall layer, and
exposes manual block/unblock operations for the dashboard.
"""

from datetime import datetime

from ips_engine.firewall import FirewallController
from utils.logger import log_event
from utils.helpers import minutes_from_now, get_setting

# Attack types severe enough to auto-block on a single occurrence
IMMEDIATE_BLOCK_TYPES = {"Command Injection", "SQL Injection", "Directory Traversal"}


class IPSEngine:
    def __init__(self, app, socketio):
        self.app = app
        self.socketio = socketio
        self.firewall = FirewallController()
        self._active_ips_cache = set()
        self._cache_loaded = False

    # ------------------------------------------------------------------
    def _refresh_cache(self):
        from models.blocked_ip import BlockedIP
        self._active_ips_cache = {
            row.ip_address for row in BlockedIP.query.filter_by(is_active=True).all()
        }
        self._cache_loaded = True

    def is_blocked(self, ip_address):
        """Fast application-layer check used by request middleware."""
        with self.app.app_context():
            if not self._cache_loaded:
                self._refresh_cache()
            return ip_address in self._active_ips_cache

    def is_whitelisted(self, ip_address):
        return ip_address in self.app.config.get("WHITELIST_IPS", [])

    # ------------------------------------------------------------------
    def auto_block_if_needed(self, alert):
        """Called by the IDS engine right after an alert is created."""
        if self.is_whitelisted(alert.source_ip):
            return False

        should_block = (
            alert.attack_type in IMMEDIATE_BLOCK_TYPES
            or alert.severity in ("High", "Critical")
        )
        if not should_block:
            return False

        duration = get_setting("block_duration_minutes", self.app.config["DEFAULT_BLOCK_DURATION_MINUTES"], int)
        self.block_ip(
            alert.source_ip,
            reason=f"Auto-blocked: {alert.attack_type} (score {alert.threat_score})",
            block_type="Temporary",
            duration_minutes=duration,
            blocked_by="IPS Engine",
        )
        return True

    def block_ip(self, ip_address, reason="Manual block", block_type="Temporary",
                  duration_minutes=60, blocked_by="admin"):
        from database import db
        from models.blocked_ip import BlockedIP

        if self.is_whitelisted(ip_address):
            return False, "IP is whitelisted and cannot be blocked"

        existing = BlockedIP.query.filter_by(ip_address=ip_address, is_active=True).first()
        if existing:
            return False, "IP is already blocked"

        expires_at = None if block_type == "Permanent" else minutes_from_now(duration_minutes)

        entry = BlockedIP(
            ip_address=ip_address,
            reason=reason,
            block_type=block_type,
            expires_at=expires_at,
            is_active=True,
            blocked_by=blocked_by,
        )
        db.session.add(entry)
        db.session.commit()

        self.firewall.block_ip(ip_address)
        self._active_ips_cache.add(ip_address)

        log_event(f"Blocked IP {ip_address} ({block_type}) - {reason}", level="WARNING", source="ips_engine")

        if self.socketio:
            self.socketio.emit("ip_blocked", entry.to_dict())

        return True, "IP blocked successfully"

    def unblock_ip(self, ip_address, unblocked_by="admin"):
        from database import db
        from models.blocked_ip import BlockedIP

        entry = BlockedIP.query.filter_by(ip_address=ip_address, is_active=True).first()
        if not entry:
            return False, "IP is not currently blocked"

        entry.is_active = False
        entry.unblocked_at = datetime.utcnow()
        db.session.commit()

        self.firewall.unblock_ip(ip_address)
        self._active_ips_cache.discard(ip_address)

        log_event(f"Unblocked IP {ip_address} by {unblocked_by}", level="INFO", source="ips_engine")

        if self.socketio:
            self.socketio.emit("ip_unblocked", entry.to_dict())

        return True, "IP unblocked successfully"

    def expire_stale_blocks(self):
        """Periodic sweep to lift temporary blocks whose expiry has passed."""
        from database import db
        from models.blocked_ip import BlockedIP

        with self.app.app_context():
            now = datetime.utcnow()
            expired = BlockedIP.query.filter(
                BlockedIP.is_active.is_(True),
                BlockedIP.block_type == "Temporary",
                BlockedIP.expires_at.isnot(None),
                BlockedIP.expires_at <= now,
            ).all()
            for entry in expired:
                entry.is_active = False
                entry.unblocked_at = now
                self.firewall.unblock_ip(entry.ip_address)
                self._active_ips_cache.discard(entry.ip_address)
                log_event(f"Temporary block expired for {entry.ip_address}", level="INFO", source="ips_engine")
                if self.socketio:
                    self.socketio.emit("ip_unblocked", entry.to_dict())
            if expired:
                db.session.commit()

    def get_stats(self):
        with self.app.app_context():
            from models.blocked_ip import BlockedIP
            active_count = BlockedIP.query.filter_by(is_active=True).count()
            return {"active_blocks": active_count, "firewall_capable": self.firewall.capable}
