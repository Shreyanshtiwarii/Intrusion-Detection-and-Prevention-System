"""
Thin abstraction over the host firewall so the IPS engine can attempt a real
network-level block (iptables on Linux, netsh on Windows) while degrading
gracefully to "logical block only" (DB blacklist enforced at the application
layer) when the process lacks privileges or the OS tool is unavailable.
"""

import platform
import subprocess

from utils.logger import log_event


class FirewallController:
    def __init__(self):
        self.system = platform.system()
        self.capable = self._detect_capability()

    def _detect_capability(self):
        try:
            if self.system == "Linux":
                result = subprocess.run(["which", "iptables"], capture_output=True, timeout=3)
                return result.returncode == 0
            if self.system == "Windows":
                result = subprocess.run(["where", "netsh"], capture_output=True, timeout=3, shell=True)
                return result.returncode == 0
        except Exception:  # noqa: BLE001
            return False
        return False

    def block_ip(self, ip_address):
        """Attempt an OS-level block. Always returns True for the logical
        (application-layer) block; OS-level enforcement is best-effort."""
        if not self.capable:
            log_event(f"OS firewall unavailable; logical block only for {ip_address}",
                       level="INFO", source="ips_engine")
            return True
        try:
            if self.system == "Linux":
                subprocess.run(
                    ["iptables", "-I", "INPUT", "-s", ip_address, "-j", "DROP"],
                    capture_output=True, timeout=5, check=False,
                )
            elif self.system == "Windows":
                rule_name = f"CyberShield_Block_{ip_address}"
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name={rule_name}", "dir=in", "action=block",
                     f"remoteip={ip_address}"],
                    capture_output=True, timeout=5, check=False, shell=True,
                )
            log_event(f"OS-level firewall block applied for {ip_address}", level="INFO", source="ips_engine")
        except Exception as exc:  # noqa: BLE001
            log_event(f"OS-level block failed for {ip_address}: {exc} (logical block still active)",
                       level="WARNING", source="ips_engine")
        return True

    def unblock_ip(self, ip_address):
        if not self.capable:
            return True
        try:
            if self.system == "Linux":
                subprocess.run(
                    ["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"],
                    capture_output=True, timeout=5, check=False,
                )
            elif self.system == "Windows":
                rule_name = f"CyberShield_Block_{ip_address}"
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                    capture_output=True, timeout=5, check=False, shell=True,
                )
            log_event(f"OS-level firewall block removed for {ip_address}", level="INFO", source="ips_engine")
        except Exception as exc:  # noqa: BLE001
            log_event(f"OS-level unblock failed for {ip_address}: {exc}", level="WARNING", source="ips_engine")
        return True
