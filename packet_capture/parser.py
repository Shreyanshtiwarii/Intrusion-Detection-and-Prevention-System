"""
Translates raw Scapy packet objects into a normalized dictionary
that the rest of the application (IDS engine, DB, dashboard) can consume.
"""

from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS
from datetime import datetime


def parse_packet(pkt):
    """
    Normalize a sniffed packet into a plain dict.
    Returns None if the packet doesn't contain a recognizable protocol.
    """
    record = {
        "timestamp": datetime.utcnow(),
        "source_ip": None,
        "destination_ip": None,
        "protocol": None,
        "source_port": None,
        "destination_port": None,
        "packet_size": len(pkt) if pkt else 0,
        "flags": None,
        "summary": None,
        "payload": b"",
    }

    try:
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            record["protocol"] = "ARP"
            record["source_ip"] = arp.psrc
            record["destination_ip"] = arp.pdst
            record["flags"] = "request" if arp.op == 1 else "reply"
            record["summary"] = f"ARP {record['flags']} {arp.hwsrc} -> {arp.pdst}"
            return record

        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            record["source_ip"] = ip_layer.src
            record["destination_ip"] = ip_layer.dst

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                record["protocol"] = "TCP"
                record["source_port"] = int(tcp.sport)
                record["destination_port"] = int(tcp.dport)
                record["flags"] = str(tcp.flags)
                if pkt.haslayer(DNS):
                    record["protocol"] = "DNS"
                try:
                    record["payload"] = bytes(tcp.payload)
                except Exception:  # noqa: BLE001
                    record["payload"] = b""
                record["summary"] = f"TCP {ip_layer.src}:{tcp.sport} -> {ip_layer.dst}:{tcp.dport} [{tcp.flags}]"

            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                record["protocol"] = "UDP"
                record["source_port"] = int(udp.sport)
                record["destination_port"] = int(udp.dport)
                if pkt.haslayer(DNS):
                    record["protocol"] = "DNS"
                try:
                    record["payload"] = bytes(udp.payload)
                except Exception:  # noqa: BLE001
                    record["payload"] = b""
                record["summary"] = f"UDP {ip_layer.src}:{udp.sport} -> {ip_layer.dst}:{udp.dport}"

            elif pkt.haslayer(ICMP):
                icmp = pkt[ICMP]
                record["protocol"] = "ICMP"
                record["flags"] = f"type={icmp.type}"
                record["summary"] = f"ICMP {ip_layer.src} -> {ip_layer.dst} (type {icmp.type})"

            else:
                record["protocol"] = "IP"
                record["summary"] = f"IP {ip_layer.src} -> {ip_layer.dst}"

            return record

    except Exception:  # noqa: BLE001
        return None

    return None
