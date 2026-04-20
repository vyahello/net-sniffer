#!/usr/bin/env python3
"""
Advanced WiFi Activity Monitor
Tracks all network activities, websites, and user actions
"""

import ctypes
import json
import logging
import os
from collections import defaultdict
from datetime import datetime
from pathlib import Path
import signal
import sys
from types import FrameType
from typing import DefaultDict, Optional, TypedDict

from scapy.all import get_if_list, sniff
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw


class DNSQueryRecord(TypedDict):
    timestamp: str
    domain: str


class HTTPRequestRecord(TypedDict):
    timestamp: str
    method: str
    url: str


class HostActivity(TypedDict):
    dns_queries: list[DNSQueryRecord]
    http_requests: list[HTTPRequestRecord]
    https_domains: list[str]
    ports_accessed: set[int]
    bytes_sent: int
    bytes_received: int
    first_seen: Optional[str]
    last_seen: Optional[str]


class Statistics(TypedDict):
    total_packets: int
    http_requests: int
    dns_queries: int
    https_connections: int
    credentials_found: int


class ReportHost(TypedDict):
    dns_queries: list[DNSQueryRecord]
    http_requests: list[HTTPRequestRecord]
    bytes_sent: int
    bytes_received: int
    ports_accessed: list[int]
    first_seen: Optional[str]
    last_seen: Optional[str]


class Report(TypedDict):
    timestamp: str
    statistics: Statistics
    hosts: dict[str, ReportHost]


class Colors:
    HEADER: str = "\033[95m"
    BLUE: str = "\033[94m"
    CYAN: str = "\033[96m"
    GREEN: str = "\033[92m"
    YELLOW: str = "\033[93m"
    RED: str = "\033[91m"
    END: str = "\033[0m"
    BOLD: str = "\033[1m"


APP_NAME: str = "wifi_monitor"


def get_log_dir() -> Path:
    """Return a platform-appropriate log directory."""
    if os.name == "nt":
        local_app_data: Optional[str] = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            return Path(local_app_data) / APP_NAME
        return Path.home() / "AppData" / "Local" / APP_NAME

    if sys.platform == "darwin":
        return Path.home() / "Library" / "Logs" / APP_NAME

    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return Path("/var/log") / APP_NAME

    return Path.home() / ".local" / "state" / APP_NAME


LOG_DIR: Path = get_log_dir()


def make_host_activity() -> HostActivity:
    """Create the default activity record for a host."""
    return {
        "dns_queries": [],
        "http_requests": [],
        "https_domains": [],
        "ports_accessed": set(),
        "bytes_sent": 0,
        "bytes_received": 0,
        "first_seen": None,
        "last_seen": None,
    }


host_activities: DefaultDict[str, HostActivity] = defaultdict(make_host_activity)

stats: Statistics = {
    "total_packets": 0,
    "http_requests": 0,
    "dns_queries": 0,
    "https_connections": 0,
    "credentials_found": 0,
}


def setup_logging() -> None:
    """Set up logging to file and stdout."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(LOG_DIR / "monitor.log"),
            logging.StreamHandler(sys.stdout),
        ],
    )


def is_running_as_admin() -> bool:
    """Return True when the process has elevated capture privileges."""
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False

    if hasattr(os, "geteuid"):
        return os.geteuid() == 0

    return False


def get_default_interface() -> tuple[str, list[str]]:
    """Pick a reasonable default from Scapy's detected interfaces."""
    interfaces: list[str] = sorted(dict.fromkeys(get_if_list()))
    if not interfaces:
        return ("Wi-Fi" if os.name == "nt" else "wlan0"), interfaces

    preferred_keywords: tuple[str, ...]
    if os.name == "nt":
        preferred_keywords = ("wi-fi", "wifi", "wlan", "wireless", "ethernet")
    elif sys.platform == "darwin":
        preferred_keywords = ("en0", "en1", "bridge", "awdl")
    else:
        preferred_keywords = ("wlan0", "wlp", "wl", "eth0", "enp", "eno", "enx")

    for keyword in preferred_keywords:
        for interface in interfaces:
            lowered: str = interface.lower()
            if keyword in lowered and "loopback" not in lowered:
                return interface, interfaces

    for interface in interfaces:
        lowered = interface.lower()
        if lowered not in {"lo", "lo0"} and "loopback" not in lowered:
            return interface, interfaces

    return interfaces[0], interfaces


def print_banner() -> None:
    """Print the startup banner."""
    banner: str = f"""
{Colors.CYAN}{'=' * 60}
    Advanced WiFi Activity Monitor
    Track: Hosts | Websites | Activities | Credentials
{'=' * 60}{Colors.END}
"""
    print(banner)


def extract_credentials(packet: Packet) -> None:
    """Extract potential credentials from HTTP traffic."""
    if not packet.haslayer(Raw):
        return

    payload: str = packet[Raw].load.decode("utf-8", errors="ignore")
    patterns: list[str] = [
        "password=",
        "passwd=",
        "pwd=",
        "pass=",
        "login=",
        "username=",
        "user=",
        "email=",
        "auth=",
    ]

    for pattern in patterns:
        if pattern not in payload.lower():
            continue

        timestamp: str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src_ip: str = packet[IP].src if packet.haslayer(IP) else "Unknown"

        try:
            start: int = payload.lower().find(pattern) + len(pattern)
            end: int = payload.find("&", start)
            if end == -1:
                end = start + 50
            value: str = payload[start:end]

            log_msg: str = f"[CREDENTIAL] {timestamp} | IP: {src_ip} | {pattern}{value}"
            print(f"{Colors.RED}{log_msg}{Colors.END}")

            with open(
                LOG_DIR / "credentials.log", "a", encoding="utf-8"
            ) as file_handle:
                file_handle.write(log_msg + "\n")

            stats["credentials_found"] += 1
        except (AttributeError, IndexError, TypeError, ValueError):
            continue


def process_dns(packet: Packet) -> None:
    """Process DNS packets."""
    if not packet.haslayer(DNSQR):
        return

    query: str = packet[DNSQR].qname.decode("utf-8", errors="ignore")
    src_ip: str = packet[IP].src if packet.haslayer(IP) else "Unknown"
    timestamp: str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log_msg: str = f"[DNS] {timestamp} | {src_ip} -> {query}"
    print(f"{Colors.YELLOW}{log_msg}{Colors.END}")

    host_activities[src_ip]["dns_queries"].append(
        {"timestamp": timestamp, "domain": query}
    )
    host_activities[src_ip]["last_seen"] = timestamp
    if not host_activities[src_ip]["first_seen"]:
        host_activities[src_ip]["first_seen"] = timestamp

    with open(LOG_DIR / "dns.log", "a", encoding="utf-8") as file_handle:
        file_handle.write(log_msg + "\n")

    stats["dns_queries"] += 1


def process_http(packet: Packet) -> None:
    """Process HTTP packets."""
    if not packet.haslayer(HTTPRequest):
        return

    http_layer: Packet = packet[HTTPRequest]
    src_ip: str = packet[IP].src
    method: str = http_layer.Method.decode("utf-8", errors="ignore")
    host: str = (
        http_layer.Host.decode("utf-8", errors="ignore")
        if http_layer.Host
        else "Unknown"
    )
    path: str = (
        http_layer.Path.decode("utf-8", errors="ignore") if http_layer.Path else "/"
    )
    timestamp: str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    url: str = f"http://{host}{path}"

    log_msg: str = f"[HTTP] {timestamp} | {src_ip} | {method} {url}"
    print(f"{Colors.GREEN}{log_msg}{Colors.END}")

    host_activities[src_ip]["http_requests"].append(
        {"timestamp": timestamp, "method": method, "url": url}
    )
    host_activities[src_ip]["last_seen"] = timestamp

    with open(LOG_DIR / "http.log", "a", encoding="utf-8") as file_handle:
        file_handle.write(log_msg + "\n")

    stats["http_requests"] += 1
    extract_credentials(packet)


def process_https(packet: Packet) -> None:
    """Process HTTPS/TLS packets to extract SNI-like connection metadata."""
    if not packet.haslayer(TCP) or packet[TCP].dport != 443 or not packet.haslayer(Raw):
        return

    payload: bytes = packet[Raw].load
    if len(payload) <= 40:
        return

    try:
        if b"\x00\x00" not in payload[30:]:
            return

        src_ip: str = packet[IP].src
        timestamp: str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_msg: str = f"[HTTPS] {timestamp} | {src_ip} -> TLS connection"
        print(f"{Colors.CYAN}{log_msg}{Colors.END}")
        stats["https_connections"] += 1
    except (AttributeError, IndexError, TypeError, ValueError):
        return


def process_packet(packet: Packet) -> None:
    """Process one captured packet."""
    stats["total_packets"] += 1

    try:
        if packet.haslayer(IP):
            src_ip: str = packet[IP].src
            dst_ip: str = packet[IP].dst
            size: int = len(packet)

            host_activities[src_ip]["bytes_sent"] += size
            host_activities[dst_ip]["bytes_received"] += size

            if packet.haslayer(TCP):
                port: int = packet[TCP].dport
                host_activities[src_ip]["ports_accessed"].add(port)

        if packet.haslayer(DNS):
            process_dns(packet)
        elif packet.haslayer(HTTPRequest):
            process_http(packet)
        elif packet.haslayer(TCP) and packet[TCP].dport == 443:
            process_https(packet)
    except Exception as error:
        logging.error("Error processing packet: %s", error)


def print_statistics() -> None:
    """Print monitoring statistics."""
    print(f"\n{Colors.BOLD}{'=' * 60}")
    print("MONITORING STATISTICS")
    print(f"{'=' * 60}{Colors.END}")
    print(f"Total Packets:      {stats['total_packets']}")
    print(f"DNS Queries:        {stats['dns_queries']}")
    print(f"HTTP Requests:      {stats['http_requests']}")
    print(f"HTTPS Connections:  {stats['https_connections']}")
    print(f"Credentials Found:  {Colors.RED}{stats['credentials_found']}{Colors.END}")
    print(f"Active Hosts:       {len(host_activities)}")
    print(f"{'=' * 60}\n")


def print_host_summary() -> None:
    """Print a summary of host activities."""
    print(f"\n{Colors.BOLD}HOST ACTIVITY SUMMARY{Colors.END}")
    print(f"{'=' * 60}\n")

    for ip, activity in list(host_activities.items())[:10]:
        print(f"{Colors.CYAN}Host: {ip}{Colors.END}")
        print(f"  DNS Queries:    {len(activity['dns_queries'])}")
        print(f"  HTTP Requests:  {len(activity['http_requests'])}")
        print(f"  Bytes Sent:     {activity['bytes_sent']:,}")
        print(f"  Bytes Received: {activity['bytes_received']:,}")
        print(f"  Ports Accessed: {len(activity['ports_accessed'])}")
        print(f"  First Seen:     {activity['first_seen']}")
        print(f"  Last Seen:      {activity['last_seen']}")
        print()


def save_report() -> None:
    """Save a detailed report to JSON."""
    report: Report = {
        "timestamp": datetime.now().isoformat(),
        "statistics": dict(stats),
        "hosts": {},
    }

    for ip, activity in host_activities.items():
        report["hosts"][ip] = {
            "dns_queries": activity["dns_queries"],
            "http_requests": activity["http_requests"],
            "bytes_sent": activity["bytes_sent"],
            "bytes_received": activity["bytes_received"],
            "ports_accessed": list(activity["ports_accessed"]),
            "first_seen": activity["first_seen"],
            "last_seen": activity["last_seen"],
        }

    report_file: Path = (
        LOG_DIR / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )
    with open(report_file, "w", encoding="utf-8") as file_handle:
        json.dump(report, file_handle, indent=2)

    print(f"\n{Colors.GREEN}[+] Report saved: {report_file}{Colors.END}")


def signal_handler(sig: int, frame: Optional[FrameType]) -> None:
    """Handle Ctrl+C gracefully."""
    _ = (sig, frame)
    print(f"\n{Colors.YELLOW}[!] Stopping monitor...{Colors.END}")
    print_statistics()
    print_host_summary()
    save_report()
    sys.exit(0)


def main() -> None:
    """Run the network monitor."""
    if not is_running_as_admin():
        privilege_name: str = "Administrator" if os.name == "nt" else "root"
        print(
            f"{Colors.RED}[!] This script requires {privilege_name} privileges{Colors.END}"
        )
        sys.exit(1)

    print_banner()
    setup_logging()
    default_interface, interfaces = get_default_interface()
    print(f"{Colors.BLUE}[i] Logs directory: {LOG_DIR}{Colors.END}")
    if interfaces:
        preview: str = ", ".join(interfaces[:8])
        suffix: str = "..." if len(interfaces) > 8 else ""
        print(f"{Colors.BLUE}[i] Detected interfaces: {preview}{suffix}{Colors.END}")

    interface: str = input(
        f"{Colors.CYAN}Enter interface to monitor (default: {default_interface}): {Colors.END}"
    ).strip()
    if not interface:
        interface = default_interface

    print(f"\n{Colors.GREEN}[+] Starting monitor on {interface}...{Colors.END}")
    print(f"{Colors.YELLOW}[!] Press Ctrl+C to stop and view report{Colors.END}\n")

    signal.signal(signal.SIGINT, signal_handler)

    try:
        sniff(iface=interface, prn=process_packet, store=False)
    except Exception as error:
        print(f"{Colors.RED}[!] Error: {error}{Colors.END}")
        print(
            f"{Colors.YELLOW}[!] Make sure the interface exists and you have permissions{Colors.END}"
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
