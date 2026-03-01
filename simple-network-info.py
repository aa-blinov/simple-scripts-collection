"""Show local network interfaces, IP addresses, and MAC addresses."""

import re
import sys
import socket
import platform
import argparse
import subprocess


def get_interfaces_windows() -> list[dict]:
    import ctypes

    oem_cp = f"cp{ctypes.windll.kernel32.GetOEMCP()}"
    raw = subprocess.check_output(["ipconfig", "/all"], stderr=subprocess.DEVNULL)
    out = raw.decode(oem_cp, errors="replace")
    interfaces: list[dict] = []
    current: dict | None = None

    # Locale-agnostic patterns: detect by value format, not by label text.
    # IPs with a parenthesised qualifier are the adapter's own addresses.
    re_ipv4 = re.compile(r":\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*\(")
    re_ipv6 = re.compile(r":\s*([0-9a-fA-F:]+(?:%\d+)?)\s*\(")
    re_mac = re.compile(r":\s*([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})\s*$")

    for line in out.splitlines():
        if not line.strip():
            continue
        if not line[0].isspace():
            if current is not None:
                interfaces.append(current)
            current = {
                "name": line.strip().rstrip(":"),
                "ipv4": [],
                "ipv6": [],
                "mac": "",
            }
        elif current is not None:
            m = re_mac.search(line)
            if m:
                current["mac"] = m.group(1)
                continue
            m = re_ipv4.search(line)
            if m:
                current["ipv4"].append(m.group(1))
                continue
            m = re_ipv6.search(line)
            if m and ":" in m.group(1):
                current["ipv6"].append(m.group(1).split("%")[0])

    if current is not None:
        interfaces.append(current)
    return interfaces


def get_hostname_ips() -> list[str]:
    try:
        host = socket.gethostname()
        return socket.gethostbyname_ex(host)[2]
    except Exception:
        return []


def get_external_ip() -> str:
    try:
        with socket.create_connection(("8.8.8.8", 80), timeout=3) as s:
            return s.getsockname()[0]
    except Exception:
        return "n/a"


def get_interfaces_unix() -> list[dict]:
    out = subprocess.check_output(["ip", "addr"], text=True, stderr=subprocess.DEVNULL)
    interfaces: list[dict] = []
    current: dict = {}
    for line in out.splitlines():
        m_iface = line.split(":")
        if line and line[0].isdigit() and len(m_iface) >= 2:
            if current:
                interfaces.append(current)
            current = {"name": m_iface[1].strip(), "ipv4": [], "ipv6": [], "mac": ""}
        elif "inet " in line:
            parts = line.split()
            current.setdefault("ipv4", []).append(parts[1])
        elif "inet6 " in line:
            parts = line.split()
            current.setdefault("ipv6", []).append(parts[1])
        elif "link/ether" in line:
            current["mac"] = line.split()[1]
    if current:
        interfaces.append(current)
    return interfaces


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Show local network interfaces and IPs."
    )
    parser.add_argument(
        "--all", action="store_true", help="Include interfaces with no IP assigned"
    )
    args = parser.parse_args()

    try:
        if platform.system() == "Windows":
            ifaces = get_interfaces_windows()
        else:
            ifaces = get_interfaces_unix()
    except Exception as e:
        print(f"Error reading interfaces: {e}", file=sys.stderr)
        sys.exit(1)

    hostname = socket.gethostname()
    outbound = get_external_ip()
    print(f"  {'Hostname':<16} {hostname}")
    print(f"  {'Outbound IP':<16} {outbound}\n")

    for iface in ifaces:
        has_ip = iface.get("ipv4") or iface.get("ipv6")
        if not has_ip and not args.all:
            continue
        print(f"  {iface['name']}")
        if iface.get("mac"):
            print(f"    {'MAC':<12} {iface['mac']}")
        for ip in iface.get("ipv4", []):
            print(f"    {'IPv4':<12} {ip}")
        for ip in iface.get("ipv6", []):
            print(f"    {'IPv6':<12} {ip}")
