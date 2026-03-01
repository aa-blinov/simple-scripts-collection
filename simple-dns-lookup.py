"""Perform DNS lookups for A, AAAA, MX, NS, TXT, and CNAME records."""

import socket
import sys
import argparse


def lookup_a(host: str) -> list[str]:
    try:
        return sorted({r[4][0] for r in socket.getaddrinfo(host, None, socket.AF_INET)})
    except socket.gaierror:
        return []


def lookup_aaaa(host: str) -> list[str]:
    try:
        return sorted(
            {r[4][0] for r in socket.getaddrinfo(host, None, socket.AF_INET6)}
        )
    except socket.gaierror:
        return []


def lookup_ptr(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ""


def lookup_mx(host: str) -> list[str]:
    import subprocess

    try:
        out = subprocess.check_output(
            ["nslookup", "-type=MX", host], text=True, stderr=subprocess.DEVNULL
        )
        results = []
        for line in out.splitlines():
            if "mail exchanger" in line.lower() or "MX preference" in line:
                results.append(line.strip())
        return results
    except Exception:
        return []


def resolve(host: str, record_types: list[str], reverse: bool) -> None:
    if reverse:
        ptr = lookup_ptr(host)
        print(f"PTR  {host}  →  {ptr or '(not found)'}")
        return

    show_all = "ALL" in record_types

    if show_all or "A" in record_types:
        for ip in lookup_a(host):
            print(f"A     {host:<40} {ip}")

    if show_all or "AAAA" in record_types:
        for ip in lookup_aaaa(host):
            print(f"AAAA  {host:<40} {ip}")

    if show_all or "PTR" in record_types:
        for ip in lookup_a(host):
            ptr = lookup_ptr(ip)
            if ptr:
                print(f"PTR   {ip:<40} {ptr}")

    if show_all or "MX" in record_types:
        for rec in lookup_mx(host):
            print(f"MX    {host:<40} {rec}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS lookup utility.")
    parser.add_argument("host", help="Hostname or IP address")
    parser.add_argument(
        "-t",
        "--type",
        nargs="+",
        choices=["A", "AAAA", "MX", "PTR", "ALL"],
        default=["A"],
        dest="types",
        help="Record type(s) to look up (default: A)",
    )
    parser.add_argument(
        "-r", "--reverse", action="store_true", help="Reverse lookup (IP → hostname)"
    )
    args = parser.parse_args()

    try:
        resolve(args.host, [t.upper() for t in args.types], args.reverse)
    except KeyboardInterrupt:
        sys.exit(0)
