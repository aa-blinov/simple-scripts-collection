"""Check SSL certificate expiry for one or more domains."""

import ssl
import socket
import sys
import argparse
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

ANSI = {"ok": "\033[32m", "warn": "\033[33m", "err": "\033[31m", "dim": "\033[90m"}
RESET = "\033[0m"


def check_cert(host: str, port: int, timeout: int) -> dict:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        days_left = (not_after - datetime.now(timezone.utc)).days
        subject = dict(x[0] for x in cert.get("subject", []))
        sans = [v for _, v in cert.get("subjectAltName", []) if _ == "DNS"]
        return {
            "host": host,
            "port": port,
            "days_left": days_left,
            "expires": not_after.strftime("%Y-%m-%d"),
            "cn": subject.get("commonName", ""),
            "sans": sans,
            "error": None,
        }
    except ssl.SSLCertVerificationError as e:
        return {"host": host, "port": port, "error": f"Verification failed: {e}"}
    except Exception as e:
        return {"host": host, "port": port, "error": str(e)}


def status_color(days: int, no_color: bool) -> str:
    if no_color:
        return ""
    if days < 0:
        return ANSI["err"]
    if days < 14:
        return ANSI["warn"]
    return ANSI["ok"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check SSL certificate expiry.")
    parser.add_argument("hosts", nargs="*", help="Domains to check (host[:port])")
    parser.add_argument("-f", "--file", help="File with one host[:port] per line")
    parser.add_argument(
        "-p", "--port", type=int, default=443, help="Default port (default: 443)"
    )
    parser.add_argument(
        "-t", "--timeout", type=int, default=10, help="Timeout seconds (default: 10)"
    )
    parser.add_argument(
        "-w",
        "--warn",
        type=int,
        default=30,
        help="Warn threshold in days (default: 30)",
    )
    parser.add_argument(
        "-s", "--sans", action="store_true", help="Show Subject Alternative Names"
    )
    parser.add_argument("--no-color", action="store_true", help="Disable color output")
    args = parser.parse_args()

    entries: list[tuple[str, int]] = []
    for raw in args.hosts:
        h, _, p = raw.partition(":")
        entries.append((h, int(p) if p else args.port))
    if args.file:
        for line in open(args.file):
            line = line.strip()
            if line and not line.startswith("#"):
                h, _, p = line.partition(":")
                entries.append((h, int(p) if p else args.port))

    if not entries:
        parser.print_help()
        sys.exit(1)

    results = []
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {
            pool.submit(check_cert, h, p, args.timeout): (h, p) for h, p in entries
        }
        for f in as_completed(futures):
            results.append(f.result())

    results.sort(key=lambda r: r.get("days_left", 9999))

    for r in results:
        if r["error"]:
            c = "" if args.no_color else ANSI["err"]
            print(f"{c}ERR  {r['host']}:{r['port']}  {r['error']}{RESET}")
        else:
            d = r["days_left"]
            tag = "OK " if d >= args.warn else ("WARN" if d >= 0 else "EXP ")
            c = status_color(d, args.no_color)
            print(
                f"{c}{tag}  {r['host']}:{r['port']}  {d:>4}d  expires {r['expires']}  CN={r['cn']}{RESET}"
            )
            if args.sans and r["sans"]:
                dim = "" if args.no_color else ANSI["dim"]
                print(f"{dim}       SANs: {', '.join(r['sans'][:6])}{RESET}")
