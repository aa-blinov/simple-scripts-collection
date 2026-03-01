"""Decode and inspect a JWT token without verifying the signature."""

import base64
import json
import sys
import argparse
from datetime import datetime, timezone


def b64_decode(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded)


def decode_part(segment: str) -> dict:
    return json.loads(b64_decode(segment).decode("utf-8"))


def fmt_timestamp(ts: int) -> str:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    now = datetime.now(timezone.utc)
    diff = dt - now
    rel = (
        f"in {int(diff.total_seconds())}s"
        if diff.total_seconds() > 0
        else f"{int(-diff.total_seconds())}s ago"
    )
    return f"{dt.strftime('%Y-%m-%d %H:%M:%S UTC')}  ({rel})"


def print_section(title: str, data: dict, ts_keys: set[str]) -> None:
    print(f"\n── {title} {'─' * (40 - len(title))}")
    for k, v in data.items():
        if k in ts_keys and isinstance(v, int):
            print(f"  {k:<12} {fmt_timestamp(v)}")
        else:
            print(f"  {k:<12} {json.dumps(v, ensure_ascii=False)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Decode a JWT token and display its header and payload."
    )
    parser.add_argument("token", nargs="?", help="JWT string (reads stdin if omitted)")
    parser.add_argument(
        "--raw", action="store_true", help="Print raw JSON without formatting"
    )
    args = parser.parse_args()

    token = (args.token or sys.stdin.read()).strip()
    token = token.removeprefix("Bearer ").strip()

    parts = token.split(".")
    if len(parts) != 3:
        print("Invalid JWT: expected 3 dot-separated parts.", file=sys.stderr)
        sys.exit(1)

    try:
        header = decode_part(parts[0])
        payload = decode_part(parts[1])
    except Exception as e:
        print(f"Failed to decode token: {e}", file=sys.stderr)
        sys.exit(1)

    if args.raw:
        print(
            json.dumps(
                {"header": header, "payload": payload}, indent=2, ensure_ascii=False
            )
        )
        sys.exit(0)

    print_section("Header", header, set())
    print_section("Payload", payload, {"iat", "exp", "nbf"})
    print(f"\n── Signature {'─' * 29}")
    print(f"  {parts[2][:40]}{'...' if len(parts[2]) > 40 else ''}")
    print("  (not verified)")
