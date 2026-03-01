"""Convert between Unix timestamps and human-readable dates."""

import sys
import argparse
from datetime import datetime, timezone, timedelta


def parse_offset(s: str) -> timezone:
    """Parse UTC offset like +03:00, -05:00, or 0."""
    s = s.strip()
    if s in ("0", "UTC", "utc"):
        return timezone.utc
    sign = 1 if s.startswith("+") else -1
    s = s.lstrip("+-")
    parts = s.split(":")
    hours = int(parts[0])
    minutes = int(parts[1]) if len(parts) > 1 else 0
    return timezone(timedelta(hours=sign * hours, minutes=sign * minutes))


def timestamp_to_dt(ts: float, tz: timezone) -> str:
    dt = datetime.fromtimestamp(ts, tz=tz)
    return dt.strftime("%Y-%m-%d %H:%M:%S %Z")


def dt_to_timestamp(s: str, tz: timezone) -> float:
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(s, fmt).replace(tzinfo=tz)
            return dt.timestamp()
        except ValueError:
            continue
    raise ValueError(f"Unrecognized date format: {s!r}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Convert Unix timestamps to dates and vice versa."
    )
    parser.add_argument(
        "value",
        nargs="?",
        help="Unix timestamp or date string (YYYY-MM-DD [HH:MM[:SS]]). Omit for current time.",
    )
    parser.add_argument(
        "-z",
        "--timezone",
        default="+00:00",
        metavar="OFFSET",
        help="UTC offset, e.g. +03:00 or -05:00 (default: +00:00)",
    )
    parser.add_argument(
        "--ms", action="store_true", help="Input timestamp is in milliseconds"
    )
    args = parser.parse_args()

    try:
        tz = parse_offset(args.timezone)
    except Exception:
        print(f"Invalid timezone offset: {args.timezone!r}", file=sys.stderr)
        sys.exit(1)

    if args.value is None:
        now = datetime.now(tz=timezone.utc)
        local = datetime.now(tz=tz)
        print(f"UTC timestamp : {int(now.timestamp())}")
        print(f"UTC ms        : {int(now.timestamp() * 1000)}")
        print(f"UTC date      : {now.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"Local date    : {local.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    elif args.value.lstrip("-+").replace(".", "").isdigit():
        ts = float(args.value)
        if args.ms:
            ts /= 1000
        print(timestamp_to_dt(ts, tz))
    else:
        try:
            ts = dt_to_timestamp(args.value, tz)
            print(f"{int(ts)}")
        except ValueError as e:
            print(e, file=sys.stderr)
            sys.exit(1)
