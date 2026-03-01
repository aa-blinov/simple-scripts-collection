"""Run a command on a cron-like schedule (minute granularity)."""

import sys
import shlex
import time
import argparse
import subprocess
from datetime import datetime


def parse_field(field: str, lo: int, hi: int) -> set[int]:
    result: set[int] = set()
    for part in field.split(","):
        if part == "*":
            result.update(range(lo, hi + 1))
        elif "/" in part:
            base, step_str = part.split("/", 1)
            step = int(step_str)
            start = lo if base == "*" else int(base.split("-")[0])
            end = (
                hi
                if base == "*"
                else (int(base.split("-")[1]) if "-" in base else start)
            )
            result.update(range(start, end + 1, step))
        elif "-" in part:
            a, b = part.split("-")
            result.update(range(int(a), int(b) + 1))
        else:
            result.add(int(part))
    return result


def parse_cron(expr: str) -> tuple[set, set, set, set, set]:
    parts = expr.strip().split()
    if len(parts) != 5:
        raise ValueError(
            "Cron expression must have exactly 5 fields: min hour dom mon dow"
        )
    mins = parse_field(parts[0], 0, 59)
    hours = parse_field(parts[1], 0, 23)
    doms = parse_field(parts[2], 1, 31)
    months = parse_field(parts[3], 1, 12)
    dows = parse_field(parts[4], 0, 6)
    return mins, hours, doms, months, dows


def matches(dt: datetime, schedule: tuple) -> bool:
    mins, hours, doms, months, dows = schedule
    return (
        dt.minute in mins
        and dt.hour in hours
        and dt.day in doms
        and dt.month in months
        and dt.isoweekday() % 7 in dows  # isoweekday: Mon=1..Sun=7 → Sun=0
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run a command on a cron schedule.",
        epilog=(
            "Cron format: min(0-59) hour(0-23) dom(1-31) month(1-12) dow(0-6,Sun=0)\n"
            "Examples:\n"
            '  %(prog)s "*/5 * * * *" -- python sync.py      # every 5 minutes\n'
            '  %(prog)s "0 9 * * 1"   -- python report.py    # Mondays at 09:00'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "schedule", help='Cron expression in quotes, e.g. "*/5 * * * *"'
    )
    parser.add_argument(
        "cmd", nargs=argparse.REMAINDER, help="Command to run (after --)"
    )
    parser.add_argument("--shell", action="store_true", help="Run via shell")
    args = parser.parse_args()

    cmd = args.cmd
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        parser.error("Provide a command after --")

    try:
        schedule = parse_cron(args.schedule)
    except ValueError as e:
        print(f"Invalid cron expression: {e}", file=sys.stderr)
        sys.exit(1)

    argv = cmd[0] if args.shell else (shlex.split(cmd[0]) if len(cmd) == 1 else cmd)
    print(f"Schedule : {args.schedule}")
    print(f"Command  : {' '.join(cmd)}")
    print("Press Ctrl+C to stop.\n")

    last_run: int | None = None
    try:
        while True:
            now = datetime.now()
            tick = (
                now.year * 525960
                + now.month * 43800
                + now.day * 1440
                + now.hour * 60
                + now.minute
            )
            if tick != last_run and matches(now, schedule):
                last_run = tick
                ts = now.strftime("%Y-%m-%d %H:%M")
                print(f"[{ts}] Running: {' '.join(cmd)}")
                result = subprocess.run(argv, shell=args.shell)
                if result.returncode != 0:
                    print(f"[{ts}] Exit code: {result.returncode}")
            time.sleep(5)
    except KeyboardInterrupt:
        print("\nStopped.")
        sys.exit(0)
