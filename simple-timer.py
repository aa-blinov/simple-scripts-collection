"""CLI countdown timer with optional Pomodoro mode."""

import re
import time
import sys
import argparse

POMODORO = [
    (25 * 60, "Work"),
    (5 * 60, "Short break"),
    (25 * 60, "Work"),
    (5 * 60, "Short break"),
    (25 * 60, "Work"),
    (5 * 60, "Short break"),
    (25 * 60, "Work"),
    (15 * 60, "Long break"),
]


def parse_duration(s: str) -> int:
    """Parse duration strings like 25m, 1h30m, 90s into total seconds."""
    total = 0
    for value, unit in re.findall(r"(\d+)([hHmMsS]?)", s):
        n = int(value)
        if unit in ("h", "H"):
            total += n * 3600
        elif unit in ("m", "M"):
            total += n * 60
        else:
            total += n
    return total


def format_time(seconds: int) -> str:
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


def beep(verbose: bool = True) -> None:
    try:
        import winsound

        freqs = [880, 1320, 1760, 1320, 880, 1320, 1760]
        for freq in freqs:
            winsound.Beep(freq, 150)
            time.sleep(0.05)
    except ImportError:
        for _ in range(5):
            print("\a", end="", flush=True)
            time.sleep(0.1)


def run_timer(duration: int, label: str = "") -> None:
    prefix = f"[{label}] " if label else ""
    for remaining in range(duration, -1, -1):
        print(f"\r{prefix}{format_time(remaining)} ", end="", flush=True)
        if remaining:
            time.sleep(1)
    print(f"\r{prefix}Done!{' ' * 12}")
    beep()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Countdown timer. Duration format: 25m, 1h30m, 90s."
    )
    parser.add_argument("duration", nargs="?", help="Duration (e.g. 25m, 1h30m, 90s)")
    parser.add_argument(
        "--pomodoro",
        action="store_true",
        help="Run a standard Pomodoro cycle (4×25min work + breaks)",
    )
    parser.add_argument("-l", "--label", default="", help="Label to display")
    args = parser.parse_args()

    try:
        if args.pomodoro:
            for duration, label in POMODORO:
                print(f"\n--- {label} ({format_time(duration)}) ---")
                run_timer(duration, label)
        elif args.duration:
            run_timer(parse_duration(args.duration), args.label)
        else:
            parser.print_help()
            sys.exit(1)
    except KeyboardInterrupt:
        print("\nCancelled.")
