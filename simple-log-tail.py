"""Follow the tail of a log file in real time (like tail -f)."""

import re
import sys
import time
import argparse
from pathlib import Path

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"


def tail_lines(path: Path, n: int) -> list[str]:
    """Read the last n lines of a file efficiently."""
    with open(path, "rb") as f:
        f.seek(0, 2)
        size = f.tell()
        block = min(size, 8192)
        buf = b""
        while len(buf.splitlines()) <= n and f.tell() > 0:
            pos = max(f.tell() - block, 0)
            f.seek(pos)
            buf = f.read() + buf
            f.seek(pos)
        return buf.decode("utf-8", errors="replace").splitlines()[-n:]


def highlight_line(line: str, grep: str | None, use_color: bool) -> str:
    if not grep or not use_color:
        return line
    try:
        # Highlight ERROR in red, WARN in yellow, INFO in green
        line = re.sub(r"\bERROR\b", f"{RED}ERROR{RESET}", line, flags=re.IGNORECASE)
        line = re.sub(
            r"\bWARN(ING)?\b", f"{YELLOW}WARN{RESET}", line, flags=re.IGNORECASE
        )
        line = re.sub(r"\bINFO\b", f"{GREEN}INFO{RESET}", line, flags=re.IGNORECASE)
        # Highlight grep pattern
        line = re.sub(
            f"({re.escape(grep)})",
            f"{RED}\\1{RESET}",
            line,
            flags=re.IGNORECASE,
        )
    except Exception:
        pass
    return line


def follow(path: Path, interval: float, grep: str | None, use_color: bool) -> None:
    with open(path, encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(interval)
                continue
            if grep and grep.lower() not in line.lower():
                continue
            line_out = highlight_line(line.rstrip("\n"), grep, use_color)
            print(line_out, flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Follow a log file in real time.")
    parser.add_argument("file", help="Log file to watch")
    parser.add_argument(
        "-n",
        "--lines",
        type=int,
        default=10,
        help="Initial lines to show (default: 10)",
    )
    parser.add_argument(
        "-i",
        "--interval",
        type=float,
        default=0.2,
        help="Poll interval in seconds (default: 0.2)",
    )
    parser.add_argument("-g", "--grep", help="Only show lines containing this string")
    parser.add_argument(
        "--no-follow",
        action="store_true",
        help="Print last N lines and exit (no follow)",
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable color highlighting"
    )
    args = parser.parse_args()

    use_color = not args.no_color and sys.stdout.isatty()

    path = Path(args.file)
    if not path.is_file():
        print(f"File not found: {path}", file=sys.stderr)
        sys.exit(1)

    for line in tail_lines(path, args.lines):
        if not args.grep or args.grep.lower() in line.lower():
            line_out = highlight_line(line, args.grep, use_color)
            print(line_out)

    if args.no_follow:
        sys.exit(0)

    try:
        follow(path, args.interval, args.grep, use_color)
    except KeyboardInterrupt:
        print("\nStopped.")
