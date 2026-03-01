"""Watch a directory for file system changes using polling."""

import time
import argparse
from pathlib import Path
from datetime import datetime


def scan(directory: Path, recursive: bool) -> dict[str, float]:
    snapshot: dict[str, float] = {}
    files = directory.rglob("*") if recursive else directory.glob("*")
    for path in files:
        if path.is_file():
            try:
                snapshot[str(path)] = path.stat().st_mtime
            except OSError:
                pass
    return snapshot


def watch(directory: str, interval: float, recursive: bool) -> None:
    root = Path(directory).resolve()
    print(
        f"Watching {root}  (interval: {interval}s, recursive: {recursive})", flush=True
    )
    previous = scan(root, recursive)

    while True:
        time.sleep(interval)
        current = scan(root, recursive)
        ts = datetime.now().strftime("%H:%M:%S")

        for path in sorted(set(current) - set(previous)):
            print(f"[{ts}] CREATED   {path}", flush=True)
        for path in sorted(set(previous) - set(current)):
            print(f"[{ts}] DELETED   {path}", flush=True)
        for path in sorted(set(current) & set(previous)):
            if current[path] != previous[path]:
                print(f"[{ts}] MODIFIED  {path}", flush=True)

        previous = current


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Watch a directory for file changes.")
    parser.add_argument(
        "directory",
        nargs="?",
        default=".",
        help="Directory to watch (default: current)",
    )
    parser.add_argument(
        "-i",
        "--interval",
        type=float,
        default=1.0,
        help="Poll interval in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--no-recursive", action="store_true", help="Do not watch subdirectories"
    )
    args = parser.parse_args()

    try:
        watch(args.directory, args.interval, not args.no_recursive)
    except KeyboardInterrupt:
        print("\nStopped.")
