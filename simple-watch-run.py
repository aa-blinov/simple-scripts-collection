"""Re-run a command whenever watched files change."""

import os
import sys
import time
import glob
import argparse
import subprocess


def snapshot(patterns: list[str]) -> dict[str, tuple[float, int]]:
    snap: dict[str, tuple[float, int]] = {}
    for pattern in patterns:
        for path in glob.glob(pattern, recursive=True):
            try:
                st = os.stat(path)
                snap[path] = (st.st_mtime, st.st_size)
            except OSError:
                pass
    return snap


def terminate(proc: subprocess.Popen) -> None:  # type: ignore[type-arg]
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Re-run a command when watched files change.",
        epilog='Example: %(prog)s -w "src/**/*.py" -- python app.py',
    )
    parser.add_argument(
        "-w",
        "--watch",
        nargs="+",
        required=True,
        metavar="PATTERN",
        help="Glob patterns to watch (supports **)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Poll interval in seconds (default: 1.0)",
    )
    parser.add_argument(
        "cmd", nargs=argparse.REMAINDER, help="Command to run (after --)"
    )
    args = parser.parse_args()

    cmd = args.cmd
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        parser.error("Provide a command after --")

    print(f"Watching : {args.watch}")
    print(f"Command  : {' '.join(cmd)}")
    print("Press Ctrl+C to stop.\n")

    snap = snapshot(args.watch)
    proc = subprocess.Popen(cmd)

    try:
        while True:
            time.sleep(args.interval)
            new = snapshot(args.watch)
            if new != snap:
                changed = [
                    p for p in set(list(snap) + list(new)) if snap.get(p) != new.get(p)
                ]
                print(f"\n[changed] {', '.join(changed)}")
                snap = new
                terminate(proc)
                proc = subprocess.Popen(cmd)
    except KeyboardInterrupt:
        terminate(proc)
        print("\nStopped.")
        sys.exit(0)
