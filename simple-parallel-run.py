"""Run multiple commands in parallel and stream their output."""

import sys
import shlex
import argparse
import threading
import subprocess
from queue import Queue


COLORS = [
    "\033[33m",
    "\033[36m",
    "\033[32m",
    "\033[35m",
    "\033[34m",
    "\033[31m",
    "\033[37m",
    "\033[93m",
]
RESET = "\033[0m"


def stream(
    label: str, color: str, proc: subprocess.Popen, q: Queue, use_color: bool
) -> None:  # type: ignore[type-arg]
    prefix = f"{color}[{label}]{RESET} " if use_color else f"[{label}] "
    for line in proc.stdout:  # type: ignore[union-attr]
        q.put(prefix + line.rstrip("\n"))
    proc.wait()
    q.put(("__done__", label, proc.returncode))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run commands in parallel and stream their output.",
        epilog='Example: %(prog)s "npm run build" "python tests.py" "eslint src/"',
    )
    parser.add_argument("commands", nargs="+", help="Commands to run (quote each one)")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument(
        "--names",
        nargs="+",
        metavar="NAME",
        help="Labels for each command (default: cmd-0, cmd-1 …)",
    )
    parser.add_argument("--shell", action="store_true", help="Run commands via shell")
    args = parser.parse_args()

    names = args.names or [f"cmd-{i}" for i in range(len(args.commands))]
    if len(names) < len(args.commands):
        parser.error("--names must have the same number of entries as commands")

    use_color = not args.no_color and sys.stdout.isatty()
    q: Queue = Queue()
    procs = []

    for i, (cmd, name) in enumerate(zip(args.commands, names)):
        color = COLORS[i % len(COLORS)]
        argv = cmd if args.shell else shlex.split(cmd)
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            shell=args.shell,
        )
        procs.append((name, proc))
        t = threading.Thread(
            target=stream, args=(name, color, proc, q, use_color), daemon=True
        )
        t.start()

    finished: dict[str, int] = {}
    try:
        while len(finished) < len(procs):
            item = q.get()
            if isinstance(item, tuple) and item[0] == "__done__":
                _, name, code = item
                finished[name] = code
                status = "✓" if code == 0 else f"✗ (exit {code})"
                label_color = (
                    COLORS[names.index(name) % len(COLORS)] if use_color else ""
                )
                badge = f"{label_color}[{name}]{RESET}" if use_color else f"[{name}]"
                print(f"{badge} {status}")
            else:
                print(item)
    except KeyboardInterrupt:
        print("\nTerminating...", file=sys.stderr)
        for _, proc in procs:
            if proc.poll() is None:
                proc.terminate()
        for _, proc in procs:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        sys.exit(1)

    any_failed = any(c != 0 for c in finished.values())
    sys.exit(1 if any_failed else 0)
