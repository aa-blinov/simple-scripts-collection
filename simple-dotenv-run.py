"""Run a command with environment variables loaded from a .env file."""

import os
import sys
import argparse
import subprocess
from pathlib import Path


def parse_dotenv(path: str) -> dict[str, str]:
    env: dict[str, str] = {}
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
            val = val[1:-1]
        env[key] = val
    return env


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run a command with variables from a .env file.",
        epilog="Example: %(prog)s .env -- python app.py",
    )
    parser.add_argument("envfile", help=".env file path")
    parser.add_argument(
        "--override",
        action="store_true",
        help="Override existing env vars (default: only set if unset)",
    )
    parser.add_argument(
        "--print-env",
        action="store_true",
        help="Print loaded variables and exit without running a command",
    )
    parser.add_argument(
        "cmd", nargs=argparse.REMAINDER, help="Command to run (after --)"
    )
    args = parser.parse_args()

    loaded = parse_dotenv(args.envfile)

    if args.print_env:
        for k, v in loaded.items():
            print(f"{k}={v}")
        sys.exit(0)

    cmd = args.cmd
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        parser.error("Provide a command after --")

    merged = dict(os.environ)
    for k, v in loaded.items():
        if args.override or k not in merged:
            merged[k] = v

    result = subprocess.run(cmd, env=merged)
    sys.exit(result.returncode)
