"""Compare two .env files and report missing, extra, and changed keys."""

import sys
import argparse
from pathlib import Path

ANSI = {"add": "\033[32m", "del": "\033[31m", "chg": "\033[33m", "hdr": "\033[36m"}
RESET = "\033[0m"


def parse_env(path: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if sep:
            result[key.strip()] = value.strip().strip("\"'")
    return result


def color(code: str, text: str, no_color: bool) -> str:
    return text if no_color else f"{ANSI[code]}{text}{RESET}"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Diff two .env files.")
    parser.add_argument("file_a", help="Base file (e.g. .env.example)")
    parser.add_argument("file_b", help="Comparison file (e.g. .env)")
    parser.add_argument("--no-color", action="store_true", help="Disable color output")
    parser.add_argument(
        "--hide-values", action="store_true", help="Do not show secret values"
    )
    args = parser.parse_args()

    a = parse_env(args.file_a)
    b = parse_env(args.file_b)

    missing = sorted(set(a) - set(b))
    extra = sorted(set(b) - set(a))
    changed = sorted(k for k in set(a) & set(b) if a[k] != b[k])

    def val(v: str) -> str:
        return "***" if args.hide_values else v

    if not missing and not extra and not changed:
        print("Files are identical.")
        sys.exit(0)

    if missing:
        print(
            color("hdr", f"Missing in {args.file_b} ({len(missing)}):", args.no_color)
        )
        for k in missing:
            print(color("del", f"  - {k}={val(a[k])}", args.no_color))

    if extra:
        print(color("hdr", f"\nExtra in {args.file_b} ({len(extra)}):", args.no_color))
        for k in extra:
            print(color("add", f"  + {k}={val(b[k])}", args.no_color))

    if changed:
        print(color("hdr", f"\nChanged ({len(changed)}):", args.no_color))
        for k in changed:
            print(color("chg", f"  ~ {k}", args.no_color))
            if not args.hide_values:
                print(f"      {args.file_a}: {a[k]}")
                print(f"      {args.file_b}: {b[k]}")
