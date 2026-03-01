"""Format, validate, and pretty-print JSON from a file or stdin."""

import json
import sys
import argparse
from pathlib import Path


def format_json(data: str, indent: int, sort_keys: bool, compact: bool) -> str:
    parsed = json.loads(data)
    if compact:
        return json.dumps(parsed, separators=(",", ":"), ensure_ascii=False)
    return json.dumps(parsed, indent=indent, sort_keys=sort_keys, ensure_ascii=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Format and validate JSON.")
    parser.add_argument("file", nargs="?", help="JSON file (reads stdin if omitted)")
    parser.add_argument(
        "-i", "--indent", type=int, default=2, help="Indentation spaces (default: 2)"
    )
    parser.add_argument(
        "-s", "--sort-keys", action="store_true", help="Sort object keys"
    )
    parser.add_argument(
        "-c", "--compact", action="store_true", help="Output compact single-line JSON"
    )
    parser.add_argument(
        "--in-place", action="store_true", help="Overwrite the input file"
    )
    args = parser.parse_args()

    raw = Path(args.file).read_text(encoding="utf-8") if args.file else sys.stdin.read()

    try:
        result = format_json(raw, args.indent, args.sort_keys, args.compact)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)

    if args.in_place and args.file:
        Path(args.file).write_text(result + "\n", encoding="utf-8")
        print(f"Written to {args.file}")
    else:
        print(result)
