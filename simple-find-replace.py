"""Find and replace text across multiple files using regex or plain strings."""

import re
import sys
import argparse
from pathlib import Path


def process_file(
    path: Path,
    pattern: re.Pattern,
    replacement: str,
    dry_run: bool,
    encoding: str,
) -> int:
    try:
        original = path.read_text(encoding=encoding)
    except (OSError, UnicodeDecodeError) as e:
        print(f"  skip  {path}  ({e})", file=sys.stderr)
        return 0

    new_content, count = pattern.subn(replacement, original)
    if count == 0:
        return 0

    print(
        f"  {'(dry) ' if dry_run else ''}{'':0}{path}  ({count} match{'es' if count > 1 else ''})"
    )
    if not dry_run:
        path.write_text(new_content, encoding=encoding)
    return count


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Find and replace text across files by glob pattern."
    )
    parser.add_argument(
        "pattern", help="Search pattern (regex or plain string with --fixed)"
    )
    parser.add_argument(
        "replacement", help=r"Replacement string (supports \1 capture groups)"
    )
    parser.add_argument(
        "glob",
        nargs="?",
        default="**/*",
        help="Glob pattern for files (default: **/*)",
    )
    parser.add_argument(
        "-d", "--dir", default=".", help="Root directory (default: current)"
    )
    parser.add_argument(
        "-F", "--fixed", action="store_true", help="Treat pattern as plain string"
    )
    parser.add_argument(
        "-i", "--ignore-case", action="store_true", help="Case-insensitive match"
    )
    parser.add_argument(
        "--apply", action="store_true", help="Actually modify files (default: dry-run)"
    )
    parser.add_argument(
        "--encoding", default="utf-8", help="File encoding (default: utf-8)"
    )
    args = parser.parse_args()

    pat_str = re.escape(args.pattern) if args.fixed else args.pattern
    flags = re.IGNORECASE if args.ignore_case else 0
    try:
        compiled = re.compile(pat_str, flags)
    except re.error as e:
        print(f"Invalid pattern: {e}", file=sys.stderr)
        sys.exit(1)

    root = Path(args.dir)
    files = [p for p in root.glob(args.glob) if p.is_file()]

    if not files:
        print("No files matched.")
        sys.exit(0)

    total_files, total_matches = 0, 0
    for path in sorted(files):
        count = process_file(
            path, compiled, args.replacement, not args.apply, args.encoding
        )
        if count:
            total_files += 1
            total_matches += count

    mode = "Applied" if args.apply else "Dry run"
    print(f"\n{mode}: {total_matches} replacement(s) in {total_files} file(s).")
