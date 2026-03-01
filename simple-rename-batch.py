"""Batch rename files in a directory using regex patterns."""

import re
import argparse
from pathlib import Path


def rename_files(
    directory: str,
    pattern: str,
    replacement: str,
    extension: str | None = None,
    dry_run: bool = True,
    counter_start: int | None = None,
) -> list[tuple[Path, Path]]:
    root = Path(directory)
    files = sorted(f for f in root.iterdir() if f.is_file())
    if extension:
        files = [f for f in files if f.suffix.lstrip(".").lower() == extension.lower()]

    renames: list[tuple[Path, Path]] = []
    counter = counter_start if counter_start is not None else 0

    for path in files:
        repl = replacement
        if counter_start is not None:
            repl = repl.replace("{n}", str(counter))
            counter += 1
        new_name = re.sub(pattern, repl, path.name)
        new_path = path.with_name(new_name)
        if new_path != path:
            renames.append((path, new_path))
            if not dry_run:
                path.rename(new_path)

    return renames


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Batch rename files using regex.")
    parser.add_argument("directory", help="Directory with files to rename")
    parser.add_argument("pattern", help="Regex pattern to match in filename")
    parser.add_argument(
        "replacement",
        help=r"Replacement string (supports \1 capture groups, {n} for counter)",
    )
    parser.add_argument(
        "-e", "--extension", help="Only rename files with this extension"
    )
    parser.add_argument(
        "-n",
        "--counter",
        type=int,
        metavar="START",
        help="Enable numeric counter starting at START",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually rename files (default is dry-run)",
    )
    args = parser.parse_args()

    renames = rename_files(
        args.directory,
        args.pattern,
        args.replacement,
        args.extension,
        not args.apply,
        args.counter,
    )

    if not renames:
        print("No files matched.")
    else:
        mode = "Applied" if args.apply else "Dry run"
        print(f"{mode}: {len(renames)} rename(s)\n")
        for old, new in renames:
            print(f"  {old.name}  →  {new.name}")
