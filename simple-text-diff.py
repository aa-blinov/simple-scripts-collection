"""Show a colored diff between two text files."""

import difflib
import sys
import argparse
from pathlib import Path

ANSI: dict[str, str] = {
    "+": "\033[32m",
    "-": "\033[31m",
    "?": "\033[33m",
    "@": "\033[36m",
    "!": "\033[35m",
}
RESET = "\033[0m"


def diff(file_a: str, file_b: str, mode: str, context: int) -> list[str]:
    lines_a = Path(file_a).read_text(encoding="utf-8").splitlines(keepends=True)
    lines_b = Path(file_b).read_text(encoding="utf-8").splitlines(keepends=True)
    if mode == "unified":
        return list(
            difflib.unified_diff(
                lines_a, lines_b, fromfile=file_a, tofile=file_b, n=context
            )
        )
    if mode == "context":
        return list(
            difflib.context_diff(
                lines_a, lines_b, fromfile=file_a, tofile=file_b, n=context
            )
        )
    return list(difflib.ndiff(lines_a, lines_b))


def print_colored(lines: list[str]) -> None:
    for line in lines:
        color = ANSI.get(line[0], "") if line else ""
        print(f"{color}{line}{RESET}", end="")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Show diff between two text files.")
    parser.add_argument("file_a", help="First file")
    parser.add_argument("file_b", help="Second file")
    parser.add_argument(
        "-m",
        "--mode",
        choices=["unified", "context", "ndiff"],
        default="unified",
        help="Diff mode (default: unified)",
    )
    parser.add_argument(
        "-c", "--context", type=int, default=3, help="Context lines (default: 3)"
    )
    parser.add_argument("--no-color", action="store_true", help="Disable color output")
    args = parser.parse_args()

    result = diff(args.file_a, args.file_b, args.mode, args.context)

    if not result:
        print("Files are identical.")
        sys.exit(0)

    if args.no_color:
        print("".join(result), end="")
    else:
        print_colored(result)
