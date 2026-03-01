"""Test regular expressions interactively against text input."""

import re
import sys
import argparse

ANSI_MATCH = "\033[42;30m"
ANSI_GROUP = "\033[43;30m"
RESET = "\033[0m"


def highlight(text: str, pattern: re.Pattern, no_color: bool) -> str:
    if no_color:
        return text
    result, last = [], 0
    for m in pattern.finditer(text):
        result.append(text[last : m.start()])
        result.append(f"{ANSI_MATCH}{m.group(0)}{RESET}")
        last = m.end()
    result.append(text[last:])
    return "".join(result)


def run(pattern: re.Pattern, text: str, mode: str, no_color: bool) -> None:
    matches = list(pattern.finditer(text))

    if mode == "match":
        m = pattern.fullmatch(text.strip())
        if m:
            print(f"Full match: {m.group(0)!r}")
            for i, g in enumerate(m.groups(), 1):
                print(f"  group {i}: {g!r}")
        else:
            print("No full match.")
        return

    if not matches:
        print("No matches found.")
        return

    print(f"{len(matches)} match(es):\n")
    for i, m in enumerate(matches, 1):
        print(f"  [{i}] pos {m.start()}-{m.end()}  {m.group(0)!r}")
        for j, g in enumerate(m.groups(), 1):
            print(f"       group {j}: {g!r}")

    print(f"\nHighlighted:\n  {highlight(text, pattern, no_color)}")

    if mode == "split":
        parts = pattern.split(text)
        print(f"\nSplit ({len(parts)} parts):")
        for p in parts:
            print(f"  {p!r}")

    if mode == "sub":
        print("\nReplacement: provide --replace to use sub mode.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test regex patterns against text.")
    parser.add_argument("pattern", help="Regular expression pattern")
    parser.add_argument(
        "text", nargs="?", help="Text to match (reads stdin if omitted)"
    )
    parser.add_argument(
        "-m", "--mode", choices=["search", "match", "split"], default="search"
    )
    parser.add_argument(
        "-r", "--replace", help="Replace matches with this string (activates sub mode)"
    )
    parser.add_argument("-i", "--ignore-case", action="store_true")
    parser.add_argument("-M", "--multiline", action="store_true")
    parser.add_argument("-s", "--dotall", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args()

    text = args.text if args.text is not None else sys.stdin.read()

    flags = 0
    if args.ignore_case:
        flags |= re.IGNORECASE
    if args.multiline:
        flags |= re.MULTILINE
    if args.dotall:
        flags |= re.DOTALL

    try:
        compiled = re.compile(args.pattern, flags)
    except re.error as e:
        print(f"Invalid pattern: {e}", file=sys.stderr)
        sys.exit(1)

    if args.replace is not None:
        result, count = compiled.subn(args.replace, text)
        print(f"{count} substitution(s):\n\n{result}")
    else:
        run(compiled, text, args.mode, args.no_color)
