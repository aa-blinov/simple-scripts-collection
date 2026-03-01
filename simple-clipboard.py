"""Read from or write to the system clipboard."""

import sys
import platform
import argparse
import subprocess


def _find_cmd(candidates: list[list[str]]) -> list[str]:
    import shutil

    for cmd in candidates:
        if shutil.which(cmd[0]):
            return cmd
    raise RuntimeError(f"No clipboard tool found. Tried: {[c[0] for c in candidates]}")


def paste() -> str:
    system = platform.system()
    if system == "Windows":
        cmd = ["powershell", "-NoProfile", "-Command", "Get-Clipboard"]
    elif system == "Darwin":
        cmd = ["pbpaste"]
    else:
        cmd = _find_cmd(
            [
                ["xclip", "-selection", "clipboard", "-out"],
                ["xsel", "--clipboard", "--output"],
                ["wl-paste"],
            ]
        )
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout


def copy(text: str) -> None:
    system = platform.system()
    if system == "Windows":
        cmd = ["clip"]
    elif system == "Darwin":
        cmd = ["pbcopy"]
    else:
        cmd = _find_cmd(
            [
                ["xclip", "-selection", "clipboard"],
                ["xsel", "--clipboard", "--input"],
                ["wl-copy"],
            ]
        )
    subprocess.run(cmd, input=text, text=True, check=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Read/write the system clipboard.",
        epilog="Copy: echo hello | %(prog)s    Paste: %(prog)s --paste",
    )
    parser.add_argument(
        "--paste", "-p", action="store_true", help="Print clipboard to stdout"
    )
    parser.add_argument(
        "text", nargs="?", help="Text to copy (alternative to stdin pipe)"
    )
    args = parser.parse_args()

    if args.paste:
        sys.stdout.write(paste())
    elif args.text:
        copy(args.text)
    elif not sys.stdin.isatty():
        copy(sys.stdin.read())
    else:
        parser.print_help()
        sys.exit(1)
