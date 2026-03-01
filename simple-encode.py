"""Encode and decode strings: hex, HTML entities, URL, ROT13, and binary."""

import sys
import html
import codecs
import argparse


MODES = ["hex", "unhex", "html", "unhtml", "rot13", "bin", "unbin"]


def process(data: str, mode: str) -> str:
    match mode:
        case "hex":
            return data.encode("utf-8").hex()
        case "unhex":
            return bytes.fromhex(data.strip()).decode("utf-8")
        case "html":
            return html.escape(data, quote=True)
        case "unhtml":
            return html.unescape(data)
        case "rot13":
            return codecs.encode(data, "rot_13")
        case "bin":
            return " ".join(f"{b:08b}" for b in data.encode("utf-8"))
        case "unbin":
            bits = data.replace(" ", "").replace("\n", "")
            if len(bits) % 8:
                raise ValueError("Binary string length must be a multiple of 8.")
            return bytes(
                int(bits[i : i + 8], 2) for i in range(0, len(bits), 8)
            ).decode("utf-8")
        case _:
            raise ValueError(f"Unknown mode: {mode!r}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Encode/decode strings: hex, HTML entities, ROT13, binary.",
        epilog=f"Modes: {', '.join(MODES)}",
    )
    parser.add_argument("mode", choices=MODES, help="Encoding/decoding mode")
    parser.add_argument("text", nargs="?", help="Input text (reads stdin if omitted)")
    args = parser.parse_args()

    data = args.text if args.text is not None else sys.stdin.read().rstrip("\n")

    try:
        print(process(data, args.mode))
    except (ValueError, UnicodeDecodeError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
