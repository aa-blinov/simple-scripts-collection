"""Encode and decode Base64 from strings, files, or stdin."""

import base64
import sys
import argparse
from pathlib import Path


def encode(data: bytes, urlsafe: bool) -> str:
    fn = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    return fn(data).decode("ascii")


def decode(data: str, urlsafe: bool) -> bytes:
    fn = base64.urlsafe_b64decode if urlsafe else base64.b64decode
    return fn(data + "==")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encode or decode Base64.")
    parser.add_argument("mode", choices=["encode", "decode"], help="Operation mode")
    parser.add_argument(
        "text", nargs="?", help="String to process (reads stdin if omitted)"
    )
    parser.add_argument("-f", "--file", help="Input file path")
    parser.add_argument("-o", "--output", help="Output file path (binary decode only)")
    parser.add_argument(
        "--urlsafe", action="store_true", help="Use URL-safe alphabet (- and _)"
    )
    args = parser.parse_args()

    if args.file:
        raw_bytes = Path(args.file).read_bytes()
    elif args.text:
        raw_bytes = args.text.encode("utf-8")
    else:
        raw_bytes = sys.stdin.buffer.read()

    if args.mode == "encode":
        print(encode(raw_bytes, args.urlsafe))
    else:
        result = decode(raw_bytes.decode("ascii").strip(), args.urlsafe)
        if args.output:
            Path(args.output).write_bytes(result)
            print(f"Written to {args.output}")
        else:
            try:
                print(result.decode("utf-8"))
            except UnicodeDecodeError:
                sys.stdout.buffer.write(result)
