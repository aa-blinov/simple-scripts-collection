"""Compute cryptographic hashes for strings, files, or stdin."""

import hashlib
import sys
import argparse
from pathlib import Path

ALGORITHMS = ["md5", "sha1", "sha256", "sha512", "sha3_256"]


def hash_bytes(data: bytes, algorithm: str) -> str:
    return hashlib.new(algorithm, data).hexdigest()


def hash_file(path: Path, algorithm: str, chunk_size: int = 65536) -> str:
    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compute hash of a string or file.")
    parser.add_argument(
        "text", nargs="?", help="String to hash (reads stdin if omitted)"
    )
    parser.add_argument("-f", "--file", help="File to hash")
    parser.add_argument(
        "-a",
        "--algorithm",
        choices=ALGORITHMS,
        default="sha256",
        help="Hash algorithm (default: sha256)",
    )
    parser.add_argument(
        "--all", action="store_true", help="Show all algorithms at once"
    )
    args = parser.parse_args()

    if args.file:
        path = Path(args.file)
        if args.all:
            for algo in ALGORITHMS:
                print(f"{algo:<12} {hash_file(path, algo)}")
        else:
            print(hash_file(path, args.algorithm))
    else:
        raw = args.text.encode("utf-8") if args.text else sys.stdin.buffer.read()
        if args.all:
            for algo in ALGORITHMS:
                print(f"{algo:<12} {hash_bytes(raw, algo)}")
        else:
            print(hash_bytes(raw, args.algorithm))
