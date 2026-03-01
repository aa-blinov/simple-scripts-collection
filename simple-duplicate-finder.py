"""Find duplicate files in a directory by content hash."""

import hashlib
import argparse
from pathlib import Path
from collections import defaultdict


def hash_file(path: Path, algorithm: str = "sha256", chunk_size: int = 65536) -> str:
    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def find_duplicates(
    directory: str, algorithm: str = "sha256", recursive: bool = True
) -> dict[str, list[Path]]:
    hashes: dict[str, list[Path]] = defaultdict(list)
    root = Path(directory)
    files = root.rglob("*") if recursive else root.glob("*")
    for path in files:
        if path.is_file():
            hashes[hash_file(path, algorithm)].append(path)
    return {h: paths for h, paths in hashes.items() if len(paths) > 1}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Find duplicate files by content hash."
    )
    parser.add_argument("directory", help="Directory to scan")
    parser.add_argument(
        "-a",
        "--algorithm",
        choices=["md5", "sha1", "sha256"],
        default="sha256",
        help="Hash algorithm (default: sha256)",
    )
    parser.add_argument(
        "--no-recursive", action="store_true", help="Do not scan subdirectories"
    )
    parser.add_argument(
        "--delete",
        action="store_true",
        help="Delete duplicates, keeping the first occurrence",
    )
    args = parser.parse_args()

    duplicates = find_duplicates(args.directory, args.algorithm, not args.no_recursive)

    if not duplicates:
        print("No duplicates found.")
    else:
        total = sum(len(v) - 1 for v in duplicates.values())
        print(
            f"Found {len(duplicates)} duplicate group(s), {total} redundant file(s):\n"
        )
        for digest, paths in duplicates.items():
            print(f"  [{digest[:12]}...]")
            for i, path in enumerate(paths):
                marker = "keep " if i == 0 else "extra"
                print(f"    [{marker}] {path}")
            if args.delete:
                for path in paths[1:]:
                    path.unlink()
                    print(f"    Deleted: {path}")
            print()
