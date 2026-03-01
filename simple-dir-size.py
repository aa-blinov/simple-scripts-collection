"""Display a directory tree with file and folder sizes."""

import argparse
from pathlib import Path


def human_size(size: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size //= 1024
    return f"{size:.1f} PB"


def dir_size(path: Path) -> int:
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file())


def entry_size(path: Path) -> int:
    return dir_size(path) if path.is_dir() else path.stat().st_size


def print_tree(
    path: Path,
    depth: int,
    max_depth: int,
    sort_by_size: bool,
    indent: str = "",
    is_last: bool = True,
) -> None:
    size = entry_size(path)
    connector = "└── " if is_last else "├── "
    suffix = "/" if path.is_dir() else ""
    print(f"{indent}{connector}{path.name}{suffix}  {human_size(size)}")

    if path.is_dir() and depth < max_depth:
        children = list(path.iterdir())
        children.sort(
            key=lambda c: entry_size(c) if sort_by_size else (c.is_file(), c.name),
            reverse=sort_by_size,
        )
        new_indent = indent + ("    " if is_last else "│   ")
        for i, child in enumerate(children):
            print_tree(
                child,
                depth + 1,
                max_depth,
                sort_by_size,
                new_indent,
                i == len(children) - 1,
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Show directory tree with sizes.")
    parser.add_argument(
        "directory", nargs="?", default=".", help="Root directory (default: current)"
    )
    parser.add_argument(
        "-d", "--depth", type=int, default=2, help="Max depth (default: 2)"
    )
    parser.add_argument(
        "-s", "--sort-size", action="store_true", help="Sort entries by size descending"
    )
    args = parser.parse_args()

    root = Path(args.directory).resolve()
    total = dir_size(root)
    print(f"{root}/  {human_size(total)}")

    children = list(root.iterdir())
    children.sort(
        key=lambda c: entry_size(c) if args.sort_size else (c.is_file(), c.name),
        reverse=args.sort_size,
    )
    for i, child in enumerate(children):
        print_tree(child, 1, args.depth, args.sort_size, "", i == len(children) - 1)
