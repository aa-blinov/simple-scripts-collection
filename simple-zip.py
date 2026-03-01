"""Create, extract, and inspect ZIP archives."""

import sys
import argparse
import zipfile
from pathlib import Path
from datetime import datetime


def cmd_create(archive: str, sources: list[str], compression: int) -> None:
    with zipfile.ZipFile(archive, "w", compression=compression) as zf:
        for src in sources:
            p = Path(src)
            if p.is_dir():
                for f in sorted(p.rglob("*")):
                    if f.is_file():
                        zf.write(f, f.relative_to(p.parent))
                        print(f"  added  {f.relative_to(p.parent)}")
            elif p.is_file():
                zf.write(p, p.name)
                print(f"  added  {p.name}")
            else:
                print(f"  skip   {src} (not found)", file=sys.stderr)
    print(f"\nCreated {archive}  ({Path(archive).stat().st_size:,} bytes)")


def cmd_extract(archive: str, dest: str, members: list[str]) -> None:
    with zipfile.ZipFile(archive, "r") as zf:
        targets = members or zf.namelist()
        zf.extractall(dest, members=targets)
        for name in targets:
            print(f"  extracted  {name}")
    print(f"\nExtracted to {dest}/")


def cmd_list(archive: str) -> None:
    with zipfile.ZipFile(archive, "r") as zf:
        total = 0
        print(f"{'Size':>10}  {'Compressed':>10}  {'Date':>16}  Name")
        print("-" * 60)
        for info in zf.infolist():
            dt = datetime(*info.date_time).strftime("%Y-%m-%d %H:%M")
            print(
                f"{info.file_size:>10,}  {info.compress_size:>10,}  {dt:>16}  {info.filename}"
            )
            total += info.file_size
        print("-" * 60)
        print(f"{total:>10,}  {len(zf.infolist())} file(s)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Create, extract, or list ZIP archives."
    )
    sub = parser.add_subparsers(dest="command")

    p_c = sub.add_parser("create", help="Create a new archive")
    p_c.add_argument("archive", help="Output .zip file")
    p_c.add_argument("sources", nargs="+", help="Files or directories to add")
    p_c.add_argument("--store", action="store_true", help="Store without compression")

    p_x = sub.add_parser("extract", help="Extract archive")
    p_x.add_argument("archive", help="ZIP file to extract")
    p_x.add_argument(
        "-d", "--dest", default=".", help="Destination directory (default: .)"
    )
    p_x.add_argument(
        "members", nargs="*", help="Specific files to extract (default: all)"
    )

    p_l = sub.add_parser("list", help="List archive contents")
    p_l.add_argument("archive", help="ZIP file to inspect")

    args = parser.parse_args()

    match args.command:
        case "create":
            compression = zipfile.ZIP_STORED if args.store else zipfile.ZIP_DEFLATED
            cmd_create(args.archive, args.sources, compression)
        case "extract":
            cmd_extract(args.archive, args.dest, args.members)
        case "list":
            cmd_list(args.archive)
        case _:
            parser.print_help()
