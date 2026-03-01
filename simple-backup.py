"""Incremental directory backup to timestamped ZIP or TAR archives."""

import os
import re
import sys
import tarfile
import zipfile
import argparse
import fnmatch
from datetime import datetime
from pathlib import Path


def should_exclude(path: str, excludes: list[str]) -> bool:
    name = os.path.basename(path)
    return any(fnmatch.fnmatch(name, pat) for pat in excludes)


def collect_files(src: Path, excludes: list[str]) -> list[Path]:
    files = []
    for root, dirs, names in os.walk(src):
        dirs[:] = [d for d in dirs if not should_exclude(d, excludes)]
        for name in names:
            if not should_exclude(name, excludes):
                files.append(Path(root) / name)
    return files


def find_last_backup(dest: Path, prefix: str) -> datetime | None:
    pattern = re.compile(rf"^{re.escape(prefix)}_(\d{{8}}_\d{{6}})\.(zip|tar\.gz)$")
    latest = None
    for f in dest.iterdir():
        m = pattern.match(f.name)
        if m:
            dt = datetime.strptime(m.group(1), "%Y%m%d_%H%M%S")
            if latest is None or dt > latest:
                latest = dt
    return latest


def backup_zip(
    files: list[Path], src: Path, archive: Path, since: datetime | None
) -> tuple[int, int]:
    added = skipped = 0
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for f in files:
            mtime = datetime.fromtimestamp(f.stat().st_mtime)
            if since and mtime <= since:
                skipped += 1
                continue
            zf.write(f, f.relative_to(src))
            added += 1
    return added, skipped


def backup_tar(
    files: list[Path], src: Path, archive: Path, since: datetime | None
) -> tuple[int, int]:
    added = skipped = 0
    with tarfile.open(archive, "w:gz") as tf:
        for f in files:
            mtime = datetime.fromtimestamp(f.stat().st_mtime)
            if since and mtime <= since:
                skipped += 1
                continue
            tf.add(f, arcname=str(f.relative_to(src)))
            added += 1
    return added, skipped


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Incremental directory backup.")
    parser.add_argument("source", help="Directory to back up")
    parser.add_argument("dest", help="Destination directory for archives")
    parser.add_argument(
        "--format",
        choices=["zip", "tar.gz"],
        default="zip",
        help="Archive format (default: zip)",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Force a full backup (ignore previous backups)",
    )
    parser.add_argument(
        "--exclude",
        nargs="+",
        metavar="PATTERN",
        default=[
            "*.pyc",
            "__pycache__",
            ".git",
            "node_modules",
            ".DS_Store",
        ],
        help="Glob patterns to exclude",
    )
    parser.add_argument(
        "--prefix", default=None, help="Archive name prefix (default: source dir name)"
    )
    args = parser.parse_args()

    src = Path(args.source).resolve()
    if not src.is_dir():
        print(f"Not a directory: {src}", file=sys.stderr)
        sys.exit(1)

    dest = Path(args.dest)
    dest.mkdir(parents=True, exist_ok=True)

    prefix = args.prefix or src.name
    since: datetime | None = None
    if not args.full:
        since = find_last_backup(dest, prefix)
        if since:
            print(f"Incremental since: {since:%Y-%m-%d %H:%M:%S}")
        else:
            print("No previous backup found — performing full backup.")

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = args.format
    archive = dest / f"{prefix}_{stamp}.{ext}"

    files = collect_files(src, args.exclude)
    if args.format == "zip":
        added, skipped = backup_zip(files, src, archive, since)
    else:
        added, skipped = backup_tar(files, src, archive, since)

    if added == 0:
        archive.unlink()
        print("Nothing changed — no archive created.")
    else:
        size = archive.stat().st_size
        print(f"Created : {archive.name}")
        print(f"Files   : {added} added, {skipped} unchanged skipped")
        print(f"Size    : {size / 1024:.1f} KB")
