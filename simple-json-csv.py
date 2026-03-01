"""Convert JSON arrays to CSV and CSV to JSON arrays."""

import sys
import csv
import json
import argparse
from pathlib import Path


def json_to_csv(src: str | None, dest: str | None, flatten: bool) -> None:
    raw = Path(src).read_text(encoding="utf-8") if src else sys.stdin.read()
    data = json.loads(raw)
    if isinstance(data, dict):
        data = [data]
    if not data:
        print("Empty input.", file=sys.stderr)
        sys.exit(1)

    def flat(obj: dict, prefix: str = "") -> dict:
        out: dict = {}
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict) and flatten:
                out.update(flat(v, key))
            else:
                out[key] = json.dumps(v) if isinstance(v, (dict, list)) else v
        return out

    rows = [flat(r) if flatten else r for r in data]
    cols = list(dict.fromkeys(k for row in rows for k in row))
    out = open(dest, "w", newline="", encoding="utf-8") if dest else sys.stdout
    writer = csv.DictWriter(out, fieldnames=cols, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    if dest:
        out.close()
        print(f"Written {len(rows)} rows to {dest}")


def csv_to_json(src: str | None, dest: str | None, indent: int | None) -> None:
    f = open(src, encoding="utf-8") if src else sys.stdin
    reader = csv.DictReader(f)
    rows = list(reader)
    if src:
        f.close()

    output = json.dumps(rows, ensure_ascii=False, indent=indent)
    if dest:
        Path(dest).write_text(output, encoding="utf-8")
        print(f"Written {len(rows)} records to {dest}")
    else:
        print(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert between JSON arrays and CSV.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_jc = sub.add_parser("to-csv", help="JSON array → CSV")
    p_jc.add_argument("input", nargs="?", help="Input JSON file (default: stdin)")
    p_jc.add_argument("-o", "--out", help="Output CSV file (default: stdout)")
    p_jc.add_argument(
        "--flatten",
        action="store_true",
        help="Flatten nested objects with dot notation",
    )

    p_cj = sub.add_parser("to-json", help="CSV → JSON array")
    p_cj.add_argument("input", nargs="?", help="Input CSV file (default: stdin)")
    p_cj.add_argument("-o", "--out", help="Output JSON file (default: stdout)")
    p_cj.add_argument(
        "--indent", type=int, default=2, help="JSON indent (default: 2, 0=compact)"
    )

    args = parser.parse_args()
    if args.cmd == "to-csv":
        json_to_csv(args.input, args.out, args.flatten)
    elif args.cmd == "to-json":
        indent = args.indent if args.indent > 0 else None
        csv_to_json(args.input, args.out, indent)
