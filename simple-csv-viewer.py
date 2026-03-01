"""Display CSV files as a formatted table in the terminal."""

import csv
import sys
import argparse


def read_csv(
    source: str | None, delimiter: str, encoding: str
) -> tuple[list[str], list[list[str]]]:
    if source:
        with open(source, encoding=encoding, newline="") as f:
            rows = list(csv.reader(f, delimiter=delimiter))
    else:
        rows = list(csv.reader(sys.stdin, delimiter=delimiter))
    if not rows:
        return [], []
    return rows[0], rows[1:]


def print_table(
    headers: list[str],
    rows: list[list[str]],
    max_rows: int | None,
    columns: list[str] | None,
) -> None:
    if columns:
        indices = [headers.index(c) for c in columns if c in headers]
        headers = [headers[i] for i in indices]
        rows = [[row[i] if i < len(row) else "" for i in indices] for row in rows]

    if max_rows:
        rows = rows[:max_rows]

    def cell(row: list[str], i: int) -> str:
        return row[i] if i < len(row) else ""

    col_widths = [
        max(len(h), max((len(cell(r, i)) for r in rows), default=0))
        for i, h in enumerate(headers)
    ]
    sep = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"
    row_fmt = "|" + "|".join(f" {{:<{w}}} " for w in col_widths) + "|"

    print(sep)
    print(row_fmt.format(*headers))
    print(sep)
    for row in rows:
        print(row_fmt.format(*[cell(row, i) for i in range(len(headers))]))
    print(sep)
    print(f"{len(rows)} row(s)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="View CSV files as a formatted table.")
    parser.add_argument("file", nargs="?", help="CSV file (reads stdin if omitted)")
    parser.add_argument(
        "-d", "--delimiter", default=",", help="Field delimiter (default: ,)"
    )
    parser.add_argument("-n", "--max-rows", type=int, help="Maximum rows to display")
    parser.add_argument(
        "-c", "--columns", nargs="+", help="Columns to show (by header name)"
    )
    parser.add_argument(
        "--encoding", default="utf-8", help="File encoding (default: utf-8)"
    )
    args = parser.parse_args()

    headers, rows = read_csv(args.file, args.delimiter, args.encoding)
    if not headers:
        print("Empty file.")
        sys.exit(0)

    print_table(headers, rows, args.max_rows, args.columns)
