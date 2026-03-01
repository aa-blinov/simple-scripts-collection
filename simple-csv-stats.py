"""Compute descriptive statistics for numeric columns in a CSV file."""

import csv
import sys
import argparse
import statistics


def load_column(
    source: str | None, column: str, delimiter: str, encoding: str
) -> list[float]:
    if source:
        f = open(source, encoding=encoding, newline="")
    else:
        f = sys.stdin

    try:
        reader = csv.DictReader(f, delimiter=delimiter)
        if column not in (reader.fieldnames or []):
            available = ", ".join(reader.fieldnames or [])
            print(
                f"Column {column!r} not found. Available: {available}", file=sys.stderr
            )
            sys.exit(1)
        values = []
        for row in reader:
            raw = row[column].strip()
            try:
                values.append(float(raw))
            except ValueError:
                pass
    finally:
        if source:
            f.close()

    return values


def print_stats(column: str, values: list[float]) -> None:
    n = len(values)
    if n == 0:
        print(f"No numeric values in column {column!r}.")
        return

    sorted_vals = sorted(values)
    width = 12

    def row(label: str, val: float) -> None:
        print(f"  {label:<{width}} {val:,.4f}")

    print(f"\nColumn: {column!r}  ({n} values)\n")
    row("min", min(values))
    row("max", max(values))
    row("sum", sum(values))
    row("mean", statistics.mean(values))
    row("median", statistics.median(values))
    if n >= 2:
        row("stdev", statistics.stdev(values))
        row("variance", statistics.variance(values))
    p25 = sorted_vals[int(n * 0.25)]
    p75 = sorted_vals[int(n * 0.75)]
    row("p25", p25)
    row("p75", p75)
    row("iqr", p75 - p25)
    try:
        row("mode", statistics.mode(values))
    except statistics.StatisticsError:
        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Descriptive statistics for a CSV column."
    )
    parser.add_argument("file", nargs="?", help="CSV file (reads stdin if omitted)")
    parser.add_argument("-c", "--column", required=True, help="Column name to analyze")
    parser.add_argument(
        "-d", "--delimiter", default=",", help="Field delimiter (default: ,)"
    )
    parser.add_argument(
        "--encoding", default="utf-8", help="File encoding (default: utf-8)"
    )
    args = parser.parse_args()

    values = load_column(args.file, args.column, args.delimiter, args.encoding)
    print_stats(args.column, values)
