"""SQLite database browser and query runner."""

import sys
import csv
import sqlite3
import argparse
from pathlib import Path


def cmd_query(db: str, sql: str, csv_out: bool) -> None:
    con = sqlite3.connect(db)
    cur = con.execute(sql)
    con.commit()
    if cur.description is None:
        print(f"{cur.rowcount} row(s) affected.")
        con.close()
        return
    rows = cur.fetchall()
    con.close()
    if not rows:
        print("(no rows)")
        return
    cols = [d[0] for d in cur.description]
    if csv_out:
        w = csv.writer(sys.stdout)
        w.writerow(cols)
        w.writerows(rows)
    else:
        widths = [
            max(len(str(c)), max(len(str(r[i])) for r in rows))
            for i, c in enumerate(cols)
        ]
        sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
        fmt = "|" + "|".join(f" {{:<{w}}} " for w in widths) + "|"
        print(sep)
        print(fmt.format(*cols))
        print(sep)
        for row in rows:
            print(fmt.format(*[str(v) for v in row]))
        print(sep)
        print(f"{len(rows)} row(s)")


def cmd_tables(db: str) -> None:
    con = sqlite3.connect(db)
    rows = con.execute(
        "SELECT name, type FROM sqlite_master WHERE type IN ('table','view') ORDER BY name"
    ).fetchall()
    con.close()
    if not rows:
        print("(empty database)")
        return
    for name, kind in rows:
        print(f"  {kind:<6} {name}")


def cmd_schema(db: str, table: str) -> None:
    con = sqlite3.connect(db)
    row = con.execute("SELECT sql FROM sqlite_master WHERE name=?", (table,)).fetchone()
    con.close()
    if not row:
        print(f"Table '{table}' not found.", file=sys.stderr)
        sys.exit(1)
    print(row[0])


def cmd_import(db: str, table: str, csv_path: str) -> None:
    with Path(csv_path).open(encoding="utf-8") as f:
        rows = list(csv.reader(f))
    if not rows:
        print("Empty CSV.", file=sys.stderr)
        sys.exit(1)
    cols = rows[0]
    data = rows[1:]
    con = sqlite3.connect(db)
    placeholders = ",".join("?" * len(cols))
    col_defs = ",".join(f'"{c}" TEXT' for c in cols)
    con.execute(f'CREATE TABLE IF NOT EXISTS "{table}" ({col_defs})')
    con.executemany(f'INSERT INTO "{table}" VALUES ({placeholders})', data)
    con.commit()
    con.close()
    print(f"Imported {len(data)} rows into '{table}'.")


def cmd_export(db: str, table: str, out: str | None) -> None:
    con = sqlite3.connect(db)
    cur = con.execute(f'SELECT * FROM "{table}"')
    cols = [d[0] for d in cur.description]
    rows = cur.fetchall()
    con.close()
    dest = open(out, "w", newline="", encoding="utf-8") if out else sys.stdout
    w = csv.writer(dest)
    w.writerow(cols)
    w.writerows(rows)
    if out:
        dest.close()
        print(f"Exported {len(rows)} rows to '{out}'.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SQLite browser and query runner.")
    parser.add_argument("db", help="Path to .sqlite / .db file")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_q = sub.add_parser("query", aliases=["q"], help="Run a SQL statement")
    p_q.add_argument("sql", help="SQL statement")
    p_q.add_argument("--csv", action="store_true", help="Output SELECT results as CSV")

    sub.add_parser("tables", aliases=["t"], help="List tables and views")

    p_s = sub.add_parser(
        "schema", aliases=["s"], help="Show CREATE statement for a table"
    )
    p_s.add_argument("table")

    p_i = sub.add_parser("import-csv", help="Import a CSV file into a table")
    p_i.add_argument("table")
    p_i.add_argument("csv_file")

    p_e = sub.add_parser("export-csv", help="Export a table to CSV")
    p_e.add_argument("table")
    p_e.add_argument("--out", help="Output file (default: stdout)")

    args = parser.parse_args()
    if args.cmd in ("query", "q"):
        cmd_query(args.db, args.sql, args.csv)
    elif args.cmd in ("tables", "t"):
        cmd_tables(args.db)
    elif args.cmd in ("schema", "s"):
        cmd_schema(args.db, args.table)
    elif args.cmd == "import-csv":
        cmd_import(args.db, args.table, args.csv_file)
    elif args.cmd == "export-csv":
        cmd_export(args.db, args.table, args.out)
