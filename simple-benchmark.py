"""Benchmark Python expressions and scripts with timeit and cProfile."""

import sys
import timeit
import cProfile
import pstats
import argparse
from io import StringIO


def fmt_time(s: float) -> str:
    if s < 1e-6:
        return f"{s * 1e9:.2f} ns"
    if s < 1e-3:
        return f"{s * 1e6:.2f} µs"
    if s < 1:
        return f"{s * 1e3:.2f} ms"
    return f"{s:.4f} s"


def cmd_time(stmt: str, setup: str, number: int, repeat: int) -> None:
    times = timeit.repeat(stmt, setup=setup, number=number, repeat=repeat)
    best = min(times) / number
    worst = max(times) / number
    avg = sum(times) / len(times) / number
    print(f"  stmt    {stmt!r}")
    print(f"  loops   {number:,} × {repeat} repeats")
    print(f"  best    {fmt_time(best)}")
    print(f"  avg     {fmt_time(avg)}")
    print(f"  worst   {fmt_time(worst)}")


def cmd_profile(script: str, lines: int, sort_key: str) -> None:
    pr = cProfile.Profile()
    globs: dict = {"__name__": "__main__", "__file__": script}
    pr.enable()
    try:
        with open(script) as f:
            exec(compile(f.read(), script, "exec"), globs)
    finally:
        pr.disable()
    buf = StringIO()
    pstats.Stats(pr, stream=buf).sort_stats(sort_key).print_stats(lines)
    print(buf.getvalue())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Benchmark Python expressions and scripts."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_t = sub.add_parser("time", help="Time a Python expression with timeit")
    p_t.add_argument("stmt", help="Python statement to benchmark")
    p_t.add_argument("-s", "--setup", default="pass", help="Setup code (default: pass)")
    p_t.add_argument(
        "-n",
        "--number",
        type=int,
        default=100_000,
        help="Loops per repeat (default: 100000)",
    )
    p_t.add_argument(
        "-r", "--repeat", type=int, default=5, help="Number of repeats (default: 5)"
    )

    p_p = sub.add_parser("profile", help="Profile a Python script with cProfile")
    p_p.add_argument("script", help="Path to .py file")
    p_p.add_argument(
        "-n", "--lines", type=int, default=20, help="Top N functions (default: 20)"
    )
    p_p.add_argument(
        "--sort",
        default="cumulative",
        choices=["cumulative", "tottime", "calls", "pcalls", "name"],
        dest="sort_key",
        help="Sort key (default: cumulative)",
    )

    args = parser.parse_args()
    if args.cmd == "time":
        cmd_time(args.stmt, args.setup, args.number, args.repeat)
    elif args.cmd == "profile":
        cmd_profile(args.script, args.lines, args.sort_key)
    else:
        sys.exit(1)
