"""Pretty-print git log with branch graph, stats, and author/date filtering."""

import sys
import argparse
import subprocess


COLORS = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
}
GRAPH_COLORS = ["\033[33m", "\033[32m", "\033[34m", "\033[35m", "\033[36m"]


def c(name: str, text: str, use_color: bool) -> str:
    return f"{COLORS[name]}{text}{COLORS['reset']}" if use_color else text


def git_log(args: argparse.Namespace) -> list[dict]:
    cmd = [
        "git",
        "log",
        "--pretty=format:%H|%h|%P|%an|%ae|%ad|%s|%D",
        "--date=format:%Y-%m-%d %H:%M",
    ]
    if args.graph:
        cmd.append("--graph")
    if args.all:
        cmd.append("--all")
    if args.n:
        cmd += [f"-n{args.n}"]
    if args.author:
        cmd += [f"--author={args.author}"]
    if args.since:
        cmd += [f"--since={args.since}"]
    if args.until:
        cmd += [f"--until={args.until}"]
    if args.grep:
        cmd += [f"--grep={args.grep}"]
    if args.file:
        cmd += ["--", args.file]
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print(e.stderr.strip(), file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print("git not found.", file=sys.stderr)
        sys.exit(1)
    return out.splitlines()


def stat_for(sha: str) -> str:
    try:
        out = subprocess.check_output(
            ["git", "diff-tree", "--no-commit-id", "-r", "--stat", sha],
            text=True,
            stderr=subprocess.DEVNULL,
        )
        last = [ln for ln in out.splitlines() if "changed" in ln]
        return last[0].strip() if last else ""
    except Exception:
        return ""


def print_log(lines: list[str], args: argparse.Namespace, color: bool) -> None:
    for line in lines:
        if args.graph and not line.strip().startswith("*") and "|" not in line:
            print(line)
            continue
        parts = line.split("|")
        if len(parts) < 8:
            print(line)
            continue
        _, short, _parents, author, _email, date, subject, refs = (
            parts[0],
            parts[1],
            parts[2],
            parts[3],
            parts[4],
            parts[5],
            parts[6],
            "|".join(parts[7:]),
        )
        ref_tags = []
        for ref in refs.split(","):
            ref = ref.strip()
            if not ref:
                continue
            if "HEAD" in ref:
                ref_tags.append(c("cyan", ref, color))
            elif "tag:" in ref:
                ref_tags.append(c("yellow", ref, color))
            else:
                ref_tags.append(c("green", ref, color))

        ref_str = (" " + " ".join(f"({r})" for r in ref_tags)) if ref_tags else ""
        hash_str = c("yellow", short, color)
        date_str = c("dim", date, color)
        author_str = c("blue", author, color)
        subj_str = c("bold", subject, color)

        line_out = f"{hash_str} {date_str} {author_str}{ref_str}"
        print(line_out)
        print(f"  {subj_str}")
        if args.stat:
            st = stat_for(parts[0].strip().lstrip("*\\ |"))
            if st:
                print(f"  {c('dim', st, color)}")
        print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pretty git log viewer.")
    parser.add_argument(
        "-n", type=int, default=20, help="Number of commits (default: 20)"
    )
    parser.add_argument("--all", action="store_true", help="Show all branches")
    parser.add_argument("--graph", action="store_true", help="Show branch graph")
    parser.add_argument(
        "--stat", action="store_true", help="Show changed files summary"
    )
    parser.add_argument("--author", help="Filter by author name/email")
    parser.add_argument("--since", help="Show commits after date (e.g. '2 weeks ago')")
    parser.add_argument("--until", help="Show commits before date")
    parser.add_argument("--grep", help="Filter by commit message")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("file", nargs="?", help="Limit to commits touching this file")
    args = parser.parse_args()

    color = not args.no_color and sys.stdout.isatty()
    lines = git_log(args)
    print_log(lines, args, color)
