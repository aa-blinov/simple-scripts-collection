"""Simple CLI to-do list stored as a JSON file in the home directory."""

import json
import sys
import argparse
from pathlib import Path
from datetime import datetime

TODO_FILE = Path.home() / ".simple-todo.json"


def load() -> list[dict]:
    if not TODO_FILE.exists():
        return []
    return json.loads(TODO_FILE.read_text(encoding="utf-8"))


def save(tasks: list[dict]) -> None:
    TODO_FILE.write_text(
        json.dumps(tasks, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def cmd_add(text: str, priority: str = "normal") -> None:
    tasks = load()
    next_id = max((t["id"] for t in tasks), default=0) + 1
    tasks.append(
        {
            "id": next_id,
            "text": text,
            "priority": priority,
            "done": False,
            "created": datetime.now().isoformat(timespec="seconds"),
        }
    )
    save(tasks)
    print(f"Added #{next_id} [{priority}]: {text}")


def cmd_list(show_all: bool, filter_priority: str | None = None) -> None:
    tasks = load()
    shown = tasks if show_all else [t for t in tasks if not t["done"]]
    if filter_priority and filter_priority != "all":
        shown = [t for t in shown if t.get("priority", "normal") == filter_priority]
    if not shown:
        print("Nothing to do." if not show_all else "No tasks.")
        return

    priority_marks = {"high": "🔴", "normal": "🟡", "low": "🟢"}
    for t in shown:
        mark = "✓" if t["done"] else "○"
        prio = priority_marks.get(t.get("priority", "normal"), "")
        print(f"  [{t['id']:>3}] {mark} {prio}  {t['text']}")


def cmd_done(task_id: int) -> None:
    tasks = load()
    for t in tasks:
        if t["id"] == task_id:
            t["done"] = True
            save(tasks)
            print(f"Done: {t['text']}")
            return
    print(f"Task {task_id} not found.", file=sys.stderr)
    sys.exit(1)


def cmd_remove(task_id: int) -> None:
    tasks = load()
    remaining = [t for t in tasks if t["id"] != task_id]
    if len(remaining) == len(tasks):
        print(f"Task {task_id} not found.", file=sys.stderr)
        sys.exit(1)
    save(remaining)
    print(f"Removed task {task_id}.")


def cmd_clear() -> None:
    tasks = [t for t in load() if not t["done"]]
    save(tasks)
    print("Cleared completed tasks.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple CLI to-do list.")
    sub = parser.add_subparsers(dest="command")

    p_add = sub.add_parser("add", help="Add a new task")
    p_add.add_argument("text", nargs="+")
    p_add.add_argument(
        "-p",
        "--priority",
        choices=["high", "normal", "low"],
        default="normal",
        help="Priority (default: normal)",
    )

    p_list = sub.add_parser("list", help="List tasks")
    p_list.add_argument(
        "-a", "--all", action="store_true", help="Include completed tasks"
    )
    p_list.add_argument(
        "-p",
        "--priority",
        choices=["high", "normal", "low", "all"],
        default=None,
        help="Filter by priority",
    )

    p_done = sub.add_parser("done", help="Mark a task as done")
    p_done.add_argument("id", type=int)

    p_remove = sub.add_parser("remove", help="Remove a task")
    p_remove.add_argument("id", type=int)

    sub.add_parser("clear", help="Remove all completed tasks")

    args = parser.parse_args()

    match args.command:
        case "add":
            cmd_add(" ".join(args.text), args.priority)
        case "list":
            cmd_list(args.all, args.priority)
        case "done":
            cmd_done(args.id)
        case "remove":
            cmd_remove(args.id)
        case "clear":
            cmd_clear()
        case _:
            parser.print_help()
