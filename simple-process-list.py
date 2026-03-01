"""List, search, and kill processes by name or PID."""

import sys
import argparse
import subprocess
import platform
import signal


def list_processes_windows(name_filter: str | None) -> list[dict]:
    out = subprocess.check_output(
        ["tasklist", "/fo", "csv", "/nh"], text=True, stderr=subprocess.DEVNULL
    )
    results = []
    for line in out.strip().splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) < 5:
            continue
        proc_name, pid, _, _, mem = parts[0], parts[1], parts[2], parts[3], parts[4]
        if name_filter and name_filter.lower() not in proc_name.lower():
            continue
        try:
            mem_kb = int(
                mem.replace(",", "")
                .replace(".", "")
                .replace("\xa0", "")
                .replace(" K", "")
                .strip()
            )
        except ValueError:
            mem_kb = 0
        results.append(
            {
                "name": proc_name,
                "pid": int(pid),
                "mem_kb": mem_kb,
                "cpu_pct": None,
                "mem_pct": None,
            }
        )
    return results


def list_processes_unix(name_filter: str | None) -> list[dict]:
    out = subprocess.check_output(["ps", "aux"], text=True, stderr=subprocess.DEVNULL)
    results = []
    for line in out.strip().splitlines()[1:]:
        parts = line.split(None, 10)
        if len(parts) < 11:
            continue
        proc_name = parts[10].split()[0] if parts[10].strip() else parts[10]
        if name_filter and name_filter.lower() not in proc_name.lower():
            continue
        try:
            cpu_pct = float(parts[2])
            mem_pct = float(parts[3])
            mem_kb = int(float(parts[5]))
        except ValueError:
            cpu_pct = mem_pct = 0.0
            mem_kb = 0
        try:
            pid = int(parts[1])
        except ValueError:
            continue
        results.append(
            {
                "name": proc_name,
                "pid": pid,
                "mem_kb": mem_kb,
                "cpu_pct": cpu_pct,
                "mem_pct": mem_pct,
            }
        )
    return results


def list_processes(name_filter: str | None) -> list[dict]:
    if platform.system() == "Windows":
        return list_processes_windows(name_filter)
    return list_processes_unix(name_filter)


def kill_process(pid: int, force: bool) -> None:
    if platform.system() == "Windows":
        cmd = ["taskkill", "/pid", str(pid)] + (["/f"] if force else [])
        subprocess.run(cmd, check=True)
    else:
        sig = signal.SIGKILL if force else signal.SIGTERM
        subprocess.run(["kill", f"-{sig.value}", str(pid)], check=True)
    print(f"Sent {'KILL' if force else 'TERM'} to PID {pid}")


def human_mem(kb: int) -> str:
    if kb >= 1024 * 1024:
        return f"{kb / 1024 / 1024:.1f} GB"
    if kb >= 1024:
        return f"{kb / 1024:.1f} MB"
    return f"{kb} KB"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="List or kill processes by name or PID."
    )
    sub = parser.add_subparsers(dest="command")

    p_list = sub.add_parser("list", help="List running processes")
    p_list.add_argument(
        "name", nargs="?", help="Filter by name substring (case-insensitive)"
    )
    p_list.add_argument("-s", "--sort", choices=["name", "pid", "mem"], default="name")
    p_list.add_argument("-n", "--limit", type=int, help="Max results to show")

    p_kill = sub.add_parser("kill", help="Kill a process by PID or name")
    p_kill.add_argument("target", help="PID (integer) or process name substring")
    p_kill.add_argument(
        "-f", "--force", action="store_true", help="Force kill (SIGKILL/taskkill /f)"
    )

    args = parser.parse_args()

    match args.command:
        case "list":
            procs = list_processes(args.name)
            key = {
                "name": lambda p: p["name"].lower(),
                "pid": lambda p: p["pid"],
                "mem": lambda p: -p["mem_kb"],
            }[args.sort]
            procs.sort(key=key)
            if args.limit:
                procs = procs[: args.limit]
            has_cpu = any(p.get("cpu_pct") is not None for p in procs)
            header_fmt = (
                f"  {'PID':>7}  {'CPU%':>6}  {'MEM%':>6}  {'Memory':>9}  Name"
                if has_cpu
                else f"  {'PID':>7}  {'Memory':>9}  Name"
            )
            print(header_fmt)
            sep_len = 60 if has_cpu else 40
            print(f"  {'-' * sep_len}")
            for p in procs:
                if has_cpu:
                    cpu = (
                        f"{p.get('cpu_pct', 0):>5.1f}%"
                        if p.get("cpu_pct")
                        else "  n/a "
                    )
                    mem = (
                        f"{p.get('mem_pct', 0):>5.1f}%"
                        if p.get("mem_pct")
                        else "  n/a "
                    )
                    print(
                        f"  {p['pid']:>7}  {cpu}  {mem}  {human_mem(p['mem_kb']):>9}  {p['name']}"
                    )
                else:
                    print(f"  {p['pid']:>7}  {human_mem(p['mem_kb']):>9}  {p['name']}")
            print(f"\n  {len(procs)} process(es)")

        case "kill":
            try:
                pid = int(args.target)
                kill_process(pid, args.force)
            except ValueError:
                procs = list_processes(args.target)
                if not procs:
                    print(f"No processes matching {args.target!r}", file=sys.stderr)
                    sys.exit(1)
                if len(procs) > 1:
                    print("Multiple matches — specify a PID:\n")
                    for p in procs:
                        print(f"  {p['pid']:>7}  {p['name']}")
                    sys.exit(1)
                kill_process(procs[0]["pid"], args.force)
        case _:
            parser.print_help()
