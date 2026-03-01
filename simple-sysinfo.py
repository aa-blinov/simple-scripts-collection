"""Display system information: OS, CPU, memory, disk, and GPU usage."""

import os
import platform
import shutil
import argparse
import subprocess
from pathlib import Path
from datetime import timedelta


def human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def bar(used: float, total: float, width: int = 20) -> str:
    pct = used / total if total else 0
    filled = int(pct * width)
    return f"[{'█' * filled}{'░' * (width - filled)}] {pct * 100:.1f}%"


def uptime() -> str:
    try:
        if platform.system() == "Windows":
            import ctypes

            ms = ctypes.windll.kernel32.GetTickCount64()
            delta = timedelta(milliseconds=ms)
        else:
            with open("/proc/uptime") as f:
                secs = float(f.read().split()[0])
            delta = timedelta(seconds=secs)
        h, rem = divmod(int(delta.total_seconds()), 3600)
        m = rem // 60
        return f"{h}h {m}m"
    except Exception:
        return "n/a"


def cpu_count() -> str:
    logical = os.cpu_count() or 0
    try:
        physical = len(
            set(
                line.split(":")[1].strip()
                for line in Path("/proc/cpuinfo").read_text().splitlines()
                if line.startswith("core id")
            )
        )
        return f"{physical} physical, {logical} logical"
    except Exception:
        return f"{logical} logical"


def memory_info() -> tuple[int, int] | None:
    try:
        if platform.system() == "Windows":
            import ctypes

            class MEMSTATUS(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            ms = MEMSTATUS()
            ms.dwLength = ctypes.sizeof(MEMSTATUS)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms))
            return ms.ullTotalPhys, ms.ullAvailPhys
        else:
            info = {}
            for line in Path("/proc/meminfo").read_text().splitlines():
                k, _, v = line.partition(":")
                info[k.strip()] = int(v.strip().split()[0]) * 1024
            return info["MemTotal"], info["MemAvailable"]
    except Exception:
        return None


def disk_info(paths: list[str]) -> list[tuple[str, int, int, int]]:
    results = []
    for p in paths:
        try:
            u = shutil.disk_usage(p)
            results.append((p, u.total, u.used, u.free))
        except Exception:
            pass
    return results


def all_disks() -> list[str]:
    if platform.system() == "Windows":
        import ctypes

        buf = ctypes.create_unicode_buffer(256)
        ctypes.windll.kernel32.GetLogicalDriveStringsW(len(buf), buf)
        # buf is null-separated, double-null terminated; iterate char by char
        drives, current = [], []
        for ch in buf:
            if ch == "\x00":
                if current:
                    drives.append("".join(current))
                    current = []
                else:
                    break
            else:
                current.append(ch)
        return drives
    else:
        seen: set[str] = set()
        mounts: list[str] = []
        try:
            for line in Path("/proc/mounts").read_text().splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[1].startswith("/"):
                    mp = parts[1]
                    device = parts[0]
                    if device.startswith("/dev/") and mp not in seen:
                        seen.add(mp)
                        mounts.append(mp)
        except Exception:
            mounts = ["/"]
        return mounts or ["/"]


def gpu_info() -> list[dict]:
    """Try nvidia-smi first, then wmic (Windows fallback)."""
    results = []

    # NVIDIA via nvidia-smi
    try:
        out = subprocess.check_output(
            [
                "nvidia-smi",
                "--query-gpu=name,memory.total,memory.used,memory.free,utilization.gpu",
                "--format=csv,noheader,nounits",
            ],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        for line in out.strip().splitlines():
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 5:
                results.append(
                    {
                        "name": parts[0],
                        "vram_total": int(parts[1]) * 1024 * 1024,
                        "vram_used": int(parts[2]) * 1024 * 1024,
                        "vram_free": int(parts[3]) * 1024 * 1024,
                        "gpu_pct": parts[4],
                    }
                )
        if results:
            return results
    except Exception:
        pass

    # Windows fallback via wmic
    if platform.system() == "Windows":
        try:
            out = subprocess.check_output(
                [
                    "wmic",
                    "path",
                    "Win32_VideoController",
                    "get",
                    "Name,AdapterRAM",
                    "/format:csv",
                ],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            for line in out.strip().splitlines():
                parts = line.split(",")
                if len(parts) >= 3 and parts[1].strip().lstrip("-").isdigit():
                    vram = int(parts[1].strip())
                    name = parts[2].strip()
                    if name and vram > 0:
                        results.append(
                            {
                                "name": name,
                                "vram_total": vram,
                                "vram_used": None,
                                "vram_free": None,
                                "gpu_pct": None,
                            }
                        )
        except Exception:
            pass

    return results


def cpu_temp() -> float | None:
    """Get CPU temperature. Windows: WMI, Linux: /sys/class/thermal."""
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output(
                [
                    "wmic",
                    "os",
                    "get",
                    "CSCreationClassName",
                    "/value",
                ],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            out = subprocess.check_output(
                [
                    "powershell",
                    "-Command",
                    "(Get-WmiObject MSAcpi_ThermalZoneTemperature -Namespace 'root/wmi' -ErrorAction SilentlyContinue | Select-Object -First 1).CurrentTemperature",
                ],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            if out.strip().isdigit():
                kelvin = int(out.strip()) / 10
                celsius = kelvin - 273.15
                return round(celsius, 1)
        else:
            thermal_dir = Path("/sys/class/thermal")
            if thermal_dir.exists():
                for zone in thermal_dir.glob("thermal_zone*"):
                    temp_file = zone / "temp"
                    if temp_file.exists():
                        temp = int(temp_file.read_text().strip()) / 1000
                        return round(temp, 1)
    except Exception:
        pass
    return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Show system information.")
    parser.add_argument(
        "-d",
        "--disks",
        nargs="+",
        help="Disk paths to show (default: all detected)",
    )
    parser.add_argument("--no-gpu", action="store_true", help="Skip GPU info")
    args = parser.parse_args()

    uname = platform.uname()
    print(f"  {'OS':<14} {uname.system} {uname.release} ({uname.machine})")
    print(f"  {'Node':<14} {uname.node}")
    print(f"  {'Python':<14} {platform.python_version()}")
    print(f"  {'Uptime':<14} {uptime()}")
    print(f"  {'CPU':<14} {cpu_count()}")
    print(f"  {'CPU model':<14} {uname.processor or 'n/a'}")
    temp = cpu_temp()
    if temp:
        print(f"  {'CPU temp':<14} {temp}°C")

    mem = memory_info()
    if mem:
        total, avail = mem
        used = total - avail
        print(
            f"\n  {'Memory':<14} {human_size(used)} / {human_size(total)}  {bar(used, total)}"
        )

    print()
    disk_paths = args.disks or all_disks()
    for path, total, used, free in disk_info(disk_paths):
        label = f"Disk {path}"
        print(
            f"  {label:<14} {human_size(used)} / {human_size(total)}  {bar(used, total)}  free {human_size(free)}"
        )

    if not args.no_gpu:
        gpus = gpu_info()
        if gpus:
            print()
            for i, g in enumerate(gpus):
                label = f"GPU {i}"
                name_str = g["name"][:38]
                print(f"  {label:<14} {name_str}")
                if g["vram_used"] is not None:
                    vram_label = f"  VRAM {i}"
                    print(
                        f"  {vram_label:<14} "
                        f"{human_size(g['vram_used'])} / {human_size(g['vram_total'])}  "
                        f"{bar(g['vram_used'], g['vram_total'])}  "
                        f"free {human_size(g['vram_free'])}"
                    )
                elif g["vram_total"]:
                    vram_label = f"  VRAM {i}"
                    print(
                        f"  {vram_label:<14} {human_size(g['vram_total'])} total  (usage n/a without nvidia-smi)"
                    )
                if g["gpu_pct"] is not None:
                    print(f"  {'  Utilization':<14} {g['gpu_pct']}%")
