"""Send a desktop notification from the command line."""

import sys
import platform
import argparse
import subprocess


def notify_windows(title: str, body: str, duration: int) -> None:
    script = (
        f"Add-Type -AssemblyName System.Windows.Forms; "
        f"$n = New-Object System.Windows.Forms.NotifyIcon; "
        f"$n.Icon = [System.Drawing.SystemIcons]::Information; "
        f"$n.Visible = $true; "
        f"$n.ShowBalloonTip({duration * 1000}, '{title}', '{body}', "
        f"[System.Windows.Forms.ToolTipIcon]::None); "
        f"Start-Sleep -Milliseconds {duration * 1000 + 200}; "
        f"$n.Dispose()"
    )
    subprocess.Popen(
        ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", script],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def notify_macos(title: str, body: str) -> None:
    script = f'display notification "{body}" with title "{title}"'
    subprocess.run(["osascript", "-e", script], check=True)


def notify_linux(title: str, body: str, duration: int) -> None:
    import shutil

    if shutil.which("notify-send"):
        subprocess.run(
            ["notify-send", "-t", str(duration * 1000), title, body], check=True
        )
    elif shutil.which("zenity"):
        subprocess.Popen(
            ["zenity", "--info", f"--title={title}", f"--text={body}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        print(f"[notify] {title}: {body}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Send a desktop notification.",
        epilog="Example: python long_task.py ; python simple-notify.py 'Done'",
    )
    parser.add_argument("body", help="Notification message")
    parser.add_argument(
        "-t", "--title", default="Notification", help="Notification title"
    )
    parser.add_argument(
        "-d",
        "--duration",
        type=int,
        default=5,
        help="Display duration in seconds (default: 5)",
    )
    args = parser.parse_args()

    system = platform.system()
    try:
        if system == "Windows":
            notify_windows(args.title, args.body, args.duration)
        elif system == "Darwin":
            notify_macos(args.title, args.body)
        else:
            notify_linux(args.title, args.body, args.duration)
        print(f"Notification sent: {args.title} — {args.body}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
