"""Check HTTP status codes for a list of URLs concurrently."""

import sys
import argparse
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

ANSI: dict[int, str] = {
    2: "\033[32m",
    3: "\033[33m",
    4: "\033[31m",
    5: "\033[31m",
}
RESET = "\033[0m"
DIM = "\033[90m"


def check_url(url: str, timeout: int) -> tuple[str, int | None, str]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return url, resp.status, resp.reason
    except urllib.error.HTTPError as e:
        return url, e.code, e.reason
    except urllib.error.URLError as e:
        return url, None, str(e.reason)
    except Exception as e:
        return url, None, str(e)


def status_color(code: int | None) -> str:
    if code is None:
        return DIM
    return ANSI.get(code // 100, "")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check HTTP status codes for URLs.")
    parser.add_argument("urls", nargs="*", help="URLs to check")
    parser.add_argument("-f", "--file", help="File with URLs, one per line")
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=10,
        help="Concurrent workers (default: 10)",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable color output")
    args = parser.parse_args()

    urls: list[str] = list(args.urls)
    if args.file:
        with open(args.file) as f:
            urls += [
                line.strip() for line in f if line.strip() and not line.startswith("#")
            ]

    if not urls:
        print("No URLs provided.", file=sys.stderr)
        sys.exit(1)

    results: list[tuple[str, int | None, str]] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(check_url, url, args.timeout): url for url in urls}
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda r: (r[1] is None, r[1]))
    max_url = max(len(r[0]) for r in results)

    for url, code, reason in results:
        code_str = str(code) if code is not None else "ERR"
        color = "" if args.no_color else status_color(code)
        print(f"{color}{code_str:<4}{RESET}  {url:<{max_url}}  {reason}")
