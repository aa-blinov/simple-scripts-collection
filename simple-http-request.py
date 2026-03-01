"""curl-like HTTP client: GET/POST/PUT/DELETE with headers, JSON body, and timing."""

import sys
import json
import time
import argparse
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode


def build_request(
    method: str,
    url: str,
    headers: dict[str, str],
    data: bytes | None,
) -> Request:
    req = Request(url, data=data, method=method.upper())
    for k, v in headers.items():
        req.add_header(k, v)
    return req


def run(
    method: str,
    url: str,
    headers: dict[str, str],
    data: bytes | None,
    follow: bool,
    verbose: bool,
    output: str | None,
) -> int:
    t0 = time.perf_counter()
    current_url = url
    current_method = method.upper()
    current_data = data
    redirects = 0
    max_redirects = 10 if follow else 0

    while True:
        req = build_request(current_method, current_url, headers, current_data)
        try:
            with urlopen(req) as resp:
                elapsed = time.perf_counter() - t0
                if verbose:
                    print(f"HTTP/1.1 {resp.status} {resp.reason}")
                    for k, v in resp.headers.items():
                        print(f"{k}: {v}")
                    print()
                body = resp.read()
                if output:
                    with open(output, "wb") as f:
                        f.write(body)
                    print(
                        f"Saved to {output}  ({len(body):,} bytes)  {elapsed * 1000:.1f}ms"
                    )
                else:
                    text = body.decode(
                        resp.headers.get_content_charset("utf-8"), errors="replace"
                    )
                    print(text, end="" if text.endswith("\n") else "\n")
                    if verbose:
                        print(
                            f"\n{len(body):,} bytes  {elapsed * 1000:.1f}ms",
                            file=sys.stderr,
                        )
                return 0
        except HTTPError as e:
            if 300 <= e.code < 400 and follow and redirects < max_redirects:
                location = e.headers.get("Location")
                if location:
                    redirects += 1
                    current_url = location
                    current_method = "GET"
                    current_data = None
                    if verbose:
                        print(f"Redirect -> {location}", file=sys.stderr)
                    continue
            elapsed = time.perf_counter() - t0
            body = e.read().decode("utf-8", errors="replace")
            print(
                f"HTTP {e.code} {e.reason}  ({elapsed * 1000:.1f}ms)", file=sys.stderr
            )
            if body:
                print(body, file=sys.stderr)
            return e.code
        except URLError as e:
            print(f"Error: {e.reason}", file=sys.stderr)
            return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Simple HTTP client.",
        epilog="Examples:\n"
        "  %(prog)s https://httpbin.org/get\n"
        '  %(prog)s -X POST https://httpbin.org/post -j \'{"key":"val"}\'\n'
        "  %(prog)s -X PUT https://api/item/1 -j @body.json -H Authorization:'Bearer token'",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("url")
    parser.add_argument(
        "-X", "--method", default="GET", help="HTTP method (default: GET)"
    )
    parser.add_argument(
        "-j",
        "--json",
        dest="json_body",
        metavar="JSON|@FILE",
        help="JSON body (prefix with @ to read from file)",
    )
    parser.add_argument(
        "-d",
        "--data",
        metavar="DATA|@FILE",
        help="Raw body string (prefix with @ to read from file)",
    )
    parser.add_argument(
        "-H",
        "--header",
        action="append",
        dest="headers",
        metavar="K:V",
        default=[],
        help="Extra header (repeatable)",
    )
    parser.add_argument(
        "-F", "--form", action="append", metavar="K=V", help="Form field (repeatable)"
    )
    parser.add_argument("-o", "--output", help="Save response body to file")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show response headers"
    )
    parser.add_argument(
        "--no-follow", action="store_true", help="Do not follow redirects"
    )
    args = parser.parse_args()

    method = args.method.upper()
    hdrs: dict[str, str] = {}
    for h in args.headers:
        if ":" not in h:
            parser.error(f"Invalid header (use K:V): {h}")
        k, _, v = h.partition(":")
        hdrs[k.strip()] = v.strip()

    body: bytes | None = None

    if args.json_body:
        raw = args.json_body
        if raw.startswith("@"):
            raw = open(raw[1:]).read()
        json.loads(raw)  # validate
        body = raw.encode()
        hdrs.setdefault("Content-Type", "application/json")
        if method == "GET":
            method = "POST"
    elif args.data:
        raw = args.data
        if raw.startswith("@"):
            raw = open(raw[1:]).read()
        body = raw.encode()
        if method == "GET":
            method = "POST"
    elif args.form:
        pairs = {}
        for item in args.form:
            k, _, v = item.partition("=")
            pairs[k] = v
        body = urlencode(pairs).encode()
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        if method == "GET":
            method = "POST"

    sys.exit(
        run(method, args.url, hdrs, body, not args.no_follow, args.verbose, args.output)
    )
