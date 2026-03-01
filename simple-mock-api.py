"""Lightweight HTTP mock API server driven by a JSON config file.

Config format (mock-api.json):
{
  "routes": [
    {"method": "GET",  "path": "/health", "status": 200, "body": {"ok": true}},
    {"method": "POST", "path": "/echo",   "status": 201, "body": {"created": true}, "delay": 0.3}
  ]
}
"""

import json
import time
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse


def load_config(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def make_handler(routes: dict, verbose: bool) -> type:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args) -> None:  # type: ignore[override]
            if verbose:
                super().log_message(fmt, *args)

        def handle_request(self) -> None:
            parsed = urlparse(self.path)
            route = routes.get(f"{self.command} {parsed.path}") or routes.get(
                f"ANY {parsed.path}"
            )
            if route is None:
                self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "not found"}).encode())
                return

            delay = route.get("delay", 0)
            if delay:
                time.sleep(delay)

            status = route.get("status", 200)
            body = route.get("body", {})
            headers = route.get("headers", {})

            self.send_response(status)
            self.send_header(
                "Content-Type", headers.get("Content-Type", "application/json")
            )
            for k, v in headers.items():
                if k != "Content-Type":
                    self.send_header(k, v)
            self.end_headers()

            if isinstance(body, (dict, list)):
                self.wfile.write(json.dumps(body).encode())
            else:
                self.wfile.write(str(body).encode())

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = handle_request

    return Handler


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Lightweight HTTP mock API server.")
    parser.add_argument(
        "config",
        nargs="?",
        default="mock-api.json",
        help="JSON config file (default: mock-api.json)",
    )
    parser.add_argument("-p", "--port", type=int, default=8000)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Suppress request logs"
    )
    args = parser.parse_args()

    cfg = load_config(args.config)
    routes: dict = {}
    for route in cfg.get("routes", []):
        method = route.get("method", "ANY").upper()
        routes[f"{method} {route['path']}"] = route

    server = HTTPServer((args.host, args.port), make_handler(routes, not args.quiet))
    print(
        f"Mock API on http://{args.host}:{args.port}  ({len(routes)} routes)  Ctrl+C to stop"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
