"""
A simple HTTP file server that serves files from a specified directory.
This script uses Python's built-in http.server module to create a basic file server.
"""

import http.server
import socketserver
import os
import argparse


class Handler(http.server.SimpleHTTPRequestHandler):
    """Custom request handler that serves files from the specified directory."""

    pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple file server.")
    parser.add_argument(
        "-b",
        "--bind",
        default="0.0.0.0",
        help="IP address for listening (default: 0.0.0.0)",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=8001,
        help="Listening port (default: 8001)",
    )
    parser.add_argument(
        "-d",
        "--directory",
        default="files",
        help="Publication directory (default: files)",
    )

    args = parser.parse_args()

    host = args.bind
    port = args.port
    directory = args.directory

    os.makedirs(directory, exist_ok=True)
    os.chdir(directory)

    with socketserver.TCPServer((host, port), Handler) as httpd:
        print(
            f"> The server is running at http://{host}:{port} and serves files from the directory: {directory}"
        )
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print(">> Server stopped.")
            httpd.server_close()
