"""Simple TCP Ping Utility."""

import socket
import time
import argparse


def ping(host: str, port: int = 80, timeout: int = 1) -> float | None:
    """Check if a host is reachable by attempting to connect to it on a specified port."""
    try:
        start_time = time.time()
        with socket.create_connection((host, port), timeout=timeout):
            end_time = time.time()
            delay = end_time - start_time
            return delay
    except (socket.error, socket.timeout):
        return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="A simple utility for checking host availability (TCP ping)."
    )
    parser.add_argument("host", help="Hostname or IP address for verification")
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=80,
        help="Port for connection (default: 80)",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=4,
        help="Number of attempts (default: 4)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=1,
        help="Connection timeout in seconds (default: 1)",
    )

    args = parser.parse_args()

    target_host = args.host
    try_port = args.port
    try_count = args.count
    timeout_sec = args.timeout

    print(
        f"Pinging {target_host}:{try_port} with {try_count} attempts (timeout: {timeout_sec} sec):"
    )

    for index in range(try_count):
        print(f"Attempt {index + 1}: ", end="")
        delay = ping(target_host, port=try_port, timeout=timeout_sec)
        if delay is not None:
            print(f"Success! Delay: {delay:.4f} sec.")
        else:
            print("Failed.")

        time.sleep(1)
