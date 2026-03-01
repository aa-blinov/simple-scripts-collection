"""Generate UUIDs from the command line."""

import uuid
import sys
import argparse


GENERATORS = {
    1: uuid.uuid1,
    4: uuid.uuid4,
}


def generate(
    version: int, count: int, namespace: str | None, name: str | None
) -> list[str]:
    if version == 5:
        if not namespace or not name:
            raise ValueError("Version 5 requires --namespace and --name.")
        ns = getattr(uuid, f"NAMESPACE_{namespace.upper()}", None)
        if ns is None:
            raise ValueError(
                f"Unknown namespace: {namespace!r}. Use DNS, URL, OID, or X500."
            )
        return [str(uuid.uuid5(ns, name)) for _ in range(count)]
    if version not in GENERATORS:
        raise ValueError(f"Unsupported version: {version}")
    return [str(GENERATORS[version]()) for _ in range(count)]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate UUIDs.")
    parser.add_argument(
        "-v",
        "--version",
        type=int,
        choices=[1, 4, 5],
        default=4,
        help="UUID version (default: 4)",
    )
    parser.add_argument(
        "-n", "--count", type=int, default=1, help="Number of UUIDs to generate"
    )
    parser.add_argument("--upper", action="store_true", help="Output in uppercase")
    parser.add_argument(
        "--namespace",
        choices=["DNS", "URL", "OID", "X500"],
        help="Namespace for v5 (DNS, URL, OID, X500)",
    )
    parser.add_argument("--name", help="Name string for v5")
    args = parser.parse_args()

    try:
        results = generate(args.version, args.count, args.namespace, args.name)
    except ValueError as e:
        print(e, file=sys.stderr)
        sys.exit(1)

    for u in results:
        print(u.upper() if args.upper else u)
