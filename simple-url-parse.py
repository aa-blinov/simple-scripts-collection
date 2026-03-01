"""Parse, encode, and decode URLs and query strings."""

import sys
import argparse
from urllib.parse import (
    urlparse,
    urlencode,
    quote,
    unquote,
    parse_qs,
    urljoin,
)


def print_parsed(url: str) -> None:
    p = urlparse(url)
    fields = {
        "scheme": p.scheme,
        "host": p.hostname or "",
        "port": str(p.port) if p.port else "",
        "path": p.path,
        "query": p.query,
        "fragment": p.fragment,
        "username": p.username or "",
    }
    width = max(len(k) for k in fields)
    for k, v in fields.items():
        if v:
            print(f"  {k:<{width}}  {v}")

    params = parse_qs(p.query, keep_blank_values=True)
    if params:
        print(f"\n  {'params':<{width}}")
        for key, values in params.items():
            for val in values:
                print(f"  {'':>{width}}  {key} = {unquote(val)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse, encode, and decode URLs.")
    sub = parser.add_subparsers(dest="command")

    p_parse = sub.add_parser("parse", help="Break a URL into components")
    p_parse.add_argument("url")

    p_encode = sub.add_parser("encode", help="Percent-encode a string")
    p_encode.add_argument("text")
    p_encode.add_argument("--safe", default="", help="Characters to leave unencoded")

    p_decode = sub.add_parser("decode", help="Decode a percent-encoded string")
    p_decode.add_argument("text")

    p_build = sub.add_parser("build", help="Build query string from key=value pairs")
    p_build.add_argument("params", nargs="+", metavar="key=value")

    p_join = sub.add_parser("join", help="Resolve a relative URL against a base")
    p_join.add_argument("base")
    p_join.add_argument("relative")

    args = parser.parse_args()

    match args.command:
        case "parse":
            print_parsed(args.url)
        case "encode":
            print(quote(args.text, safe=args.safe))
        case "decode":
            print(unquote(args.text))
        case "build":
            pairs: list[tuple[str, str]] = []
            for item in args.params:
                k, sep, v = item.partition("=")
                if not sep:
                    print(
                        f"Invalid param (expected key=value): {item!r}", file=sys.stderr
                    )
                    sys.exit(1)
                pairs.append((k, v))
            print(urlencode(pairs))
        case "join":
            print(urljoin(args.base, args.relative))
        case _:
            parser.print_help()
