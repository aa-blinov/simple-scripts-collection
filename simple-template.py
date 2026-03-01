"""Fill a template file with values from arguments, environment, or a .env file."""

import sys
import re
import argparse
from pathlib import Path
from string import Template


def load_env_file(path: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if sep:
            values[key.strip()] = value.strip().strip("\"'")
    return values


def parse_vars(pairs: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for pair in pairs:
        key, sep, val = pair.partition("=")
        if not sep:
            print(f"Invalid var (expected key=value): {pair!r}", file=sys.stderr)
            sys.exit(1)
        result[key.strip()] = val
    return result


def list_placeholders(template_str: str) -> list[str]:
    return sorted(
        {
            m.group(1) or m.group(2)
            for m in re.finditer(r"\$\{(\w+)\}|\$(\w+)", template_str)
        }
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Fill $placeholders in a template from key=value args or a .env file.",
        epilog="Example: python simple-template.py config.tmpl -v HOST=prod PORT=5432 -o config.ini",
    )
    parser.add_argument("template", help="Template file (use - for stdin)")
    parser.add_argument(
        "-v", "--var", nargs="+", metavar="KEY=VALUE", help="Variables to substitute"
    )
    parser.add_argument("-e", "--env-file", help=".env file to load variables from")
    parser.add_argument("-o", "--output", help="Output file (stdout if omitted)")
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all placeholders in the template and exit",
    )
    parser.add_argument(
        "--safe",
        action="store_true",
        help="Leave missing variables as-is instead of erroring",
    )
    args = parser.parse_args()

    if args.template == "-":
        raw = sys.stdin.read()
    else:
        raw = Path(args.template).read_text(encoding="utf-8")

    if args.list:
        for p in list_placeholders(raw):
            print(f"  ${p}")
        sys.exit(0)

    values: dict[str, str] = {}
    if args.env_file:
        values.update(load_env_file(args.env_file))
    if args.var:
        values.update(parse_vars(args.var))

    tmpl = Template(raw)
    try:
        result = tmpl.safe_substitute(values) if args.safe else tmpl.substitute(values)
    except KeyError as e:
        print(
            f"Missing variable: {e}. Use --safe to skip missing vars.", file=sys.stderr
        )
        sys.exit(1)

    if args.output:
        Path(args.output).write_text(result, encoding="utf-8")
        print(f"Written to {args.output}")
    else:
        print(result, end="")
