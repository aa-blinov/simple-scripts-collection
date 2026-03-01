"""Format, validate, and XPath-query XML documents."""

import sys
import argparse
import xml.etree.ElementTree as ET
from xml.dom import minidom


def pretty(raw: str, indent: int) -> str:
    dom = minidom.parseString(raw)
    lines = dom.toprettyxml(indent=" " * indent).splitlines()
    if lines and lines[0].startswith("<?xml"):
        lines = lines[1:]
    return "\n".join(line for line in lines if line.strip())


def cmd_format(path: str, indent: int, in_place: bool) -> None:
    tree = ET.parse(path)
    raw = ET.tostring(tree.getroot(), encoding="unicode", xml_declaration=False)
    output = pretty(raw, indent)
    if in_place:
        with open(path, "w", encoding="utf-8") as f:
            f.write(output + "\n")
        print(f"Formatted: {path}")
    else:
        print(output)


def cmd_validate(path: str) -> None:
    try:
        ET.parse(path)
        print(f"Valid: {path}")
    except ET.ParseError as e:
        print(f"Invalid XML: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_xpath(path: str, expr: str) -> None:
    tree = ET.parse(path)
    matches = tree.getroot().findall(expr)
    if not matches:
        print("(no matches)")
        return
    for el in matches:
        raw = ET.tostring(el, encoding="unicode")
        print(pretty(raw, 2))
        print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Format, validate, and query XML.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_f = sub.add_parser("format", help="Pretty-print an XML file")
    p_f.add_argument("file")
    p_f.add_argument("--indent", type=int, default=2, help="Indent size (default: 2)")
    p_f.add_argument(
        "--in-place", action="store_true", help="Overwrite the source file"
    )

    p_v = sub.add_parser("validate", help="Check that an XML file is well-formed")
    p_v.add_argument("file")

    p_x = sub.add_parser("xpath", help="Find elements with an XPath expression")
    p_x.add_argument("file")
    p_x.add_argument("expr", help="XPath expression (ElementTree subset)")

    args = parser.parse_args()
    if args.cmd == "format":
        cmd_format(args.file, args.indent, args.in_place)
    elif args.cmd == "validate":
        cmd_validate(args.file)
    elif args.cmd == "xpath":
        cmd_xpath(args.file, args.expr)
