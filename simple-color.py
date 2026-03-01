"""Convert colors between HEX, RGB, and HSL with terminal preview."""

import re
import sys
import argparse


def hex_to_rgb(h: str) -> tuple[int, int, int]:
    h = h.lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def rgb_to_hex(r: int, g: int, b: int) -> str:
    return f"#{r:02X}{g:02X}{b:02X}"


def rgb_to_hsl(r: int, g: int, b: int) -> tuple[float, float, float]:
    rf, gf, bf = r / 255, g / 255, b / 255
    cmax, cmin = max(rf, gf, bf), min(rf, gf, bf)
    delta = cmax - cmin
    lum = (cmax + cmin) / 2
    s = 0.0 if delta == 0 else delta / (1 - abs(2 * lum - 1))
    if delta == 0:
        h = 0.0
    elif cmax == rf:
        h = 60 * (((gf - bf) / delta) % 6)
    elif cmax == gf:
        h = 60 * (((bf - rf) / delta) + 2)
    else:
        h = 60 * (((rf - gf) / delta) + 4)
    return round(h, 1), round(s * 100, 1), round(lum * 100, 1)


def hsl_to_rgb(h: float, s: float, lum: float) -> tuple[int, int, int]:
    s /= 100
    lum /= 100
    c = (1 - abs(2 * lum - 1)) * s
    x = c * (1 - abs((h / 60) % 2 - 1))
    m = lum - c / 2
    if h < 60:
        rf, gf, bf = c, x, 0.0
    elif h < 120:
        rf, gf, bf = x, c, 0.0
    elif h < 180:
        rf, gf, bf = 0.0, c, x
    elif h < 240:
        rf, gf, bf = 0.0, x, c
    elif h < 300:
        rf, gf, bf = x, 0.0, c
    else:
        rf, gf, bf = c, 0.0, x
    return round((rf + m) * 255), round((gf + m) * 255), round((bf + m) * 255)


def ansi_preview(r: int, g: int, b: int) -> str:
    fg = "\033[38;2;{};{};{}m".format(r, g, b)
    bg = "\033[48;2;{};{};{}m".format(r, g, b)
    reset = "\033[0m"
    text_color = "\033[37m" if (r * 0.299 + g * 0.587 + b * 0.114) < 128 else "\033[30m"
    return f"{bg}{text_color}  ████  {reset}  {fg}███{reset}"


def parse_color(value: str) -> tuple[int, int, int]:
    value = value.strip()
    if value.startswith("#") or re.fullmatch(r"[0-9a-fA-F]{3,6}", value):
        return hex_to_rgb(value)
    m = re.fullmatch(r"rgb\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)", value, re.I)
    if m:
        return int(m.group(1)), int(m.group(2)), int(m.group(3))
    m = re.fullmatch(
        r"hsl\(\s*([\d.]+)\s*,\s*([\d.]+)%?\s*,\s*([\d.]+)%?\s*\)", value, re.I
    )
    if m:
        return hsl_to_rgb(
            float(m.group(1)), float(m.group(2)), float(m.group(3))
        )  # h, s, lum
    # bare "r g b" or "r,g,b"
    parts = re.split(r"[\s,]+", value)
    if len(parts) == 3:
        return int(parts[0]), int(parts[1]), int(parts[2])
    raise ValueError(f"Unrecognized color format: {value!r}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Convert colors between HEX, RGB, and HSL.",
        epilog="Examples: '#ff6600'  'rgb(255,102,0)'  'hsl(24,100,50)'  'ff6600'",
    )
    parser.add_argument("color", help="Color value in any supported format")
    parser.add_argument(
        "--no-preview", action="store_true", help="Skip terminal color preview"
    )
    args = parser.parse_args()

    try:
        r, g, b = parse_color(args.color)
    except ValueError as e:
        print(e, file=sys.stderr)
        sys.exit(1)

    for v in (r, g, b):
        if not 0 <= v <= 255:
            print(f"RGB values must be 0–255, got {r},{g},{b}", file=sys.stderr)
            sys.exit(1)

    h, s, lum = rgb_to_hsl(r, g, b)
    print(f"  HEX   {rgb_to_hex(r, g, b)}")
    print(f"  RGB   rgb({r}, {g}, {b})")
    print(f"  HSL   hsl({h}, {s}%, {lum}%)")
    if not args.no_preview:
        print(f"\n  {ansi_preview(r, g, b)}")
