"""IPv4/IPv6 subnet calculator using the standard ipaddress module."""

import ipaddress
import argparse
import sys


def print_network(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> None:
    is_v4 = isinstance(net, ipaddress.IPv4Network)
    print(f"  {'Network':<16} {net}")
    print(f"  {'Address':<16} {net.network_address}")
    if is_v4:
        print(f"  {'Netmask':<16} {net.netmask}")
        print(f"  {'Wildcard':<16} {net.hostmask}")
        print(f"  {'Broadcast':<16} {net.broadcast_address}")
    print(f"  {'Prefix':<16} /{net.prefixlen}")
    num_hosts = net.num_addresses - (2 if is_v4 and net.prefixlen < 31 else 0)
    print(f"  {'Hosts':<16} {num_hosts:,}")
    if is_v4 and net.prefixlen <= 30:
        first = next(net.hosts())
        last = list(net.hosts())[-1]
        print(f"  {'First host':<16} {first}")
        print(f"  {'Last host':<16} {last}")
    print(f"  {'Version':<16} IPv{net.version}")
    if is_v4:
        print(f"  {'Private':<16} {net.is_private}")
        print(f"  {'Multicast':<16} {net.is_multicast}")


def cmd_info(target: str, strict: bool) -> None:
    try:
        net = ipaddress.ip_network(target, strict=strict)
        print_network(net)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_contains(network: str, address: str) -> None:
    try:
        net = ipaddress.ip_network(network, strict=False)
        addr = ipaddress.ip_address(address)
        result = addr in net
        print(
            f"  {address} {'∈' if result else '∉'} {network}  →  {'yes' if result else 'no'}"
        )
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_split(network: str, prefix: int) -> None:
    try:
        net = ipaddress.ip_network(network, strict=False)
        subnets = list(net.subnets(new_prefix=prefix))
        print(f"  {network} split into /{prefix}  →  {len(subnets)} subnet(s)\n")
        for i, sn in enumerate(subnets[:64]):
            print(f"  {i:<4} {sn}")
        if len(subnets) > 64:
            print(f"  ... and {len(subnets) - 64} more")
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_range(start: str, end: str) -> None:
    try:
        nets = list(
            ipaddress.summarize_address_range(
                ipaddress.ip_address(start), ipaddress.ip_address(end)
            )
        )
        print(f"  {start} – {end}  →  {len(nets)} network(s)\n")
        for net in nets:
            print(f"  {net}")
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IP/subnet calculator.")
    sub = parser.add_subparsers(dest="command")

    p_info = sub.add_parser("info", help="Show network details for a CIDR block")
    p_info.add_argument(
        "network", help="CIDR notation, e.g. 192.168.1.0/24 or 10.0.0.5/24"
    )
    p_info.add_argument(
        "--strict", action="store_true", help="Require host bits to be zero"
    )

    p_in = sub.add_parser("contains", help="Check if an IP belongs to a network")
    p_in.add_argument("network", help="CIDR block")
    p_in.add_argument("address", help="IP address to check")

    p_split = sub.add_parser("split", help="Split a network into smaller subnets")
    p_split.add_argument("network", help="CIDR block to split")
    p_split.add_argument("prefix", type=int, help="New prefix length")

    p_range = sub.add_parser("range", help="Summarize an IP range into CIDR blocks")
    p_range.add_argument("start", help="First IP address")
    p_range.add_argument("end", help="Last IP address")

    args = parser.parse_args()

    match args.command:
        case "info":
            cmd_info(args.network, args.strict)
        case "contains":
            cmd_contains(args.network, args.address)
        case "split":
            cmd_split(args.network, args.prefix)
        case "range":
            cmd_range(args.start, args.end)
        case _:
            parser.print_help()
