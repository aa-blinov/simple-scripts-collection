"""
Advanced port scanner for network discovery and service identification.
This script provides functionality to scan networks for open ports,
identify running services, and visualize network topology.
"""

import argparse
import ipaddress
import json
import logging
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field


@dataclass
class ScanResult:
    """Class for storing port scan results."""

    host: str
    port: int
    is_open: bool
    service: str = ""
    banner: str = ""
    response_time: float = 0.0
    protocol: str = "tcp"


@dataclass
class HostResult:
    """Class for storing host scan results."""

    ip: str
    hostname: str = ""
    is_up: bool = False
    mac_address: str = ""
    open_ports: list[ScanResult] = field(default_factory=list)
    os_guess: str = ""
    last_seen: float = 0.0


def setup_logging(log_file: str | None = None, verbose: bool = False) -> None:
    """Configure logging for the application.

    Args:
        log_file: Optional file to write logs to
        verbose: Whether to enable verbose logging
    """
    log_level = logging.DEBUG if verbose else logging.INFO
    log_format = "%(asctime)s - %(levelname)s - %(message)s"

    handlers = [logging.StreamHandler()]
    if log_file:
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(level=log_level, format=log_format, handlers=handlers)


def is_port_open(
    host: str,
    port: int,
    timeout: float = 1.0,
    protocol: str = "tcp",
    grab_banner: bool = True,
) -> ScanResult:
    """Check if a specific port is open on a host.

    Args:
        host: Target host IP or hostname
        port: Port number to check
        timeout: Connection timeout in seconds
        protocol: Protocol to use (tcp/udp)
        grab_banner: Whether to attempt banner grabbing

    Returns:
        ScanResult object with port status and details
    """
    result = ScanResult(host=host, port=port, is_open=False, protocol=protocol)

    try:
        start_time = time.time()

        if protocol.lower() == "tcp":
            socket_instance = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_instance.settimeout(timeout)

            # Attempt to connect
            conn_result = socket_instance.connect_ex((host, port))
            result.is_open = conn_result == 0

            # If port is open and we want to grab banner
            if result.is_open and grab_banner:
                try:
                    # Try common protocols based on port
                    if port in [21, 22, 25, 110, 143]:  # FTP, SSH, SMTP, POP3, IMAP
                        socket_instance.settimeout(2.0)
                        banner = (
                            socket_instance.recv(1024)
                            .decode("utf-8", errors="ignore")
                            .strip()
                        )
                        result.banner = banner
                    elif port == 80 or port == 443:  # HTTP/HTTPS
                        socket_instance.send(
                            b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n"
                        )
                        socket_instance.settimeout(2.0)
                        response = (
                            socket_instance.recv(1024)
                            .decode("utf-8", errors="ignore")
                            .strip()
                        )
                        if response:
                            # Extract first line for banner
                            result.banner = response.split("\n")[0]
                except Exception:
                    pass

        elif protocol.lower() == "udp":
            socket_instance = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            socket_instance.settimeout(timeout)

            # Send empty data to UDP port
            socket_instance.sendto(b"", (host, port))

            try:
                # Try to receive data
                data, _ = socket_instance.recvfrom(1024)
                result.is_open = True
                result.banner = data.decode("utf-8", errors="ignore").strip()
            except socket.timeout:
                # For UDP, timeout doesn't necessarily mean port is closed
                # but we can't confirm it's open either
                result.is_open = False

        # Calculate response time
        result.response_time = time.time() - start_time

        # Try to identify service
        try:
            service_name = socket.getservbyport(port, protocol.lower())
            result.service = service_name
        except (socket.error, OSError):
            # Use common port mappings for well-known services
            common_ports = {
                21: "ftp",
                22: "ssh",
                23: "telnet",
                25: "smtp",
                53: "domain",
                80: "http",
                110: "pop3",
                143: "imap",
                443: "https",
                3306: "mysql",
                3389: "rdp",
                5432: "postgresql",
                8080: "http-alt",
                8443: "https-alt",
            }
            result.service = common_ports.get(port, "")

        socket_instance.close()

    except (socket.error, socket.timeout, socket.gaierror) as exc:
        logging.debug(f"Error scanning {host}:{port}/{protocol}: {str(exc)}")
        result.is_open = False

    return result


def scan_host_ports(
    host: str,
    ports: list[int],
    timeout: float = 1.0,
    protocol: str = "tcp",
    grab_banner: bool = True,
    max_workers: int = 50,
) -> list[ScanResult]:
    """Scan multiple ports on a single host.

    Args:
        host: Target host IP or hostname
        ports: List of ports to scan
        timeout: Connection timeout in seconds
        protocol: Protocol to use (tcp/udp)
        grab_banner: Whether to attempt banner grabbing
        max_workers: Maximum number of concurrent workers

    Returns:
        List of ScanResult objects
    """
    results: list[ScanResult] = []

    # Resolve hostname to IP if possible
    try:
        ip = socket.gethostbyname(host)
        if ip != host:
            logging.info(f"Resolved {host} to {ip}")
    except socket.gaierror:
        logging.warning(f"Could not resolve hostname: {host}")
        return results

    # Use ThreadPoolExecutor for concurrent scanning
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all port scanning tasks
        future_to_port = {
            executor.submit(
                is_port_open, host, port, timeout, protocol, grab_banner
            ): port
            for port in ports
        }

        # Process results as they complete
        for future in future_to_port:
            try:
                result = future.result()
                if result.is_open:
                    results.append(result)
                    logging.info(
                        f"Port {result.port} is open on {host} "
                        f"({result.service if result.service else 'unknown service'})"
                    )
            except Exception as exc:
                port = future_to_port[future]
                logging.error(f"Error scanning port {port} on {host}: {str(exc)}")

    return results


def get_host_info(ip: str) -> HostResult:
    """Get detailed information about a host.

    Args:
        ip: Target IP address

    Returns:
        HostResult object with host details
    """
    host_result = HostResult(ip=ip)
    host_result.last_seen = time.time()

    # Check if host is up using ICMP ping (platform specific)
    try:
        if sys.platform.startswith("win"):
            # Windows ping
            import subprocess

            response = subprocess.call(
                ["ping", "-n", "1", "-w", "1000", ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            host_result.is_up = response == 0
        else:
            # Linux/Unix ping
            import subprocess

            response = subprocess.call(
                ["ping", "-c", "1", "-W", "1", ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            host_result.is_up = response == 0
    except Exception:
        # Fallback: try to connect to common port
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            s.connect((ip, 22))  # Try SSH port
            s.close()
            host_result.is_up = True
        except (socket.error, socket.timeout):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                s.connect((ip, 80))  # Try HTTP port
                s.close()
                host_result.is_up = True
            except (socket.error, socket.timeout):
                host_result.is_up = False

    # Try to get hostname
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        host_result.hostname = hostname
    except (socket.herror, socket.error):
        host_result.hostname = ""

    # Try to identify OS (simplified guess based on open ports)
    # For a more accurate OS detection, tools like Nmap would be needed

    return host_result


def scan_network(
    network: str,
    ports: list[int],
    timeout: float = 1.0,
    protocol: str = "tcp",
    grab_banner: bool = True,
    max_host_workers: int = 50,
    max_port_workers: int = 50,
) -> dict[str, HostResult]:
    """Scan an entire network range for hosts and open ports.

    Args:
        network: Network in CIDR notation (e.g., "192.168.1.0/24")
        ports: List of ports to scan
        timeout: Connection timeout in seconds
        protocol: Protocol to use (tcp/udp)
        grab_banner: Whether to attempt banner grabbing
        max_host_workers: Maximum concurrent hosts to scan
        max_port_workers: Maximum concurrent ports per host

    Returns:
        Dictionary mapping IP addresses to HostResult objects
    """
    try:
        network_obj = ipaddress.ip_network(network, strict=False)
    except ValueError as exc:
        logging.error(f"Invalid network format: {exc}")
        return {}

    hosts = list(map(str, network_obj.hosts()))
    total_hosts = len(hosts)

    if total_hosts == 0:
        logging.error(f"No hosts in network {network}")
        return {}

    logging.info(f"Scanning {total_hosts} hosts in {network}...")

    results: dict[str, HostResult] = {}
    host_count = 0
    active_hosts = 0

    # First pass: identify which hosts are up
    with ThreadPoolExecutor(max_workers=max_host_workers) as executor:
        future_to_host = {executor.submit(get_host_info, ip): ip for ip in hosts}

        for future in future_to_host:
            try:
                host_info = future.result()
                host_count += 1

                # Log progress
                if host_count % 10 == 0 or host_count == total_hosts:
                    logging.info(f"Progress: {host_count}/{total_hosts} hosts checked")

                if host_info.is_up:
                    active_hosts += 1
                    results[host_info.ip] = host_info
                    logging.info(
                        f"Host {host_info.ip} is up"
                        f"{' (' + host_info.hostname + ')' if host_info.hostname else ''}"
                    )
            except Exception as exc:
                ip = future_to_host[future]
                logging.error(f"Error checking host {ip}: {str(exc)}")

    logging.info(f"Found {active_hosts} active hosts")

    # Second pass: scan ports on active hosts
    active_ips = list(results.keys())

    with ThreadPoolExecutor(max_workers=max_host_workers) as host_executor:
        future_to_host_scan = {
            host_executor.submit(
                scan_host_ports,
                ip,
                ports,
                timeout,
                protocol,
                grab_banner,
                max_port_workers,
            ): ip
            for ip in active_ips
        }

        for future in future_to_host_scan:
            try:
                open_ports = future.result()
                ip = future_to_host_scan[future]
                results[ip].open_ports = open_ports

                if open_ports:
                    logging.info(f"Found {len(open_ports)} open ports on {ip}")

                # Basic OS fingerprinting based on open ports
                if 3389 in [p.port for p in open_ports if p.is_open]:
                    results[ip].os_guess = "Windows (RDP)"
                elif 22 in [p.port for p in open_ports if p.is_open]:
                    if 5900 in [p.port for p in open_ports if p.is_open]:
                        results[ip].os_guess = "Linux/Unix (SSH+VNC)"
                    else:
                        results[ip].os_guess = "Linux/Unix (SSH)"
                elif any(
                    p.port in [80, 443, 8080, 8443] for p in open_ports if p.is_open
                ):
                    results[ip].os_guess = "Web Server"

            except Exception as exc:
                ip = future_to_host_scan[future]
                logging.error(f"Error scanning ports on {ip}: {str(exc)}")

    return results


def export_results(
    results: dict[str, HostResult], output_file: str, format_type: str = "json"
) -> None:
    """Export scan results to a file.

    Args:
        results: Scan results to export
        output_file: Output file path
        format_type: Output format (json, csv)
    """
    if format_type.lower() == "json":
        # Convert results to serializable format
        serializable_results = {}

        for ip, host_result in results.items():
            serializable_host = {
                "ip": host_result.ip,
                "hostname": host_result.hostname,
                "is_up": host_result.is_up,
                "mac_address": host_result.mac_address,
                "os_guess": host_result.os_guess,
                "last_seen": host_result.last_seen,
                "open_ports": [],
            }

            for port_result in host_result.open_ports:
                serializable_host["open_ports"].append(
                    {
                        "port": port_result.port,
                        "is_open": port_result.is_open,
                        "service": port_result.service,
                        "banner": port_result.banner,
                        "response_time": port_result.response_time,
                        "protocol": port_result.protocol,
                    }
                )

            serializable_results[ip] = serializable_host

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(serializable_results, f, indent=2)

    elif format_type.lower() == "csv":
        with open(output_file, "w", encoding="utf-8") as f:
            # Write header
            f.write("IP,Hostname,Status,OS Guess,Port,Protocol,Service,Banner\n")

            # Write data
            for ip, host_result in results.items():
                base_row = f'"{ip}","{host_result.hostname}","{host_result.is_up}","{host_result.os_guess}"'

                if not host_result.open_ports:
                    f.write(f"{base_row},,,,\n")
                else:
                    for port_result in host_result.open_ports:
                        # Escape quotes in banner
                        banner = port_result.banner.replace('"', '""')
                        f.write(
                            f"{base_row},{port_result.port},{port_result.protocol},"
                            f'"{port_result.service}","{banner}"\n'
                        )

    logging.info(f"Results exported to {output_file}")


def parse_port_range(port_spec: str) -> list[int]:
    """Parse port specification into a list of port numbers.

    Args:
        port_spec: Port specification (e.g., "80,443,8000-8100")

    Returns:
        List of port numbers
    """
    ports = []

    # Handle comma-separated parts
    parts = port_spec.split(",")
    for part in parts:
        part = part.strip()

        # Handle ranges (e.g., "1000-2000")
        if "-" in part:
            try:
                start, end = map(int, part.split("-"))
                if start > end:
                    start, end = end, start
                ports.extend(range(start, end + 1))
            except ValueError:
                logging.warning(f"Invalid port range: {part}")
        else:
            # Handle single port
            try:
                ports.append(int(part))
            except ValueError:
                logging.warning(f"Invalid port: {part}")

    # Remove duplicates and sort
    return sorted(list(set(ports)))


def generate_common_ports(count: int = 100) -> list[int]:
    """Generate a list of common ports to scan.

    Args:
        count: Number of common ports to include

    Returns:
        List of common port numbers
    """
    # Most common ports for services
    common_ports = [
        # Standard services
        20,
        21,  # FTP
        22,  # SSH
        23,  # Telnet
        25,
        587,  # SMTP
        53,  # DNS
        80,
        443,  # HTTP(S)
        110,  # POP3
        123,  # NTP
        143,
        993,  # IMAP
        161,
        162,  # SNMP
        194,  # IRC
        389,
        636,  # LDAP
        # Database ports
        1433,  # MS SQL
        1521,  # Oracle
        3306,  # MySQL
        5432,  # PostgreSQL
        6379,  # Redis
        27017,  # MongoDB
        # Remote management
        135,
        139,  # NetBIOS
        445,  # SMB
        3389,  # RDP
        5900,  # VNC
        # Web applications
        8000,
        8008,
        8080,
        8443,  # Alternative HTTP/HTTPS
        8888,
        9000,
        9090,
        # Miscellaneous
        514,  # Syslog
        873,  # rsync
        3000,  # Development servers (Node, React, etc.)
        5000,
        5001,  # Development servers (Flask, etc.)
        6000,  # X11
        6666,
        6667,  # IRC
        8081,
        8082,
        8083,
        8084,
        8085,
        8086,
        8087,
        8088,
        8089,  # HTTP alternatives
        9100,  # Printer
        9200,
        9300,  # Elasticsearch
        # Common higher ports
        10000,  # Webmin
        32400,  # Plex
    ]

    # Ensure we only return up to count ports
    return sorted(common_ports[: min(count, len(common_ports))])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Advanced Port Scanner for network discovery"
    )

    # Target specification
    target_group = parser.add_argument_group("Target Specification")
    target_group.add_argument(
        "-t", "--target", help="Target host(s) to scan (IP, hostname, or CIDR notation)"
    )
    target_group.add_argument(
        "--host-list", help="File containing hosts to scan (one per line)"
    )

    # Port specification
    port_group = parser.add_argument_group("Port Specification")
    port_group.add_argument(
        "-p", "--ports", help="Port(s) to scan (e.g., '80,443,8000-8100')"
    )
    port_group.add_argument("--top-ports", type=int, help="Scan N most common ports")
    port_group.add_argument(
        "--protocol",
        choices=["tcp", "udp", "both"],
        default="tcp",
        help="Protocol to scan (default: tcp)",
    )

    # Scan options
    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0)",
    )
    scan_group.add_argument(
        "--max-host-workers",
        type=int,
        default=50,
        help="Maximum concurrent hosts to scan (default: 50)",
    )
    scan_group.add_argument(
        "--max-port-workers",
        type=int,
        default=50,
        help="Maximum concurrent ports per host (default: 50)",
    )
    scan_group.add_argument(
        "--no-banner",
        action="store_false",
        dest="grab_banner",
        help="Disable banner grabbing",
    )

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument("-o", "--output", help="Output file for scan results")
    output_group.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        help="Output format (default: json)",
    )
    output_group.add_argument("--log", help="Log file to write to")
    output_group.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.log, args.verbose)

    # Validate arguments
    if not args.target and not args.host_list:
        parser.error("No target specified. Use -t/--target or --host-list")

    # Parse ports
    ports = []
    if args.ports:
        ports = parse_port_range(args.ports)
    elif args.top_ports:
        ports = generate_common_ports(args.top_ports)
    else:
        # Default to top 1000 ports
        ports = generate_common_ports(1000)

    if not ports:
        parser.error("No valid ports specified")

    logging.info(f"Starting port scanner with {len(ports)} ports")

    # Parse targets
    targets = []

    if args.target:
        # Handle CIDR notation
        if "/" in args.target:
            # It's a network in CIDR notation
            try:
                network = ipaddress.ip_network(args.target, strict=False)
                targets.append(args.target)
            except ValueError as exc:
                parser.error(f"Invalid network format: {exc}")
        else:
            # It's a single host
            targets.append(args.target)

    if args.host_list:
        try:
            with open(args.host_list, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
        except Exception as exc:
            parser.error(f"Error reading host list file: {exc}")

    if not targets:
        parser.error("No valid targets specified")

    # Start scanning
    all_results = {}

    for target in targets:
        try:
            if "/" in target:
                # Network scan
                logging.info(f"Scanning network {target}...")
                network_results = scan_network(
                    target,
                    ports,
                    timeout=args.timeout,
                    protocol=args.protocol,
                    grab_banner=args.grab_banner,
                    max_host_workers=args.max_host_workers,
                    max_port_workers=args.max_port_workers,
                )
                all_results.update(network_results)
            else:
                # Single host scan
                logging.info(f"Scanning host {target}...")
                host_info = get_host_info(target)

                if host_info.is_up:
                    open_ports = scan_host_ports(
                        target,
                        ports,
                        timeout=args.timeout,
                        protocol=args.protocol,
                        grab_banner=args.grab_banner,
                        max_workers=args.max_port_workers,
                    )
                    host_info.open_ports = open_ports
                    all_results[target] = host_info
                else:
                    logging.warning(f"Host {target} appears to be down")
        except Exception as exc:
            logging.error(f"Error scanning {target}: {exc}")

    # Print summary
    total_hosts = len(all_results)
    hosts_with_open_ports = sum(1 for host in all_results.values() if host.open_ports)
    total_open_ports = sum(len(host.open_ports) for host in all_results.values())

    logging.info(
        f"Scan completed: {total_hosts} hosts up, {hosts_with_open_ports} with open ports, {total_open_ports} open ports total"
    )

    # Export results if requested
    if args.output:
        export_results(all_results, args.output, args.format)
        logging.info(f"Results exported to {args.output}")

    # Print open ports on hosts
    for ip, host_info in all_results.items():
        if host_info.open_ports:
            print(
                f"\nHost: {ip} {f'({host_info.hostname})' if host_info.hostname else ''}"
            )
            print(f"OS: {host_info.os_guess if host_info.os_guess else 'Unknown'}")
            print("Open ports:")
            for port_info in host_info.open_ports:
                service_info = (
                    f"{port_info.service}" if port_info.service else "unknown"
                )
                banner_info = f": {port_info.banner}" if port_info.banner else ""
                print(
                    f"  {port_info.port}/{port_info.protocol} - {service_info}{banner_info}"
                )
