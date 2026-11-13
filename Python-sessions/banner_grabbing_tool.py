# Banner Grabbing Tool

import socket
import re
import argparse
import time

def identify_service(port, banner):
    """Identify service type and disclosed version."""
    text = banner.strip()
    upper = text.upper()

    if upper.startswith("SSH-"):
        service = "SSH"
        match = re.search(r"SSH-\d+\.\d+-([^\s]+)", text)
        version = match.group(1) if match else "Unknown"

    elif upper.startswith("HTTP/"):
        service = "HTTP"
        match = re.search(r"^Server:\s*(.+)$", text, re.I | re.M)
        version = match.group(1).strip() if match else "Not disclosed"

    elif port == 21 or "FTP" in upper:
        service = "FTP"
        version = text.splitlines()[0] if text else "Unknown"

    elif port == 25 or "SMTP" in upper:
        service = "SMTP"
        version = text.splitlines()[0] if text else "Unknown"

    else:
        service = "Unknown"
        version = "Not disclosed"

    return service, version

def grab_banner(target_ip, port, timeout=3):
    """Connect to a TCP port and collect a service banner."""
    try:
        with socket.create_connection(
            (target_ip, port), timeout=timeout
        ) as sock:

            sock.settimeout(timeout)

            # HTTP servers usually require an initial request.
            if port in (80, 8080, 3000):
                request = (
                    "HEAD / HTTP/1.1\r\n"
                    f"Host: {target_ip}\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                )
                sock.sendall(request.encode("utf-8"))

            # SSH and FTP usually send banners automatically.
            response = sock.recv(1024)

            if not response:
                return None

            banner = response.decode(
                "utf-8", errors="ignore"
            ).strip()

            if not banner:
                return None

            return banner

    except socket.timeout:
        return None

    except (ConnectionRefusedError, OSError):
        return None


def scan_services(target_ip, ports):
    """Read and display banners from specified TCP ports."""
    print("\n" + "=" * 50)
    print("TCP BANNER GRABBER")
    print("=" * 50)
    print(f"Target: {target_ip}")
    print(f"Ports: {ports}")
    print("-" * 50)

    start_time = time.perf_counter()

    for port in ports:
        print(f"\n[SCANNING] Port {port}")

        banner = grab_banner(target_ip, port)

        if banner:
            service, version = identify_service(port, banner)

            first_line = banner.splitlines()[0]

            print("[RESULT DETECTED]")
            print(f"Port: {port}")
            print(f"Service: {service}")
            print(f"Version: {version}")
            print(f"Banner: {first_line}")

        else:
            print(f"[NO BANNER] Port {port}")

    elapsed = time.perf_counter() - start_time

    print("\n" + "=" * 50)
    print(f"Scan completed in {elapsed:.2f} seconds")
    print("=" * 50)


def main():
    parser = argparse.ArgumentParser(
        description="Python TCP Banner Grabber"
    )

    parser.add_argument(
        "--target",
        default="127.0.0.1",
        help="Target IPv4 address"
    )

    parser.add_argument(
        "--ports",
        type=int,
        nargs="+",
        default=[21, 22, 25, 80, 3000],
        help="TCP ports to inspect"
    )

    args = parser.parse_args()

    if any(port < 1 or port > 65535 for port in args.ports):
        parser.error("Port numbers must be between 1 and 65535.")

    scan_services(args.target, args.ports)

if __name__ == "__main__":
    main()
