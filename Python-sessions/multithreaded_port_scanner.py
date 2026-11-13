# Multithreaded Port Scanner

import socket
import time
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_port(target_ip, port, timeout=0.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))

            if result == 0:
                return port

    except (socket.error, OSError):
        pass

    return None


def scan_ports(target_ip, start_port=1, end_port=1024, max_workers=50):
    # scan range of ports
    print(f"\nTarget IP: {target_ip}")
    print(f"Port range: {start_port}-{end_port}")
    # print(f"Threads: {max_workers}")
    print("-" * 45)

    start_time = time.perf_counter()
    open_ports = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(scan_port, target_ip, port)
            for port in range(start_port, end_port + 1)
        ]

        for future in as_completed(futures):
            port = future.result()

            if port is not None:
                open_ports.append(port)
                print(f"[OPEN] Port {port}", flush=True)

    elapsed_time = time.perf_counter() - start_time

    print("\n" + "=" * 45)
    print("COMPLETED")
    print("=" * 45)
    print(f"Open ports: {sorted(open_ports)}")
    print(f"Total open ports: {len(open_ports)}")
    # print(f"Time taken: {elapsed_time:.2f} seconds")

    return sorted(open_ports)


def main():
    parser = argparse.ArgumentParser(
        description="Multithreaded TCP Port Scanner"
    )

    parser.add_argument(
        "--target", default="127.0.0.1",
        help="Target IPv4 address (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--start", type=int, default=1,
        help="Starting port"
    )
    parser.add_argument(
        "--end", type=int, default=1024,
        help="Ending port"
    )
    parser.add_argument(
        "--threads", type=int, default=50,
        help="Number of worker threads"
    )

    args = parser.parse_args()

    if not (1 <= args.start <= args.end <= 65535):
        parser.error("Ports must be between 1 and 65535.")

    if not (1 <= args.threads <= 50):
        parser.error("Threads must be between 1 and 50.")

    try:
        socket.inet_aton(args.target)
    except OSError:
        parser.error("Please provide a valid IPv4 address.")

    scan_ports(
        args.target,
        args.start,
        args.end,
        args.threads
    )


if __name__ == "__main__":
    main()
