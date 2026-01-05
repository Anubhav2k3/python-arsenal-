#!/usr/bin/env python3
import asyncio
import argparse
import socket
import sys

TIMEOUT = 0.5  # seconds
CONCURRENCY = 500  # increase for faster scans (careful)

async def scan_port(semaphore, target, port):
    async with semaphore:
        try:
            conn = asyncio.open_connection(target, port)
            reader, writer = await asyncio.wait_for(conn, timeout=TIMEOUT)
            writer.close()
            await writer.wait_closed()
            return port
        except:
            return None

async def scan(target, ports):
    semaphore = asyncio.Semaphore(CONCURRENCY)
    tasks = [scan_port(semaphore, target, p) for p in ports]
    results = await asyncio.gather(*tasks)
    return sorted(p for p in results if p)

def parse_ports(port_range):
    if "-" in port_range:
        start, end = map(int, port_range.split("-"))
        return range(start, end + 1)
    return [int(port_range)]

def main():
    parser = argparse.ArgumentParser(
        description="Fast Async Python Port Scanner"
    )
    parser.add_argument("target", help="Target IP or domain")
    parser.add_argument(
        "-p", "--ports", default="1-1024", help="Port range (e.g. 22 or 1-65535)"
    )
    args = parser.parse_args()

    try:
        socket.gethostbyname(args.target)
    except socket.error:
        print("Invalid target")
        sys.exit(1)

    ports = parse_ports(args.ports)

    print(f"[+] Scanning {args.target} ({len(list(ports))} ports)")
    open_ports = asyncio.run(scan(args.target, ports))

    if open_ports:
        print("\n[+] Open ports:")
        for p in open_ports:
            print(f"    {p}")
    else:
        print("\n[-] No open ports found")

if __name__ == "__main__":
    main()
