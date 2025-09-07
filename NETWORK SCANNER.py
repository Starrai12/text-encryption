# vuln_scanner/main.py
import sys
from scanner import PortScanner

def main():
    if len(sys.argv) != 4:
        print("Usage: python main.py <target> <port_num> <vul_file>")
        print("Example: python main.py 192.168.1.1 100 vulnerabilities.txt")
        sys.exit(1)

    target = sys.argv[1]
    try:
        port_num = int(sys.argv[2])
    except ValueError:
        print("Port number must be an integer.")
        sys.exit(1)
    vul_file = sys.argv[3]

    print(f"\nScanning {target} for open ports up to {port_num}...\n")

    scanner = PortScanner(target, port_num)
    scanner.scan()

    if not scanner.open_ports:
        print("No open ports found.")
        return

    print("Open ports and banners:")
    for i, port in enumerate(scanner.open_ports):
        print(f"Port {port}: {scanner.banners[i]}")

    print("\nChecking for vulnerabilities...\n")

    try:
        with open(vul_file, 'r') as file:
            vulnerable_banners = [line.strip() for line in file.readlines() if line.strip()]
    except FileNotFoundError:
        print(f"Vulnerability file '{vul_file}' not found.")
        return

    vulnerabilities_found = False
    for i, banner in enumerate(scanner.banners):
        for vul in vulnerable_banners:
            if vul.lower() in banner.lower():
                print(f"[!!] Potential vulnerability: '{vul}' matches banner '{banner}' on port {scanner.open_ports[i]}")
                vulnerabilities_found = True

    if not vulnerabilities_found:
        print("No known vulnerabilities found in banners.")

if _name_ == "_main_":
    main()