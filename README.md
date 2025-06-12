# Penetration-testing-toolkit
import socket
import argparse
import threading
import requests
from queue import Queue
import textwrap

# ------------------ Port Scanner ------------------
def scan_port(target, port):
    """Scan a single TCP port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((target, port))
            if result == 0:
                print(f"[+] Port {port} is open on {target}")
    except Exception:
        pass

def port_scanner(target, start_port, end_port):
    """Scan a range of ports using threads."""
    print(f"\n[+] Scanning ports {start_port}-{end_port} on {target}")
    threads = []
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(target, port))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    print("[+] Port scan completed.\n")

# ------------------ Brute-Force Module ------------------
def brute_force_login(url, username_field, password_field, username, password_file):
    """Attempt brute-force on a login form."""
    print(f"\n[+] Starting brute-force attack on {url}")
    try:
        with open(password_file, 'r') as f:
            for line in f:
                password = line.strip()
                data = {username_field: username, password_field: password}
                try:
                    res = requests.post(url, data=data, timeout=5)
                    if "invalid" not in res.text.lower() and res.status_code == 200:
                        print(f"[!] Successful login: {username}:{password}")
                        return
                    else:
                        print(f"[-] Failed login: {username}:{password}")
                except requests.RequestException:
                    print("[-] Connection error. Skipping...")
    except FileNotFoundError:
        print("[-] Password file not found.")
    print("[+] Brute-force completed.\n")

# ------------------ Documentation ------------------
def show_help():
    banner = """
    =========================================
     PENETRATION TESTING TOOLKIT - PYTHON
     Modules: Port Scanner | Brute-Forcer
     Author: ChatGPT Security Lab
    =========================================
    """
    usage = """
    USAGE:
        python pentest_toolkit.py portscan <target> [--start <start>] [--end <end>]
        python pentest_toolkit.py bruteforce <url> <username> <password_file>
                                      [--user-field <field>] [--pass-field <field>]

    MODULES:

    [1] Port Scanner:
        Scan open TCP ports on a target host.
        Example:
            python pentest_toolkit.py portscan 192.168.1.1 --start 20 --end 80

    [2] Brute-Forcer:
        Basic dictionary-based login brute-force.
        Example:
            python pentest_toolkit.py bruteforce http://example.com/login admin passwords.txt \\
                --user-field=username --pass-field=password

    NOTES:
        - Use only on systems you are authorized to test.
        - Brute-force requires a password file (one password per line).

    """
    print(banner)
    print(textwrap.dedent(usage))

# ------------------ Main Parser ------------------
def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("command", nargs='?', help="Command to run: portscan | bruteforce | --help")
    parser.add_argument("arg1", nargs='?', help="Target IP or URL")
    parser.add_argument("arg2", nargs='?', help="Username or start port")
    parser.add_argument("arg3", nargs='?', help="Password file or end port")
    parser.add_argument("--start", type=int, help="Start port")
    parser.add_argument("--end", type=int, help="End port")
    parser.add_argument("--user-field", default="username", help="Form field name for username")
    parser.add_argument("--pass-field", default="password", help="Form field name for password")

    args = parser.parse_args()

    if args.command in ("-h", "--help", None):
        show_help()
    elif args.command == "portscan" and args.arg1:
        target = args.arg1
        start_port = args.start if args.start else (int(args.arg2) if args.arg2 else 1)
        end_port = args.end if args.end else (int(args.arg3) if args.arg3 else 1024)
        port_scanner(target, start_port, end_port)
    elif args.command == "bruteforce" and args.arg1 and args.arg2 and args.arg3:
        brute_force_login(args.arg1, args.user_field, args.pass_field, args.arg2, args.arg3)
    else:
        print("[-] Invalid command or missing arguments. Use --help to see usage.")

if __name__ == "__main__":
    main()
