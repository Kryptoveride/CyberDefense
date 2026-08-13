import socket
import time

from . import formatting


COMMON_PORTS = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
}


def resolve_host(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        formatting.message("Unable to resolve the hostname or IP address.", "danger")
        return None


def check_port(ip_address, port, timeout=2):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            return connection.connect_ex((ip_address, port)) == 0
    except OSError:
        return False


def run_repeated_check(ip_address, port, attempts=5):
    rows = []
    successes = 0

    for attempt in range(1, attempts + 1):
        ok = check_port(ip_address, port)
        successes += int(ok)
        status = formatting.badge("OPEN", "success") if ok else formatting.badge("CLOSED", "danger")
        rows.append((attempt, status, f"Port {port} {'accepted' if ok else 'rejected or timed out'}"))
        time.sleep(0.2)

    return rows, successes


def http_check():
    formatting.page_title("HTTP CONNECTION CHECK", "Checks whether a host accepts connections on port 80.")

    hostname = formatting.ask("Enter hostname or IP address")

    if not hostname:
        formatting.message("A hostname or IP address is required.", "danger")
        return

    ip_address = resolve_host(hostname)
    if ip_address is None:
        return

    formatting.section("Target Information")
    formatting.key_values([("Hostname", hostname), ("Resolved IP", ip_address), ("Port", 80), ("Service", "HTTP")])
    formatting.section_end()

    formatting.section("Connection Results")
    rows, successes = run_repeated_check(ip_address, 80)
    formatting.table(["ATTEMPT", "STATUS", "DESCRIPTION"], rows)
    formatting.section_end()

    attempts = len(rows)
    if successes == attempts:
        final_status = formatting.badge("AVAILABLE", "success")
    elif successes > 0:
        final_status = formatting.badge("INTERMITTENT", "warning")
    else:
        final_status = formatting.badge("UNAVAILABLE", "danger")

    formatting.section("Scan Summary")
    formatting.key_values([("Successful connections", f"{successes}/{attempts}"), ("HTTP service status", final_status)])
    formatting.section_end()


def single_port_scan():
    formatting.page_title("SINGLE PORT SCANNER", "Scans one TCP port on a target host.")

    hostname = formatting.ask("Enter hostname or IP address")
    if not hostname:
        formatting.message("A hostname or IP address is required.", "danger")
        return

    try:
        port = int(formatting.ask("Enter port number"))
    except ValueError:
        formatting.message("Port must be a number.", "danger")
        return

    if port < 1 or port > 65535:
        formatting.message("Port must be between 1 and 65535.", "danger")
        return

    ip_address = resolve_host(hostname)
    if ip_address is None:
        return

    try:
        service_name = socket.getservbyport(port, "tcp")
    except OSError:
        service_name = "Unknown"

    formatting.section("Target Information")
    formatting.key_values([("Hostname", hostname), ("Resolved IP", ip_address), ("Port", port), ("Service", service_name)])
    formatting.section_end()

    formatting.section("Connection Results")
    rows, successes = run_repeated_check(ip_address, port)
    formatting.table(["ATTEMPT", "STATUS", "DESCRIPTION"], rows)
    formatting.section_end()

    attempts = len(rows)
    if successes == attempts:
        final_status = formatting.badge("OPEN", "success")
    elif successes > 0:
        final_status = formatting.badge("INTERMITTENT", "warning")
    else:
        final_status = formatting.badge("CLOSED OR FILTERED", "danger")

    formatting.section("Scan Summary")
    formatting.key_values([("Successful connections", f"{successes}/{attempts}"), ("Final port status", final_status)])
    formatting.section_end()


def top_port_scan():
    formatting.page_title("TOP 10 PORT SCANNER", "Scans the 10 most common TCP ports.")

    hostname = formatting.ask("Enter hostname or IP address")
    if not hostname:
        formatting.message("A hostname or IP address is required.", "danger")
        return

    ip_address = resolve_host(hostname)
    if ip_address is None:
        return

    formatting.section("Target Information")
    formatting.key_values([("Hostname", hostname), ("Resolved IP", ip_address), ("Ports scanned", len(COMMON_PORTS))])
    formatting.section_end()

    formatting.section("Scan Results")
    open_ports = []
    rows = []

    for port, service in COMMON_PORTS.items():
        ok = check_port(ip_address, port, timeout=1.5)
        if ok:
            open_ports.append(port)
        rows.append((port, service, formatting.badge("OPEN", "success") if ok else formatting.badge("CLOSED/FILTERED", "danger")))

    formatting.table(["PORT", "SERVICE", "STATUS"], rows)
    formatting.section_end()

    formatting.section("Scan Summary")
    formatting.key_values([
        ("Total ports scanned", len(COMMON_PORTS)),
        ("Open ports found", len(open_ports)),
        ("Open port numbers", ", ".join(str(p) for p in open_ports) or "None"),
    ])
    formatting.section_end()


def run():
    formatting.page_title("PORT & HOST SCANNER", "HTTP checks, single-port scans, and top-10 port scans in one place.")

    print()
    formatting.menu([
        ("HTTP Check (port 80)", "Verify a host accepts HTTP connections"),
        ("Single Port Scan", "Check one specific TCP port"),
        ("Top 10 Port Scan", "Check the 10 most common TCP ports"),
    ])

    choice = formatting.ask("Select a mode", "1")

    if choice == "2":
        single_port_scan()
    elif choice == "3":
        top_port_scan()
    else:
        http_check()
