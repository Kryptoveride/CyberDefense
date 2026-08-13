import os
import re
import socket
import subprocess
import sys
import time

from . import formatting


SEVERITY_LEVELS = {"INFO": 0, "WARNING": 1, "ERROR": 2, "CRITICAL": 3}

ALERT_KEYWORDS = [
    "failed", "unauthorized", "malware", "injection", "blocked", "attack",
    "denied", "suspicious", "ransomware", "exfiltration", "compromise", "exploit",
]

SUPPORT_DIR = os.path.join(os.path.dirname(__file__), "support")
DEFAULT_LOG_FILE = os.path.join(SUPPORT_DIR, "sample_logs.txt")
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5555


def is_alert(severity, message, baseline="ERROR"):
    baseline_rank = SEVERITY_LEVELS.get(baseline, SEVERITY_LEVELS["ERROR"])
    severity_rank = SEVERITY_LEVELS.get(severity, 0)

    if severity_rank >= baseline_rank:
        return True

    message = message.lower()
    return any(word in message for word in ALERT_KEYWORDS)


def parse_mac_log(line):
    parts = line.split(maxsplit=7)
    if len(parts) < 8:
        return None
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", parts[0]):
        return None

    mac_type = parts[3]
    severity_map = {"Default": "INFO", "Info": "INFO", "Debug": "INFO", "Error": "ERROR", "Fault": "CRITICAL", "Activity": "INFO"}

    if mac_type not in severity_map:
        return None

    return f"{parts[0]} {parts[1]}", severity_map[mac_type], parts[7]


def scan_logs(logs, delay=0, baseline="ERROR"):
    pattern = r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(INFO|WARNING|ERROR|CRITICAL)\s+(.*)$"

    stats = {"total_events": 0, "total_alerts": 0, "critical_alerts": 0, "invalid_logs": 0}

    formatting.section("Security Log Monitor")
    rows = []

    for line in logs:
        if delay > 0:
            time.sleep(delay)

        line = line.strip()
        if not line:
            continue

        match = re.match(pattern, line)

        if match:
            timestamp, severity, message = match.groups()
        else:
            mac_result = parse_mac_log(line)
            if mac_result is None:
                stats["invalid_logs"] += 1
                rows.append(("Unknown", formatting.badge("INVALID", "danger"), "UNKNOWN", line))
                continue
            timestamp, severity, message = mac_result

        stats["total_events"] += 1

        if is_alert(severity, message, baseline):
            stats["total_alerts"] += 1
            status = formatting.badge("ALERT", "danger")
            if severity == "CRITICAL":
                stats["critical_alerts"] += 1
        else:
            status = formatting.badge("NORMAL", "success") if severity != "WARNING" else formatting.badge("NORMAL", "warning")

        rows.append((timestamp, status, severity, message))

    formatting.table(["TIME", "STATUS", "LEVEL", "MESSAGE"], rows)
    formatting.section_end()

    formatting.section("Summary")
    formatting.key_values([
        ("Events analyzed", stats["total_events"]),
        ("Normal events", stats["total_events"] - stats["total_alerts"]),
        ("Security alerts", stats["total_alerts"]),
        ("Critical alerts", stats["critical_alerts"]),
        ("Invalid logs", stats["invalid_logs"]),
    ])
    formatting.section_end()

    return stats


def scan_file(file_path, baseline="ERROR"):
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            formatting.message(f"Scanning log file: {file_path}", "info")
            return scan_logs(file, delay=0, baseline=baseline)
    except FileNotFoundError:
        formatting.message(f"File not found: {file_path}", "danger")
    except PermissionError:
        formatting.message(f"Permission denied: {file_path}", "danger")
    except OSError as error:
        formatting.message(f"Could not read file: {error}", "danger")
    return None


def socket_log_stream(sock):
    buffer = ""
    while True:
        data = sock.recv(2048)
        if not data:
            break
        buffer += data.decode(errors="ignore")
        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            yield line
    if buffer.strip():
        yield buffer


def run_live(host, port, baseline):
    formatting.message(f"Connecting to live log feed at {host}:{port} ...", "info")
    server_process = None

    try:
        sock = socket.create_connection((host, port), timeout=3)
    except (ConnectionRefusedError, socket.timeout, OSError):
        formatting.message(f"No live feed detected at {host}:{port}.", "warning")

        if formatting.ask_yes_no("Start the Sample log generator now", default_no=False):
            generator_path = os.path.join(SUPPORT_DIR, "log_generator.py")
            server_process = subprocess.Popen([sys.executable, generator_path, str(port), host])
            time.sleep(1)

            try:
                sock = socket.create_connection((host, port), timeout=3)
            except OSError as error:
                formatting.message(f"Still could not connect: {error}", "danger")
                return
        else:
            return

    try:
        scan_logs(socket_log_stream(sock), delay=0, baseline=baseline)
    finally:
        sock.close()
        if server_process is not None:
            server_process.terminate()


def parse_location(text):
    if ":" in text:
        host, _, port_str = text.rpartition(":")
        if port_str.isdigit():
            return "live", host, int(port_str)
    return "file", text, None


def run():
    formatting.page_title("LOG PARSER", "Parses security logs and flags alerts.")

    if formatting.ask_yes_no("Run the live demo log feed", default_no=False):
        run_live(DEFAULT_HOST, DEFAULT_PORT, "ERROR")
        return

    location = formatting.ask("Enter a file path, or a live address as host:port", DEFAULT_LOG_FILE)
    kind, value, port = parse_location(location)

    if kind == "live":
        run_live(value, port, "ERROR")
    else:
        scan_file(value, baseline="ERROR")
