import os
import subprocess
import sys

from . import formatting


UNSAFE_PATHS_MAC = ["/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/Users/Shared/", "/Users/Guest/", "/Library/Caches/"]
UNSAFE_PATH_WIN = ["\\Windows\\Temp\\", "\\AppData\\Local\\Temp\\", "\\AppData\\Roaming\\", "\\Users\\Public\\", "\\ProgramData\\", "\\Temp\\"]


def get_running_process_mac():
    cmd = ["ps", "-eo", "user,pid,ppid,command"]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    processes = []
    for line in result.stdout.strip().split("\n")[1:]:
        parts = line.split(maxsplit=3)
        if len(parts) == 4:
            processes.append({"user": parts[0], "pid": parts[1], "ppid": parts[2], "path": parts[3]})
    return processes


def get_running_process_windows():
    cmd = ["tasklist", "/FO", "CSV", "/NH"]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    processes = []
    for line in result.stdout.strip().split("\n"):
        line = line.replace('"', "")
        parts = line.split(",")
        if len(parts) >= 2:
            processes.append({"user": "Unknown", "pid": parts[1], "ppid": "Unknown", "path": parts[0]})
    return processes


def kill_process(pid, is_windows):
    try:
        if is_windows:
            subprocess.run(["taskkill", "/PID", str(pid), "/F"], check=True)
        else:
            os.kill(int(pid), 15)
        formatting.message(f"Process {pid} terminated successfully.", "success")
    except PermissionError:
        formatting.message("Permission denied. Run with administrator privileges.", "danger")
    except ProcessLookupError:
        formatting.message(f"Process {pid} no longer exists.", "danger")
    except subprocess.CalledProcessError:
        formatting.message(f"Unable to terminate process {pid}.", "danger")
    except ValueError:
        formatting.message("Invalid PID.", "danger")


def run(extra_unsafe_paths=None):
    formatting.page_title("EDR AUDITOR", "Flags running processes launched from known unsafe directories.")

    is_windows = sys.platform.startswith("win")
    target_unsafe = list(UNSAFE_PATH_WIN if is_windows else UNSAFE_PATHS_MAC)
    if extra_unsafe_paths:
        target_unsafe.extend(extra_unsafe_paths)

    active_process = get_running_process_windows() if is_windows else get_running_process_mac()

    formatting.section("Audit Summary")
    formatting.key_values([("Total processes audited", len(active_process)), ("Baseline unsafe paths", len(target_unsafe))])
    formatting.section_end()

    alerts = []
    for proc in active_process:
        for unsafe_dir in target_unsafe:
            if unsafe_dir.lower() in proc["path"].lower():
                alerts.append((proc, unsafe_dir))
                break

    formatting.section("Suspicious Processes")
    if alerts:
        rows = [(proc["user"], proc["pid"], proc["path"][:40], matched) for proc, matched in alerts]
        formatting.table(["USER", "PID", "PATH", "MATCHED"], rows)
    else:
        formatting.message("System Clean", "success")
    formatting.section_end()

    if not alerts:
        return

    suspicious_pids = [proc["pid"] for proc, _ in alerts]

    if not formatting.ask_yes_no("Would you like to kill a process using its PID", default_no=True):
        return

    pid = formatting.ask("Enter the PID to terminate")

    if pid not in suspicious_pids:
        formatting.message("PID is not in the suspicious process list.", "danger")
        return

    if formatting.ask_yes_no(f"Are you sure you want to terminate PID {pid}", default_no=True):
        kill_process(pid, is_windows)
    else:
        formatting.message("Process termination cancelled.", "info")
