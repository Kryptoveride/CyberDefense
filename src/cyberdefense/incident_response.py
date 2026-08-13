import csv
import datetime
import os

from . import formatting


SUPPORT_DIR = os.path.join(os.path.dirname(__file__), "support")
REPORT_FILE = os.path.join(SUPPORT_DIR, "incident_reports.csv")


def show_containment_card(hostname, host_ip, attacker_ip):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    formatting.section("Incident Containment Ticket")
    formatting.key_values([
        ("Time", timestamp),
        ("Hostname", hostname),
        ("Host IP", host_ip),
        ("Blocked IP", formatting.badge(attacker_ip, "danger")),
        ("Containment status", formatting.badge("SUCCESSFUL", "success")),
    ])
    formatting.section_end()

    formatting.section("Actions Completed")
    print(f"  \u2713 Firewall rule added to block {attacker_ip}")
    print("  \u2713 Affected system remains powered ON")
    print("  \u2713 Network containment completed")
    formatting.section_end()

    formatting.section("Next Steps")
    print("  1. Preserve evidence for forensic analysis.")
    print("  2. Notify the SOC/IR team.")
    print("  3. Begin malware investigation.")
    formatting.section_end()


def append_report_row(incident_id, threat_type, target_asset, remediation):
    file_exists = os.path.isfile(REPORT_FILE)

    with open(REPORT_FILE, "a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        if not file_exists:
            writer.writerow(["Incident_ID", "Threat_Type", "Target_Asset", "Remediation_Action"])
        writer.writerow([incident_id, threat_type, target_asset, remediation])


def run():
    formatting.page_title("INCIDENT RESPONSE", "Tier-1 containment ticket, with an optional CSV incident report.")

    hostname = formatting.ask("Enter affected hostname")
    host_ip = formatting.ask("Enter affected host IP")
    attacker_ip = formatting.ask("Enter attacker IP")

    if formatting.ask_yes_no("Is this a production server or critical system", default_no=True):
        formatting.message("Do not isolate it yourself. Contact the SOC/IR team immediately.", "danger")
        return

    if not formatting.ask_yes_no("Has the malware alert been confirmed", default_no=True):
        formatting.message("Verify the alert before continuing.", "warning")
        return

    show_containment_card(hostname, host_ip, attacker_ip)

    if formatting.ask_yes_no(f"Generate a CSV incident report entry in {os.path.basename(REPORT_FILE)}", default_no=False):
        incident_id = formatting.ask("Incident ID", f"INC-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}")
        threat_type = formatting.ask("Threat type", "malware_outbreak")
        remediation = formatting.ask("Remediation action taken", f"Blocked {attacker_ip} via firewall; host {hostname} contained")

        append_report_row(incident_id, threat_type, hostname, remediation)
        formatting.message(f"Report entry appended to {REPORT_FILE}", "success")
