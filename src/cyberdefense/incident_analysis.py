from . import formatting


DEMO_INCIDENTS = [
    ("INC-2026-001", "production_database", "data_exfiltration"),
    ("INC-2026-002", "employee_laptop", "phishing"),
    ("INC-2026-003", "domain_controller", "ransomware"),
    ("INC-2026-004", "web_server", "ddos_attack"),
    ("INC-2026-005", "email_server", "unauthorised_login"),
    ("INC-2026-006", "customer_database", "sql_injection"),
    ("INC-2026-007", "file_server", "malware_outbreak"),
    ("INC-2026-008", "employee_desktop", "brute_force_attack"),
]

FORENSIC_ARTIFACTS = [
    {"timestamp": "2026-08-05 11:52:00", "source": "Authentication Logs", "event": "Several failed SSH login attempts were detected for the root account", "severity": "HIGH", "mitigation": "Block the source IP address and disable direct root login"},
    {"timestamp": "2026-08-05 11:55:30", "source": "Authentication Logs", "event": "A successful SSH login occurred from an unknown external IP address", "severity": "CRITICAL", "mitigation": "Terminate the SSH session and reset the affected account password"},
    {"timestamp": "2026-08-05 11:57:10", "source": "Shell History", "event": "A suspicious script was downloaded using the curl command", "severity": "HIGH", "mitigation": "Isolate the system and block the malicious download address"},
    {"timestamp": "2026-08-05 11:58:25", "source": "File System Monitoring", "event": "A suspicious file named ransomware.sh was created inside the /tmp directory", "severity": "HIGH", "mitigation": "Preserve the file as evidence and remove its execution permission"},
    {"timestamp": "2026-08-05 12:00:00", "source": "Process Monitoring", "event": "Malicious script execution ran through the zsh shell with PID 4232", "severity": "CRITICAL", "mitigation": "Kill the process using the kill -9 4232 command"},
    {"timestamp": "2026-08-05 12:00:15", "source": "Process Monitoring", "event": "The malicious process created a child encryption process with PID 4251", "severity": "CRITICAL", "mitigation": "Terminate PID 4251 and isolate the affected system"},
    {"timestamp": "2026-08-05 12:00:45", "source": "File System Monitoring", "event": "Multiple user documents were renamed with the .locked extension", "severity": "CRITICAL", "mitigation": "Stop the encryption process and disconnect shared storage"},
    {"timestamp": "2026-08-05 12:01:20", "source": "Network Monitoring", "event": "The system connected to an unknown external IP address on port 443", "severity": "HIGH", "mitigation": "Block the external IP address and disconnect the system from the network"},
    {"timestamp": "2026-08-05 12:02:10", "source": "Cron Job Monitoring", "event": "A new cron job was created to execute ransomware.sh every five minutes", "severity": "HIGH", "mitigation": "Remove the unauthorized cron job after preserving it as evidence"},
    {"timestamp": "2026-08-05 12:03:05", "source": "User Account Monitoring", "event": "An unauthorized user account named system_backup was created", "severity": "CRITICAL", "mitigation": "Disable the unauthorized account and review its activity"},
    {"timestamp": "2026-08-05 12:04:30", "source": "Security Logs", "event": "The attacker attempted to stop the system logging service", "severity": "HIGH", "mitigation": "Restart the logging service and preserve all available logs"},
    {"timestamp": "2026-08-05 12:05:40", "source": "File System Monitoring", "event": "A ransom note named RECOVER_FILES.txt was created in the Documents directory", "severity": "CRITICAL", "mitigation": "Preserve the ransom note and investigate its contents"},
    {"timestamp": "2026-08-05 12:06:20", "source": "Backup Monitoring", "event": "The attacker attempted to delete local backup files", "severity": "CRITICAL", "mitigation": "Protect offline backups and prevent access to backup storage"},
]


def cal_incident_priority(impacted_asset, threat_type, baseline_critical=6, baseline_elevated=3):
    if impacted_asset in ["production_database", "domain_controller", "payment_server", "customer_database"]:
        impact_score = 3
    elif impacted_asset in ["web_server", "email_server", "file_server", "backup_server"]:
        impact_score = 2
    elif impacted_asset in ["employee_laptop", "employee_desktop", "test_server", "printer"]:
        impact_score = 1
    else:
        impact_score = 2

    if threat_type in ["ransomware", "data_exfiltration", "database_breach", "malware_outbreak"]:
        threat_score = 3
    elif threat_type in ["phishing", "unauthorised_login", "brute_force_attack", "ddos_attack", "sql_injection"]:
        threat_score = 2
    else:
        threat_score = 1

    total_severity = impact_score * threat_score

    if total_severity >= baseline_critical:
        return "CRITICAL", "Immediate investigation and containment required", impact_score, threat_score, total_severity
    elif total_severity >= baseline_elevated:
        return "ELEVATED", "SOC analyst investigation required", impact_score, threat_score, total_severity
    else:
        return "STANDARD", "Monitor and review event", impact_score, threat_score, total_severity


def run_triage():
    formatting.page_title("IR TRIAGE", "Scores incidents by impact x threat type.")

    formatting.section("Incident Queue")
    rows = []
    for event_id, system, attack in DEMO_INCIDENTS:
        severity, action, impact, threat, total = cal_incident_priority(system, attack)
        tone = "danger" if severity == "CRITICAL" else ("warning" if severity == "ELEVATED" else "success")
        rows.append((event_id, system, attack, f"{total}/9", formatting.badge(severity, tone)))

    formatting.table(["EVENT", "ASSET", "THREAT", "SCORE", "SEVERITY"], rows)
    formatting.section_end()


def run_timeline():
    formatting.page_title("FORENSIC TIMELINE", "Reconstructs a chronological timeline of forensic artifacts.")

    artifacts = sorted(FORENSIC_ARTIFACTS, key=lambda item: item["timestamp"])

    formatting.section("Timeline")

    for artifact in artifacts:
        tone = "danger" if artifact["severity"] == "CRITICAL" else "warning"
        formatting.key_values([
            ("Timestamp", artifact["timestamp"]),
            ("Severity", formatting.badge(artifact["severity"], tone)),
            ("Event", f"{artifact['event']} (via {artifact['source']})"),
            ("Mitigation", artifact["mitigation"]),
        ])
        print()

    formatting.section_end()


def run():
    formatting.page_title("INCIDENT ANALYSIS", "IR triage scoring and forensic timeline reconstruction.")

    print()
    formatting.menu([
        ("IR Triage", "Score incidents by risk"),
        ("Forensic Timeline", "Lay out events in order"),
        ("Both", "Run triage, then the timeline"),
    ])

    choice = formatting.ask("Select a mode", "1")

    if choice == "2":
        run_timeline()
    elif choice == "3":
        run_triage()
        run_timeline()
    else:
        run_triage()
