import importlib
import sys

from . import config
from . import formatting


TOOLS = [
    ("Port & Host Scanner", "Check if a host or port is open", "network_scanner"),
    ("Malicious IP Scanner", "Check if an IP is known malicious", "malicious_ip"),
    ("Live Packet Sniffer", "Watch live network traffic", "packet_sniffer"),
    ("SQL Injection Checker", "Test a URL for SQL injection", "sqli_checker"),
    ("Log Parser", "Scan logs and flag suspicious activity", "log_parser"),
    ("Code Security Scanner", "Find XSS and insecure code patterns", "code_scanner"),
    ("EDR Auditor", "Check running processes for malware signs", "edr_auditor"),
    ("Incident Analysis", "Score and timeline a security incident", "incident_analysis"),
    ("Credential Handling Demo", "See why logging secrets is risky", "credential_handling_demo"),
    ("Incident Response", "Contain a compromised host and log it", "incident_response"),
]

# Index (1-based, matches the menu) of tools that need a VirusTotal API key.
TOOLS_NEEDING_API_KEY = {"malicious_ip"}


def run_tool(module_name):
    try:
        module = importlib.import_module(f"cyberdefense.{module_name}")
    except ImportError as error:
        formatting.message(f"This tool needs an extra package that isn't installed: {error}", "danger")
        formatting.message("Install the missing package(s) and try again (see README.md).", "warning")
        return

    module.run()


def first_run_setup():
    """On first launch (no API key configured yet), offer to set it up."""
    if config.get_api_key():
        return

    formatting.clear_screen()
    formatting.banner()
    formatting.message("Welcome! CyberDefense is ready to go.", "info")
    formatting.message(
        "One tool (Malicious IP Scanner) needs a free VirusTotal API key.", "info"
    )
    formatting.message(
        "Have it ready at https://www.virustotal.com/gui/my-apikey if you'd like to set it up now.",
        "info",
    )

    if formatting.ask_yes_no("Set up your VirusTotal API key now?", default_no=False):
        config.prompt_and_save_api_key()
    else:
        formatting.message(
            "No problem - you can set it up later from the main menu or when you first "
            "use the Malicious IP Scanner.",
            "warning",
        )

    input("\nPress Enter to continue...")


def menu():
    while True:
        formatting.clear_screen()
        formatting.banner()

        print()
        options = [(title, description) for title, description, _ in TOOLS]
        options.append(("Configure VirusTotal API Key", "Set or update your saved API key"))
        options.append(("Exit", "Quit CyberDefense"))
        formatting.menu(options)

        choice = formatting.prompt("Select an option")

        try:
            choice_num = int(choice)
        except ValueError:
            formatting.message("Invalid menu option.", "danger")
            input("\nPress Enter to continue...")
            continue

        if choice_num == len(TOOLS) + 2:
            formatting.message("CyberDefense terminated.", "info")
            break

        if choice_num == len(TOOLS) + 1:
            config.prompt_and_save_api_key()
        elif 1 <= choice_num <= len(TOOLS):
            _, _, module_name = TOOLS[choice_num - 1]
            try:
                run_tool(module_name)
            except KeyboardInterrupt:
                formatting.message("Tool interrupted by user.", "warning")
        else:
            formatting.message("Invalid menu option.", "danger")

        input("\nPress Enter to continue...")


def main():
    try:
        first_run_setup()
        menu()
    except KeyboardInterrupt:
        formatting.message("Program terminated by user.", "warning")
        sys.exit(0)


if __name__ == "__main__":
    main()
