import ipaddress

import requests

from . import config
from . import formatting


def validate_ip(ip_address):
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False


def run():
    formatting.page_title("MALICIOUS IP SCANNER", "Looks up an IP address's reputation via VirusTotal.")

    ip_address = formatting.ask("Enter the IP address to scan")

    if not ip_address:
        formatting.message("An IP address is required.", "danger")
        return

    if not validate_ip(ip_address):
        formatting.message("Invalid IP address format.", "danger")
        return

    api_key = config.ensure_api_key()

    if not api_key:
        formatting.message("A VirusTotal API key is required to use this tool.", "danger")
        return

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"accept": "application/json", "x-apikey": api_key}

    formatting.message("Querying VirusTotal...", "info")

    try:
        response = requests.get(url, headers=headers, timeout=20)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.Timeout:
        formatting.message("VirusTotal request timed out.", "danger")
        return
    except requests.exceptions.HTTPError:
        if response.status_code == 401:
            reason = "The VirusTotal API key is invalid."
        elif response.status_code == 404:
            reason = "VirusTotal has no record for this IP address."
        elif response.status_code == 429:
            reason = "VirusTotal API request limit was reached."
        else:
            reason = f"VirusTotal returned HTTP status {response.status_code}."
        formatting.message(reason, "danger")
        return
    except requests.exceptions.RequestException as error:
        formatting.message(f"VirusTotal request failed: {error}", "danger")
        return
    except ValueError:
        formatting.message("VirusTotal returned invalid data.", "danger")
        return

    try:
        record = data["data"]
        attributes = record["attributes"]
    except (KeyError, TypeError):
        formatting.message("Unexpected VirusTotal response format.", "danger")
        return

    votes = attributes.get("total_votes", {})
    analysis = attributes.get("last_analysis_stats", {})

    harmless_votes = votes.get("harmless", 0)
    malicious_votes = votes.get("malicious", 0)

    harmless_results = analysis.get("harmless", 0)
    malicious_results = analysis.get("malicious", 0)
    suspicious_results = analysis.get("suspicious", 0)
    undetected_results = analysis.get("undetected", 0)

    country = attributes.get("country") or "Unknown"
    network = attributes.get("network") or "Unknown"
    owner = attributes.get("as_owner") or "Unknown"
    reputation = attributes.get("reputation", 0)

    formatting.section("IP Information")
    formatting.key_values([
        ("IP address", record.get("id", ip_address)),
        ("Country", country),
        ("Network", network),
        ("Network owner", owner),
        ("Reputation score", reputation),
    ])
    formatting.section_end()

    formatting.section("Security Analysis")
    formatting.table(
        ["CATEGORY", "RESULTS"],
        [
            ("Harmless", harmless_results),
            ("Malicious", malicious_results),
            ("Suspicious", suspicious_results),
            ("Undetected", undetected_results),
        ],
    )
    formatting.section_end()

    formatting.section("Community Votes")
    formatting.key_values([("Harmless votes", harmless_votes), ("Malicious votes", malicious_votes)])
    formatting.section_end()

    formatting.section("Final Assessment")
    if malicious_results > 0 or suspicious_results > 0:
        formatting.message("Security vendors flagged this IP as malicious or suspicious.", "danger")
    elif malicious_votes > 0:
        formatting.message("The VirusTotal community has reported this IP as malicious.", "warning")
    else:
        formatting.message("No malicious or suspicious detections were reported by VirusTotal.", "success")
    formatting.section_end()
