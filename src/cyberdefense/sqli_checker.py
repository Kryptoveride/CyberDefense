import requests

from . import formatting


DEFAULT_URL = "https://demo.owasp-juice.shop/rest/products/search"
DEFAULT_PAYLOAD = "test'"

DATABASE_ERRORS = [
    "sql syntax",
    "mysql",
    "sqlite",
    "postgresql",
    "ora-",
    "odbc",
    "database error",
    "syntax error",
    "unterminated quoted string",
]


def run():
    formatting.page_title("SQL INJECTION CHECKER", "Sends a basic SQLi probe payload and inspects the response.")

    target_url = formatting.ask("Enter authorized target URL", DEFAULT_URL)
    payload = formatting.ask("Enter test payload", DEFAULT_PAYLOAD)

    formatting.section("Scan Configuration")
    formatting.key_values([
        ("Target URL", target_url),
        ("Parameter", "q"),
        ("Test payload", payload),
        ("Request method", "GET"),
    ])
    formatting.section_end()

    formatting.message("Sending test request...", "info")

    try:
        response = requests.get(
            target_url,
            params={"q": payload},
            timeout=20,
            allow_redirects=True,
            headers={"User-Agent": "Educational-SQLi-Checker/1.0"},
        )
    except requests.exceptions.Timeout:
        formatting.message("The request timed out.", "danger")
        return
    except requests.exceptions.ConnectionError:
        formatting.message("Unable to connect to the target.", "danger")
        return
    except requests.exceptions.RequestException as error:
        formatting.message(f"Request failed: {error}", "danger")
        return

    response_text = response.text.lower()
    detected_errors = [msg for msg in DATABASE_ERRORS if msg in response_text]

    formatting.section("Response Information")
    formatting.key_values([
        ("HTTP status", response.status_code),
        ("Final URL", response.url),
        ("Response length", f"{len(response.content)} bytes"),
        ("Redirected", "Yes" if response.history else "No"),
    ])
    formatting.section_end()

    formatting.section("Detection Results")
    if response.status_code >= 500:
        formatting.message("The payload caused a server-side error.", "warning")
    else:
        formatting.message("No server-side error was returned.", "success")

    if detected_errors:
        formatting.message("Possible database error messages were detected.", "warning")
        for error_message in detected_errors:
            print(f"    - {error_message}")
    else:
        formatting.message("No common database error messages were detected.", "success")
    formatting.section_end()

    formatting.section("Final Assessment")
    if response.status_code >= 500 and detected_errors:
        formatting.message("SQL injection may be possible. Manual verification is required.", "danger")
    elif response.status_code >= 500:
        formatting.message("The request caused a server error, but this does not prove SQL injection.", "warning")
    elif detected_errors:
        formatting.message("Database-related text was detected, but manual verification is required.", "warning")
    else:
        formatting.message("No obvious SQL injection indicators were detected in this request.", "success")
    formatting.section_end()
