import os

from dotenv import load_dotenv
import requests

from . import formatting


SUPPORT_DIR = os.path.join(os.path.dirname(__file__), "support")
DUMMY_ENV_PATH = os.path.join(SUPPORT_DIR, "dummy_credentials.env")


def charge_customer(amount, stripe_sk):
    try:
        payload = {"amount": amount, "currency": "usd"}
        headers = {"Authorization": f"Bearer {stripe_sk}"}

        formatting.message(f"Sending authorization header: Authorization: Bearer {stripe_sk}", "danger")
        formatting.message("This is exactly the mistake this demo is illustrating: never log secrets in cleartext.", "warning")

        response = requests.post("https://api.stripe.com/v1/charges", json=payload, headers=headers, timeout=5)
        return response.status_code
    except Exception as e:
        formatting.message(f"Request failed (expected in this offline demo): {e}", "info")
        return None


def run():
    formatting.page_title("CREDENTIAL HANDLING DEMO", "Illustrates an anti-pattern: secrets logged in cleartext.")

    load_dotenv()
    load_dotenv(DUMMY_ENV_PATH)

    key = os.environ.get("KEY")
    dbuser = os.environ.get("DBUSER")
    stripe_sk = os.environ.get("STRIPE_SK")

    formatting.section("Loaded Configuration (from support/dummy_credentials.env)")
    formatting.key_values([("KEY", key), ("DBUSER", dbuser), ("STRIPE_SK", stripe_sk)])
    formatting.section_end()

    formatting.message("Notice these are printed in plain text below - that is the vulnerability.", "warning")

    charge_customer(50, stripe_sk)

    formatting.section("Takeaway")
    formatting.message("Never log API keys, tokens, or passwords - use masked values (e.g. sk_***1234) in logs and error messages.", "info")
    formatting.section_end()
