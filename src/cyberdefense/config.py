"""Handles the VirusTotal API key: where it lives and how it's collected."""

import os
from pathlib import Path

from dotenv import load_dotenv, set_key

from . import formatting

CONFIG_DIR = Path.home() / ".cyberdefense"
CONFIG_FILE = CONFIG_DIR / ".env"

ENV_VAR = "VIRUS_TOTAL_API"


def _load_saved_key():
    """Load the key from ~/.cyberdefense/.env (if it exists) into the environment."""
    if CONFIG_FILE.exists():
        load_dotenv(CONFIG_FILE)
    # Also allow a project-local .env to override, for people running from a clone.
    load_dotenv()
    return os.getenv(ENV_VAR)


def get_api_key():
    """Return the saved VirusTotal API key, or None if none is configured."""
    return _load_saved_key()


def save_api_key(api_key):
    """Write the API key to ~/.cyberdefense/.env, creating the folder/file if needed."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not CONFIG_FILE.exists():
        CONFIG_FILE.touch()
    set_key(str(CONFIG_FILE), ENV_VAR, api_key)
    os.environ[ENV_VAR] = api_key


def prompt_and_save_api_key():
    """Interactively ask the user for their VirusTotal API key and save it."""
    formatting.section("VirusTotal API Key Setup")
    formatting.message(
        "Grab a free API key from https://www.virustotal.com/gui/my-apikey", "info"
    )
    formatting.message(
        f"It will be saved to {CONFIG_FILE} for future runs.", "info"
    )

    api_key = formatting.ask("Paste your VirusTotal API key (leave blank to skip)")

    if not api_key:
        formatting.message("Skipped. You can set this up later from the main menu.", "warning")
        return None

    save_api_key(api_key)
    formatting.message("API key saved.", "success")
    return api_key


def ensure_api_key(interactive=True):
    """Return a usable API key, prompting the user to set one up if missing."""
    api_key = get_api_key()
    if api_key:
        return api_key

    if not interactive:
        return None

    formatting.message("No VirusTotal API key is configured yet.", "warning")
    if formatting.ask_yes_no("Set one up now?", default_no=False):
        return prompt_and_save_api_key()

    return None
