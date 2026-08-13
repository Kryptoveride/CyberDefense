import os
import sys

from tabulate import tabulate


USE_COLOR = os.getenv("NO_COLOR") is None

RESET = "\033[0m" if USE_COLOR else ""
BOLD = "\033[1m" if USE_COLOR else ""
DIM = "\033[2m" if USE_COLOR else ""
CYAN = "\033[96m" if USE_COLOR else ""
GREEN = "\033[92m" if USE_COLOR else ""
YELLOW = "\033[93m" if USE_COLOR else ""
RED = "\033[91m" if USE_COLOR else ""
WHITE = "\033[97m" if USE_COLOR else ""

BANNER = f"""{CYAN}{BOLD}
   ______      __              ____       ____
  / ____/_  __/ /_  ___  _____/ __ \\___  / __/__  ____  _________
 / /   / / / / __ \\/ _ \\/ ___/ / / / _ \\/ /_/ _ \\/ __ \\/ ___/ _ \\
/ /___/ /_/ / /_/ /  __/ /  / /_/ /  __/ __/  __/ / / (__  )  __/
\\____/\\__, /_.___/\\___/_/  /_____/\\___/_/  \\___/_/ /_/____/\\___/
     /____/

              *      CYBERDEFENSE      *
{RESET}"""


def paint(text, color="", *, bold=False, dim=False):
    prefix = f"{color}{BOLD if bold else ''}{DIM if dim else ''}"
    return f"{prefix}{text}{RESET}" if prefix else str(text)


def clear_screen():
    if sys.stdout.isatty():
        print("\033[2J\033[H", end="")


def banner():
    print(BANNER)


def page_title(title, subtitle=None):
    print()
    print(paint(title, WHITE, bold=True))
    if subtitle:
        print(paint(subtitle, DIM))


def section(title):
    print()
    print(paint(f"-- {title} --", CYAN, bold=True))


def section_end():
    pass


def key_values(rows):
    if not rows:
        return
    key_width = max(len(str(key)) for key, _ in rows)
    for key, value in rows:
        print(f"  {str(key).ljust(key_width)} : {value}")


def table(headers, rows, tablefmt="rounded_grid"):
    print(tabulate(rows, headers=headers, tablefmt=tablefmt))


def badge(label, tone="info"):
    palette = {
        "success": (GREEN, "+"),
        "danger": (RED, "x"),
        "warning": (YELLOW, "!"),
        "info": (CYAN, "i"),
        "neutral": (WHITE, "-"),
    }
    color, symbol = palette.get(tone, palette["info"])
    return paint(f"{symbol} {label}", color, bold=True)


def message(text, tone="info"):
    palette = {
        "success": (GREEN, "OK"),
        "danger": (RED, "ERROR"),
        "warning": (YELLOW, "WARN"),
        "info": (CYAN, "INFO"),
    }
    color, symbol = palette.get(tone, palette["info"])
    print(f"{paint(f'[{symbol}]', color, bold=True)} {text}")


def prompt(label, default=None):
    default_text = f" {paint(f'[{default}]', DIM)}" if default else ""
    return input(f"{paint('>', CYAN, bold=True)} {label}{default_text}: ")


def ask(label, default=None):
    value = prompt(label, default).strip()
    return value if value else (default or "")


def ask_yes_no(label, default_no=True):
    default_label = "y/N" if default_no else "Y/n"
    value = prompt(f"{label} ({default_label})").strip().lower()
    if not value:
        return not default_no
    return value == "y"


def menu_item(number, title, description):
    print(f"  {paint(f'[{number}]', CYAN, bold=True)} {paint(f'{title:<25}', WHITE, bold=True)} {paint(description, DIM)}")


def menu(options):
    rows = []
    for index, (title, description) in enumerate(options, start=1):
        rows.append((paint(str(index), CYAN, bold=True), paint(title, WHITE, bold=True), paint(description, DIM)))
    print(tabulate(rows, headers=["#", "OPTION", "DESCRIPTION"], tablefmt="rounded_grid"))
