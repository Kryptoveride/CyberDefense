# Contributing

Thanks for considering a contribution to CyberDefense!

## Development setup

```bash
git clone https://github.com/Kryptoveride/CyberDefense.git
cd CyberDefense
uv sync
uv run cyberdefense
```

## Running tests

```bash
uv run pytest
```

## Before opening a PR

- Keep changes focused and small where possible.
- Add or update a test for any behavior change.
- Run `uv run pytest` and make sure it passes.
- Update `README.md` if you add or change a tool.

## Adding a new tool

1. Add a new module under `src/cyberdefense/`, with a `run()` function as
   its entry point (see any existing tool, e.g. `network_scanner.py`).
2. Register it in the `TOOLS` list in `src/cyberdefense/main.py`.
3. Add a row to the tools table in `README.md`.
