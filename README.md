# CyberDefense

A single security toolkit with 10 tools, run from one menu.

## Features

- Port & host scanning (HTTP check, single port, top-10 ports)
- Malicious IP reputation lookups via VirusTotal
- Live packet sniffing
- SQL injection checking against a URL
- Log parsing for suspicious activity
- Static code scanning for XSS and other insecure patterns
- EDR-style process auditing
- Incident scoring/timeline analysis
- A credential-handling anti-pattern demo
- Incident response / host containment logging

## Installation

### uv (recommended)

```bash
uv tool install CyberDefense
```

### pip

```bash
pip install CyberDefense
```

## Usage

```bash
cyberdefense
```

On first run, the app will offer to set up your VirusTotal API key (see
below). You can skip this and set it up later from the main menu, at any
time, or when you first open the Malicious IP Scanner.

## Tools

| # | Tool | Description |
|---|---|---|
| 1 | Port & Host Scanner | Check if a host or port is open |
| 2 | Malicious IP Scanner | Check if an IP is known malicious |
| 3 | Live Packet Sniffer | Watch live network traffic |
| 4 | SQL Injection Checker | Test a URL for SQL injection |
| 5 | Log Parser | Scan logs and flag suspicious activity |
| 6 | Code Security Scanner | Find XSS and insecure code patterns |
| 7 | EDR Auditor | Check running processes for malware signs |
| 8 | Incident Analysis | Score and timeline a security incident |
| 9 | Credential Handling Demo | See why logging secrets is risky |
| 10 | Incident Response | Contain a compromised host and log it |

## VirusTotal API key

The Malicious IP Scanner needs a free VirusTotal API key:
[get one here](https://www.virustotal.com/gui/my-apikey).

Have the key ready, then either:

- Accept the prompt on first launch, or
- Choose **Configure VirusTotal API Key** from the main menu at any time.

Paste the key when asked. It's saved to `~/.cyberdefense/.env` so it works no
matter where you run `cyberdefense` from, and it's never printed back out or
committed anywhere.

If you're running from a cloned copy of the repo instead of an installed
package, you can alternatively copy `.env.example` to `.env` in the project
root and fill it in there - see that file for details.

## Privileged features

The Live Packet Sniffer needs elevated privileges (`sudo` on Linux/macOS, an
Administrator terminal on Windows) because raw packet capture is a
privileged operation on all three platforms.

## Supported platforms

- Linux
- macOS
- Windows (packet sniffing requires [Npcap](https://npcap.com/))

## Responsible use

Only use these tools against systems and applications you own or have
explicit permission to test. See [SECURITY.md](SECURITY.md) for details on
the intentionally insecure demo code bundled with this project.

## Development

```bash
git clone https://github.com/Kryptoveride/CyberDefense.git
cd CyberDefense
uv sync
uv run cyberdefense
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for more.

## License

This project is licensed under the [MIT License](LICENSE).
