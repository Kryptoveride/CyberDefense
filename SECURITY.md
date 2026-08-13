# Security Policy

CyberDefense is a defensive/educational security toolkit. It includes
tools such as a port scanner, a packet sniffer, a SQL injection checker, and
an EDR auditor.

**Only run these tools against systems and applications you own or have
explicit permission to test.** Unauthorized scanning or testing of systems
you do not control may be illegal in your jurisdiction.

## Intentionally insecure demo code

`src/cyberdefense/support/sample_vulnerable_code.py` contains intentionally
vulnerable patterns (e.g. `os.system(...)`, `subprocess.run(..., shell=True)`)
used as sample input for the Code Security Scanner. It is demonstration data,
not application logic, and is not meant to be run directly.

`credential_handling_demo.py` intentionally logs a dummy secret in cleartext
to illustrate why that's a bad practice. The values it prints come from the
bundled `support/dummy_credentials.env` file - they are not real credentials.

## Reporting a vulnerability

If you find a security issue in the project itself (not the intentional demo
code above), please open a GitHub issue or contact the maintainer directly
rather than filing a public exploit.
