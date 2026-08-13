from cyberdefense import network_scanner


def test_resolve_host_localhost():
    assert network_scanner.resolve_host("localhost") == "127.0.0.1"


def test_resolve_host_invalid_returns_none():
    assert network_scanner.resolve_host("this-host-does-not-exist.invalid") is None


def test_common_ports_table_has_expected_entries():
    assert network_scanner.COMMON_PORTS[80] == "HTTP"
    assert network_scanner.COMMON_PORTS[443] == "HTTPS"
