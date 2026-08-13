from cyberdefense import malicious_ip


def test_validate_ip_accepts_ipv4():
    assert malicious_ip.validate_ip("8.8.8.8") is True


def test_validate_ip_accepts_ipv6():
    assert malicious_ip.validate_ip("::1") is True


def test_validate_ip_rejects_garbage():
    assert malicious_ip.validate_ip("not-an-ip") is False
    assert malicious_ip.validate_ip("999.999.999.999") is False
