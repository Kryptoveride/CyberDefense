import importlib

import cyberdefense.config as config_module


def test_save_and_load_api_key_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(config_module, "CONFIG_DIR", tmp_path / ".cyberdefense")
    monkeypatch.setattr(config_module, "CONFIG_FILE", tmp_path / ".cyberdefense" / ".env")
    monkeypatch.delenv(config_module.ENV_VAR, raising=False)

    assert config_module.get_api_key() is None

    config_module.save_api_key("test-key-12345")

    assert config_module.CONFIG_FILE.exists()
    assert config_module.get_api_key() == "test-key-12345"
