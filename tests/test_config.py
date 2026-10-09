"""The hardened Streamlit settings must stay in .streamlit/config.toml.

Streamlit only reads this file when launched from the repository root, so
deployment instructions must start the app from there.
"""
import tomllib
from pathlib import Path

CONFIG = Path(__file__).resolve().parent.parent / ".streamlit" / "config.toml"


def test_hardened_streamlit_config_values():
    cfg = tomllib.loads(CONFIG.read_text(encoding="utf-8"))
    assert cfg["client"]["showErrorDetails"] == "none"
    assert cfg["client"]["toolbarMode"] == "viewer"
    assert cfg["server"]["maxMessageSize"] <= 1
    assert cfg["server"]["maxUploadSize"] <= 1
    assert cfg["server"]["enableXsrfProtection"] is True
    assert cfg["server"]["enableStaticServing"] is False
    assert cfg["browser"]["gatherUsageStats"] is False


def test_no_secrets_file_committed_alongside_config():
    assert not (CONFIG.parent / "secrets.toml").exists()
