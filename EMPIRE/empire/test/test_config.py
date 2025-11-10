from pathlib import Path

import pytest

from empire.server.core.config.config_manager import EmpireConfig
from empire.server.core.db.defaults import get_staging_key
from empire.test.conftest import load_test_config


def test_config_resolves_path():
    server_config_dict = load_test_config()
    server_config_dict["directories"]["downloads"] = "~/.empire/server/downloads"
    empire_config = EmpireConfig(server_config_dict)
    assert isinstance(empire_config.directories.downloads, Path)
    assert not str(empire_config.directories.downloads).startswith("~")
    assert empire_config.directories.downloads.is_absolute()

    server_config_dict["directories"]["downloads"] = "/tmp/empire"
    empire_config = EmpireConfig(server_config_dict)
    assert isinstance(empire_config.directories.downloads, Path)
    assert (str(empire_config.directories.downloads).startswith("/private/tmp")) or (
        str(empire_config.directories.downloads).startswith("/tmp")
    )
    assert empire_config.directories.downloads.is_absolute()

    server_config_dict["directories"]["downloads"] = "empire/test"
    empire_config = EmpireConfig(server_config_dict)
    assert isinstance(empire_config.directories.downloads, Path)
    assert str(empire_config.directories.downloads).endswith(
        ".local/share/empire-test/empire/test"
    )
    assert empire_config.directories.downloads.is_absolute()


def test_config_validates_registry_location_or_url():
    server_config_dict = load_test_config()

    server_config_dict["plugin_marketplace"]["registries"][0]["location"] = None
    server_config_dict["plugin_marketplace"]["registries"][0]["url"] = None

    with pytest.raises(
        ValueError, match="Either location, url, or git_url must be set"
    ):
        EmpireConfig(server_config_dict)


def test_staging_key_validation(monkeypatch):
    """
    Test that get_staging_key() properly validates provided staging keys.
    """
    expected_length = 32
    # No staging key set, should generate a valid random key (32 chars)
    monkeypatch.delenv("STAGING_KEY", raising=False)
    random_key = get_staging_key()
    assert random_key.isalnum(), (
        f"Generated key contains invalid characters: {random_key}"
    )
    assert len(random_key) == expected_length

    # Valid preset key (32 chars, letters + numbers only)
    monkeypatch.setenv("STAGING_KEY", "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6")
    assert get_staging_key() == "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6"

    # Invalid preset key (contains punctuation)
    monkeypatch.setenv("STAGING_KEY", "Bad#Key$With!Special")
    with pytest.raises(
        ValueError, match="Staging key must only contain letters .* and numbers"
    ):
        get_staging_key()

    # Invalid preset key (too short)
    monkeypatch.setenv("STAGING_KEY", "ShortKey123")
    with pytest.raises(
        ValueError, match="Staging key must be exactly 32 characters long"
    ):
        get_staging_key()

    # Invalid preset key (too long)
    monkeypatch.setenv("STAGING_KEY", "ThisKeyIsWayTooLongForValidation12345")
    with pytest.raises(
        ValueError, match="Staging key must be exactly 32 characters long"
    ):
        get_staging_key()

    # Empty staging key still generates a valid random key
    monkeypatch.setenv("STAGING_KEY", "")
    random_key = get_staging_key()
    assert random_key.isalnum(), (
        f"Generated key contains invalid characters: {random_key}"
    )
    assert len(random_key) == expected_length
