from typing import override
from unittest.mock import MagicMock

import pytest

from empire.server.core.db.models import PluginInfo
from empire.server.core.plugins import BasePlugin


class Plugin(BasePlugin):
    @override
    def on_load(self, db):
        self.settings_options = {
            "test_setting": {
                "Description": "Test setting",
                "Required": True,
                "Value": "default",
                "SuggestedValues": ["default", "other"],
                "Strict": True,
            },
            "file_option": {
                "Description": "File option",
                "Required": False,
                "Value": "",
                "File": True,
            },
        }

    @override
    def on_settings_change(self, db, settings):
        pass


@pytest.fixture
def _setup_database(session_local, models):
    with session_local.begin() as db:
        db.add(models.Plugin(id="example", name="example", enabled=True))

    yield

    with session_local.begin() as db:
        db.query(models.Plugin).filter(models.Plugin.id == "example").delete()


@pytest.mark.usefixtures("_setup_database")
def test_on_settings_change_called(session_local):
    main_menu_mock = MagicMock()
    example_plugin = Plugin(
        main_menu_mock, PluginInfo(id="example", name="example", main=""), None
    )

    on_settings_change_mock = MagicMock()
    example_plugin.on_settings_change = on_settings_change_mock

    with session_local.begin() as db:
        example_plugin.set_settings(db, {"test_setting": "other"})

    on_settings_change_mock.assert_called_once_with(db, {"test_setting": "other"})
