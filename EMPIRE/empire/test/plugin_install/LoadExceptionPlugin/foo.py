import logging
from typing import override

from empire.server.core.plugins import BasePlugin

log = logging.getLogger(__name__)


class Plugin(BasePlugin):
    @override
    def on_load(self, db):
        raise Exception("This plugin is meant to fail to load.")
