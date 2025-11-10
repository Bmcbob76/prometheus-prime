import logging

from empire.server.core.plugins import BasePlugin

from . import foo_utils

log = logging.getLogger(__name__)

foo_utils.bar()


class Plugin(BasePlugin):
    pass
