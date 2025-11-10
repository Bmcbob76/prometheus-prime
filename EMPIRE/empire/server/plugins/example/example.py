"""An example of a plugin."""

import logging
from typing import override

from empire.server.core.plugins import BasePlugin

# Relative imports don't work in plugins right now.
# from . import example_helpers
# example_helpers.this_is_an_example_function()
from empire.server.plugins.example import example_helpers

example_helpers.this_is_an_example_function()

log = logging.getLogger(__name__)

# anything you simply write out (like a script) will run immediately when the
# module is imported (before the class is instantiated)
log.info("Hello from your new plugin!")


# this class MUST be named Plugin
class Plugin(BasePlugin):
    @override
    def on_load(self, db):
        """
        Any custom loading behavior - called by init, so any
        behavior you'd normally put in __init__ goes here
        """
        log.info("Custom loading behavior happens now.")

        # you can store data here that will persist until the plugin
        # is unloaded (i.e. Empire closes)
        self.called_times = 0

        # Any options needed by the plugin for the execute function
        self.execution_options = {
            # Format:
            #   value_name : {description, required, default_value}
            "Status": {
                "Description": "Example Status update",
                "Required": True,
                "Value": "start",
            },
            "Message": {
                "Description": "Message to print",
                "Required": True,
                "Value": "test",
            },
        }

        # These can be changed via plugin_service and the API.
        # With the exception of "editable": False
        # Using BasePlugin's functions for setting and getting the current
        # state, it will ensure things are kept in sync with the db
        self.settings_options = {
            "SomeEditableSetting": {
                "Description": "Edit This",
                "Required": True,
                "Value": "",
            },
            "SomeNonEditableSetting": {
                "Description": "This is displayed to users, but can't be changed via the API",
                "Required": True,
                "Value": "Hello World",
                "Editable": False,
            },
        }

        # This is not necessary, it is only here for tests.
        super().on_load(db)

    @override
    def on_start(self, db):
        self.set_internal_state(db, {"SomeInternalSetting": "internal_state_value"})

    @override
    def execute(self, command, **kwargs):
        """
        Parses commands from the API
        """
        try:
            return self.do_test(command)
        except Exception:
            return False

    def do_test(self, command):
        """
        An example of a plugin function.
        Usage: test <start|stop> <message>
        """
        log.info("This is executed from a plugin!")

        self.status = command["Status"]

        if self.status == "start":
            self.called_times += 1
            log.info(f"This function has been called {self.called_times} times.")
            log.info("Message: " + command["Message"])

        else:
            log.info("Usage: example <start|stop> <message>")

    @override
    def on_stop(self, db):
        """
        Kills additional processes that were spawned
        """
        # If the plugin spawns a process provide a shutdown method for when Empire exits else leave it as pass
        pass
