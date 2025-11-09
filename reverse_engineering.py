"""
PROMETHEUS PRIME - REVERSE ENGINEERING TOOLKIT
Authority Level: 11.0
Status: OPERATIONAL

Binary analysis, malware analysis, and reverse engineering tools.
"""

import subprocess
import os
import json
import hashlib
from typing import Dict, List, Optional, Any


class ReverseEngineeringToolkit:
    """Complete reverse engineering and malware analysis toolkit."""

    def __init__(self):
        self.analysis_results = []

    def binary_info(self, binary_path: str) -> Dict[str, Any]:
        """
        Get comprehensive binary information.

        Args:
            binary_path: Path to binary file

        Returns:
            Binary information
        """
        if not os.path.exists(binary_path):
            return {"error": "Binary not found"}

        info = {
            "file": binary_path,
            "size": os.path.getsize(binary_path),
            "file_type": None,
            "architecture": None,
            "stripped": None,
            "dynamic_libs": [],
            "security_features": {}
        }

        # Get file type
        try:
            result = subprocess.run(
                ["file", binary_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            info["file_type"] = result.stdout.strip()
        except:
            pass

        # Get detailed info with readelf (for ELF binaries)
        try:
            result = subprocess.run(
                ["readelf", "-h", binary_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            info["elf_header"] = result.stdout
        except:
            pass

        # Check if stripped
        try:
            result = subprocess.run(
                ["nm", binary_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            info["stripped"] = "no symbols" in result.stderr.lower()
        except:
            pass

        # Get dynamic libraries
        try:
            result = subprocess.run(
                ["ldd", binary_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            info["dynamic_libs"] = result.stdout.strip().split('\n')
        except:
            pass

        # Check security features
        info["security_features"] = self._check_security_features(binary_path)

        return info

    def _check_security_features(self, binary_path: str) -> Dict[str, bool]:
        """Check binary security features (NX, PIE, RELRO, etc.)."""
        features = {
            "nx": False,
            "pie": False,
            "relro": False,
            "stack_canary": False
        }

        try:
            # Use checksec if available
            result = subprocess.run(
                ["checksec", "--file=" + binary_path],
                capture_output=True,
                text=True,
                timeout=10
            )

            output = result.stdout.lower()
            features["nx"] = "nx enabled" in output
            features["pie"] = "pie enabled" in output
            features["relro"] = "full relro" in output or "partial relro" in output
            features["stack_canary"] = "canary found" in output

        except FileNotFoundError:
            # Fallback to readelf
            try:
                result = subprocess.run(
                    ["readelf", "-l", binary_path],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                features["nx"] = "GNU_STACK" in result.stdout and "RWE" not in result.stdout
                features["relro"] = "GNU_RELRO" in result.stdout
            except:
                pass

        return features

    def disassemble(self, binary_path: str, function: Optional[str] = None,
                   format: str = "intel") -> Dict[str, Any]:
        """
        Disassemble binary with objdump.

        Args:
            binary_path: Path to binary
            function: Specific function to disassemble
            format: Assembly syntax (intel, att)

        Returns:
            Disassembly output
        """
        if not os.path.exists(binary_path):
            return {"error": "Binary not found"}

        cmd = ["objdump", "-d"]

        if format == "intel":
            cmd.append("-M intel")

        cmd.append(binary_path)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            disassembly = result.stdout

            # If specific function requested, filter output
            if function:
                lines = disassembly.split('\n')
                function_lines = []
                in_function = False

                for line in lines:
                    if f"<{function}>:" in line:
                        in_function = True
                    elif in_function and line and line[0].isalnum():
                        break

                    if in_function:
                        function_lines.append(line)

                disassembly = '\n'.join(function_lines)

            return {
                "status": "success",
                "binary": binary_path,
                "function": function,
                "format": format,
                "disassembly": disassembly
            }

        except FileNotFoundError:
            return {"error": "objdump not found. Install binutils"}
        except subprocess.TimeoutExpired:
            return {"error": "Disassembly timeout"}

    def radare2_analyze(self, binary_path: str, commands: List[str]) -> Dict[str, Any]:
        """
        Analyze binary with radare2.

        Args:
            binary_path: Path to binary
            commands: List of r2 commands to execute

        Returns:
            Analysis results
        """
        if not os.path.exists(binary_path):
            return {"error": "Binary not found"}

        # Combine commands
        r2_commands = ";".join(commands)

        cmd = ["r2", "-q", "-c", r2_commands, binary_path]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            return {
                "status": "success",
                "binary": binary_path,
                "commands": commands,
                "output": result.stdout
            }

        except FileNotFoundError:
            return {"error": "radare2 not found. Install from https://rada.re/"}
        except subprocess.TimeoutExpired:
            return {"error": "Analysis timeout"}

    def ghidra_decompile(self, binary_path: str, output_dir: str) -> Dict[str, Any]:
        """
        Decompile binary with Ghidra (headless mode).

        Args:
            binary_path: Path to binary
            output_dir: Output directory for results

        Returns:
            Decompilation results
        """
        if not os.path.exists(binary_path):
            return {"error": "Binary not found"}

        os.makedirs(output_dir, exist_ok=True)

        # Ghidra headless analyzer
        cmd = [
            "analyzeHeadless",
            output_dir,
            "prometheus_project",
            "-import", binary_path,
            "-scriptPath", "/usr/share/ghidra/scripts",
            "-postScript", "DecompileAllFunctions.java"
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            return {
                "status": "success",
                "binary": binary_path,
                "output_dir": output_dir,
                "output": result.stdout
            }

        except FileNotFoundError:
            return {
                "error": "Ghidra not found",
                "note": "Install Ghidra from https://ghidra-sre.org/"
            }
        except subprocess.TimeoutExpired:
            return {"error": "Decompilation timeout (5 minutes)"}

    def ltrace_trace(self, binary_path: str, args: List[str] = None) -> Dict[str, Any]:
        """
        Trace library calls with ltrace.

        Args:
            binary_path: Path to binary
            args: Command-line arguments for binary

        Returns:
            Library call trace
        """
        if not os.path.exists(binary_path):
            return {"error": "Binary not found"}

        cmd = ["ltrace", binary_path]

        if args:
            cmd.extend(args)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            return {
                "status": "success",
                "binary": binary_path,
                "library_calls": result.stderr  # ltrace outputs to stderr
            }

        except FileNotFoundError:
            return {"error": "ltrace not found. Install with: apt-get install ltrace"}
        except subprocess.TimeoutExpired:
            return {"error": "Trace timeout"}

    def strace_trace(self, binary_path: str, args: List[str] = None) -> Dict[str, Any]:
        """
        Trace system calls with strace.

        Args:
            binary_path: Path to binary
            args: Command-line arguments for binary

        Returns:
            System call trace
        """
        if not os.path.exists(binary_path):
            return {"error": "Binary not found"}

        cmd = ["strace", "-f", binary_path]

        if args:
            cmd.extend(args)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            return {
                "status": "success",
                "binary": binary_path,
                "system_calls": result.stderr  # strace outputs to stderr
            }

        except FileNotFoundError:
            return {"error": "strace not found. Install with: apt-get install strace"}
        except subprocess.TimeoutExpired:
            return {"error": "Trace timeout"}

    def malware_static_analysis(self, file_path: str) -> Dict[str, Any]:
        """
        Perform static malware analysis.

        Args:
            file_path: Path to suspected malware

        Returns:
            Static analysis results
        """
        if not os.path.exists(file_path):
            return {"error": "File not found"}

        analysis = {
            "file": file_path,
            "hashes": {},
            "file_type": None,
            "strings": [],
            "imports": [],
            "exports": [],
            "suspicious_indicators": []
        }

        # Calculate hashes
        hash_algorithms = [hashlib.md5(), hashlib.sha1(), hashlib.sha256()]
        with open(file_path, 'rb') as f:
            data = f.read()
            for algo in hash_algorithms:
                algo.update(data)
                analysis["hashes"][algo.name] = algo.hexdigest()

        # Get file type
        try:
            result = subprocess.run(["file", file_path], capture_output=True, text=True)
            analysis["file_type"] = result.stdout.strip()
        except:
            pass

        # Extract strings
        try:
            result = subprocess.run(
                ["strings", "-n", "8", file_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            analysis["strings"] = result.stdout.split('\n')[:100]  # First 100 strings
        except:
            pass

        # Get imports (for PE files)
        try:
            result = subprocess.run(
                ["objdump", "-p", file_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            if "DLL Name:" in result.stdout:
                analysis["imports"] = [
                    line.strip() for line in result.stdout.split('\n')
                    if "DLL Name:" in line
                ]
        except:
            pass

        # Check for suspicious indicators
        suspicious_strings = [
            "cmd.exe", "powershell", "/c ", "certutil", "bitsadmin",
            "registry", "RunDLL32", "wscript", "cscript",
            "http://", "https://", ".exe", ".dll", ".bat"
        ]

        for string in analysis["strings"]:
            for sus in suspicious_strings:
                if sus.lower() in string.lower():
                    analysis["suspicious_indicators"].append(string)
                    break

        return analysis

    def yara_scan(self, file_path: str, rules_file: str) -> Dict[str, Any]:
        """
        Scan file with YARA rules.

        Args:
            file_path: File to scan
            rules_file: YARA rules file

        Returns:
            YARA scan results
        """
        if not os.path.exists(file_path):
            return {"error": "File not found"}

        if not os.path.exists(rules_file):
            return {"error": "YARA rules file not found"}

        cmd = ["yara", rules_file, file_path]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            matches = result.stdout.strip().split('\n') if result.stdout else []

            return {
                "status": "success",
                "file": file_path,
                "rules_file": rules_file,
                "matches": matches,
                "match_count": len([m for m in matches if m])
            }

        except FileNotFoundError:
            return {"error": "YARA not found. Install with: apt-get install yara"}
        except subprocess.TimeoutExpired:
            return {"error": "Scan timeout"}

    def peid_detect(self, file_path: str) -> Dict[str, Any]:
        """
        Detect packer/compiler with PEiD signatures.

        Args:
            file_path: PE file to analyze

        Returns:
            Detection results
        """
        if not os.path.exists(file_path):
            return {"error": "File not found"}

        # Use DIE (Detect It Easy) as modern alternative to PEiD
        cmd = ["diec", file_path]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            return {
                "status": "success",
                "file": file_path,
                "detections": result.stdout
            }

        except FileNotFoundError:
            return {
                "error": "DIE (Detect It Easy) not found",
                "note": "Install from https://github.com/horsicq/Detect-It-Easy"
            }
        except subprocess.TimeoutExpired:
            return {"error": "Detection timeout"}

    def upx_unpack(self, packed_file: str, output_file: str) -> Dict[str, Any]:
        """
        Unpack UPX-packed executable.

        Args:
            packed_file: Packed executable
            output_file: Output unpacked file

        Returns:
            Unpacking results
        """
        if not os.path.exists(packed_file):
            return {"error": "Packed file not found"}

        cmd = ["upx", "-d", packed_file, "-o", output_file]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if os.path.exists(output_file):
                return {
                    "status": "success",
                    "packed_file": packed_file,
                    "unpacked_file": output_file,
                    "output": result.stdout
                }
            else:
                return {"error": "Unpacking failed", "output": result.stderr}

        except FileNotFoundError:
            return {"error": "UPX not found. Install with: apt-get install upx-ucl"}
        except subprocess.TimeoutExpired:
            return {"error": "Unpacking timeout"}


# Example usage
if __name__ == "__main__":
    toolkit = ReverseEngineeringToolkit()

    # Test binary info
    print("=== Binary Information ===")
    result = toolkit.binary_info("/bin/ls")
    print(json.dumps(result, indent=2))

    # Test static malware analysis
    print("\n=== Static Analysis ===")
    result = toolkit.malware_static_analysis("/bin/ls")
    print(json.dumps(result, indent=2))
