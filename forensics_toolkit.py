"""
PROMETHEUS PRIME - DIGITAL FORENSICS TOOLKIT
Authority Level: 11.0
Status: OPERATIONAL

Comprehensive digital forensics, memory analysis, and evidence collection tools.
"""

import subprocess
import os
import hashlib
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
import mimetypes


class ForensicsToolkit:
    """Complete digital forensics toolkit."""

    def __init__(self):
        self.evidence_chain = []

    def file_hash_all(self, file_path: str) -> Dict[str, Any]:
        """
        Calculate all hash types for a file (forensic integrity).

        Args:
            file_path: Path to file

        Returns:
            Dictionary of all hashes
        """
        if not os.path.exists(file_path):
            return {"error": "File not found"}

        hashes = {}
        hash_algorithms = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256(),
            'sha512': hashlib.sha512()
        }

        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    for algo in hash_algorithms.values():
                        algo.update(chunk)

            for name, algo in hash_algorithms.items():
                hashes[name] = algo.hexdigest()

            # Get file metadata
            stats = os.stat(file_path)

            result = {
                "file": file_path,
                "size_bytes": stats.st_size,
                "modified_time": datetime.fromtimestamp(stats.st_mtime).isoformat(),
                "accessed_time": datetime.fromtimestamp(stats.st_atime).isoformat(),
                "created_time": datetime.fromtimestamp(stats.st_ctime).isoformat(),
                "hashes": hashes
            }

            # Add to evidence chain
            self.evidence_chain.append({
                "timestamp": datetime.now().isoformat(),
                "action": "file_hash",
                "file": file_path,
                "hashes": hashes
            })

            return result

        except Exception as e:
            return {"error": str(e)}

    def disk_image_create(self, device: str, output_file: str,
                         block_size: str = "4M") -> Dict[str, Any]:
        """
        Create forensic disk image using dd.

        Args:
            device: Source device (e.g., /dev/sda)
            output_file: Output image file
            block_size: Block size for dd

        Returns:
            Imaging results
        """
        cmd = [
            "dd",
            f"if={device}",
            f"of={output_file}",
            f"bs={block_size}",
            "conv=noerror,sync",
            "status=progress"
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)

            # Hash the image
            image_hashes = self.file_hash_all(output_file)

            return {
                "status": "success",
                "source_device": device,
                "output_file": output_file,
                "image_hashes": image_hashes.get("hashes", {}),
                "output": result.stderr  # dd outputs to stderr
            }

        except FileNotFoundError:
            return {"error": "dd command not found"}
        except subprocess.TimeoutExpired:
            return {"error": "Imaging timeout (1 hour)"}

    def strings_extract(self, file_path: str, min_length: int = 4,
                       encoding: str = "s") -> Dict[str, Any]:
        """
        Extract readable strings from binary file.

        Args:
            file_path: Path to file
            min_length: Minimum string length
            encoding: Encoding (s=7bit, b=8bit, l=16bit little, L=16bit big)

        Returns:
            Extracted strings
        """
        if not os.path.exists(file_path):
            return {"error": "File not found"}

        cmd = ["strings", f"-{encoding}", "-n", str(min_length), file_path]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            strings_list = result.stdout.split('\n')

            return {
                "status": "success",
                "file": file_path,
                "strings_found": len(strings_list),
                "strings": strings_list[:1000],  # Limit to first 1000
                "note": "Results limited to 1000 strings" if len(strings_list) > 1000 else ""
            }

        except FileNotFoundError:
            return {"error": "strings command not found. Install binutils"}
        except subprocess.TimeoutExpired:
            return {"error": "Extraction timeout"}

    def file_carving(self, image_file: str, output_dir: str) -> Dict[str, Any]:
        """
        Recover deleted files using foremost.

        Args:
            image_file: Disk image file
            output_dir: Output directory for carved files

        Returns:
            Carving results
        """
        if not os.path.exists(image_file):
            return {"error": "Image file not found"}

        os.makedirs(output_dir, exist_ok=True)

        cmd = ["foremost", "-i", image_file, "-o", output_dir, "-v"]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)

            # Count recovered files
            recovered_files = []
            for root, dirs, files in os.walk(output_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    recovered_files.append({
                        "file": file_path,
                        "size": os.path.getsize(file_path),
                        "type": mimetypes.guess_type(file_path)[0]
                    })

            return {
                "status": "success",
                "source_image": image_file,
                "output_directory": output_dir,
                "files_recovered": len(recovered_files),
                "recovered_files": recovered_files,
                "output": result.stdout
            }

        except FileNotFoundError:
            return {"error": "foremost not found. Install with: apt-get install foremost"}
        except subprocess.TimeoutExpired:
            return {"error": "Carving timeout (1 hour)"}

    def volatility_analyze(self, memory_dump: str, profile: str,
                          plugin: str = "pslist") -> Dict[str, Any]:
        """
        Analyze memory dump with Volatility.

        Args:
            memory_dump: Path to memory dump
            profile: Memory profile (Win7SP1x64, LinuxUbuntu1604x64, etc.)
            plugin: Volatility plugin to run

        Returns:
            Analysis results
        """
        if not os.path.exists(memory_dump):
            return {"error": "Memory dump not found"}

        cmd = [
            "volatility",
            "-f", memory_dump,
            "--profile=" + profile,
            plugin
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            return {
                "status": "success",
                "memory_dump": memory_dump,
                "profile": profile,
                "plugin": plugin,
                "output": result.stdout,
                "errors": result.stderr
            }

        except FileNotFoundError:
            return {"error": "Volatility not found. Install from https://www.volatilityfoundation.org/"}
        except subprocess.TimeoutExpired:
            return {"error": "Analysis timeout (5 minutes)"}

    def binwalk_analyze(self, file_path: str, extract: bool = False) -> Dict[str, Any]:
        """
        Analyze firmware/binary with binwalk.

        Args:
            file_path: Path to file
            extract: Extract embedded files

        Returns:
            Analysis results
        """
        if not os.path.exists(file_path):
            return {"error": "File not found"}

        cmd = ["binwalk"]

        if extract:
            cmd.append("-e")

        cmd.append(file_path)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            return {
                "status": "success",
                "file": file_path,
                "extracted": extract,
                "analysis": result.stdout,
                "extract_dir": f"_{os.path.basename(file_path)}.extracted" if extract else None
            }

        except FileNotFoundError:
            return {"error": "binwalk not found. Install with: apt-get install binwalk"}
        except subprocess.TimeoutExpired:
            return {"error": "Analysis timeout"}

    def exif_extract(self, file_path: str) -> Dict[str, Any]:
        """
        Extract EXIF metadata from files.

        Args:
            file_path: Path to file

        Returns:
            EXIF metadata
        """
        if not os.path.exists(file_path):
            return {"error": "File not found"}

        cmd = ["exiftool", "-json", file_path]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                metadata = json.loads(result.stdout)
                return {
                    "status": "success",
                    "file": file_path,
                    "metadata": metadata[0] if metadata else {}
                }
            else:
                return {"error": "EXIF extraction failed", "output": result.stderr}

        except FileNotFoundError:
            return {"error": "exiftool not found. Install with: apt-get install libimage-exiftool-perl"}
        except subprocess.TimeoutExpired:
            return {"error": "Extraction timeout"}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON response from exiftool"}

    def timeline_create(self, mount_point: str, output_file: str) -> Dict[str, Any]:
        """
        Create filesystem timeline.

        Args:
            mount_point: Mounted filesystem or image
            output_file: Output timeline file

        Returns:
            Timeline creation results
        """
        cmd = [
            "fls",
            "-r",
            "-m", "/",
            mount_point
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            with open(output_file, 'w') as f:
                f.write(result.stdout)

            return {
                "status": "success",
                "source": mount_point,
                "timeline_file": output_file,
                "entries": len(result.stdout.split('\n'))
            }

        except FileNotFoundError:
            return {"error": "fls (Sleuth Kit) not found. Install with: apt-get install sleuthkit"}
        except subprocess.TimeoutExpired:
            return {"error": "Timeline creation timeout"}

    def network_pcap_analyze(self, pcap_file: str, filter: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze network capture with tshark.

        Args:
            pcap_file: Path to pcap file
            filter: Display filter (optional)

        Returns:
            Analysis results
        """
        if not os.path.exists(pcap_file):
            return {"error": "PCAP file not found"}

        cmd = ["tshark", "-r", pcap_file]

        if filter:
            cmd.extend(["-Y", filter])

        cmd.extend(["-T", "json"])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.returncode == 0:
                packets = json.loads(result.stdout) if result.stdout else []
                return {
                    "status": "success",
                    "pcap_file": pcap_file,
                    "filter": filter,
                    "packets_found": len(packets),
                    "packets": packets[:100]  # Limit to first 100
                }
            else:
                return {"error": "Analysis failed", "output": result.stderr}

        except FileNotFoundError:
            return {"error": "tshark not found. Install with: apt-get install tshark"}
        except subprocess.TimeoutExpired:
            return {"error": "Analysis timeout"}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON response"}

    def registry_analyze(self, hive_file: str) -> Dict[str, Any]:
        """
        Analyze Windows registry hive.

        Args:
            hive_file: Path to registry hive file

        Returns:
            Registry analysis
        """
        if not os.path.exists(hive_file):
            return {"error": "Registry hive not found"}

        cmd = ["regripper", "-r", hive_file]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            return {
                "status": "success",
                "hive_file": hive_file,
                "analysis": result.stdout
            }

        except FileNotFoundError:
            return {
                "error": "regripper not found",
                "alternative": "Use 'reglookup' or install RegRipper"
            }
        except subprocess.TimeoutExpired:
            return {"error": "Analysis timeout"}

    def evidence_chain_export(self, output_file: str) -> Dict[str, Any]:
        """
        Export chain of custody log.

        Args:
            output_file: Output file for evidence chain

        Returns:
            Export results
        """
        try:
            with open(output_file, 'w') as f:
                json.dump({
                    "evidence_chain": self.evidence_chain,
                    "export_time": datetime.now().isoformat(),
                    "total_actions": len(self.evidence_chain)
                }, f, indent=2)

            return {
                "status": "success",
                "output_file": output_file,
                "actions_logged": len(self.evidence_chain)
            }
        except Exception as e:
            return {"error": str(e)}


# Example usage
if __name__ == "__main__":
    toolkit = ForensicsToolkit()

    # Test file hashing
    print("=== File Hash Analysis ===")
    result = toolkit.file_hash_all("/etc/passwd")
    print(json.dumps(result, indent=2))

    # Test strings extraction
    print("\n=== String Extraction ===")
    result = toolkit.strings_extract("/bin/ls")
    print(json.dumps(result, indent=2))
