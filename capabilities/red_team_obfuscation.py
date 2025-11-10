"""RED TEAM - Payload Obfuscation
AUTHORIZED USE ONLY - For penetration testing in controlled lab environments
"""
import logging
import base64
import zlib
import os
import random
import string
from typing import Dict, List, Optional, Any

logger = logging.getLogger("PROMETHEUS-PRIME.RedTeam.Obfuscation")

class PayloadObfuscation:
    """
    Payload obfuscation techniques for authorized penetration testing.
    Used to test security controls and evasion detection capabilities.
    """

    def __init__(self):
        self.logger = logger
        self.logger.info("PayloadObfuscation module initialized - AUTHORIZED PENTESTING ONLY")

    def base64_encode(self, payload: str, iterations: int = 1) -> Dict[str, Any]:
        """
        Multi-layer base64 encoding
        Tests basic encoding detection
        """
        try:
            encoded = payload
            for i in range(iterations):
                encoded = base64.b64encode(encoded.encode()).decode()

            return {
                "method": "base64_encoding",
                "status": "complete",
                "iterations": iterations,
                "original_size": len(payload),
                "encoded_size": len(encoded),
                "payload": encoded
            }

        except Exception as e:
            self.logger.error(f"Base64 encoding failed: {e}")
            return {"method": "base64", "status": "failed", "error": str(e)}

    def xor_encode(self, payload: str, key: str = None) -> Dict[str, Any]:
        """
        XOR encryption with key
        Tests cryptographic obfuscation detection
        """
        try:
            if not key:
                key = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

            # XOR encode
            encoded_bytes = bytearray()
            for i, byte in enumerate(payload.encode()):
                key_byte = ord(key[i % len(key)])
                encoded_bytes.append(byte ^ key_byte)

            encoded_hex = encoded_bytes.hex()

            return {
                "method": "xor_encoding",
                "status": "complete",
                "key": key,
                "original_size": len(payload),
                "encoded_size": len(encoded_hex),
                "payload_hex": encoded_hex,
                "decoder_stub": f"# Decode with: bytes.fromhex('{encoded_hex}').decode()"
            }

        except Exception as e:
            self.logger.error(f"XOR encoding failed: {e}")
            return {"method": "xor", "status": "failed", "error": str(e)}

    def compress_payload(self, payload: str) -> Dict[str, Any]:
        """
        Compress payload using zlib
        Tests compression-based obfuscation detection
        """
        try:
            compressed = zlib.compress(payload.encode())
            compressed_b64 = base64.b64encode(compressed).decode()

            return {
                "method": "zlib_compression",
                "status": "complete",
                "original_size": len(payload),
                "compressed_size": len(compressed),
                "compression_ratio": round(len(compressed) / len(payload), 2),
                "payload_base64": compressed_b64,
                "decoder_stub": "import zlib, base64; zlib.decompress(base64.b64decode(payload))"
            }

        except Exception as e:
            self.logger.error(f"Compression failed: {e}")
            return {"method": "compression", "status": "failed", "error": str(e)}

    def string_reversal(self, payload: str) -> Dict[str, Any]:
        """
        Reverse string obfuscation
        Simple obfuscation for signature evasion
        """
        try:
            reversed_payload = payload[::-1]

            return {
                "method": "string_reversal",
                "status": "complete",
                "original": payload[:50] + "...",
                "reversed": reversed_payload[:50] + "...",
                "payload": reversed_payload,
                "decoder_stub": "payload[::-1]"
            }

        except Exception as e:
            self.logger.error(f"String reversal failed: {e}")
            return {"method": "reversal", "status": "failed", "error": str(e)}

    def hex_encode(self, payload: str) -> Dict[str, Any]:
        """
        Hexadecimal encoding
        Tests hex-based obfuscation detection
        """
        try:
            hex_encoded = payload.encode().hex()

            return {
                "method": "hex_encoding",
                "status": "complete",
                "original_size": len(payload),
                "encoded_size": len(hex_encoded),
                "payload_hex": hex_encoded,
                "decoder_stub": "bytes.fromhex(payload).decode()"
            }

        except Exception as e:
            self.logger.error(f"Hex encoding failed: {e}")
            return {"method": "hex", "status": "failed", "error": str(e)}

    def variable_name_obfuscation(self, code: str) -> Dict[str, Any]:
        """
        Obfuscate Python variable names
        Tests source code obfuscation detection
        """
        try:
            import re

            # Find variable assignments
            vars_found = set(re.findall(r'\b([a-z_][a-z0-9_]*)\s*=', code, re.IGNORECASE))

            # Generate random names
            var_mapping = {}
            for var in vars_found:
                if var not in ['if', 'for', 'while', 'def', 'class', 'import', 'from']:
                    random_name = '_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
                    var_mapping[var] = random_name

            # Replace variables
            obfuscated = code
            for original, replacement in var_mapping.items():
                obfuscated = re.sub(r'\b' + original + r'\b', replacement, obfuscated)

            return {
                "method": "variable_obfuscation",
                "status": "complete",
                "variables_renamed": len(var_mapping),
                "mapping": var_mapping,
                "original_code_length": len(code),
                "obfuscated_code_length": len(obfuscated),
                "obfuscated_code": obfuscated
            }

        except Exception as e:
            self.logger.error(f"Variable obfuscation failed: {e}")
            return {"method": "variable_obfuscation", "status": "failed", "error": str(e)}

    def char_substitution(self, payload: str) -> Dict[str, Any]:
        """
        Character substitution obfuscation
        Tests character-level pattern matching
        """
        try:
            substitutions = {
                'a': '@', 'e': '3', 'i': '!', 'o': '0', 's': '$',
                'A': '4', 'E': '3', 'I': '1', 'O': '0', 'S': '5'
            }

            obfuscated = payload
            for original, replacement in substitutions.items():
                obfuscated = obfuscated.replace(original, replacement)

            return {
                "method": "char_substitution",
                "status": "complete",
                "substitutions_made": sum(1 for c in payload if c in substitutions),
                "original": payload[:100],
                "obfuscated": obfuscated,
                "reversal_map": {v: k for k, v in substitutions.items()}
            }

        except Exception as e:
            self.logger.error(f"Character substitution failed: {e}")
            return {"method": "char_sub", "status": "failed", "error": str(e)}

    def powershell_obfuscation(self, ps_command: str) -> Dict[str, Any]:
        """
        Obfuscate PowerShell commands
        Tests PowerShell obfuscation detection
        """
        try:
            # Base64 encode PowerShell command
            encoded_bytes = ps_command.encode('utf-16-le')
            encoded_b64 = base64.b64encode(encoded_bytes).decode()

            # Create obfuscated PowerShell command
            obfuscated_cmd = f"powershell.exe -EncodedCommand {encoded_b64}"

            return {
                "method": "powershell_obfuscation",
                "status": "complete",
                "original_command": ps_command,
                "encoded_command": encoded_b64,
                "full_command": obfuscated_cmd,
                "execution_example": obfuscated_cmd
            }

        except Exception as e:
            self.logger.error(f"PowerShell obfuscation failed: {e}")
            return {"method": "powershell", "status": "failed", "error": str(e)}

    def bash_obfuscation(self, bash_command: str) -> Dict[str, Any]:
        """
        Obfuscate Bash commands
        Tests shell command obfuscation detection
        """
        try:
            # Base64 encoding
            encoded_b64 = base64.b64encode(bash_command.encode()).decode()

            # Create obfuscated bash command
            obfuscated_cmd = f"echo {encoded_b64} | base64 -d | bash"

            # Hex encoding alternative
            hex_encoded = bash_command.encode().hex()
            hex_cmd = f"echo {hex_encoded} | xxd -r -p | bash"

            return {
                "method": "bash_obfuscation",
                "status": "complete",
                "original_command": bash_command,
                "base64_variant": obfuscated_cmd,
                "hex_variant": hex_cmd,
                "execution_examples": [obfuscated_cmd, hex_cmd]
            }

        except Exception as e:
            self.logger.error(f"Bash obfuscation failed: {e}")
            return {"method": "bash", "status": "failed", "error": str(e)}

    def multilayer_obfuscation(self, payload: str, layers: List[str] = None) -> Dict[str, Any]:
        """
        Apply multiple obfuscation layers
        Tests multi-stage deobfuscation capabilities
        """
        try:
            if not layers:
                layers = ['base64', 'compress', 'hex']

            result = payload
            applied_layers = []

            for layer in layers:
                if layer == 'base64':
                    result = base64.b64encode(result.encode()).decode()
                    applied_layers.append('base64')
                elif layer == 'compress':
                    result = base64.b64encode(zlib.compress(result.encode())).decode()
                    applied_layers.append('zlib+base64')
                elif layer == 'hex':
                    result = result.encode().hex()
                    applied_layers.append('hex')
                elif layer == 'xor':
                    key = 'K3Y'
                    result = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(result))
                    applied_layers.append('xor')

            return {
                "method": "multilayer_obfuscation",
                "status": "complete",
                "layers_applied": applied_layers,
                "layer_count": len(applied_layers),
                "original_size": len(payload),
                "final_size": len(result),
                "obfuscated_payload": result[:200] + "..." if len(result) > 200 else result
            }

        except Exception as e:
            self.logger.error(f"Multilayer obfuscation failed: {e}")
            return {"method": "multilayer", "status": "failed", "error": str(e)}

    def get_capabilities(self) -> List[str]:
        """Return list of available obfuscation methods"""
        return [
            "base64_encode",
            "xor_encode",
            "compress_payload",
            "string_reversal",
            "hex_encode",
            "variable_name_obfuscation",
            "char_substitution",
            "powershell_obfuscation",
            "bash_obfuscation",
            "multilayer_obfuscation"
        ]

__all__ = ["PayloadObfuscation"]
