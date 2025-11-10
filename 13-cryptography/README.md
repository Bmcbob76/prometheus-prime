# Cryptography & Cryptanalysis

## Overview

Cryptographic attacks involve breaking or bypassing encryption, hashing, and other cryptographic mechanisms to access protected data.

---

## Hash Functions

### Common Hash Algorithms
```
MD5: 128-bit (BROKEN - collision attacks)
SHA-1: 160-bit (DEPRECATED - collision attacks)
SHA-256: 256-bit (Secure)
SHA-512: 512-bit (Secure)
SHA-3: Variable length (Secure)
NTLM: Windows authentication hash
bcrypt: Password hashing with salt
scrypt: Memory-hard password hashing
Argon2: Modern password hashing
```

### Hash Identification
```bash
# hash-identifier
hash-identifier

# hashid
hashid <hash>
hashid -m <hash>  # Show hashcat modes

# Manual identification
MD5: 32 hex characters
SHA-1: 40 hex characters
SHA-256: 64 hex characters
NTLM: 32 hex characters (similar to MD5)
```

### Hash Cracking
See `06-password-attacks/` for detailed hash cracking techniques.

---

## Encryption Attacks

### Block Cipher Modes

#### ECB (Electronic Codebook)
```
Weakness: Same plaintext = same ciphertext
Attack: Pattern analysis, block reordering

Detection:
- Identical ciphertext blocks
- Penguin image test
```

#### CBC (Cipher Block Chaining)
```
Weakness: Padding oracle attacks
Attack: Bit flipping, padding oracle

# Padbuster (padding oracle attack)
padbuster http://target/decrypt.php <ciphertext> <block_size> -cookies "auth=<ciphertext>"
```

#### CTR (Counter Mode)
```
Weakness: Nonce reuse
Attack: XOR plaintext recovery with same nonce
```

### RSA Attacks

#### Small Exponent Attack
```python
# If e = 3 and message is small
# m^3 < n, then c = m^3
# Simply take cube root

import gmpy2
c = <ciphertext>
m = gmpy2.iroot(c, 3)[0]
print(m)
```

#### Common Modulus Attack
```python
# If same message encrypted with same n but different e
# Can recover plaintext without private key

# Given: c1 = m^e1 mod n, c2 = m^e2 mod n
# If gcd(e1, e2) = 1
# Use Extended Euclidean algorithm
```

#### Wiener's Attack
```python
# When d is small relative to n
# Use continued fractions

from owiener import attack
d = attack(e, n)
```

#### Factorization Attacks
```bash
# Factor n to get p and q
# Tools:
# - yafu
# - msieve
# - factordb.com (database of known factors)

# If n is small enough
factor <n>

# Or use Python
from sympy import factorint
factors = factorint(n)
```

### Weak Random Number Generators

```python
# Predictable RNG
import random
random.seed(known_seed)
# Can predict future values

# Attack /dev/urandom vs /dev/random
# Some systems use weak entropy sources
```

---

## SSL/TLS Attacks

### POODLE (Padding Oracle On Downgraded Legacy Encryption)
```bash
# Forces downgrade to SSL 3.0
# Tests for POODLE vulnerability
./poodle-test.sh target.com 443
```

### BEAST (Browser Exploit Against SSL/TLS)
```
Affects: TLS 1.0 with CBC
Attack: Chosen plaintext attack against CBC
Mitigation: Use TLS 1.2+, RC4 (though RC4 also weak)
```

### CRIME/BREACH (Compression attacks)
```
Attack: Use compression side-channel to recover secrets
Affects: TLS compression (CRIME), HTTP compression (BREACH)
Mitigation: Disable compression
```

### Heartbleed (CVE-2014-0160)
```bash
# OpenSSL vulnerability
# Read memory from server

# Test for Heartbleed
nmap -p 443 --script ssl-heartbleed target.com

# Exploit
python heartbleed-poc.py target.com
```

### SSL/TLS Scanning
```bash
# testssl.sh
./testssl.sh target.com

# SSLyze
sslyze --regular target.com

# SSLScan
sslscan target.com

# Nmap SSL scripts
nmap --script ssl-enum-ciphers -p 443 target.com
nmap --script ssl-cert,ssl-date,ssl-known-key -p 443 target.com
```

---

## Cryptographic Protocol Attacks

### Downgrade Attacks
```
Force use of weaker cryptography:
- SSL 3.0 instead of TLS 1.2
- Weak ciphers
- Weak key exchange
```

### Man-in-the-Middle
```bash
# SSL stripping
sslstrip -l 8080

# Bettercap MITM with SSL stripping
bettercap -iface eth0
> set http.proxy.sslstrip true
> http.proxy on

# Ettercap MITM
ettercap -T -M arp:remote /target// -q
```

### Certificate Attacks
```bash
# Self-signed certificates
# Expired certificates
# Mismatched common names
# Weak signature algorithms (MD5, SHA-1)

# Create fake certificate
openssl req -new -x509 -days 365 -nodes -out cert.pem -keyout key.pem

# Certificate transparency logs
# Check for misissued certificates
https://crt.sh/
```

---

## Weak Cryptography

### Deprecated Algorithms
```
DO NOT USE:
- DES (56-bit key, broken)
- 3DES (deprecated)
- MD5 (collision attacks)
- SHA-1 (collision attacks)
- RC4 (biased output)
- ECB mode (pattern leakage)
```

### Weak Key Lengths
```
Minimum recommended:
- Symmetric: 128 bits (AES-128)
- RSA: 2048 bits
- ECC: 256 bits
- DH: 2048 bits
```

---

## Steganography

### Hide Data in Images
```bash
# Steghide (JPEG, BMP, WAV, AU)
steghide embed -cf image.jpg -ef secret.txt -p password
steghide extract -sf image.jpg -p password

# Outguess (JPEG)
outguess -d secret.txt cover.jpg stego.jpg
outguess -r stego.jpg output.txt

# LSB Steganography
# Modify least significant bits of pixels
python lsb.py embed -i image.png -f secret.txt -o stego.png
python lsb.py extract -i stego.png -o recovered.txt
```

### Detect Steganography
```bash
# StegDetect
stegdetect image.jpg

# Stegsolve (Java tool)
java -jar stegsolve.jar

# zsteg (PNG & BMP)
zsteg image.png

# Binwalk (find embedded files)
binwalk image.jpg
binwalk -e image.jpg  # Extract embedded files

# Strings
strings image.jpg | grep -i "flag\|password"

# ExifTool (metadata)
exiftool image.jpg
```

### Hide Data in Audio
```bash
# DeepSound
# Sonic Visualizer
# Audacity (analyze waveform)
```

### Other Steganography
```bash
# Hide in whitespace
# Zero-width characters
# Text encoding

# Hide in files
binwalk suspicious_file
foremost suspicious_file
dd if=file.zip bs=1 skip=12345 of=hidden.txt
```

---

## Classical Ciphers (CTF)

### Caesar Cipher
```python
# Shift each letter by n positions
def caesar_decrypt(ciphertext, shift):
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            shifted = ord(char) - shift
            if char.isupper():
                if shifted < ord('A'):
                    shifted += 26
            else:
                if shifted < ord('a'):
                    shifted += 26
            plaintext += chr(shifted)
        else:
            plaintext += char
    return plaintext

# Try all shifts
for i in range(26):
    print(f"Shift {i}: {caesar_decrypt(ciphertext, i)}")
```

### Vigenère Cipher
```bash
# Online tools or custom scripts
# Key length detection via Kasiski examination
# Index of coincidence
```

### Substitution Cipher
```python
# Frequency analysis
from collections import Counter

def frequency_analysis(text):
    freq = Counter(text.upper())
    return freq.most_common()

# English letter frequency: ETAOIN SHRDLU
```

### Rail Fence Cipher
```python
def rail_fence_decrypt(cipher, rails):
    fence = [['' for _ in range(len(cipher))] for _ in range(rails)]
    # Implementation...
```

### Transposition Ciphers
```python
# Columnar transposition
# Route cipher
# Myszkowski transposition
```

---

## Modern Cipher Attacks

### AES Attacks
```
Theoretical attacks exist but impractical:
- Related-key attacks
- Side-channel attacks (timing, power analysis)

Best attack on AES-256: ~2^254 operations (infeasible)

Real-world attacks focus on:
- Weak keys
- Poor implementation
- Side channels
```

### Timing Attacks
```python
# Measure execution time to leak information
import time

start = time.time()
result = cryptographic_operation(input)
elapsed = time.time() - start

# Differences in timing can reveal information about keys
```

### Side-Channel Attacks
```
Types:
1. Timing attacks
2. Power analysis (SPA, DPA)
3. Electromagnetic analysis
4. Acoustic cryptanalysis
5. Cache-timing attacks
```

---

## Key Exchange Attacks

### Diffie-Hellman Attacks
```
Weak parameters:
- Small prime p
- Weak generator g
- Man-in-the-middle if no authentication

Logjam attack:
- Downgrade to export-grade 512-bit DH
```

### ECDH Attacks
```
Invalid curve attacks:
- Force use of weak curve
- Small subgroup attacks
```

---

## Cryptanalysis Tools

### Hash Cracking
```bash
# John the Ripper
john hashes.txt

# Hashcat
hashcat -m <mode> hashes.txt wordlist.txt

# CrackStation (online)
# https://crackstation.net/
```

### Cipher Tools
```bash
# CyberChef (web-based)
# https://gchq.github.io/CyberChef/

# dcode.fr (cipher identifier and solver)
# https://www.dcode.fr/

# Cryptool
# https://www.cryptool.org/
```

### RSA Tools
```python
# RsaCtfTool
python3 RsaCtfTool.py --publickey pubkey.pem --uncipherfile ciphertext

# PyCrypto/PyCryptodome
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
```

### SSL/TLS Tools
```bash
# OpenSSL
openssl s_client -connect target.com:443
openssl s_client -connect target.com:443 -tls1_2

# testssl.sh
./testssl.sh --full target.com

# SSLyze
sslyze --regular target.com
```

---

## Encoding vs Encryption vs Hashing

### Encoding (Reversible, no key)
```bash
# Base64
echo "data" | base64
echo "ZGF0YQo=" | base64 -d

# Hex
echo "data" | xxd -p
echo "64617461" | xxd -r -p

# URL encoding
# HTML encoding
# ASCII/Unicode conversions
```

### Encryption (Reversible, with key)
```
Symmetric: AES, ChaCha20
Asymmetric: RSA, ECC
```

### Hashing (One-way, no key)
```
MD5, SHA family, NTLM, bcrypt, etc.
Cannot be reversed (only brute-forced)
```

---

## Certificate Pinning Bypass

### Android
```bash
# Frida
frida -U -f com.example.app -l bypass-ssl.js

# Objection
objection -g com.example.app explore
android sslpinning disable

# Magisk + TrustMeAlready module
```

### iOS
```bash
# SSL Kill Switch
# Burp Suite Mobile Assistant

# Frida script
frida -U -f com.example.app -l ios-ssl-bypass.js
```

---

## Quantum Cryptography Threats

### Post-Quantum Algorithms
```
Quantum computers threaten:
- RSA
- Diffie-Hellman
- Elliptic Curve Cryptography

Post-quantum safe:
- Lattice-based cryptography
- Hash-based cryptography
- Code-based cryptography
- Multivariate cryptography
```

---

## Cryptographic Best Practices

### Encryption
1. Use AES-256 or ChaCha20
2. Use GCM or Poly1305 for authenticated encryption
3. Generate strong random keys
4. Never reuse nonces/IVs
5. Use HKDF for key derivation

### Hashing
1. Use SHA-256 or SHA-3
2. For passwords: Argon2 > bcrypt > scrypt
3. Always salt passwords
4. Use unique salts per password
5. Use slow hashing for passwords

### Key Management
1. Secure key generation (CSPRNG)
2. Secure key storage (HSM, key vaults)
3. Key rotation
4. Principle of least privilege
5. Secure key destruction

### SSL/TLS
1. Use TLS 1.2 minimum (TLS 1.3 preferred)
2. Disable SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1
3. Use strong cipher suites
4. Implement HSTS
5. Certificate pinning
6. Regular certificate rotation

---

## CTF Cryptography Challenges

### Common Patterns
```
1. Classical ciphers (Caesar, Vigenère, etc.)
2. Weak RSA parameters
3. ECB mode detection
4. XOR with repeating key
5. Hash length extension
6. Padding oracle
7. Steganography
8. Custom encryption schemes
9. Weak random number generators
10. Known plaintext attacks
```

### Tools Arsenal
```
- CyberChef
- RsaCtfTool
- Hashcat/John
- Python (PyCryptodome)
- OpenSSL
- SageMath (for mathematical attacks)
- z3 (SMT solver)
```

---

## Resources

### Learning
- Cryptopals Challenges
- CryptoHack
- Coursera - Cryptography I (Stanford)
- Applied Cryptography (Bruce Schneier)

### Tools
- CyberChef
- Hashcat
- John the Ripper
- OpenSSL
- RsaCtfTool
- Cryptool

### References
- NIST Cryptographic Standards
- OWASP Cryptographic Storage Cheat Sheet
- IETF RFCs (cryptographic protocols)

---

## Further Reading

- Applied Cryptography (Bruce Schneier)
- Serious Cryptography (Jean-Philippe Aumasson)
- Cryptography Engineering (Ferguson, Schneier, Kohno)
- Understanding Cryptography (Paar, Pelzl)
