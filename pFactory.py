#!/usr/bin/env python3
"""
AES-256-CBC Shellcode Encryptor (Zero Padding)
Python port of the C# AES encryptor by Connor McGarr / ired.team style.

Usage:
    python3 aes_encryptor.py payload.bin

Output (to stdout):
    string finalPayload = "<base64>";
    byte[] key = new byte[32] { 0x..., ... };
    byte[] iv  = new byte[16] { 0x..., ... };
"""

import base64
import os
import sys
from Crypto.Cipher import AES


# ------------------------------------------------------------------
# Zero-pad / unpad  (matches .NET PaddingMode.Zeros)
# ------------------------------------------------------------------
def zeros_pad(data: bytes, block_size: int = 16) -> bytes:
    """Pad with \\x00 bytes up to the next block boundary.
    If already aligned, nothing is added (same as .NET Zero padding)."""
    remainder = len(data) % block_size
    if remainder == 0:
        return data
    return data + b'\x00' * (block_size - remainder)


def zeros_unpad(data: bytes) -> bytes:
    """Strip trailing null bytes (reverse of zeros_pad)."""
    return data.rstrip(b'\x00')


# ------------------------------------------------------------------
# Encryption  (identical semantics to the C# version)
# ------------------------------------------------------------------
def encrypt(buf: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-CBC encrypt with Zero padding."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = zeros_pad(buf)
    return cipher.encrypt(padded)


# ------------------------------------------------------------------
# Format helpers
# ------------------------------------------------------------------
def format_csharp_byte_array(name: str, data: bytes) -> str:
    """Return a C# byte array literal, e.g.:
    byte[] key = new byte[32] { 0xab, 0xcd, ... };
    """
    hex_bytes = ", ".join(f"0x{b:02x}" for b in data)
    return f"byte[] {name} = new byte[{len(data)}] {{ {hex_bytes} }};"


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------
def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <shellcode.bin>", file=sys.stderr)
        sys.exit(1)

    bin_path = sys.argv[1]

    # 1. Read raw shellcode
    with open(bin_path, "rb") as f:
        buf = f.read()

    print(f"[*] Read {len(buf)} bytes from {bin_path}", file=sys.stderr)

    # 2. Generate random AES-256 key and IV
    key = os.urandom(32)   # 256 bits
    iv  = os.urandom(16)   # 128 bits

    # 3. Encrypt
    encrypted_data = encrypt(buf, key, iv)

    # 4. Base64-encode the ciphertext
    final_payload = base64.b64encode(encrypted_data).decode()

    # 5. Print everything (matching the C# output format)
    print(f"[*] Final Payload:")
    print(f'string finalPayload = "{final_payload}";')
    print()
    print(format_csharp_byte_array("key", key))
    print(format_csharp_byte_array("iv",  iv))


if __name__ == "__main__":
    main()