#!/usr/bin/env python3
import os
import sys
import struct

#
# === Decryption Functions ===
#

def xor_decrypt(buffer: bytearray, key: bytes) -> None:
    """XOR decryption (self-inverse operation)"""
    key_len = len(key)
    for i in range(len(buffer)):
        buffer[i] ^= key[i % key_len] ^ (i & 0xFF)


def inverse_substitute(buffer: bytearray) -> None:
    """Reverse S-box substitution using precomputed inverse S-box"""
    # Precomputed inverse AES S-box
    inv_sbox = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ]
    
    for i in range(len(buffer)):
        buffer[i] = inv_sbox[buffer[i]]


def inverse_rotate_bits(buffer: bytearray, n: int) -> None:
    """Rotate bits right (inverse of left rotation)"""
    n = n % 8
    for i in range(len(buffer)):
        buffer[i] = ((buffer[i] >> n) | ((buffer[i] << (8 - n)) & 0xFF)) & 0xFF


def inverse_interleave(data: bytearray) -> bytearray:
    """Reverse the byte interleaving
    
    C code interleaves: first_half -> even indices, second_half -> odd indices
    To reverse: even indices -> first_half, odd indices -> second_half
    """
    size = len(data)
    half = size >> 1
    result = bytearray(size)

    # Extract data from interleaved positions
    for i in range(half):
        result[i] = data[i * 2]           # Even positions -> first half
        result[half + i] = data[i * 2 + 1]  # Odd positions -> second half
    
    # Handle odd-sized data
    if size & 1:
        result[size - 1] = data[size - 1]
    
    return result


#
# === MAIN PROGRAM ===
#

def main():
    # Configuration
    filename = "presentation.enc"
    outname = "presentation.pdf"
    key = b"wa_db_chof_ki_dir_w_kmal_steps_lakhrin"
    
    # Check if file exists
    if not os.path.exists(filename):
        print(f"[!] Error: File '{filename}' not found.")
        sys.exit(1)
    
    # Read encrypted file
    try:
        with open(filename, "rb") as f:
            content = f.read()
    except Exception as e:
        print(f"[!] Error reading file: {e}")
        sys.exit(1)
    
    # Validate minimum file size
    if len(content) < 14:
        print(f"[!] Error: File too small (expected at least 14 bytes, got {len(content)})")
        sys.exit(1)
    
    # Extract header and metadata
    magic = content[:6]
    data = bytearray(content[14:])
    
    print(f"[+] Magic header: {magic}")
    print(f"[+] Encrypted data: {len(data)} bytes")
    
    # Validate header
    if magic != b"PDFENC":
        print(f"[!] Warning: Header mismatch. Expected b'PDFENC', got {magic}")
    
    #
    # Apply inverse operations in REVERSE ORDER
    # C encryption order: XOR -> S-box -> Rotate -> Interleave
    # Decryption order: Deinterleave -> Unrotate -> Inverse S-box -> XOR
    #
    
    print("\n[*] Stage 1: Deinterleaving bytes...")
    data = inverse_interleave(data)
    
    print("[*] Stage 2: Unrotating bits (rotate right by 5)...")
    inverse_rotate_bits(data, 5)
    
    print("[*] Stage 3: Inverse S-box substitution...")
    inverse_substitute(data)
    
    print("[*] Stage 4: XOR decryption...")
    xor_decrypt(data, key)
    
    # Verify PDF magic bytes
    if data[:4] == b'%PDF':
        print("\n[+] SUCCESS! Valid PDF header detected.")
    else:
        print(f"\n[!] Warning: Output doesn't start with PDF magic bytes.")
        print(f"    First 8 bytes: {data[:8].hex()}")
        print(f"    Expected: %PDF (hex: 25504446...)")
    
    # Write output
    try:
        with open(outname, "wb") as f:
            f.write(data)
        print(f"[+] Decrypted file written to: {outname}")
        print(f"[+] Output size: {len(data)} bytes")
    except Exception as e:
        print(f"[!] Error writing output file: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()