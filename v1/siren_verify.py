#!/usr/bin/env python3
# SIREN Verification Suite
# Validates polyglot functionality

import struct
import hashlib

def verify_polyglot(filepath):
    """Comprehensive verification of SIREN polyglot"""
    print(f"Verifying: {filepath}")
    print("="*60)

    with open(filepath, 'rb') as f:
        data = f.read()

    checks = []

    # Check 1: FLAC marker
    checks.append(("FLAC marker", data[:4] == b'fLaC'))

    # Check 2: STREAMINFO block present
    offset = 4
    has_streaminfo = False
    has_vorbis = False
    has_padding = False
    has_wasm = False
    has_ssml = False

    while offset < len(data):
        if offset + 4 > len(data):
            break
        header = struct.unpack('>I', data[offset:offset+4])[0]
        block_type = (header >> 24) & 0x7F
        block_size = header & 0xFFFFFF
        offset += 4
        block_data = data[offset:offset+block_size]

        if block_type == 0:
            has_streaminfo = True
        elif block_type == 4:
            has_vorbis = True
            # Check for SSML
            vendor_len = struct.unpack('<I', block_data[:4])[0]
            vendor = block_data[4:4+vendor_len]
            if b'<speak' in vendor or b'<voice' in vendor:
                has_ssml = True
        elif block_type == 1:
            has_padding = True
            if b'\x00asm' in block_data:
                has_wasm = True

        offset += block_size

    checks.append(("STREAMINFO block", has_streaminfo))
    checks.append(("VORBIS_COMMENT block", has_vorbis))
    checks.append(("SSML in vendor", has_ssml))
    checks.append(("PADDING block", has_padding))
    checks.append(("WASM in padding", has_wasm))

    # Print results
    all_pass = True
    for name, passed in checks:
        status = "✓" if passed else "✗"
        print(f"  [{status}] {name}")
        if not passed:
            all_pass = False

    print("="*60)
    if all_pass:
        print("✓ ALL CHECKS PASSED - Valid SIREN polyglot")
    else:
        print("✗ SOME CHECKS FAILED - May not be valid")

    # Calculate hashes
    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    print(f"\nMD5:    {md5}")
    print(f"SHA256: {sha256}")

    return all_pass

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: siren_verify.py <siren_polyglot.flac>")
        sys.exit(1)

    verify_polyglot(sys.argv[1])
