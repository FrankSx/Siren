#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════════════════
# SIREN EXTRACTOR v1.0
# Extracts hidden payloads from SIREN FLAC polyglots
# 2026-03-24 06:23 - frankSx
# ═══════════════════════════════════════════════════════════════════════════════

import struct
import base64
import sys

def extract_siren_payloads(flac_path):
    """
    Extract SSML and WASM payloads from SIREN polyglot
    Demonstrates the parser differential exploitation
    """
    with open(flac_path, 'rb') as f:
        data = f.read()

    print(f"[+] Analyzing: {flac_path}")
    print(f"[+] File size: {len(data)} bytes")

    # Verify FLAC marker
    if not data.startswith(b'fLaC'):
        print("[-] Not a valid FLAC file")
        return

    print("[✓] Valid FLAC container detected")

    offset = 4  # Skip 'fLaC'
    ssml_parts = []
    wasm_candidate = None

    while offset < len(data):
        # Read block header
        if offset + 4 > len(data):
            break

        header = struct.unpack('>I', data[offset:offset+4])[0]
        last_block = (header >> 31) & 1
        block_type = (header >> 24) & 0x7F
        block_size = header & 0xFFFFFF

        offset += 4
        block_data = data[offset:offset+block_size]

        # Parse VORBIS_COMMENT (type 4)
        if block_type == 4:
            print("\n[✓] VORBIS_COMMENT block found - potential SSML injection")
            # Parse vendor string
            vendor_len = struct.unpack('<I', block_data[:4])[0]
            vendor = block_data[4:4+vendor_len].decode('utf-8', errors='ignore')
            print(f"    Vendor string ({vendor_len} bytes):")
            print(f"    {vendor[:200]}...")

            if '<speak' in vendor or '<voice' in vendor:
                print("    ⚠️  SSML DETECTED in vendor string!")
                ssml_parts.append(vendor)

            # Parse user comments
            comment_list_offset = 4 + vendor_len
            if comment_list_offset < len(block_data):
                comment_count = struct.unpack('<I', block_data[comment_list_offset:comment_list_offset+4])[0]
                print(f"    User comments: {comment_count}")

                comment_offset = comment_list_offset + 4
                for i in range(comment_count):
                    if comment_offset + 4 > len(block_data):
                        break
                    comment_len = struct.unpack('<I', block_data[comment_offset:comment_offset+4])[0]
                    comment = block_data[comment_offset+4:comment_offset+4+comment_len].decode('utf-8', errors='ignore')

                    if 'WASM:' in comment or '</voice>' in comment or '</speak>' in comment:
                        print(f"    Comment {i}: ⚠️  PAYLOAD DETECTED")
                        print(f"        {comment[:100]}...")
                        ssml_parts.append(comment)

                    comment_offset += 4 + comment_len

        # Parse PADDING (type 1) - WASM hidden here
        elif block_type == 1:
            print(f"\n[✓] PADDING block found ({block_size} bytes)")
            # Check for WASM magic in padding
            if b'\x00asm' in block_data:
                wasm_start = block_data.find(b'\x00asm')
                print(f"    ⚠️  WASM MAGIC FOUND at offset {wasm_start} within padding!")
                # Extract WASM (look for reasonable end)
                wasm_candidate = block_data[wasm_start:]
                # Trim trailing zeros
                wasm_candidate = wasm_candidate.rstrip(b'\x00')
                print(f"    Extracted WASM: {len(wasm_candidate)} bytes")

        offset += block_size

        if last_block:
            break

    # Reconstruct full SSML
    if ssml_parts:
        print("\n" + "="*60)
        print("RECONSTRUCTED SSML PAYLOAD:")
        print("="*60)
        full_ssml = ''.join(ssml_parts)
        print(full_ssml[:500])
        if len(full_ssml) > 500:
            print("...")
        print("="*60)

    # Save WASM
    if wasm_candidate:
        wasm_path = flac_path.replace('.flac', '_extracted.wasm')
        with open(wasm_path, 'wb') as f:
            f.write(wasm_candidate)
        print(f"\n[✓] WASM module saved: {wasm_path}")

        # Verify WASM
        if wasm_candidate[:4] == b'\x00asm':
            version = struct.unpack('<I', wasm_candidate[4:8])[0]
            print(f"    Valid WebAssembly module (version {version})")

            # List exports (simple parser)
            offset = 8
            while offset < len(wasm_candidate):
                if offset >= len(wasm_candidate):
                    break
                section_id = wasm_candidate[offset]
                if section_id == 0:  # custom section
                    break
                if section_id == 7:  # export section
                    # Quick and dirty export listing
                    print(f"    Exports found in section at offset {offset}")
                offset += 1

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: siren_extractor.py <siren_polyglot.flac>")
        sys.exit(1)

    extract_siren_payloads(sys.argv[1])
