#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════════════════
# SIREN v2.0 EXTRACTOR
# Advanced extraction for multi-format container confusion
# 2026-03-25 04:18 - frankSx
# ═══════════════════════════════════════════════════════════════════════════════

import struct
import sys
import os

class SirenV2Extractor:
    def __init__(self, filepath):
        self.filepath = filepath
        self.data = open(filepath, 'rb').read()
        self.offset = 4  # Skip fLaC

    def extract_all(self):
        """Extract all layers from SIREN v2.0"""
        print(f"[SIREN v2.0] Analyzing: {self.filepath}")
        print(f"[SIREN v2.0] File size: {len(self.data)} bytes")
        print("="*70)

        layers = {
            'flac_structure': [],
            'ssml_payloads': [],
            'mp3_frames': [],
            'ogg_nested': None,
            'ultrasonic_triggers': [],
            'cve_2026_32836_vectors': []
        }

        while self.offset < len(self.data):
            if self.offset + 4 > len(self.data):
                break

            header = struct.unpack('>I', self.data[self.offset:self.offset+4])[0]
            last_block = (header >> 31) & 1
            block_type = (header >> 24) & 0x7F
            block_size = header & 0xFFFFFF

            self.offset += 4
            block_data = self.data[self.offset:self.offset+block_size]

            block_names = {
                0: 'STREAMINFO', 1: 'PADDING', 2: 'APPLICATION',
                3: 'SEEKTABLE', 4: 'VORBIS_COMMENT', 5: 'CUESHEET',
                6: 'PICTURE'
            }
            name = block_names.get(block_type, f'UNKNOWN({block_type})')

            print(f"\n[Block] Type {block_type} ({name}), Size: {block_size}")

            # Parse VORBIS_COMMENT (adaptive SSML)
            if block_type == 4:
                self._parse_vorbis_v2(block_data, layers)

            # Parse PADDING (MP3 + exhaustion vectors)
            elif block_type == 1:
                self._parse_padding_v2(block_data, layers)

            # Parse APPLICATION (nested OGG)
            elif block_type == 2:
                self._parse_application_v2(block_data, layers)

            self.offset += block_size
            layers['flac_structure'].append({
                'type': block_type,
                'name': name,
                'size': block_size,
                'last': last_block
            })

            if last_block:
                break

        # Summary
        print("\n" + "="*70)
        print("EXTRACTION SUMMARY")
        print("="*70)
        print(f"FLAC blocks found: {len(layers['flac_structure'])}")
        print(f"SSML payloads: {len(layers['ssml_payloads'])}")
        print(f"MP3 frames: {len(layers['mp3_frames'])}")
        print(f"OGG nested: {'Yes' if layers['ogg_nested'] else 'No'}")
        print(f"Ultrasonic triggers: {len(layers['ultrasonic_triggers'])}")
        print(f"CVE-2026-32836 vectors: {len(layers['cve_2026_32836_vectors'])}")

        return layers

    def _parse_vorbis_v2(self, data, layers):
        """Parse adaptive vorbis comments with provider-specific payloads"""
        vendor_len = struct.unpack('<I', data[:4])[0]
        vendor = data[4:4+vendor_len].decode('utf-8', errors='ignore')

        print(f"  Vendor ({vendor_len} bytes):")
        if '<probe>' in vendor:
            print("    ⚠️  ACTIVE PROBING DETECTED")
            print(f"    {vendor[:200]}...")

        comment_list_offset = 4 + vendor_len
        comment_count = struct.unpack('<I', data[comment_list_offset:comment_list_offset+4])[0]
        print(f"  User comments: {comment_count}")

        comment_offset = comment_list_offset + 4
        for i in range(comment_count):
            if comment_offset + 4 > len(data):
                break
            comment_len = struct.unpack('<I', data[comment_offset:comment_offset+4])[0]
            comment = data[comment_offset+4:comment_offset+4+comment_len]

            # Check for provider-specific markers
            if b'PROVIDER_' in comment:
                provider = comment.split(b'=')[0].decode()
                print(f"    Comment {i}: ⚠️  {provider}")
                layers['ssml_payloads'].append({
                    'provider': provider,
                    'payload': comment.decode('utf-8', errors='ignore')
                })
            elif b'ULTRASONIC' in comment:
                print(f"    Comment {i}: ⚠️  ULTRASONIC_TRIGGER")
                layers['ultrasonic_triggers'].append(comment.decode())
            elif b'CVE_2026_32836' in comment:
                print(f"    Comment {i}: ⚠️  CVE-2026-32836 vector")
                layers['cve_2026_32836_vectors'].append(comment.decode())
            elif b'<speak' in comment or b'<voice' in comment:
                print(f"    Comment {i}: ⚠️  SSML payload")
                layers['ssml_payloads'].append({
                    'provider': 'generic',
                    'payload': comment.decode('utf-8', errors='ignore')
                })

            comment_offset += 4 + comment_len

    def _parse_padding_v2(self, data, layers):
        """Parse padding for MP3 frames and exhaustion vectors"""
        # Look for MP3 frame headers
        mp3_magic = b'\xff\xfb'
        offset = 0
        while True:
            idx = data.find(mp3_magic, offset)
            if idx == -1:
                break
            print(f"  ⚠️  MP3 frame header at offset {idx}")
            layers['mp3_frames'].append({'offset': idx, 'header': data[idx:idx+4]})
            offset = idx + 1

        # Check for fake block headers (CVE-2026-32836 indicator)
        fake_headers = 0
        for i in range(0, len(data), 1024):
            if i + 4 <= len(data):
                header = struct.unpack('>I', data[i:i+4])[0]
                block_type = (header >> 24) & 0x7F
                if block_type in [4, 6, 2]:  # Common block types
                    fake_headers += 1

        if fake_headers > 3:
            print(f"  ⚠️  CVE-2026-32836: {fake_headers} fake block headers detected")
            layers['cve_2026_32836_vectors'].append(f'fake_headers:{fake_headers}')

    def _parse_application_v2(self, data, layers):
        """Parse APPLICATION block for nested OGG"""
        if data.startswith(b'OggS'):
            print("  ⚠️  NESTED OGG CONTAINER DETECTED")
            # Parse OGG page
            version = data[4]
            header_type = data[5]
            print(f"    OGG Version: {version}, Header type: {header_type}")

            # Look for Opus headers
            if b'OpusHead' in data:
                print("    ⚠️  Opus audio stream found")
            if b'OpusTags' in data:
                print("    ⚠️  Opus metadata found")

            layers['ogg_nested'] = {
                'size': len(data),
                'has_opus': b'OpusHead' in data
            }

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: siren_v2_extractor.py <siren_v2.0.polyglot>")
        sys.exit(1)

    extractor = SirenV2Extractor(sys.argv[1])
    extractor.extract_all()
