SIREN v3.0 - Precise CVE-2026-32836 weaponization

Root cause: dr_flac.h <= 0.13.3, drflac__read_and_decode_metadata():
malloc(mimeLength + 1) at line 6750 and malloc(descriptionLength + 1) at
line 6772 execute BEFORE the blockSizeRemaining bounds check (6756+).
Both length fields are attacker-controlled BE uint32 in the PICTURE block.
Gate: only drflac_open_*_with_metadata() with non-NULL onMeta parses the
PICTURE body (dr_flac.h:6728). Fixed in fefced4 / 4f5a4cd / 663239a.

Files:
- siren_v3_generator.py   - regenerates both PoC files, tunable lengths
- siren_v3_harness.c      - vulnerable-target simulator (ASan malloc hook)
- SIREN_v3_DOCUMENTATION.md - full technical writeup + expected outcomes
- SIREN_v3_MANIFEST.txt   - spec sheet
- blog_post_cve_2026_32836.md - blog writeup (frankhacks.blogspot.com)

Generate the binaries (not committed; build locally):
  python3 siren_v3_generator.py --mode both
  # -> siren_v3_cve-2026-32836_minimal_78B.flac (78 bytes, ~4 GiB alloc)
  # -> siren_v3.0.polyglot.flac (372 bytes, dual-stage ~8 GiB + SSML carrier)

Verify:
  clang -fsanitize=address -O1 -g -o siren_harness siren_v3_harness.c
  ./siren_harness siren_v3_cve-2026-32836_minimal_78B.flac

Expected: vulnerable build aborts at dr_flac.h:6750 malloc(4294967295);
patched build returns NULL cleanly.

Authorized security research / patch verification only.
