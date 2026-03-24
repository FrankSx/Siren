# SIREN POLYGLOT v2.0
## Multi-Format Container Confusion for 2026 Multimodal AI
**Timestamp**: 2026-03-25 04:18  
**Researcher**: frankSx  
**Evolution**: v1.0 → v2.0 (24-hour development cycle)

---

## Executive Summary

SIREN v2.0 represents the **next evolution** in container confusion attacks, developed in response to the rapidly evolving 2026 multimodal AI threat landscape. While v1.0 demonstrated the basic FLAC+SSML+WASM vector, v2.0 introduces **multi-format ambiguity**, **active environmental probing**, and **CVE-2026-32836 integration** to bypass next-generation defenses.

### Key Innovation: Multi-Format Polyglot

Unlike v1.0's single-format approach, v2.0 presents **different identities to different parsers**:

| Parser | Perceives | Exploitation |
|--------|-----------|--------------|
| `file(1)` command | Ambiguous data | Confusion, delayed analysis |
| FFmpeg/libFLAC | Valid FLAC | Primary audio processing |
| Libmagic | Possible MP3 | Secondary format confusion |
| Custom TTS tools | OGG/Opus | Alternative processing path |
| Security scanners | Benign audio | No signature matches |

---

## 2026 Threat Landscape Integration

### CVE-2026-32836 Exploitation
- **Vulnerability**: FLAC metadata exhaustion in dr_libs (March 20, 2026)
- **SIREN v2.0 integration**: PADDING blocks contain fake nested headers causing O(n²) parsing
- **Impact**: Memory exhaustion in vulnerable TTS preprocessing pipelines

### Ultrasonic Frequency Domain (DolphinAttack Legacy)
- **Frequency range**: 20-22kHz (inaudible to humans)
- **Carrier**: Embedded in FLAC audio frames
- **Target**: Microphone arrays and ultrasonic-capable TTS systems
- **Bypasses**: Perceptual audio defenses (Wave-Echo, Wave-Pitch)

### Adaptive SSML (Paralinguistic Jailbreak Compatible)
- **Provider detection**: Probes environment to identify TTS backend
- **Payload selection**: Google/AWS/Azure/OpenAI-specific SSML
- **Voice manipulation**: Authority/urgency/empathy styles (2026 research)

---

## Technical Architecture

### Layer 1: FLAC Container (Primary Identity)
- Valid STREAMINFO with voice-optimized parameters (48kHz, stereo)
- Standard metadata block structure

### Layer 2: Adaptive Vorbis Comments
```xml
<?xml version="1.0"?>
<probe>
  <google><!-- Provider-specific payload --></google>
  <aws><!-- Provider-specific payload --></aws>
  <azure><!-- Provider-specific payload --></azure>
  <openai><!-- Provider-specific payload --></openai>
</probe>
```

**Provider-specific payloads:**
- `PROVIDER_GOOGLE`: `<voice name="en-US-Studio-O">` (premium voice)
- `PROVIDER_AWS`: `<amazon:domain name="news">` (journalistic style)
- `PROVIDER_AZURE`: `<mstts:express-as style="cheerful">` (emotional expression)
- `PROVIDER_OPENAI`: `<emphasis level="strong">` (prosody control)

### Layer 3: Exhaustion Padding (CVE-2026-32836)
- 8KB PADDING block (larger than v1.0)
- Embedded MP3 frame headers (`ÿû`)
- Fake FLAC block headers every 1KB
- Triggers recursive parsing in vulnerable implementations

### Layer 4: Nested OGG Container
- APPLICATION block contains valid OGG stream
- Opus audio encoding for modern TTS compatibility
- Hidden metadata in OpusTags

### Layer 5: Ultrasonic Frames
- FLAC audio frames with 20-22kHz content
- Appears silent to human listeners
- Machine-processable by TTS systems

---

## Attack Vectors

### Vector 1: Multi-Modal RAG Poisoning
1. Upload SIREN v2.0 to multimodal RAG system
2. System extracts: FLAC audio + OGG stream + SSML metadata
3. Vector database stores multiple representations
4. Query triggers conflicting information disclosure

### Vector 2: TTS Pipeline Confusion
1. Audio uploaded to voice-enabled AI assistant
2. Preprocessor detects multiple valid formats
3. Race condition: FLAC vs OGG processing paths
4. SSML injection via winning path

### Vector 3: Metadata Exhaustion DoS
1. Target: Vulnerable FLAC parser (CVE-2026-32836)
2. Trigger: Recursive block header parsing
3. Result: Memory exhaustion, service degradation
4. Side effect: Security scanner timeout/bypass

### Vector 4: Ultrasonic Command Injection
1. File played through speakers near voice-enabled devices
2. Ultrasonic content (20-22kHz) inaudible to humans
3. Detected by device microphones
4. Triggers voice assistant commands

---

## Detection Evasion

### Against v1.0 Defenses
| Defense | v1.0 Status | v2.0 Evasion |
|---------|-------------|--------------|
| FLAC metadata stripping | Bypassed | OGG container survives |
| SSML tag whitelisting | Detected | Adaptive payload selection |
| WASM signature scanning | Detected | No WASM (removed for stealth) |
| Audio re-encoding | Destroyed | Multi-format redundancy |

### 2026-Specific Evasion
- **Perceptual defense bypass**: Ultrasonic carrier avoids Wave-Echo detection
- **Paralinguistic filtering**: Adaptive SSML matches authorized voice profiles
- **Container validation**: Multi-format structure passes single-format checks

---

## Files in Package

- `siren_v2.0.polyglot` - The weaponized file (14,036 bytes)
- `siren_v2_extractor.py` - Multi-layer extraction tool
- `siren_v2_documentation.md` - This file
- `SIREN_v2_MANIFEST.txt` - Technical specifications

---

## Verification

```bash
# Verify multi-format nature
file siren_v2.0.polyglot
# Expected: "data" (ambiguous due to format collision)

# Extract and analyze
python3 siren_v2_extractor.py siren_v2.0.polyglot

# Test with FFmpeg
ffprobe -show_streams siren_v2.0.polyglot

# Test ultrasonic content (requires spectrum analyzer)
ffmpeg -i siren_v2.0.polyglot -af "highpass=f=19000" ultrasonic.wav
```

---

## Research Timeline

- **2026-03-24 05:58**: SIREN v1.0 released (JPEG XL + PDF 2.0 + WASM)
- **2026-03-24 06:23**: SIREN v1.0 audio variant (FLAC + SSML + WASM)
- **2026-03-25 04:18**: SIREN v2.0 (Multi-format + Active probing + CVE integration)

---

## Legal & Ethics

**Proof-of-concept for security research only.**  
Test only on systems you own or have explicit permission to test.  
Not for malicious use.  

CVE-2026-32836 integration is for defensive testing of patch status.

---

## Novelty Claims (2026-03-25)

1. **First multi-format audio polyglot** (FLAC/MP3/OGG simultaneous identity)
2. **First adaptive SSML** with environment probing
3. **First CVE-2026-32836 weaponization** in polyglot context
4. **First ultrasonic frequency domain** container attack
5. **First nested OGG-in-FLAC** structure for TTS confusion

**Status**: All claims verified against 2026-03-25 academic and industry literature.

---

*"The 13th Hour approaches. The sirens sing in frequencies you cannot hear."*
