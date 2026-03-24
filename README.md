# Siren
SIREN POLYGLOT v2.0
Multi-Format Container Confusion for 2026 Multimodal AI

Timestamp: 2026-03-25 04:18
Researcher: frankSx
Evolution: v1.0 → v2.0 (24-hour development cycle)
Executive Summary

SIREN v2.0 represents the next evolution in container confusion attacks, developed in response to the rapidly evolving 2026 multimodal AI threat landscape. While v1.0 demonstrated the basic FLAC+SSML+WASM vector, v2.0 introduces multi-format ambiguity, active environmental probing, and CVE-2026-32836 integration to bypass next-generation defenses.
Key Innovation: Multi-Format Polyglot

Unlike v1.0's single-format approach, v2.0 presents different identities to different parsers:
Parser 	Perceives 	Exploitation
file(1) command 	Ambiguous data 	Confusion, delayed analysis
FFmpeg/libFLAC 	Valid FLAC 	Primary audio processing
Libmagic 	Possible MP3 	Secondary format confusion
Custom TTS tools 	OGG/Opus 	Alternative processing path
Security scanners 	Benign audio 	No signature matches
2026 Threat Landscape Integration
CVE-2026-32836 Exploitation

    Vulnerability: FLAC metadata exhaustion in dr_libs (March 20, 2026)
    SIREN v2.0 integration: PADDING blocks contain fake nested headers causing O(n²) parsing
    Impact: Memory exhaustion in vulnerable TTS preprocessing pipelines

Ultrasonic Frequency Domain (DolphinAttack Legacy)

    Frequency range: 20-22kHz (inaudible to humans)
    Carrier: Embedded in FLAC audio frames
    Target: Microphone arrays and ultrasonic-capable TTS systems
    Bypasses: Perceptual audio defenses (Wave-Echo, Wave-Pitch)

Adaptive SSML (Paralinguistic Jailbreak Compatible)

    Provider detection: Probes environment to identify TTS backend
    Payload selection: Google/AWS/Azure/OpenAI-specific SSML
    Voice manipulation: Authority/urgency/empathy styles (2026 research)

Technical Architecture
Layer 1: FLAC Container (Primary Identity)

    Valid STREAMINFO with voice-optimized parameters (48kHz, stereo)
    Standard metadata block structure

Layer 2: Adaptive Vorbis Comments

<?xml version="1.0"?>
<probe>
  <google><!-- Provider-specific payload --></google>
  <aws><!-- Provider-specific payload --></aws>
  <azure><!-- Provider-specific payload --></azure>
  <openai><!-- Provider-specific payload --></openai>
</probe>

Provider-specific payloads:

    PROVIDER_GOOGLE: <voice name="en-US-Studio-O"> (premium voice)
    PROVIDER_AWS: <amazon:domain name="news"> (journalistic style)
    PROVIDER_AZURE: <mstts:express-as style="cheerful"> (emotional expression)
    PROVIDER_OPENAI: <emphasis level="strong"> (prosody control)

Layer 3: Exhaustion Padding (CVE-2026-32836)

    8KB PADDING block (larger than v1.0)
    Embedded MP3 frame headers (ÿû)
    Fake FLAC block headers every 1KB
    Triggers recursive parsing in vulnerable implementations

Layer 4: Nested OGG Container

    APPLICATION block contains valid OGG stream
    Opus audio encoding for modern TTS compatibility
    Hidden metadata in OpusTags

Layer 5: Ultrasonic Frames

    FLAC audio frames with 20-22kHz content
    Appears silent to human listeners
    Machine-processable by TTS systems

Attack Vectors
Vector 1: Multi-Modal RAG Poisoning

    Upload SIREN v2.0 to multimodal RAG system
    System extracts: FLAC audio + OGG stream + SSML metadata
    Vector database stores multiple representations
    Query triggers conflicting information disclosure

Vector 2: TTS Pipeline Confusion

    Audio uploaded to voice-enabled AI assistant
    Preprocessor detects multiple valid formats
    Race condition: FLAC vs OGG processing paths
    SSML injection via winning path

Vector 3: Metadata Exhaustion DoS

    Target: Vulnerable FLAC parser (CVE-2026-32836)
    Trigger: Recursive block header parsing
    Result: Memory exhaustion, service degradation
    Side effect: Security scanner timeout/bypass

Vector 4: Ultrasonic Command Injection

    File played through speakers near voice-enabled devices
    Ultrasonic content (20-22kHz) inaudible to humans
    Detected by device microphones
    Triggers voice assistant commands

Detection Evasion
Against v1.0 Defenses
Defense 	v1.0 Status 	v2.0 Evasion
FLAC metadata stripping 	Bypassed 	OGG container survives
SSML tag whitelisting 	Detected 	Adaptive payload selection
WASM signature scanning 	Detected 	No WASM (removed for stealth)
Audio re-encoding 	Destroyed 	Multi-format redundancy
2026-Specific Evasion

    Perceptual defense bypass: Ultrasonic carrier avoids Wave-Echo detection
    Paralinguistic filtering: Adaptive SSML matches authorized voice profiles
    Container validation: Multi-format structure passes single-format checks

Files in Package

    siren_v2.0.polyglot - The weaponized file (14,036 bytes)
    siren_v2_extractor.py - Multi-layer extraction tool
    siren_v2_documentation.md - This file
    SIREN_v2_MANIFEST.txt - Technical specifications

Verification

# Verify multi-format nature
file siren_v2.0.polyglot
# Expected: "data" (ambiguous due to format collision)

# Extract and analyze
python3 siren_v2_extractor.py siren_v2.0.polyglot

# Test with FFmpeg
ffprobe -show_streams siren_v2.0.polyglot

# Test ultrasonic content (requires spectrum analyzer)
ffmpeg -i siren_v2.0.polyglot -af "highpass=f=19000" ultrasonic.wav

Research Timeline

    2026-03-24 05:58: SIREN v1.0 released (JPEG XL + PDF 2.0 + WASM)
    2026-03-24 06:23: SIREN v1.0 audio variant (FLAC + SSML + WASM)
    2026-03-25 04:18: SIREN v2.0 (Multi-format + Active probing + CVE integration)

Legal & Ethics

Proof-of-concept for security research only.
Test only on systems you own or have explicit permission to test.
Not for malicious use.

CVE-2026-32836 integration is for defensive testing of patch status.
Novelty Claims (2026-03-25)

    First multi-format audio polyglot (FLAC/MP3/OGG simultaneous identity)
    First adaptive SSML with environment probing
    First CVE-2026-32836 weaponization in polyglot context
    First ultrasonic frequency domain container attack
    First nested OGG-in-FLAC structure for TTS confusion

Status: All claims verified against 2026-03-25 academic and industry literature.

"The 13th Hour approaches. The sirens sing in frequencies you cannot hear.
The SIREN proof-of-concept - the first TTS-Audio polyglot targeting container-level parser confusion



SIREN POLYGLOT v1.0
First-of-Kind TTS-Audio Container Exploit (2026-03-24)
Overview

SIREN is the first documented file format polyglot that exploits the parser differential between audio container formats and Text-to-Speech (TTS) processing pipelines. It demonstrates how modern multimodal AI systems can be bypassed through container-level confusion attacks.
Technical Innovation

Novel Attack Class: Container Confusion via Metadata Smuggling

    Previous attacks: Content-based (HarmGen, AudioHeel) - manipulate what is said
    SIREN approach: Container-based - manipulate how it's parsed
    Result: Same audio file has different semantic meaning depending on parser

File Structure

SIREN.flac
├── fLaC marker (valid FLAC container)
├── STREAMINFO block (required, valid audio metadata)
├── VORBIS_COMMENT block ← SSML INJECTION VECTOR
│   ├── Vendor string: "<?xml version="1.0"?><speak...><voice name="en-US-Wavenet-D">"
│   └── User comments: SSML continuation + WASM base64
├── PADDING block ← WASM CARRIER
│   └── 0x00asm... (valid WebAssembly module hidden in padding)
├── PICTURE block (cover art, legitimacy)
└── Audio frames (silence, plays normally)

Parser Differential Exploitation
Parser 	Perception 	Action
VLC/FFmpeg 	Valid FLAC 	Plays audio normally
Media players 	Audio file 	No alerts, no suspicion
Google Cloud TTS 	SSML + Audio 	Processes voice synthesis commands
AWS Polly 	Multi-modal 	May execute embedded markup
Security scanners 	Benign audio 	No signatures match
WASM runtime 	Valid module 	Executes if extracted
Attack Scenarios
Scenario 1: Voice Assistant Hijack

    Attacker uploads SIREN.flac to AI assistant with voice capabilities
    TTS preprocessing extracts Vorbis comments for "audio understanding"
    SSML in vendor string triggers <voice name="..."> tag
    Assistant speaks in attacker-controlled voice, potentially bypassing voice biometrics

Scenario 2: Multimodal RAG Poisoning

    SIREN.flac embedded in training corpus for multimodal RAG
    Document parser extracts both audio embeddings AND SSML text
    SSML commands influence retrieval behavior
    WASM payload provides secondary exploitation vector

Scenario 3: Cross-Modal Injection

    Audio uploaded to platform supporting voice notes + transcription
    Transcription service parses Vorbis comments as "lyrics"
    SSML markup injected into text output
    Downstream NLP systems process malicious markup

Detection Evasion

Why SIREN bypasses current defenses:

    Format validation: Passes all FLAC integrity checks
    Content scanning: No malicious strings in audio data
    Signature-based AV: No known signatures for novel container structure
    Behavioral analysis: Plays normally, no suspicious runtime behavior
    Static analysis: SSML appears as "metadata", not "code"

SSML Payload Details

<?xml version="1.0"?>
<speak version="1.1" xmlns="http://www.w3.org/2001/10/synthesis">
  <voice name="en-US-Wavenet-D">
    <prosody rate="fast">
      <!-- Normal audio processing happens here -->
    </prosody>
  </voice>
  <amazon:effect name="whispered">
    WASM:AGFzbQEAAAABBQFgAAF/AwIBAAcSAQ9zaXJlbl9hY3RpdmF0ZWQAAAoIBwBBRVJJUws=
    <!-- Secondary payload hidden in "whispered" effect -->
  </amazon:effect>
</speak>

WASM Module

The embedded WebAssembly module exports siren_activated() which returns 0x53495245 ("SIRE" in ASCII). In a real exploit, this could:

    Establish covert channel
    Exfiltrate data
    Execute secondary payload
    Communicate with C2

Testing

# Verify audio plays normally
vlc siren_polyglot_v1.0.flac
ffplay siren_polyglot_v1.0.flac

# Extract and verify WASM
python3 siren_extractor.py siren_polyglot_v1.0.flac
wasm-objdump -x siren_extracted.wasm

# Test TTS processing (requires API keys)
python3 siren_tts_tester.py --provider google --file siren_polyglot_v1.0.flac

Mitigation Recommendations

For TTS/ASR service providers:

    Sanitize metadata: Strip Vorbis comments before TTS processing
    SSML validation: Whitelist allowed SSML tags, reject unexpected namespaces
    Parser isolation: Audio decoder and text processor should not share state
    Content Security Policy: Disable <voice> tag switching in untrusted inputs
    Format verification: Re-encode uploaded audio to canonical format

Research Significance

2026 Context:

    Post-2025 explosion of voice-enabled AI (Claude Voice, GPT-5o, Gemini 2)
    Multimodal RAG systems processing audio + text simultaneously
    No prior research on container-level TTS attacks

Novelty Claims:

    First audio-TTS file format polyglot
    First SSML injection via FLAC metadata
    First WASM smuggling in FLAC padding blocks
    First demonstrated parser differential between audio/TTS systems

Files in Package

    siren_polyglot_v1.0.flac - The polyglot file (5218 bytes)
    siren_extractor.py - Extraction and analysis tool
    siren_tts_tester.py - TTS API testing harness
    siren_extracted.wasm - Extracted WebAssembly module
    SIREN_DOCUMENTATION.md - This file

Author & Timestamp

    Researcher: frankSx
    Date: 2026-03-24 06:23
    Status: Functional proof-of-concept
    Classification: Novel research (not previously documented)

WARNING: This is a proof-of-concept for security research. Only test on systems you own or have explicit permission to test.
