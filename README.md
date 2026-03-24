# Siren
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
