CTF Replay Lab - Stardance Production Candidate v4
A local-first browser workspace for investigating CTF artifacts, preserving evidence provenance, replaying the solve path, and verifying the final flag against a trusted SHA-256 manifest.

Built by @V01d_404 for Stardance.

What makes this version different
Signature Map scans entire artifact for primary, structural, and embedded file signatures at exact offsets.
Byte Intelligence Map shows you entropy distribution, printable/high-byte/null ratios, dominant bytes, and probable region boundaries.
Auto-probe Decoder shows you likely Base64/Base32, hex, binary, decimal ASCII, URL, ROT13, Caesar, reverse, and transformation candidates.
Evidence Constellation lets you see the artifact, your findings, evidence, decoder results, and candidates as a provenance graph.
Pulse Scan helps you find the next surface to investigate from your current solve position.
System Check runs in-browser known-answer tests for hashing, decoders, signature scanning, byte mapping, file APIs, exports, cursor fallback, storage, and runtime.
Progression lets you earn XP, levels, and achievements with your session without affecting the verification logic.
Void / Signal / Ember skins, Focus Mode, a keyboard-first command deck, live terminal feedback, and responsive layouts add to the product’s forensic-console vibe.
Animated cursor fixed
OS cursor is never hidden, and the animated cursor follower is only decorative and will disappear when you leave the page, have reduced motion enabled, or have an overlay open. Pointer, text, crosshair, and disabled cursor visuals are preserved in their respective context.

Core analysis functions
Drag and drop up to 50 MB at once; artifact + manifest can be dropped together
Magic-byte discovery rather than relying on filename extensions
SHA-256, Shannon entropy, printable ratio, strings, metadata, findings, and offset-based hex viewing
PNG/JPEG/GIF/PDF/ZIP/GZIP/7z/RAR/SQLite/ELF/PE/BMP/Ogg/Mp3/WAV/WebP/MP4/PCAP/PCAPNG/text/unknown
PNG chunks/text fields and post-IEND payload discovery
PDF metadata/object/JS/embedded-file discovery
ZIP listing with stored/deflated extraction where supported, nested analysis, decoder handoff, and protection against untrusted extraction
Carving binary data from a given offset
Base64/Base32/hex/binary/decimal ASCII/URL/ROT13/CAESAR/reverse detection, and repeating-key XOR transformations
Multi-stage decoder replay and candidate provenance
Manifest-backed validation that never considers a discovered candidate a correct flag by default
Manifest authoring that stores hashes rather than the plaintext flag
Evidence JSON, byte-map PNG, Markdown report, replay copy, and browser-local notes
No backend and no third-party JS dependencies
Self-hosted
From the project directory:

py -m http.server 5500
Then open

http://localhost:5500/
and hit Ctrl + Shift + R when deploying updates so the browser reloads the new style.css?v=400 and app.js?v=400 .

One-click reviewer path
Open the page, then open the Demo or Run live demo modals.
Open Signatures to see ZIP header discovered after the PNG IEND.
Open Archives, send the clue.txt to the decoder, and run Auto-probe input.
Commit the suggested Base64 result. Submit the flag{follow_the_signature_map} . Open the System check tab to review the browser’s test results.

The same files are available in the examples/ directory for you to load and drop manifests together without using the Demo button:
examples/ghost-tail.png
examples/ghost-tail.ctflab.json

Key shortcuts
Shortcut
Action
Ctrl/Cmd + K
Open the command deck
C
Open Evidence Constellation
S
Run Pulse Scan
T
Cycle interface skin
F
Toggle Focus Mode
Esc
Close the active overlay
Verification model
In practice mode, any string resembling a flag is stored as a candidate; in verified mode, a candidate must pass these three criteria to be accepted:

optional root-artifact SHA-256 matches
submitted value matches optional flag-format regex
submitted value’s SHA-256 matches expectedFlagSha256
Discovered candidate is never equal to the verified flag.
Deployment
The project is static HTML/JS/CSS and can be deployed to GitHub Pages, Vercel, Netlify, Cloudflare Pages, or similar static-hosting platforms. We recommend using HTTPS for the most reliable Web Crypto, clipboard, and local-storage operations.

Scopes and limitations
CTF Replay Lab is designed as an educational read-only environment for browser-based artifact analysis. It will not execute potentially malicious binaries uploaded by the user, offer network packet reconstruction, or replace the security of dedicated tools such as Ghidra, Wireshark, ExifTool, binwalk, or a malware sandbox.
