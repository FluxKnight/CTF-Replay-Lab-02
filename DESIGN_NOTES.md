# V6 final polish highlights
- Tactical rail navigation
- Persistent focus mode
- Stronger visual hierarchy and premium ambient lighting
- Cleaner panel hover states and calmer background depth

# CTF Replay Lab — Design and Product Notes

## Design thesis

This is a forensic investigation instrument, not a generic card dashboard. The visual language derives from byte offsets, signal acquisition, evidence provenance, and trusted verification: terminal typography, angular geometry, restrained status colors, dense but scannable information, and motion tied to user actions.

## Signature product interactions

### Signature Map

The scanner looks across the entire artifact rather than only at offset zero. It separates the primary file signature from container structure and suspicious embedded candidates, then allows direct navigation to the relevant hex offset.

### Byte Intelligence Map

Each visual block summarizes a real byte region. Entropy, printable/high-byte/null ratios, and dominant-byte data help reveal compressed, encrypted, padded, or appended regions. The map is analytical output rather than decorative animation.

### Auto-probe Decoder

Auto-probe evaluates common transformations, scores the outputs for printability, language structure, flag patterns, and entropy, suppresses low-confidence noise, and commits a chosen result into the evidence and replay chain.

### Evidence Constellation

The caseboard turns investigation state into a provenance graph. The root artifact connects to findings, evidence, decoder outputs, and candidates. Selecting a node reveals its source and value.

### Pulse Scan

Pulse Scan identifies the next incomplete investigation stage and visually locates the relevant surface. Its recommendation changes as the case advances from identity to inspection, extraction/decoding, verification, and export.

### Runtime diagnostics

System Check makes reliability visible. It validates interface wiring, local file APIs, SHA-256, decoder known answers, signature scanning, byte-map generation, exports, cursor fallback, storage availability, and the runtime issue log.

## Cursor model

The native cursor remains authoritative everywhere. The custom follower never replaces it and is hidden during overlays, pointer exit, reduced motion, and coarse-pointer input. This specifically avoids top-layer dialog behavior causing the user to lose the pointer.

## Color semantics

- Cyan/theme signal: active analysis and navigation
- Violet: evidence and provenance
- Amber: transformation and suspicious boundaries
- Green: trusted or verified state
- Rose: warning, mismatch, or rejection

The Void, Signal, and Ember skins preserve semantic contrast while changing the interface atmosphere.

## Safety model

Artifacts remain inside the browser. Executables are never run. Extraction is size-limited. Candidates remain unverified until a trusted manifest hash matches. Reports preserve the source and action history behind each conclusion.
