## v6 — Final premium pass
- Added a tactical side rail for faster movement between intro, intake, analysis, decode, verify, and replay sections.
- Persisted focus mode between sessions.
- Applied a final visual pass with cleaner motion, more depth, calmer highlights, and better glass-panel polish.
- Refined footer, banner sheen, hover states, and section hierarchy for a stronger final presentation.

## v5 — Visual polish
- Refined the interface into a cleaner, calmer, more premium layout.
- Upgraded the background with layered aurora lighting, softer glass panels, and improved spacing.
- Reduced harsh neon edges while keeping the futuristic forensic-console feel.
- Polished mobile readability, hero typography, tabs, cards, and notifications.

# Changelog

## 4.0.0 — Stardance Production Candidate

### Reliability

- Removed every rule that hid the native operating-system cursor
- Rebuilt the animated pointer as a decorative enhancement with safe pointer-exit, overlay, coarse-pointer, and reduced-motion behavior
- Added runtime guards for uncaught errors and unhandled promise rejections
- Added a visible System Check with known-answer tests and pass/warn/fail reporting
- Added overlay focus restoration, scroll locking, keyboard dismissal, and stronger responsive handling
- Fixed PDF metadata extraction and decoder diagnostic double execution
- Added cache-busting asset version `v=400`

### Original analysis features

- Added full-artifact Signature Map with exact offsets and primary/structural/embedded classification
- Added Byte Intelligence Map with regional entropy and byte-distribution telemetry
- Added click-to-hex navigation and byte-map PNG export
- Added Auto-probe Decoder with confidence ranking and noise suppression
- Added Base32, binary, and decimal ASCII decoder modes
- Expanded detection/parsing for GZIP, 7-Zip, RAR, SQLite, BMP, Ogg, MP3/ID3, WebP, MP4, and PCAPNG

### Demo and product flow

- Replaced the simple text demo with a generated PNG containing an appended ZIP and encoded clue
- Added matching manual demo files under `examples/`
- Improved Pulse Scan, next-move guidance, XP, findings, evidence export, and report export to incorporate Signature Map and Byte Intelligence data
- Added multi-file drop handling so an artifact and manifest can be loaded together

## 3.0.0 — Case Deck Edition

- Rebuilt the visual identity as a custom forensic operations console
- Added Evidence Constellation, Pulse Scan, XP/ranks/achievements, three skins, command deck, Focus Mode, live terminal feedback, and a SHA-256 fallback

## 2.0.0 — Evidence Replay Release

- Added manifest-backed SHA-256 verification, appended ZIP handling, decoder workflows, evidence provenance, reports, replay logs, author mode, and extraction safeguards
