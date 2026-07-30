# CTF Replay Lab v4 — QA Report

## Automated browser validation

The production candidate was exercised in Chromium through a full in-browser test harness.

### Passed checks

- 162 required DOM IDs present and unique
- 76 buttons with accessible text or labels
- native cursor states: auto, pointer, text, crosshair, and disabled
- zero CSS rules that hide the native cursor
- Base64, hex, Base32, binary, decimal ASCII, ROT13, Caesar, URL, reverse, and repeating-key XOR known-answer tests
- valid-manifest acceptance and malformed-manifest rejection
- no-manifest, artifact-mismatch, wrong-flag, and correct-flag verification paths
- Ghost Tail PNG → embedded ZIP → extracted clue → Auto-probe → verified flag end-to-end path
- Signature Map primary/embedded/structural classification
- PDF metadata, JavaScript-indicator, and embedded-file-indicator parsing
- format identification for PNG, JPEG, GIF, PDF, ZIP, GZIP, 7-Zip, RAR, ELF, PE, BMP, Ogg, MP3/ID3, SQLite, PCAPNG, and MP4 samples
- author dialog, diagnostics, caseboard, and command-deck overlay behavior
- no horizontal overflow at 320, 390, 768, 1024, 1440, and 1920 CSS-pixel widths
- evidence JSON, Markdown report, byte-map PNG, and author-manifest generation
- combined artifact + manifest drag-and-drop loading
- zero uncaught runtime errors or unhandled promise rejections during the test flow

### Environment-dependent checks

Browser-local storage and ZIP deflate extraction depend on the host/browser security context. System Check reports these as warnings rather than fatal failures when unavailable. Stored ZIP entries and all primary analysis functions continue to work.

## Manual pre-submission checklist

1. Serve the folder over `http://localhost` or deploy it over HTTPS.
2. Hard-refresh once after replacing older files.
3. Confirm the native cursor remains visible in the main UI and Author Manifest dialog.
4. Run the built-in demo through final verification.
5. Open System Check and confirm there are no failed checks.
6. Test one mobile viewport and one desktop viewport in the deployed URL.
