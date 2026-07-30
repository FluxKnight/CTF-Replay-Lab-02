# CTF Replay Lab — Stardance Production Candidate v4

A local-first browser workspace for investigating CTF artifacts, preserving evidence provenance, replaying the solve path, and verifying the final flag against a trusted SHA-256 manifest.

Built by **@V01d_404** for Stardance.

## What makes this release distinct

- **Signature Map** scans the full artifact for primary, structural, and embedded file signatures with exact offsets.
- **Byte Intelligence Map** visualizes entropy, printable/high-byte/null ratios, dominant bytes, and suspicious region boundaries.
- **Auto-probe Decoder** ranks plausible Base64, Base32, hex, binary, decimal ASCII, URL, ROT13, Caesar, and reverse transformations.
- **Evidence Constellation** renders the artifact, findings, evidence, decoder outputs, and candidates as an interactive provenance graph.
- **Pulse Scan** locates the next useful investigation surface from the current solve state.
- **System Check** runs in-browser known-answer tests for hashing, decoders, signature scanning, byte mapping, file APIs, exports, cursor fallback, storage, and runtime errors.
- **Investigator progression** provides session XP, ranks, achievements, and contextual next-move guidance without affecting verification logic.
- **Void / Signal / Ember skins**, Focus Mode, a keyboard-first command deck, live terminal feedback, and responsive layouts give the product a deliberate forensic-console identity.

## Cursor reliability fix

The operating-system cursor is never hidden. The animated cursor follower is decorative only and automatically fades when the pointer exits the page, reduced motion is enabled, or an overlay opens. Native pointer, text, crosshair, and disabled states remain available in regular content, dialogs, and canvases.

## Core analysis capabilities

- Drag-and-drop loading up to 50 MB; artifact and manifest can be dropped together
- Magic-byte identification rather than trusting filename extensions
- SHA-256, Shannon entropy, printable ratio, strings, metadata, findings, and offset-aware hex inspection
- PNG, JPEG, GIF, PDF, ZIP, GZIP, 7-Zip, RAR, SQLite, ELF, PE, BMP, Ogg, MP3/ID3, WAV, WebP, MP4, PCAP, PCAPNG, text, and unknown-binary detection
- PNG chunks/text fields and post-IEND payload detection
- PDF metadata/object/JavaScript/embedded-file indicators
- ZIP listing, stored/deflate extraction where supported, nested analysis, decoder handoff, and extraction safeguards
- Binary carving from a selected offset
- Base64, Base32, hex, binary, decimal ASCII, URL, ROT13, Caesar, reverse, and repeating-key XOR transformations
- Multi-stage decoder replay and candidate provenance
- Manifest-backed verification that never treats a discovered candidate as automatically correct
- Manifest authoring that stores hashes rather than the plaintext flag
- Evidence JSON, byte-map PNG, Markdown report, replay copy, and browser-local notes
- No backend and no third-party JavaScript dependencies

## Run locally

From the project folder:

```powershell
py -m http.server 5500
```

Then open:

```text
http://localhost:5500/
```

Use `Ctrl + Shift + R` after replacing an older deployment so the browser fetches `style.css?v=400` and `app.js?v=400`.

## One-click reviewer path

1. Open the site.
2. Select **Demo** or **Run live demo**.
3. Open **Signatures** to see the ZIP header mapped after the PNG IEND boundary.
4. Open **Archives**, send `clue.txt` to the decoder, and run **Auto-probe input**.
5. Commit the ranked Base64 result.
6. Submit `flag{follow_the_signature_map}`.
7. Open **System check** to review the browser’s runtime diagnostics.

The same files are included under `examples/` for manual testing:

- `examples/ghost-tail.png`
- `examples/ghost-tail.ctflab.json`

Load or drop both files together to reproduce the verified flow without using the built-in Demo button.

## Keyboard shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl/Cmd + K` | Open the command deck |
| `C` | Open Evidence Constellation |
| `S` | Run Pulse Scan |
| `T` | Cycle interface skin |
| `F` | Toggle Focus Mode |
| `Esc` | Close the active overlay |

## Verification model

In practice mode, flag-shaped strings are stored only as candidates. In verified mode, acceptance requires:

1. The optional root-artifact SHA-256 to match.
2. The submitted value to satisfy the optional flag-format rule.
3. The submitted value’s SHA-256 to equal `expectedFlagSha256`.

```text
Discovered candidate ≠ verified flag
```

## Deployment

The project is static and can be deployed to GitHub Pages, Vercel, Netlify, Cloudflare Pages, or another static host. HTTPS is recommended for the most reliable Web Crypto, clipboard, and local-storage behavior.

## Scope and limitations

CTF Replay Lab is an educational, read-only browser investigation environment. It does not execute uploaded binaries, emulate hostile code, provide full packet reconstruction, or replace mature tools such as Ghidra, Wireshark, ExifTool, binwalk, or a hardened malware sandbox.
