# Stardance Re-certification Notes — v4

This build directly addresses the reviewer’s two requests: replace the generic AI-dashboard appearance and add original, useful product features.

## Distinct visual identity

- custom forensic operations-deck layout rather than a template dashboard
- terminal and byte-offset visual language
- Void, Signal, and Ember interface skins
- live signal console, contextual motion, angular panels, responsive mobile composition
- native cursor preserved everywhere; the custom follower is decorative and no longer causes the pointer to disappear

## Original workflow features

1. **Signature Map** — scans the entire artifact, identifies embedded file signatures, records exact offsets, and jumps directly to hex evidence.
2. **Byte Intelligence Map** — maps entropy and byte composition by region to reveal payload boundaries.
3. **Auto-probe Decoder** — ranks plausible transforms and commits a selected result into provenance.
4. **Evidence Constellation** — interactive graph of artifact, finding, evidence, decode, and candidate relationships.
5. **Pulse Scan** — finds the next meaningful investigation action.
6. **System Check** — verifies the active browser environment and reports runtime failures visibly.

## Reviewer test path

- Click **Demo**.
- Open **Signatures** and inspect the embedded ZIP at offset `0x6a`.
- Open **Archives**, send `clue.txt` to the decoder, and select **Auto-probe input**.
- Commit the Base64 result and verify `flag{follow_the_signature_map}`.
- Open **System check**; all critical checks should pass. Storage or ZIP-deflate support may appear as a non-blocking warning in restrictive browser modes.

## Safety retained

- no server upload
- no binary execution
- read-only local analysis
- extraction safeguards
- candidates remain unverified until trusted SHA-256 verification succeeds
