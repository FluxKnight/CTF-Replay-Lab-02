# Ghost Tail example

This folder contains a complete manual test pair for CTF Replay Lab v4:

- `ghost-tail.png` — a valid PNG with an appended ZIP containing `clue.txt`
- `ghost-tail.ctflab.json` — the matching SHA-256 verification manifest

Load or drag both files into the site together. Then:

1. Inspect the Signature Map.
2. Open Archives and send `clue.txt` to the decoder.
3. Run Auto-probe and commit the Base64 result.
4. Verify the recovered flag.

The manifest stores only hashes and hints, not the plaintext flag.
