# Security Model

## Intended use

CTF Replay Lab is for authorized CTF challenges, personal files, and educational artifacts.

## Browser-only analysis

- Files are read locally with browser APIs.
- The app has no backend and does not upload artifacts.
- Executables are never launched.
- Archive filenames are rendered as text, not HTML.
- Extracted ZIP entries are downloaded using their basename to reduce path-traversal risk.

## Archive protections

- Maximum uploaded artifact: 50 MB
- Maximum extracted ZIP entry: 20 MB
- Suspicious compression ratios above 250:1 are rejected
- Unsupported compression methods are not extracted

These controls reduce risk but do not make arbitrary hostile archives completely safe. Use a disposable browser profile or virtual machine for untrusted samples.

## Flag verification

A flag-shaped string is treated only as a candidate. Correctness requires a trusted challenge manifest containing the expected SHA-256. Optional artifact hashes prevent verifying a flag against the wrong artifact.

## Not provided

- Malware execution or dynamic analysis
- Network access for uploaded samples
- Shell commands
- Full antivirus scanning
- A hardened server-side sandbox
