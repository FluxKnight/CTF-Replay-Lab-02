# CTF Replay Lab

A browser-based workspace for analyzing CTF artifacts, decoding hidden data, recording evidence, and verifying flags.

All analysis is performed locally in the browser, and nothing is uploaded to a server.

**Live demo:**
https://fluxknight.github.io/CTF-Replay-Lab-02/

Built by [@V01d_404](https://github.com/FluxKnight) for Hack Club Stardance.

## What it does

* Detects file types using magic bytes
* Finds and extracts embedded files
* Displays metadata, strings, hashes, hex data, and entropy
* Inspects supported ZIP archives
* Carves data from specific byte offsets
* Decodes Base64, Base32, hex, binary, URL encoding, ROT13, Caesar cipher, reversed text, and XOR
* Records evidence and investigation steps
* Verifies flags using SHA-256 challenge manifests
* Exports Markdown reports, evidence JSON, and byte-map images
* Runs entirely in the browser with no third-party JavaScript libraries

Files up to **50 MB** are supported.

## Running locally

Clone the repository:

```bash
git clone https://github.com/FluxKnight/CTF-Replay-Lab-02.git
cd CTF-Replay-Lab-02
```

Start a local server.

### Windows

```bash
py -m http.server 5500
```

### Linux or macOS

```bash
python3 -m http.server 5500
```

Then open:

```text
http://localhost:5500/
```

## How to use

1. Upload an artifact or drag and drop it into the page.
2. Review its detected file type, metadata, strings, hex data, and signatures.
3. Extract or decode suspicious content.
4. Record useful findings as evidence.
5. Load a challenge manifest and verify the final flag.
6. Export the investigation report.

## Demo challenge

The project includes a built-in demo challenge called **Ghost Tail**:

```text
examples/ghost-tail.png
examples/ghost-tail.ctflab.json
```

Load both files, inspect the hidden signature, open the embedded archive, decode `clue.txt`, and submit the recovered flag.

The **Demo** button loads the same challenge automatically.

## Keyboard shortcuts

* `Ctrl/Cmd + K` — Open command deck
* `C` — Open caseboard
* `S` — Run Pulse Scan
* `T` — Change skin
* `F` — Toggle Focus Mode
* `Esc` — Close the active modal

## Safety

Use this application only for CTF challenges or other authorized file analysis.

CTF Replay Lab performs passive, read-only analysis in the browser and does not execute uploaded binaries. It is not a replacement for dedicated tools such as Ghidra, Wireshark, ExifTool, binwalk, or a malware sandbox.

## License

This project is licensed under the [MIT License](LICENSE).
