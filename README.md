# CTF Replay Lab

CTF Replay Lab is a small browser-based tool I made for investigating CTF files without having to switch between a bunch of different tabs and tools.

You can drop in an artifact, inspect what is inside it, decode suspicious data, save useful findings, and verify the final flag with a challenge manifest.

Everything happens locally in your browser. The file never gets uploaded to a server.

**Live demo:**
https://fluxknight.github.io/CTF-Replay-Lab-02/

Built by [@V01d_404](https://github.com/FluxKnight) for Hack Club Stardance.

## Features

The lab can:

* detect file types from their actual bytes instead of the filename
* find embedded files and signatures
* show hashes, metadata, strings, hex, and entropy
* inspect and extract supported ZIP files
* carve data from a specific offset
* decode Base64, Base32, hex, binary, URL encoding, ROT13, Caesar, reversed text, and XOR
* save evidence and replay investigation steps
* verify flags using SHA-256 manifests
* export reports, evidence, and byte maps

The maximum file size is currently **50 MB**.

There is no backend, and the project is written with plain HTML, CSS, and JavaScript.

## Running it locally

Clone the repository:

```bash
git clone https://github.com/FluxKnight/CTF-Replay-Lab-02.git
cd CTF-Replay-Lab-02
```

Start a local server.

On Windows:

```bash
py -m http.server 5500
```

On Linux or macOS:

```bash
python3 -m http.server 5500
```

Then open:

```text
http://localhost:5500/
```

## How I normally use it

1. Drop in the artifact.
2. Check the detected format and file signatures.
3. Look through strings, metadata, hex, and archive entries.
4. Send anything suspicious to the decoder.
5. Save important findings as evidence.
6. Load the manifest and test the final flag.
7. Export the report if needed.

## Demo challenge

There is a small demo challenge included in the repository:

```text
examples/ghost-tail.png
examples/ghost-tail.ctflab.json
```

The PNG contains an embedded archive. Inside it is a clue that needs to be decoded before the flag can be verified.

You can load the two files manually or just press the **Demo** button.

## Shortcuts

* `Ctrl/Cmd + K` — Open the command deck
* `C` — Open the caseboard
* `S` — Run Pulse Scan
* `T` — Change the interface skin
* `F` — Toggle Focus Mode
* `Esc` — Close the current modal

## Notes

This project is made for CTFs and other authorized file analysis.

It only performs passive analysis and does not execute uploaded binaries. For deeper investigation, tools such as Ghidra, Wireshark, ExifTool, binwalk, or a proper malware sandbox are still better choices.

## License

MIT — see [LICENSE](LICENSE).
