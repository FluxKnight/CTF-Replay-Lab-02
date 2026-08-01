# CTF Replay Lab
CTF Replay Lab is a browser-based workspace I built to make CTF file analysis easier to follow, especially for people who are still learning forensics.

When I started solving CTF challenges, I often had to switch between several tools and manually keep track of where each clue came from. I wanted one place where I could inspect a file, decode suspicious data, save evidence and verify the final flag without uploading the artifact to a server.

live : https://fluxknight.github.io/CTF-Replay-Lab-02/
Built by @V01d_404

# What it can do
- Detect file types using magic bytes
- Calculate SHA-256 hashes and entropy
- Extract metadata, ASCII strings, and UTF-16LE strings
- View files in hex with byte offsets
- Find embedded or appended file signatures
- Inspect and extract supported ZIP archives
- Carve data from a selected offset
- Decode Base64, Base32, hex, binary, URL encoding, ROT13, Caesar cipher, reversed text and XOR
- Save evidence and investigation notes
- Replay the steps taken during an investigation
- Verify flags using SHA-256 challenge manifests
- Export Markdown reports, evidence JSON and byte-map images

All analysis runs locally in the browser. Files are not uploaded and executable files are never run. The current file size limit is 50 MB.

# How to use
1. Upload an artifact on drag it into the page 
2. Check the detected file type, hash, metadata, string and signatures.
3. Inspect any archive or hidden content that was found
4. send suspicious text to the decoder.
5. Save useful finding as evidence.
6. Load a challenge manifest and verify the final flag.
7. Export the report if needed.
# Keyboard shortcuts
- Ctrl + K = Open the command deck
- C = Open the caseboard
- S = Rum pulse Scan
- T = Change the interface skin
- F = Toggle focus mode
- Esc = Clsoe the current modal
# Future plans
I pan to keep improving the project by testing it with more real CTF challenges and malformed files. 
The next improvements will focus on:
- Supporting more file and archive formats
- reducing false detections
- improving decoder suggestions
- making the investigation steps easier to understand
- improving mobile support
- fixing browser specific bugs
My main goal is to make the tool useful for beginners without trying to replace professional tools such as Ghidra, wireshark, exifTool or binwalk.
# Safety
Use this project only for CTF challenges, educational exercises or files you are authorized to inspect. CTF Replay Lab performs passive analysis and does not execute uploaded binaries.
# License
MIT License. See LICENSE.
