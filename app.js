const MAX_FILE_SIZE = 50 * 1024 * 1024;
const MAX_STRING_RESULTS = 1500;
const MAX_STRING_SCAN_BYTES = 12 * 1024 * 1024;
const MAX_EXTRACTED_ENTRY_SIZE = 20 * 1024 * 1024;
const MAX_EVIDENCE_VALUE = 100_000;
const HEX_PAGE_SIZE = 1024;
const BYTE_MAP_BLOCK_COUNT = 144;
const MAX_SIGNATURE_RESULTS = 240;
const DEFAULT_HINTS = [
  "Do not trust the filename extension. Confirm the format from magic bytes.",
  "Inspect metadata, strings, findings, hex, and archive regions. Record where each clue came from.",
  "A clue may require extraction or several transformations. Preserve the output of each stage.",
  "A flag-shaped string is only a candidate. A challenge manifest must verify its SHA-256."
];


const embeddedSignaturePatterns = [
  { id: "png", name: "PNG image", bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], category: "Image", detail: "Portable Network Graphics signature" },
  { id: "jpeg", name: "JPEG image", bytes: [0xff, 0xd8, 0xff], category: "Image", detail: "JPEG start-of-image marker" },
  { id: "gif87", name: "GIF87a image", bytes: [0x47, 0x49, 0x46, 0x38, 0x37, 0x61], category: "Image", detail: "GIF87a header" },
  { id: "gif89", name: "GIF89a image", bytes: [0x47, 0x49, 0x46, 0x38, 0x39, 0x61], category: "Image", detail: "GIF89a header" },
  { id: "pdf", name: "PDF document", bytes: [0x25, 0x50, 0x44, 0x46, 0x2d], category: "Document", detail: "PDF header" },
  { id: "zip", name: "ZIP local header", bytes: [0x50, 0x4b, 0x03, 0x04], category: "Archive", detail: "ZIP-compatible local file header" },
  { id: "zip-empty", name: "ZIP empty archive", bytes: [0x50, 0x4b, 0x05, 0x06], category: "Archive", detail: "ZIP end-of-central-directory record" },
  { id: "gzip", name: "GZIP stream", bytes: [0x1f, 0x8b, 0x08], category: "Archive", detail: "GZIP compressed stream" },
  { id: "7z", name: "7-Zip archive", bytes: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], category: "Archive", detail: "7z archive signature" },
  { id: "rar4", name: "RAR archive v4", bytes: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00], category: "Archive", detail: "RAR 4.x archive signature" },
  { id: "rar5", name: "RAR archive v5", bytes: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00], category: "Archive", detail: "RAR 5.x archive signature" },
  { id: "elf", name: "ELF executable", bytes: [0x7f, 0x45, 0x4c, 0x46], category: "Executable", detail: "ELF binary header" },
  { id: "pe", name: "DOS / PE executable", bytes: [0x4d, 0x5a], category: "Executable", detail: "MZ executable header" },
  { id: "sqlite", name: "SQLite database", bytes: [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33, 0x00], category: "Database", detail: "SQLite 3 database header" },
  { id: "riff", name: "RIFF container", bytes: [0x52, 0x49, 0x46, 0x46], category: "Media", detail: "RIFF media container" },
  { id: "webp", name: "WebP marker", bytes: [0x57, 0x45, 0x42, 0x50], category: "Image", detail: "WebP RIFF form type" },
  { id: "ftyp", name: "ISO Base Media ftyp", bytes: [0x66, 0x74, 0x79, 0x70], category: "Media", detail: "MP4/MOV file type box" },
  { id: "ogg", name: "Ogg stream", bytes: [0x4f, 0x67, 0x67, 0x53], category: "Media", detail: "Ogg page header" },
  { id: "id3", name: "ID3 audio tag", bytes: [0x49, 0x44, 0x33], category: "Media", detail: "ID3 metadata header" },
  { id: "bmp", name: "BMP image", bytes: [0x42, 0x4d], category: "Image", detail: "Windows bitmap header" },
  { id: "pcap-be", name: "PCAP capture", bytes: [0xa1, 0xb2, 0xc3, 0xd4], category: "Capture", detail: "PCAP big-endian header" },
  { id: "pcap-le", name: "PCAP capture", bytes: [0xd4, 0xc3, 0xb2, 0xa1], category: "Capture", detail: "PCAP little-endian header" },
  { id: "pcapng", name: "PCAPNG section", bytes: [0x0a, 0x0d, 0x0d, 0x0a], category: "Capture", detail: "PCAPNG section header block" }
];

const timelineSteps = [
  { title: "Identify the artifact", description: "Verify the real format, hash, and basic structure." },
  { title: "Inspect evidence", description: "Review metadata, strings, hex, findings, or archive regions." },
  { title: "Extract or decode", description: "Carve, extract, or transform hidden evidence." },
  { title: "Verify the flag", description: "Match the submitted flag against a trusted manifest hash." }
];

const commandInformation = {
  file: {
    purpose: "Identifies a file using its contents and magic signature.",
    use: "Use it first when an extension may be false or misleading.",
    risk: "Read-only and safe for authorized artifacts."
  },
  strings: {
    purpose: "Extracts printable character sequences from binary data.",
    use: "Useful for finding flags, URLs, paths, passwords, debug messages, and encoded values.",
    risk: "Read-only. Large outputs should be filtered."
  },
  exiftool: {
    purpose: "Reads metadata from images, documents, archives, and media files.",
    use: "Useful for comments, authors, timestamps, GPS data, and custom fields.",
    risk: "Safe when used only for reading metadata."
  },
  binwalk: {
    purpose: "Scans binary files for embedded signatures and nested content.",
    use: "Useful for firmware, appended archives, compressed streams, and steganography.",
    risk: "Scanning is read-only. Automatic extraction should still use a sandbox."
  },
  xxd: {
    purpose: "Displays bytes as hexadecimal with an ASCII column.",
    use: "Useful for headers, offsets, delimiters, embedded signatures, and appended data.",
    risk: "Read-only and safe."
  },
  unzip: {
    purpose: "Lists or extracts files from a ZIP archive.",
    use: "Use `unzip -l` first to inspect names before extraction.",
    risk: "Listing is safe. Extract into an isolated directory and beware path traversal."
  },
  dd: {
    purpose: "Copies an exact byte range from one file into another.",
    use: "Useful for carving an appended archive from a known offset.",
    risk: "Read the command carefully. Reversing `if` and `of` can overwrite data."
  },
  sha256sum: {
    purpose: "Calculates a SHA-256 fingerprint.",
    use: "Useful for verifying artifact identity and documenting a solve.",
    risk: "Read-only and safe."
  }
};

const interfaceThemes = [
  { id: "void", label: "Void" },
  { id: "signal", label: "Signal" },
  { id: "ember", label: "Ember" }
];

const elements = Object.fromEntries(
  [
    "loadArtifactButton", "loadChallengeButton", "authorButton", "demoButton", "pulseScanButton", "caseboardButton", "diagnosticsButton", "themeButton", "focusModeButton", "commandPaletteButton", "resetButton", "exportButton",
    "artifactInput", "challengeInput", "dropZone", "chooseArtifactButton", "chooseChallengeButton", "workspace",
    "challengeBanner", "modePill", "challengeTitle", "challengeSubtitle", "clearChallengeButton",
    "formatSummary", "categorySummary", "sizeSummary", "mimeSummary", "entropySummary", "entropyLabel",
    "evidenceSummary", "evidenceLabel", "progressSummary", "progressLabel", "artifactTitle", "categoryBadge",
    "riskBadge", "metadataCount", "stringsCount", "signatureCount", "archiveCount", "findingsCount", "evidenceCount",
    "fileName", "mimeType", "detectedFormat", "fileSize", "printableRatio", "artifactRole", "fileHash",
    "initialFinding", "artifactHashWarning", "metadataList", "stringSearch", "interestingOnly", "copyStringsButton",
    "stringsOutput", "hexOffsetInput", "jumpHexButton", "downloadSelectionButton", "hexOutput", "byteMapCanvas", "byteMapTooltip", "byteMapBlockSize", "byteMapPeakEntropy", "byteMapDominantByte", "byteMapNullRatio", "exportByteMapButton", "signatureSearch", "copySignaturesButton", "signatureList", "archiveList",
    "findingsList", "exportEvidenceButton", "clearEvidenceButton", "evidenceList", "progressText", "timeline",
    "hintText", "unlockHintButton", "sessionStatus", "decoderMode", "decoderKey", "caesarShift",
    "decoderInputEncoding", "decoderOutputEncoding", "keyControl", "shiftControl", "inputEncodingControl",
    "outputEncodingControl", "decoderInput", "decodeButton", "autoProbeButton", "autoProbeResults", "swapDecoderButton", "saveDecodeEvidenceButton",
    "downloadDecodeButton", "decoderOutput", "decoderHistory", "verificationMode", "flagInput", "submitFlagButton",
    "flagResult", "candidateCount", "candidateList", "commandSelect", "commandExplanation", "notesInput",
    "notesStatus", "replayList", "copyReplayButton", "authorDialog", "authorForm", "authorTitle", "authorId",
    "authorCategory", "authorDifficulty", "authorFlag", "authorArtifactHash", "authorHints", "useCurrentHashButton",
    "exportManifestButton", "ambientCanvas", "heroSignalCanvas", "heroClock", "heroTerminal", "scanBeam",
    "investigatorRank", "xpValue", "xpBar", "xpPulse", "xpNext", "achievementStrip", "nextMoveText", "hudPulseButton",
    "caseboardOverlay", "caseboardCanvas", "caseboardInspector", "caseboardNodeCount", "caseboardCenterButton",
    "diagnosticsOverlay", "diagnosticsOverall", "diagnosticsPassed", "diagnosticsWarnings", "diagnosticsFailed", "diagnosticsList", "runDiagnosticsButton", "copyDiagnosticsButton",
    "commandPalette", "commandPaletteInput", "commandPaletteList", "toast"
  ].map((id) => [id, document.getElementById(id)])
);

const state = {
  challenge: null,
  artifactHashMatches: true,
  rootArtifactHash: "",
  rootArtifactName: "",
  file: null,
  bytes: null,
  role: "Primary artifact",
  parentSource: null,
  hash: "",
  typeInfo: null,
  metadata: {},
  structures: {},
  strings: [],
  visibleStrings: [],
  findings: [],
  archives: [],
  signatures: [],
  byteMap: { blocks: [], blockSize: 0, peakEntropy: 0, dominantByte: 0, nullRatio: 0 },
  autoProbeResults: [],
  diagnosticsResults: [],
  runtimeIssues: [],
  candidates: new Map(),
  evidence: [],
  decoderHistory: [],
  replay: [],
  completedSteps: new Set(),
  revealedHints: 0,
  entropy: 0,
  printable: 0,
  hexOffset: 0,
  lastDecoderResult: null,
  startedAt: null,
  solvedAt: null,
  manualEvidenceIds: new Set(),
  focusMode: false,
  commandPaletteIndex: 0,
  themeIndex: 0,
  xpLast: 0,
  achievements: new Set(),
  caseboardNodes: [],
  caseboardSelected: null,
  caseboardAnimationFrame: null,
  pointer: { x: innerWidth * 0.5, y: innerHeight * 0.5, ringX: innerWidth * 0.5, ringY: innerHeight * 0.5 },
  lastFocusedElement: null
};

installRuntimeGuards();
setupEvents();
setupAmbientEffects();
setupHeroSignal();
setupTiltEffects();
restoreTheme();
restoreFocusMode();
renderTimeline();
updateHints();
updateChallengeUI();
updateDecoderControls();
renderCommandPaletteList();
updateFocusModeUI();
updateInvestigatorHUD();
initSectionRail();

function setupEvents() {
  elements.loadArtifactButton.addEventListener("click", () => elements.artifactInput.click());
  elements.chooseArtifactButton.addEventListener("click", () => elements.artifactInput.click());
  elements.loadChallengeButton.addEventListener("click", () => elements.challengeInput.click());
  elements.chooseChallengeButton.addEventListener("click", () => elements.challengeInput.click());
  elements.authorButton.addEventListener("click", openAuthorDialog);
  elements.demoButton.addEventListener("click", loadDemo);
  elements.pulseScanButton.addEventListener("click", pulseScan);
  elements.caseboardButton.addEventListener("click", openCaseboard);
  elements.diagnosticsButton.addEventListener("click", openDiagnostics);
  elements.themeButton.addEventListener("click", cycleTheme);
  elements.hudPulseButton.addEventListener("click", pulseScan);
  elements.caseboardCenterButton.addEventListener("click", () => { state.caseboardSelected = null; buildCaseboardNodes(); updateCaseboardInspector(); });
  elements.focusModeButton.addEventListener("click", toggleFocusMode);
  elements.commandPaletteButton.addEventListener("click", openCommandPalette);
  elements.resetButton.addEventListener("click", () => resetSession({ keepChallenge: false }));
  elements.exportButton.addEventListener("click", exportReport);
  elements.clearChallengeButton.addEventListener("click", clearChallenge);

  elements.artifactInput.addEventListener("change", async () => {
    const file = elements.artifactInput.files?.[0];
    if (file) await analyzeFile(file, { role: "Primary artifact", preserveSession: false });
    elements.artifactInput.value = "";
  });

  elements.challengeInput.addEventListener("change", async () => {
    const file = elements.challengeInput.files?.[0];
    if (file) await loadChallengeManifest(file);
    elements.challengeInput.value = "";
  });

  elements.dropZone.addEventListener("click", (event) => {
    if (!event.target.closest("button")) elements.artifactInput.click();
  });
  elements.dropZone.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      elements.artifactInput.click();
    }
  });
  ["dragenter", "dragover"].forEach((name) => {
    elements.dropZone.addEventListener(name, (event) => {
      event.preventDefault();
      elements.dropZone.classList.add("dragging");
    });
  });
  ["dragleave", "drop"].forEach((name) => {
    elements.dropZone.addEventListener(name, (event) => {
      event.preventDefault();
      elements.dropZone.classList.remove("dragging");
    });
  });
  elements.dropZone.addEventListener("drop", async (event) => {
    const files = [...(event.dataTransfer?.files || [])];
    if (files.length) await handleDroppedFiles(files);
  });

  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => activateTab(tab.dataset.tab, true));
  });

  document.addEventListener("click", handleDelegatedClick);
  document.addEventListener("keydown", handleGlobalShortcuts);
  elements.commandPaletteInput.addEventListener("input", renderCommandPaletteList);
  window.addEventListener("resize", handleImmersiveResize, { passive: true });
  elements.caseboardCanvas.addEventListener("mousemove", handleCaseboardPointerMove);
  elements.caseboardCanvas.addEventListener("mouseleave", () => { elements.caseboardCanvas.style.cursor = "crosshair"; });
  elements.caseboardCanvas.addEventListener("click", handleCaseboardClick);
  elements.byteMapCanvas.addEventListener("mousemove", handleByteMapPointerMove);
  elements.byteMapCanvas.addEventListener("mouseleave", hideByteMapTooltip);
  elements.byteMapCanvas.addEventListener("click", handleByteMapClick);
  elements.exportByteMapButton.addEventListener("click", exportByteMapPng);
  elements.signatureSearch.addEventListener("input", renderSignatures);
  elements.copySignaturesButton.addEventListener("click", copySignatureMap);
  elements.stringSearch.addEventListener("input", filterStrings);
  elements.interestingOnly.addEventListener("change", filterStrings);
  elements.copyStringsButton.addEventListener("click", copyVisibleStrings);
  elements.jumpHexButton.addEventListener("click", jumpHex);
  elements.downloadSelectionButton.addEventListener("click", downloadFromOffset);
  elements.exportEvidenceButton.addEventListener("click", exportEvidenceJson);
  elements.clearEvidenceButton.addEventListener("click", clearManualEvidence);
  elements.unlockHintButton.addEventListener("click", revealHint);

  elements.decoderMode.addEventListener("change", updateDecoderControls);
  elements.decodeButton.addEventListener("click", runDecoder);
  elements.autoProbeButton.addEventListener("click", autoProbeInput);
  elements.swapDecoderButton.addEventListener("click", useDecoderOutputAsInput);
  elements.saveDecodeEvidenceButton.addEventListener("click", saveDecoderEvidence);
  elements.downloadDecodeButton.addEventListener("click", downloadDecoderOutput);
  elements.submitFlagButton.addEventListener("click", verifyFlag);
  elements.commandSelect.addEventListener("change", updateCommandExplanation);
  elements.notesInput.addEventListener("input", saveNotes);
  elements.copyReplayButton.addEventListener("click", copyReplay);

  elements.useCurrentHashButton.addEventListener("click", () => {
    elements.authorArtifactHash.value = state.hash || "";
  });
  elements.exportManifestButton.addEventListener("click", exportAuthorManifest);
  elements.runDiagnosticsButton.addEventListener("click", runDiagnostics);
  elements.copyDiagnosticsButton.addEventListener("click", copyDiagnostics);
  elements.authorDialog.addEventListener("close", () => { syncOverlayState(); restoreOverlayFocus(); });
}

function installRuntimeGuards() {
  const rememberIssue = (kind, value) => {
    const message = value instanceof Error ? value.message : String(value || "Unknown runtime issue");
    const signature = `${kind}:${message}`;
    if (state.runtimeIssues.some((issue) => issue.signature === signature)) return;
    state.runtimeIssues.push({ signature, kind, message, timestamp: new Date().toISOString() });
    if (state.runtimeIssues.length > 25) state.runtimeIssues.shift();
  };

  window.addEventListener("error", (event) => rememberIssue("error", event.error || event.message));
  window.addEventListener("unhandledrejection", (event) => rememberIssue("promise", event.reason));
}

async function handleDroppedFiles(files) {
  const manifest = files.find((file) => /\.ctflab\.json$/i.test(file.name));
  const artifact = files.find((file) => file !== manifest);

  if (!manifest && files.length === 1 && /\.json$/i.test(files[0].name)) {
    try {
      const candidate = JSON.parse(await files[0].text());
      if (candidate?.schemaVersion === 1 && candidate?.expectedFlagSha256) {
        await loadChallengeManifest(files[0]);
        return;
      }
    } catch {
      // A regular JSON file is still a valid artifact.
    }
  }

  if (artifact) await analyzeFile(artifact, { role: "Primary artifact", preserveSession: false });
  if (manifest) await loadChallengeManifest(manifest);
}

function setupAmbientEffects() {
  const canvas = elements.ambientCanvas;
  const context = canvas?.getContext?.("2d");
  const core = document.querySelector(".cursor-core");
  const ring = document.querySelector(".cursor-ring");
  if (!canvas || !context) return;

  const particles = [];
  const pointerTrail = [];
  const reducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches;
  let lastTrailTime = 0;

  const resetCanvas = () => {
    const ratio = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.max(1, Math.floor(window.innerWidth * ratio));
    canvas.height = Math.max(1, Math.floor(window.innerHeight * ratio));
    canvas.style.width = `${window.innerWidth}px`;
    canvas.style.height = `${window.innerHeight}px`;
    context.setTransform(ratio, 0, 0, ratio, 0, 0);

    particles.length = 0;
    const count = reducedMotion ? 0 : Math.min(76, Math.max(34, Math.floor(window.innerWidth / 24)));
    for (let index = 0; index < count; index += 1) {
      particles.push({
        x: Math.random() * window.innerWidth,
        y: Math.random() * window.innerHeight,
        vx: (Math.random() - 0.5) * 0.18,
        vy: (Math.random() - 0.5) * 0.18,
        size: Math.random() * 1.5 + 0.35,
        phase: Math.random() * Math.PI * 2
      });
    }
  };

  const updatePointer = (event) => {
    state.pointer.x = event.clientX;
    state.pointer.y = event.clientY;
    document.documentElement.style.setProperty("--cursor-x", `${event.clientX}px`);
    document.documentElement.style.setProperty("--cursor-y", `${event.clientY}px`);
    document.body.classList.add("pointer-active");
    document.body.classList.remove("pointer-outside");

    const now = performance.now();
    if (!reducedMotion && now - lastTrailTime > 28) {
      pointerTrail.push({ x: event.clientX, y: event.clientY, life: 1 });
      if (pointerTrail.length > 20) pointerTrail.shift();
      lastTrailTime = now;
    }
  };

  document.addEventListener("pointermove", updatePointer, { passive: true });
  document.addEventListener("pointerover", (event) => {
    document.body.classList.toggle("cursor-interactive", Boolean(event.target.closest("button, a, input, textarea, select, [role='button'], .drop-zone, canvas")));
  }, { passive: true });
  document.documentElement.addEventListener("pointerleave", () => document.body.classList.add("pointer-outside"), { passive: true });
  document.documentElement.addEventListener("pointerenter", () => document.body.classList.remove("pointer-outside"), { passive: true });

  const draw = (time) => {
    const width = window.innerWidth;
    const height = window.innerHeight;
    const theme = getComputedStyle(document.body).getPropertyValue("--case-signal-rgb").trim() || "111, 235, 255";
    context.clearRect(0, 0, width, height);

    if (!document.hidden && !reducedMotion) {
      particles.forEach((particle) => {
        particle.x += particle.vx;
        particle.y += particle.vy;
        if (particle.x < -30) particle.x = width + 30;
        if (particle.x > width + 30) particle.x = -30;
        if (particle.y < -30) particle.y = height + 30;
        if (particle.y > height + 30) particle.y = -30;

        const pulse = 0.45 + Math.sin(time * 0.0007 + particle.phase) * 0.2;
        context.beginPath();
        context.arc(particle.x, particle.y, particle.size, 0, Math.PI * 2);
        context.fillStyle = `rgba(${theme}, ${Math.max(0.08, pulse * 0.34)})`;
        context.fill();
      });

      for (let first = 0; first < particles.length; first += 1) {
        for (let second = first + 1; second < particles.length; second += 1) {
          const dx = particles[first].x - particles[second].x;
          const dy = particles[first].y - particles[second].y;
          const distance = Math.hypot(dx, dy);
          if (distance < 116) {
            context.beginPath();
            context.moveTo(particles[first].x, particles[first].y);
            context.lineTo(particles[second].x, particles[second].y);
            context.strokeStyle = `rgba(${theme}, ${(1 - distance / 116) * 0.08})`;
            context.lineWidth = 0.6;
            context.stroke();
          }
        }
      }

      pointerTrail.forEach((point) => {
        point.life -= 0.03;
        context.beginPath();
        context.arc(point.x, point.y, Math.max(0.6, point.life * 2.3), 0, Math.PI * 2);
        context.fillStyle = `rgba(${theme}, ${Math.max(0, point.life * 0.18)})`;
        context.fill();
      });
      while (pointerTrail.length && pointerTrail[0].life <= 0) pointerTrail.shift();
    }

    state.pointer.ringX += (state.pointer.x - state.pointer.ringX) * 0.18;
    state.pointer.ringY += (state.pointer.y - state.pointer.ringY) * 0.18;
    if (core && ring) {
      core.style.transform = `translate3d(${state.pointer.x - 3}px, ${state.pointer.y - 3}px, 0)`;
      const ringSize = document.body.classList.contains("cursor-interactive") ? 52 : 34;
      ring.style.transform = `translate3d(${state.pointer.ringX - ringSize / 2}px, ${state.pointer.ringY - ringSize / 2}px, 0)`;
    }

    requestAnimationFrame(draw);
  };

  resetCanvas();
  window.addEventListener("resize", resetCanvas, { passive: true });
  requestAnimationFrame(draw);
}

function setupHeroSignal() {
  const canvas = elements.heroSignalCanvas;
  const context = canvas.getContext("2d");
  const points = Array.from({ length: 7 }, (_, index) => ({
    angle: (Math.PI * 2 * index) / 7,
    radius: 0.18 + Math.random() * 0.24,
    phase: Math.random() * Math.PI * 2
  }));

  const draw = (time) => {
    const rect = canvas.getBoundingClientRect();
    if (rect.width > 0 && rect.height > 0) {
      const ratio = Math.min(window.devicePixelRatio || 1, 2);
      const targetWidth = Math.floor(rect.width * ratio);
      const targetHeight = Math.floor(rect.height * ratio);
      if (canvas.width !== targetWidth || canvas.height !== targetHeight) {
        canvas.width = targetWidth;
        canvas.height = targetHeight;
      }
      context.setTransform(ratio, 0, 0, ratio, 0, 0);
      context.clearRect(0, 0, rect.width, rect.height);

      const rgb = getComputedStyle(document.body).getPropertyValue("--case-signal-rgb").trim() || "111, 235, 255";
      const centerX = rect.width * 0.5;
      const centerY = rect.height * 0.52;
      const radius = Math.min(rect.width, rect.height) * 0.34;

      for (let ring = 1; ring <= 4; ring += 1) {
        context.beginPath();
        context.arc(centerX, centerY, (radius * ring) / 4, 0, Math.PI * 2);
        context.strokeStyle = `rgba(${rgb}, ${0.025 + ring * 0.012})`;
        context.lineWidth = 1;
        context.stroke();
      }

      context.beginPath();
      for (let x = 0; x <= rect.width; x += 3) {
        const normalized = x / rect.width;
        const wave = Math.sin(normalized * Math.PI * 8 + time * 0.0022) * 15;
        const noise = Math.sin(normalized * Math.PI * 21 - time * 0.0013) * 5;
        const y = centerY + wave + noise;
        if (x === 0) context.moveTo(x, y);
        else context.lineTo(x, y);
      }
      context.strokeStyle = `rgba(${rgb}, 0.7)`;
      context.lineWidth = 1.4;
      context.shadowBlur = 12;
      context.shadowColor = `rgba(${rgb}, 0.55)`;
      context.stroke();
      context.shadowBlur = 0;

      const nodePositions = points.map((point) => ({
        x: centerX + Math.cos(point.angle + time * 0.00015) * radius * (1 + Math.sin(time * 0.0007 + point.phase) * 0.08),
        y: centerY + Math.sin(point.angle + time * 0.00015) * radius * 0.72
      }));

      nodePositions.forEach((node, index) => {
        const next = nodePositions[(index + 2) % nodePositions.length];
        context.beginPath();
        context.moveTo(node.x, node.y);
        context.lineTo(next.x, next.y);
        context.strokeStyle = `rgba(${rgb}, 0.12)`;
        context.lineWidth = 0.8;
        context.stroke();

        context.beginPath();
        context.arc(node.x, node.y, index === 0 ? 4 : 2.6, 0, Math.PI * 2);
        context.fillStyle = index === 0 ? `rgba(${rgb}, 1)` : `rgba(${rgb}, 0.64)`;
        context.fill();
      });
    }
    requestAnimationFrame(draw);
  };

  const updateClock = () => {
    elements.heroClock.textContent = new Date().toLocaleTimeString([], { hour12: false });
  };
  updateClock();
  setInterval(updateClock, 1000);
  requestAnimationFrame(draw);
}

function pushHeroTerminal(message, tone = "signal") {
  if (!elements.heroTerminal) return;
  const rows = [...elements.heroTerminal.querySelectorAll("p")];
  rows.forEach((row) => row.classList.remove("terminal-current", "terminal-success", "terminal-error"));
  const row = document.createElement("p");
  row.className = `terminal-current${tone === "success" ? " terminal-success" : tone === "error" ? " terminal-error" : ""}`;
  const index = String((Number(rows.at(-1)?.querySelector("span")?.textContent) || rows.length) + 1).padStart(2, "0");
  row.innerHTML = `<span>${index}</span>${escapeHtml(message)}<span class="terminal-caret">_</span>`;
  elements.heroTerminal.appendChild(row);
  while (elements.heroTerminal.children.length > 5) elements.heroTerminal.firstElementChild.remove();
}

function setupTiltEffects() {
  document.querySelectorAll("[data-tilt], .summary-card, .drop-zone").forEach((card) => {
    card.addEventListener("mousemove", (event) => {
      const rect = card.getBoundingClientRect();
      const x = (event.clientX - rect.left) / Math.max(rect.width, 1) - 0.5;
      const y = (event.clientY - rect.top) / Math.max(rect.height, 1) - 0.5;
      card.style.setProperty("--tilt-x", `${(-y * 3.2).toFixed(2)}deg`);
      card.style.setProperty("--tilt-y", `${(x * 4.4).toFixed(2)}deg`);
    });
    card.addEventListener("mouseleave", () => {
      card.style.setProperty("--tilt-x", "0deg");
      card.style.setProperty("--tilt-y", "0deg");
    });
  });
}

function handleImmersiveResize() {
  if (!elements.caseboardOverlay.classList.contains("hidden")) {
    buildCaseboardNodes();
    renderCaseboard();
  }
  if (document.getElementById("tab-byte-map")?.classList.contains("active")) requestAnimationFrame(drawByteMap);
}

function pulseScan() {
  document.body.classList.remove("scan-active");
  void document.body.offsetWidth;
  document.body.classList.add("scan-active");
  pushHeroTerminal("pulse scan initiated");
  setTimeout(() => document.body.classList.remove("scan-active"), 1500);

  let target = elements.dropZone;
  let message = "Artifact intake located.";
  if (state.file && !state.completedSteps.has(1)) {
    target = document.querySelector(".analysis-panel");
    message = state.signatures.some((signature) => signature.role === "embedded")
      ? "Embedded signatures detected. Open the Signature map or Byte map."
      : "Evidence surfaces located. Inspect metadata, strings, byte map, hex, or findings.";
  } else if (state.file && !state.completedSteps.has(2)) {
    target = document.querySelector(".decoder-panel");
    message = "Decoder workbench located. Transform the suspicious clue or run Auto-probe.";
  } else if (state.file && !state.completedSteps.has(3)) {
    target = document.querySelector(".verification-panel");
    message = "Verification panel located. Submit the recovered flag against a trusted manifest.";
  } else if (state.file && state.completedSteps.size >= timelineSteps.length) {
    target = elements.exportButton;
    message = "Case complete. Export the investigation replay.";
  }

  target?.classList.remove("pulse-target");
  void target?.offsetWidth;
  target?.classList.add("pulse-target");
  target?.scrollIntoView({ behavior: "smooth", block: "center" });
  setTimeout(() => target?.classList.remove("pulse-target"), 1700);
  showToast(message);
}

function restoreTheme() {
  let saved = null;
  try {
    saved = localStorage.getItem("ctf-replay-theme");
  } catch {
    saved = null;
  }
  const index = interfaceThemes.findIndex((theme) => theme.id === saved);
  state.themeIndex = index >= 0 ? index : 0;
  applyTheme(false);
}

function cycleTheme() {
  state.themeIndex = (state.themeIndex + 1) % interfaceThemes.length;
  applyTheme(true);
}

function applyTheme(announce) {
  const theme = interfaceThemes[state.themeIndex];
  document.body.dataset.theme = theme.id;
  elements.themeButton.textContent = `Skin: ${theme.label}`;
  try {
    localStorage.setItem("ctf-replay-theme", theme.id);
  } catch {
    // Theme still applies when storage is unavailable.
  }
  renderCommandPaletteList();
  if (announce) showToast(`${theme.label} interface skin loaded.`);
}

function restoreFocusMode() {
  try {
    state.focusMode = localStorage.getItem("ctf-replay-focus-mode") === "on";
  } catch {
    state.focusMode = false;
  }
}

function initSectionRail() {
  const rail = document.getElementById("sectionRail");
  if (!rail) return;
  const links = [...rail.querySelectorAll("[data-rail-target]")];
  if (!links.length) return;

  const setActive = (id) => {
    links.forEach((link) => link.classList.toggle("active", link.dataset.railTarget === id));
  };

  links.forEach((link) => {
    link.addEventListener("click", (event) => {
      const targetId = link.dataset.railTarget;
      const target = document.getElementById(targetId);
      if (!target) return;
      event.preventDefault();
      setActive(targetId);
      target.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  });

  const observer = new IntersectionObserver((entries) => {
    const visible = entries
      .filter((entry) => entry.isIntersecting)
      .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
    if (visible?.target?.id) setActive(visible.target.id);
  }, { rootMargin: "-22% 0px -58% 0px", threshold: [0.1, 0.2, 0.35, 0.55] });

  links.forEach((link) => {
    const target = document.getElementById(link.dataset.railTarget);
    if (target) observer.observe(target);
  });

  setActive("heroSection");
}

function calculateInvestigatorXP() {
  let xp = state.completedSteps.size * 260;
  xp += state.evidence.length * 45;
  xp += state.decoderHistory.length * 90;
  xp += state.candidates.size * 70;
  xp += state.findings.length * 12;
  xp += state.archives.length * 30;
  xp += state.signatures.filter((signature) => signature.role === "embedded").length * 24;
  if (state.completedSteps.has(3)) xp += 500;
  return xp;
}

function investigatorRankForXP(xp) {
  const ranks = [
    { minimum: 0, name: "Packet Scout" },
    { minimum: 250, name: "Signal Hunter" },
    { minimum: 700, name: "Byte Sleuth" },
    { minimum: 1300, name: "Forensic Operator" },
    { minimum: 2100, name: "Replay Architect" },
    { minimum: 3200, name: "Ghost Protocol" }
  ];
  let current = ranks[0];
  let next = null;
  ranks.forEach((rank, index) => {
    if (xp >= rank.minimum) {
      current = rank;
      next = ranks[index + 1] || null;
    }
  });
  return { current, next };
}

function updateInvestigatorHUD() {
  if (!elements.investigatorRank) return;
  const xp = calculateInvestigatorXP();
  const rank = investigatorRankForXP(xp);
  const lower = rank.current.minimum;
  const upper = rank.next?.minimum || Math.max(lower + 1000, xp + 1);
  const progress = Math.max(0, Math.min(100, ((xp - lower) / Math.max(upper - lower, 1)) * 100));

  elements.investigatorRank.textContent = rank.current.name;
  elements.xpValue.textContent = `${xp.toLocaleString()} XP`;
  elements.xpBar.style.width = `${progress}%`;
  elements.xpNext.textContent = rank.next
    ? `${Math.max(0, rank.next.minimum - xp)} XP until ${rank.next.name}`
    : "Maximum operator clearance achieved";

  if (xp > state.xpLast) {
    elements.xpPulse.classList.remove("animate");
    void elements.xpPulse.offsetWidth;
    elements.xpPulse.classList.add("animate");
  }
  state.xpLast = xp;

  const unlocks = {
    "first-byte": Boolean(state.file),
    "evidence-hunter": state.evidence.length >= 5,
    "decoder-chain": state.decoderHistory.length >= 3,
    verified: state.completedSteps.has(3)
  };

  Object.entries(unlocks).forEach(([id, unlocked]) => {
    const badge = elements.achievementStrip.querySelector(`[data-achievement="${id}"]`);
    badge?.classList.toggle("unlocked", unlocked);
    badge?.classList.toggle("locked", !unlocked);
    if (unlocked && !state.achievements.has(id)) {
      state.achievements.add(id);
      if (state.file) showToast(`Achievement unlocked: ${badge?.title || id}`);
    }
  });

  let nextMove = "Load an artifact and establish identity.";
  if (state.file && !state.completedSteps.has(1)) {
    nextMove = state.signatures.some((signature) => signature.role === "embedded")
      ? "Inspect the embedded Signature map and entropy boundaries."
      : "Inspect metadata, strings, Byte map, hex, or findings.";
  } else if (state.file && !state.completedSteps.has(2)) {
    nextMove = "Extract or decode the most suspicious clue; Auto-probe can rank common transforms.";
  } else if (state.file && !state.completedSteps.has(3)) {
    nextMove = "Verify the candidate against a trusted manifest.";
  } else if (state.file && state.completedSteps.size >= timelineSteps.length) {
    nextMove = "Export the replay, evidence JSON, and byte intelligence map.";
  }
  elements.nextMoveText.textContent = nextMove;
}

function openDiagnostics() {
  closeCommandPalette(true);
  closeCaseboard(true);
  rememberOverlayFocus();
  elements.diagnosticsOverlay.classList.remove("hidden");
  elements.diagnosticsOverlay.setAttribute("aria-hidden", "false");
  syncOverlayState();
  requestAnimationFrame(() => elements.runDiagnosticsButton.focus());
  if (!state.diagnosticsResults.length) runDiagnostics();
}

function closeDiagnostics(silent = false) {
  if (elements.diagnosticsOverlay.classList.contains("hidden")) return;
  elements.diagnosticsOverlay.classList.add("hidden");
  elements.diagnosticsOverlay.setAttribute("aria-hidden", "true");
  syncOverlayState();
  restoreOverlayFocus();
  if (!silent) showToast("System check closed.");
}

async function runDiagnostics() {
  elements.runDiagnosticsButton.disabled = true;
  elements.runDiagnosticsButton.textContent = "Running checks…";
  const results = [];
  const add = (status, name, detail) => results.push({ status, name, detail });

  const missing = Object.entries(elements).filter(([, element]) => !element).map(([name]) => name);
  add(missing.length ? "fail" : "pass", "Interface wiring", missing.length ? `Missing elements: ${missing.join(", ")}` : `${Object.keys(elements).length} required interface nodes are connected.`);

  const context = document.createElement("canvas").getContext?.("2d");
  add(context ? "pass" : "fail", "Canvas renderer", context ? "2D canvas is available for the signal deck, byte map, and caseboard." : "Canvas 2D is unavailable.");

  add(typeof File === "function" && typeof FileReader === "function" && typeof Blob === "function" ? "pass" : "fail", "Local file APIs", "File, FileReader, and Blob support are required for local-only analysis.");

  try {
    const hash = await sha256Text("abc");
    add(hash === "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ? "pass" : "fail", "SHA-256 engine", hash === "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ? "Known-answer test passed." : `Unexpected digest: ${hash}`);
  } catch (error) {
    add("fail", "SHA-256 engine", error.message || "Hashing failed.");
  }

  const decoderTests = [
    ["Base64 decoder", () => bytesToUtf8(decodeBase64Bytes("SGVsbG8=") || new Uint8Array()) === "Hello"],
    ["Hex decoder", () => bytesToUtf8(decodeHexBytes("48656c6c6f") || new Uint8Array()) === "Hello"],
    ["Base32 decoder", () => bytesToUtf8(decodeBase32Bytes("JBSWY3DP") || new Uint8Array()) === "Hello"],
    ["Binary decoder", () => bytesToUtf8(decodeBinaryBytes("01001000 01101001") || new Uint8Array()) === "Hi"],
    ["Decimal ASCII decoder", () => bytesToUtf8(decodeDecimalBytes("72 105") || new Uint8Array()) === "Hi"],
    ["ROT/Caesar engine", () => rotateAscii("uryyb", 13) === "hello"]
  ];
  decoderTests.forEach(([name, test]) => {
    try {
      const passed = Boolean(test());
      add(passed ? "pass" : "fail", name, passed ? "Known-answer test passed." : "Known-answer output did not match.");
    } catch (error) {
      add("fail", name, error.message || "Decoder test failed.");
    }
  });

  try {
    const key = "ctf-replay-diagnostic";
    localStorage.setItem(key, "ok");
    const passed = localStorage.getItem(key) === "ok";
    localStorage.removeItem(key);
    add(passed ? "pass" : "warn", "Local note storage", passed ? "Browser-local persistence is available." : "Storage returned an unexpected value.");
  } catch {
    add("warn", "Local note storage", "Unavailable in this browser mode; analysis still works without persistence.");
  }

  add("DecompressionStream" in window ? "pass" : "warn", "ZIP deflate extraction", "DecompressionStream" in window ? "Deflate-compressed ZIP entries can be extracted locally." : "Stored ZIP entries work, but this browser cannot inflate compressed entries.");
  add(typeof URL?.createObjectURL === "function" ? "pass" : "fail", "Local export engine", typeof URL?.createObjectURL === "function" ? "Blob downloads are supported." : "Object URL downloads are unavailable.");

  try {
    const signatureTest = scanEmbeddedSignatures(Uint8Array.from([0, 1, 2, 3, 4, 0x50, 0x4b, 0x03, 0x04, 0, 0]));
    add(signatureTest.some((item) => item.id === "zip" && item.offset === 5) ? "pass" : "fail", "Signature scanner", "Embedded-offset known-answer test completed.");
  } catch (error) {
    add("fail", "Signature scanner", error.message || "Signature scan failed.");
  }

  try {
    const map = buildByteMapData(Uint8Array.from({ length: 1024 }, (_, index) => index % 256));
    add(map.blocks.length && Number.isFinite(map.peakEntropy) ? "pass" : "fail", "Byte intelligence map", `${map.blocks.length} diagnostic regions generated; peak entropy ${map.peakEntropy.toFixed(2)} bits.`);
  } catch (error) {
    add("fail", "Byte intelligence map", error.message || "Byte map generation failed.");
  }

  const nativeCursorVisible = getComputedStyle(document.body).cursor !== "none"
    && getComputedStyle(elements.diagnosticsButton).cursor !== "none";
  add(nativeCursorVisible ? "pass" : "fail", "Cursor fallback", nativeCursorVisible ? "The native pointer remains available; the animated follower is decorative." : "A CSS rule is hiding the native pointer.");

  add(state.runtimeIssues.length ? "fail" : "pass", "Runtime issue log", state.runtimeIssues.length ? state.runtimeIssues.map((issue) => issue.message).slice(-4).join(" · ") : "No uncaught errors or unhandled promise rejections recorded.");

  state.diagnosticsResults = results;
  renderDiagnostics();
  elements.runDiagnosticsButton.disabled = false;
  elements.runDiagnosticsButton.textContent = "Run full system check";
  pushHeroTerminal(`system check: ${results.filter((result) => result.status === "pass").length}/${results.length} passed`, results.some((result) => result.status === "fail") ? "error" : "success");
}

function renderDiagnostics() {
  const results = state.diagnosticsResults;
  const passed = results.filter((result) => result.status === "pass").length;
  const warnings = results.filter((result) => result.status === "warn").length;
  const failed = results.filter((result) => result.status === "fail").length;
  elements.diagnosticsPassed.textContent = String(passed);
  elements.diagnosticsWarnings.textContent = String(warnings);
  elements.diagnosticsFailed.textContent = String(failed);
  elements.diagnosticsOverall.textContent = failed ? "Attention required" : warnings ? "Operational with warnings" : "All systems operational";
  elements.diagnosticsOverall.className = failed ? "diagnostic-fail" : warnings ? "diagnostic-warn" : "diagnostic-pass";
  if (!results.length) {
    elements.diagnosticsList.className = "diagnostics-list empty-state";
    elements.diagnosticsList.textContent = "Run the check to verify this browser environment.";
    return;
  }
  elements.diagnosticsList.className = "diagnostics-list";
  elements.diagnosticsList.innerHTML = "";
  results.forEach((result) => {
    const row = document.createElement("div");
    row.className = `diagnostic-row ${result.status}`;
    const icon = document.createElement("span");
    icon.className = "diagnostic-icon";
    icon.textContent = result.status === "pass" ? "✓" : result.status === "warn" ? "!" : "×";
    const name = document.createElement("strong");
    name.className = "diagnostic-name";
    name.textContent = result.name;
    const detail = document.createElement("span");
    detail.className = "diagnostic-detail";
    detail.textContent = result.detail;
    const status = document.createElement("span");
    status.className = "diagnostic-status";
    status.textContent = result.status.toUpperCase();
    row.append(icon, name, detail, status);
    elements.diagnosticsList.appendChild(row);
  });
}

function copyDiagnostics() {
  if (!state.diagnosticsResults.length) return showToast("Run diagnostics before copying results.");
  const header = `CTF Replay Lab diagnostics · ${new Date().toISOString()}`;
  const body = state.diagnosticsResults.map((result) => `[${result.status.toUpperCase()}] ${result.name}: ${result.detail}`).join("\n");
  copyText(`${header}\n${body}`);
}

function syncOverlayState() {
  const open = !elements.caseboardOverlay.classList.contains("hidden")
    || !elements.diagnosticsOverlay.classList.contains("hidden")
    || !elements.commandPalette.classList.contains("hidden")
    || elements.authorDialog.open;
  document.body.classList.toggle("overlay-open", open);
}

function rememberOverlayFocus() {
  state.lastFocusedElement = document.activeElement instanceof HTMLElement ? document.activeElement : null;
}

function restoreOverlayFocus() {
  const target = state.lastFocusedElement;
  state.lastFocusedElement = null;
  if (target?.isConnected) requestAnimationFrame(() => target.focus({ preventScroll: true }));
}

function openCaseboard() {
  closeCommandPalette(true);
  closeDiagnostics(true);
  rememberOverlayFocus();
  elements.caseboardOverlay.classList.remove("hidden");
  elements.caseboardOverlay.setAttribute("aria-hidden", "false");
  syncOverlayState();
  buildCaseboardNodes();
  updateCaseboardInspector();
  startCaseboardAnimation();
  requestAnimationFrame(() => elements.caseboardCenterButton.focus());
}

function closeCaseboard(silent = false) {
  if (elements.caseboardOverlay.classList.contains("hidden")) return;
  elements.caseboardOverlay.classList.add("hidden");
  elements.caseboardOverlay.setAttribute("aria-hidden", "true");
  if (state.caseboardAnimationFrame) cancelAnimationFrame(state.caseboardAnimationFrame);
  state.caseboardAnimationFrame = null;
  syncOverlayState();
  restoreOverlayFocus();
  if (!silent) showToast("Evidence constellation closed.");
}

function caseboardSourceNodes() {
  const nodes = [{
    id: "root",
    type: "root",
    title: state.file?.name || "Awaiting artifact",
    detail: state.file ? `${state.typeInfo?.name || "Artifact"} root with SHA-256 ${state.hash.slice(0, 16)}...` : "Load an artifact to establish the graph root.",
    value: state.hash || "No artifact loaded"
  }];

  state.findings.slice(0, 8).forEach((finding, index) => nodes.push({
    id: `finding-${index}`,
    type: "finding",
    title: finding.title,
    detail: finding.detail,
    value: finding.level || "finding"
  }));

  state.evidence.slice(-18).forEach((evidence) => nodes.push({
    id: evidence.id,
    type: evidence.type === "decode" ? "decode" : "evidence",
    title: evidence.title,
    detail: `${evidence.source} - ${evidence.preview || "Recorded evidence"}`,
    value: evidence.value || evidence.preview || ""
  }));

  [...state.candidates.values()].slice(0, 6).forEach((candidate, index) => nodes.push({
    id: `candidate-${index}`,
    type: "candidate",
    title: candidate.verified ? "Verified candidate" : "Flag candidate",
    detail: candidate.source,
    value: candidate.value
  }));

  return nodes;
}

function buildCaseboardNodes() {
  const canvas = elements.caseboardCanvas;
  const rect = canvas.getBoundingClientRect();
  const width = Math.max(rect.width, 480);
  const height = Math.max(rect.height, 360);
  const sourceNodes = caseboardSourceNodes();
  const centerX = width * 0.48;
  const centerY = height * 0.5;
  const grouped = {
    finding: sourceNodes.filter((node) => node.type === "finding"),
    evidence: sourceNodes.filter((node) => node.type === "evidence"),
    decode: sourceNodes.filter((node) => node.type === "decode"),
    candidate: sourceNodes.filter((node) => node.type === "candidate")
  };

  const nodes = [{ ...sourceNodes[0], x: centerX, y: centerY, radius: 13, parent: null }];
  const groupSettings = [
    ["finding", Math.min(width, height) * 0.22, -Math.PI * 0.9],
    ["evidence", Math.min(width, height) * 0.36, -Math.PI * 0.2],
    ["decode", Math.min(width, height) * 0.29, Math.PI * 0.45],
    ["candidate", Math.min(width, height) * 0.42, Math.PI * 0.92]
  ];

  groupSettings.forEach(([type, ringRadius, offset]) => {
    const group = grouped[type];
    group.forEach((node, index) => {
      const spread = Math.min(Math.PI * 1.35, 0.38 * Math.max(group.length - 1, 1));
      const angle = offset + (group.length === 1 ? 0 : (index / (group.length - 1) - 0.5) * spread);
      const jitter = ((index % 3) - 1) * 18;
      nodes.push({
        ...node,
        x: centerX + Math.cos(angle) * (ringRadius + jitter),
        y: centerY + Math.sin(angle) * (ringRadius + jitter) * 0.72,
        radius: type === "candidate" ? 8 : type === "decode" ? 7 : 6,
        parent: "root",
        phase: Math.random() * Math.PI * 2
      });
    });
  });

  state.caseboardNodes = nodes;
  elements.caseboardNodeCount.textContent = `${nodes.length} NODES`;
}

function caseboardColors() {
  const styles = getComputedStyle(document.body);
  return {
    root: styles.getPropertyValue("--case-signal").trim() || "#6febff",
    finding: styles.getPropertyValue("--case-rose").trim() || "#ff7396",
    evidence: styles.getPropertyValue("--case-violet").trim() || "#a58cff",
    decode: styles.getPropertyValue("--case-amber").trim() || "#ffc866",
    candidate: styles.getPropertyValue("--case-green").trim() || "#74f4b1"
  };
}

function drawCaseboard(time = performance.now()) {
  if (elements.caseboardOverlay.classList.contains("hidden")) return;
  const canvas = elements.caseboardCanvas;
  const context = canvas.getContext("2d");
  const rect = canvas.getBoundingClientRect();
  const ratio = Math.min(window.devicePixelRatio || 1, 2);
  const width = Math.max(1, rect.width);
  const height = Math.max(1, rect.height);
  const targetWidth = Math.floor(width * ratio);
  const targetHeight = Math.floor(height * ratio);
  if (canvas.width !== targetWidth || canvas.height !== targetHeight) {
    canvas.width = targetWidth;
    canvas.height = targetHeight;
    buildCaseboardNodes();
  }
  context.setTransform(ratio, 0, 0, ratio, 0, 0);
  context.clearRect(0, 0, width, height);
  const colors = caseboardColors();

  const root = state.caseboardNodes[0];
  state.caseboardNodes.slice(1).forEach((node, index) => {
    const pulse = 0.38 + Math.sin(time * 0.0014 + (node.phase || index)) * 0.12;
    context.beginPath();
    context.moveTo(root.x, root.y);
    context.lineTo(node.x, node.y);
    context.strokeStyle = hexToRgba(colors[node.type] || colors.evidence, Math.max(0.08, pulse * 0.28));
    context.lineWidth = state.caseboardSelected?.id === node.id ? 1.8 : 0.8;
    context.setLineDash(node.type === "finding" ? [4, 5] : []);
    context.stroke();
    context.setLineDash([]);
  });

  state.caseboardNodes.forEach((node, index) => {
    const selected = state.caseboardSelected?.id === node.id;
    const hoverPulse = 1 + Math.sin(time * 0.002 + (node.phase || index)) * 0.08;
    const color = colors[node.type] || colors.evidence;
    context.beginPath();
    context.arc(node.x, node.y, (node.radius + (selected ? 3 : 0)) * hoverPulse, 0, Math.PI * 2);
    context.fillStyle = hexToRgba(color, node.type === "root" ? 0.92 : 0.74);
    context.shadowBlur = selected ? 28 : node.type === "root" ? 22 : 12;
    context.shadowColor = color;
    context.fill();
    context.shadowBlur = 0;

    context.beginPath();
    context.arc(node.x, node.y, node.radius + 7 + Math.sin(time * 0.0018 + index) * 2, 0, Math.PI * 2);
    context.strokeStyle = hexToRgba(color, selected ? 0.65 : 0.14);
    context.lineWidth = selected ? 1.4 : 0.7;
    context.stroke();

    if (selected || node.type === "root") {
      context.font = `${node.type === "root" ? 10 : 9}px Cascadia Mono, monospace`;
      context.fillStyle = selected ? "rgba(236, 248, 255, 0.96)" : "rgba(185, 211, 225, 0.72)";
      context.textAlign = "center";
      context.fillText(truncateCanvasLabel(node.title, node.type === "root" ? 26 : 18), node.x, node.y + node.radius + 22);
    }
  });
}

function startCaseboardAnimation() {
  if (state.caseboardAnimationFrame) cancelAnimationFrame(state.caseboardAnimationFrame);
  const loop = (time) => {
    drawCaseboard(time);
    state.caseboardAnimationFrame = requestAnimationFrame(loop);
  };
  state.caseboardAnimationFrame = requestAnimationFrame(loop);
}

function renderCaseboard() {
  if (elements.caseboardOverlay.classList.contains("hidden")) return;
  buildCaseboardNodes();
  updateCaseboardInspector();
}

function nearestCaseboardNode(event) {
  const rect = elements.caseboardCanvas.getBoundingClientRect();
  const x = event.clientX - rect.left;
  const y = event.clientY - rect.top;
  let nearest = null;
  let distance = Infinity;
  state.caseboardNodes.forEach((node) => {
    const current = Math.hypot(node.x - x, node.y - y);
    if (current < distance && current < node.radius + 14) {
      nearest = node;
      distance = current;
    }
  });
  return nearest;
}

function handleCaseboardPointerMove(event) {
  const node = nearestCaseboardNode(event);
  elements.caseboardCanvas.style.cursor = node ? "pointer" : "crosshair";
}

function handleCaseboardClick(event) {
  const node = nearestCaseboardNode(event);
  if (!node) return;
  state.caseboardSelected = node;
  updateCaseboardInspector();
}

function updateCaseboardInspector() {
  const node = state.caseboardSelected || state.caseboardNodes[0];
  if (!node) return;
  elements.caseboardInspector.innerHTML = `
    <small>SELECTED ${escapeHtml(node.type.toUpperCase())} NODE</small>
    <h3>${escapeHtml(node.title)}</h3>
    <p>${escapeHtml(node.detail || "No additional detail recorded.")}</p>
    <code>${escapeHtml(String(node.value || "No raw value available").slice(0, 520))}</code>
  `;
}

function hexToRgba(hex, alpha) {
  const clean = String(hex).trim().replace("#", "");
  if (!/^[0-9a-f]{6}$/i.test(clean)) return `rgba(111, 235, 255, ${alpha})`;
  const red = Number.parseInt(clean.slice(0, 2), 16);
  const green = Number.parseInt(clean.slice(2, 4), 16);
  const blue = Number.parseInt(clean.slice(4, 6), 16);
  return `rgba(${red}, ${green}, ${blue}, ${alpha})`;
}

function truncateCanvasLabel(value, length) {
  const text = String(value || "node");
  return text.length > length ? `${text.slice(0, length - 1)}...` : text;
}


function handleGlobalShortcuts(event) {
  const key = event.key.toLowerCase();
  const inTypingContext = ["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement?.tagName);

  if ((event.ctrlKey || event.metaKey) && key === "k") {
    event.preventDefault();
    if (elements.commandPalette.classList.contains("hidden")) openCommandPalette();
    else closeCommandPalette();
    return;
  }

  if (key === "escape" && !elements.diagnosticsOverlay.classList.contains("hidden")) {
    event.preventDefault();
    closeDiagnostics();
    return;
  }

  if (key === "escape" && !elements.caseboardOverlay.classList.contains("hidden")) {
    event.preventDefault();
    closeCaseboard();
    return;
  }

  if (!inTypingContext && elements.commandPalette.classList.contains("hidden")) {
    if (key === "f") {
      event.preventDefault();
      toggleFocusMode();
      return;
    }
    if (key === "c") {
      event.preventDefault();
      openCaseboard();
      return;
    }
    if (key === "s") {
      event.preventDefault();
      pulseScan();
      return;
    }
    if (key === "t") {
      event.preventDefault();
      cycleTheme();
      return;
    }
    if (key === "d") {
      event.preventDefault();
      openDiagnostics();
      return;
    }
  }

  if (elements.commandPalette.classList.contains("hidden")) return;

  if (key === "escape") {
    closeCommandPalette();
    return;
  }

  const items = getCommandPaletteActions();
  if (key === "arrowdown") {
    event.preventDefault();
    state.commandPaletteIndex = (state.commandPaletteIndex + 1) % Math.max(items.length, 1);
    renderCommandPaletteList();
  } else if (key === "arrowup") {
    event.preventDefault();
    state.commandPaletteIndex = (state.commandPaletteIndex - 1 + Math.max(items.length, 1)) % Math.max(items.length, 1);
    renderCommandPaletteList();
  } else if (key === "enter") {
    const action = items[state.commandPaletteIndex];
    if (action) {
      event.preventDefault();
      runCommandPaletteAction(action.id);
    }
  }
}

function baseCommandPaletteActions() {
  return [
    { id: "load-artifact", label: "Load artifact", description: "Open a local artifact for analysis.", run: () => elements.artifactInput.click() },
    { id: "load-challenge", label: "Load challenge manifest", description: "Attach a .ctflab.json verification manifest.", run: () => elements.challengeInput.click() },
    { id: "author-manifest", label: "Author verification manifest", description: "Create a safe hash-backed challenge manifest.", run: openAuthorDialog },
    { id: "demo", label: "Launch demo challenge", description: "Load the built-in demo artifact and manifest.", run: loadDemo },
    { id: "pulse", label: "Pulse scan", description: "Scan the interface and locate the next best move.", run: pulseScan },
    { id: "caseboard", label: "Open evidence constellation", description: "Visualize provenance links across the active case.", run: openCaseboard },
    { id: "diagnostics", label: "Run system integrity check", description: "Test hashing, decoders, storage, canvas, cursor fallback, and browser capabilities.", run: openDiagnostics },
    { id: "theme", label: "Cycle interface skin", description: "Switch between Void, Signal, and Ember decks.", run: cycleTheme },
    { id: "focus", label: state.focusMode ? "Disable focus mode" : "Enable focus mode", description: "Reduce distractions and emphasize the workspace.", run: toggleFocusMode },
    { id: "export-report", label: "Export report", description: "Download the current investigation report.", run: exportReport },
    { id: "export-evidence", label: "Export evidence JSON", description: "Download structured evidence and replay data.", run: exportEvidenceJson },
    { id: "notes", label: "Jump to notes", description: "Focus the reasoning notes panel.", run: () => { elements.notesInput.scrollIntoView({ behavior: "smooth", block: "center" }); elements.notesInput.focus(); } },
    { id: "decoder", label: "Jump to decoder", description: "Focus the decoder input quickly.", run: () => { elements.decoderInput.scrollIntoView({ behavior: "smooth", block: "center" }); elements.decoderInput.focus(); } },
    { id: "tab-overview", label: "Open Overview tab", description: "See the basic artifact profile.", run: () => activateTab("overview") },
    { id: "tab-metadata", label: "Open Metadata tab", description: "Inspect metadata fields and parsed structure.", run: () => activateTab("metadata") },
    { id: "tab-strings", label: "Open Strings tab", description: "Review extracted strings.", run: () => activateTab("strings") },
    { id: "tab-hex", label: "Open Hex tab", description: "Jump into byte-level analysis.", run: () => activateTab("hex") },
    { id: "tab-byte-map", label: "Open Byte map", description: "Visualize entropy, printable density, and payload boundaries.", run: () => activateTab("byte-map") },
    { id: "tab-signatures", label: "Open Signature map", description: "Inspect embedded file signatures and jump to their offsets.", run: () => activateTab("signatures") },
    { id: "auto-probe", label: "Auto-probe decoder input", description: "Rank common transformations for the current decoder input.", run: autoProbeInput },
    { id: "tab-archives", label: "Open Archives tab", description: "Inspect embedded or carved archives.", run: () => activateTab("archives") },
    { id: "tab-findings", label: "Open Findings tab", description: "Review notable clues detected automatically.", run: () => activateTab("findings") },
    { id: "tab-evidence", label: "Open Evidence tab", description: "Review saved evidence and provenance.", run: () => activateTab("evidence") },
    { id: "reset", label: "Reset session", description: "Clear the current session and start over.", run: () => resetSession({ keepChallenge: false }) }
  ];
}

function getCommandPaletteActions() {
  const query = (elements.commandPaletteInput.value || "").trim().toLowerCase();
  const actions = baseCommandPaletteActions();
  if (!query) return actions;
  return actions.filter((action) => `${action.label} ${action.description}`.toLowerCase().includes(query));
}

function renderCommandPaletteList() {
  const actions = getCommandPaletteActions();
  state.commandPaletteIndex = Math.min(state.commandPaletteIndex, Math.max(actions.length - 1, 0));
  if (!actions.length) {
    elements.commandPaletteList.innerHTML = '<div class="empty-state">No actions match that search.</div>';
    return;
  }

  elements.commandPaletteList.innerHTML = actions.map((action, index) => `
    <button class="command-item ${index === state.commandPaletteIndex ? "active" : ""}" type="button" data-command-action="${action.id}">
      <strong>${escapeHtml(action.label)}</strong>
      <small>${escapeHtml(action.description)}</small>
    </button>
  `).join("");
}

function openCommandPalette() {
  closeCaseboard(true);
  closeDiagnostics(true);
  rememberOverlayFocus();
  elements.commandPalette.classList.remove("hidden");
  elements.commandPalette.setAttribute("aria-hidden", "false");
  state.commandPaletteIndex = 0;
  renderCommandPaletteList();
  syncOverlayState();
  requestAnimationFrame(() => elements.commandPaletteInput.focus());
}

function closeCommandPalette(silent = false) {
  if (elements.commandPalette.classList.contains("hidden")) return;
  elements.commandPalette.classList.add("hidden");
  elements.commandPalette.setAttribute("aria-hidden", "true");
  elements.commandPaletteInput.value = "";
  state.commandPaletteIndex = 0;
  renderCommandPaletteList();
  syncOverlayState();
  restoreOverlayFocus();
  if (!silent) showToast("Quick actions closed.");
}

function runCommandPaletteAction(id) {
  const action = baseCommandPaletteActions().find((item) => item.id === id);
  if (!action) return;
  closeCommandPalette(true);
  Promise.resolve(action.run()).finally(() => showToast(`Action: ${action.label}`));
}

function toggleFocusMode() {
  state.focusMode = !state.focusMode;
  try {
    localStorage.setItem("ctf-replay-focus-mode", state.focusMode ? "on" : "off");
  } catch {
    // Focus mode still applies even when storage is unavailable.
  }
  updateFocusModeUI();
  showToast(state.focusMode ? "Focus mode enabled." : "Focus mode disabled.");
}

function updateFocusModeUI() {
  document.body.classList.toggle("focus-mode", state.focusMode);
  elements.focusModeButton.textContent = state.focusMode ? "Exit focus" : "Focus mode";
  renderCommandPaletteList();
}

function handleDelegatedClick(event) {
  const diagnosticsClose = event.target.closest("[data-diagnostics-close]");
  if (diagnosticsClose) {
    closeDiagnostics();
    return;
  }

  const signatureOffset = event.target.closest("[data-signature-offset]");
  if (signatureOffset) {
    const offset = Number(signatureOffset.dataset.signatureOffset);
    elements.hexOffsetInput.value = `0x${offset.toString(16)}`;
    state.hexOffset = offset;
    activateTab("hex", true);
    renderHex();
    return;
  }

  const probeResult = event.target.closest("[data-probe-index]");
  if (probeResult) {
    applyProbeResult(Number(probeResult.dataset.probeIndex));
    return;
  }

  const caseboardClose = event.target.closest("[data-caseboard-close]");
  if (caseboardClose) {
    closeCaseboard();
    return;
  }

  const heroAction = event.target.closest("[data-hero-action]");
  if (heroAction) {
    if (heroAction.dataset.heroAction === "artifact") elements.artifactInput.click();
    if (heroAction.dataset.heroAction === "demo") loadDemo();
    return;
  }

  const closePalette = event.target.closest("[data-command-close]");
  if (closePalette) {
    closeCommandPalette();
    return;
  }

  const commandAction = event.target.closest("[data-command-action]");
  if (commandAction) {
    runCommandPaletteAction(commandAction.dataset.commandAction);
    return;
  }

  const copyButton = event.target.closest("[data-copy-target]");
  if (copyButton) {
    const target = document.getElementById(copyButton.dataset.copyTarget);
    if (target) copyText(target.textContent || "");
    return;
  }

  const candidateButton = event.target.closest("[data-candidate]");
  if (candidateButton) {
    elements.flagInput.value = candidateButton.dataset.candidate;
    showToast("Candidate placed in the flag field.");
    return;
  }

  const archiveAction = event.target.closest("[data-archive-action]");
  if (archiveAction) {
    handleArchiveAction(
      archiveAction.dataset.archiveAction,
      Number(archiveAction.dataset.archiveId),
      archiveAction.dataset.entryIndex === undefined ? null : Number(archiveAction.dataset.entryIndex)
    );
    return;
  }

  const evidenceCopy = event.target.closest("[data-evidence-copy]");
  if (evidenceCopy) {
    const item = state.evidence.find((entry) => entry.id === evidenceCopy.dataset.evidenceCopy);
    if (item) copyText(item.value || item.preview || "");
  }
}

async function analyzeFile(file, options = {}) {
  const { role = "Primary artifact", preserveSession = false, parentSource = null } = options;

  if (file.size > MAX_FILE_SIZE) {
    showToast("This release accepts artifacts up to 50 MB.");
    return;
  }

  if (!preserveSession) {
    resetArtifactState({ preserveInvestigation: false });
  } else {
    resetArtifactState({ preserveInvestigation: true });
  }

  state.file = file;
  state.role = role;
  state.parentSource = parentSource;
  state.startedAt ||= new Date();

  elements.workspace.classList.remove("hidden");
  elements.exportButton.disabled = false;
  elements.sessionStatus.textContent = "Reading bytes, hashing the artifact, and building an evidence profile...";
  pushHeroTerminal(`artifact mounted: ${file.name}`);
  recordReplay("artifact", `Loaded ${file.name}`, `${role} · ${formatFileSize(file.size)}`);

  try {
    const arrayBuffer = await file.arrayBuffer();
    state.bytes = new Uint8Array(arrayBuffer);
    state.typeInfo = detectFileType(state.bytes, file);
    state.hash = await calculateSHA256(arrayBuffer);
    if (!preserveSession || !state.rootArtifactHash) {
      state.rootArtifactHash = state.hash;
      state.rootArtifactName = file.name;
    }

    const sample = state.bytes.length > 5_000_000 ? state.bytes.slice(0, 5_000_000) : state.bytes;
    state.entropy = calculateEntropy(sample);
    state.printable = printableRatio(sample);
    state.strings = extractStrings(prepareStringScanBytes(state.bytes), 4, MAX_STRING_RESULTS);
    state.visibleStrings = [...state.strings];
    state.signatures = scanEmbeddedSignatures(state.bytes);
    state.byteMap = buildByteMapData(state.bytes);

    const parsed = await parseArtifact(state.bytes, state.typeInfo);
    state.metadata = parsed.metadata;
    state.structures = parsed.structures;
    state.archives = parsed.archives;
    state.findings = buildFindings(parsed);

    discoverCandidatesFromSources();
    discoverEncodedClues();
    addEvidence({
      type: "identity",
      source: role,
      title: `${state.typeInfo.name} identified`,
      value: state.hash,
      preview: `SHA-256 ${state.hash}`,
      verified: true
    });

    const embeddedSignatures = state.signatures.filter((signature) => signature.role === "embedded");
    if (embeddedSignatures.length) {
      addEvidence({
        type: "signature-map",
        source: file.name,
        title: `${embeddedSignatures.length} embedded signature${embeddedSignatures.length === 1 ? "" : "s"} mapped`,
        value: embeddedSignatures.map((signature) => `${signature.name}@0x${signature.offset.toString(16)}`).join("\n"),
        preview: embeddedSignatures.slice(0, 5).map((signature) => `${signature.name} at 0x${signature.offset.toString(16)}`).join(" · "),
        verified: true
      });
    }

    completeStep(0);
    compareChallengeArtifactHash();
    renderAll();
    loadNotes();

    elements.sessionStatus.textContent =
      "Initial analysis complete. Inspect evidence tabs, then extract or decode the next clue.";
    pushHeroTerminal(`${state.typeInfo.short} identified / ${state.findings.length} findings / ${state.evidence.length} evidence`, "success");
    elements.workspace.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    console.error(error);
    elements.sessionStatus.textContent = "The browser could not complete the analysis.";
    showToast("Analysis failed. Check the browser console for details.");
  }
}

function resetArtifactState({ preserveInvestigation }) {
  const preserved = preserveInvestigation
    ? {
        candidates: state.candidates,
        evidence: state.evidence,
        decoderHistory: state.decoderHistory,
        replay: state.replay,
        completedSteps: state.completedSteps,
        revealedHints: state.revealedHints,
        manualEvidenceIds: state.manualEvidenceIds,
        startedAt: state.startedAt
      }
    : null;

  state.file = null;
  state.bytes = null;
  state.role = "Primary artifact";
  state.parentSource = null;
  state.hash = "";
  if (!preserveInvestigation) {
    state.rootArtifactHash = "";
    state.rootArtifactName = "";
  }
  state.typeInfo = null;
  state.metadata = {};
  state.structures = {};
  state.strings = [];
  state.visibleStrings = [];
  state.findings = [];
  state.archives = [];
  state.signatures = [];
  state.byteMap = { blocks: [], blockSize: 0, peakEntropy: 0, dominantByte: 0, nullRatio: 0 };
  state.autoProbeResults = [];
  state.entropy = 0;
  state.printable = 0;
  state.hexOffset = 0;
  state.lastDecoderResult = null;
  state.solvedAt = null;
  state.artifactHashMatches = true;

  if (preserved) {
    Object.assign(state, preserved);
  } else {
    state.candidates = new Map();
    state.evidence = [];
    state.decoderHistory = [];
    state.replay = [];
    state.completedSteps = new Set();
    state.revealedHints = 0;
    state.manualEvidenceIds = new Set();
    state.startedAt = null;
  }

  elements.decoderInput.value = "";
  elements.decoderOutput.textContent = "Decoded output will appear here.";
  elements.decoderOutput.className = "result-box";
  elements.flagInput.value = "";
  elements.flagResult.textContent =
    "A candidate is not considered correct until a challenge manifest verifies its SHA-256.";
  elements.flagResult.className = "result-box";
  elements.stringSearch.value = "";
  elements.interestingOnly.checked = false;
  elements.hexOffsetInput.value = "0";
  elements.signatureSearch.value = "";
  elements.autoProbeResults.classList.add("hidden");
  elements.autoProbeResults.innerHTML = "";
  hideByteMapTooltip();
  activateTab("overview", false);
}

function resetSession({ keepChallenge }) {
  const challenge = keepChallenge ? state.challenge : null;
  resetArtifactState({ preserveInvestigation: false });
  state.challenge = challenge;
  elements.workspace.classList.add("hidden");
  elements.artifactInput.value = "";
  elements.exportButton.disabled = true;
  elements.notesInput.value = "";
  elements.notesStatus.textContent = "Not saved";
  state.achievements = new Set();
  state.xpLast = 0;
  state.caseboardSelected = null;
  closeCaseboard(true);
  updateChallengeUI();
  renderTimeline();
  updateHints();
  showToast("Session reset.");
}

async function parseArtifact(bytes, typeInfo) {
  const metadata = {
    "Browser MIME type": state.file?.type || "Unknown",
    "Last modified": state.file?.lastModified
      ? new Date(state.file.lastModified).toISOString()
      : "Unknown"
  };
  const structures = {};
  const archives = [];

  if (typeInfo.short === "PNG") {
    const png = parsePng(bytes);
    Object.assign(metadata, png.metadata, png.structure);
    structures.png = png;

    if (png.iendEnd !== null && png.iendEnd < bytes.length) {
      const length = bytes.length - png.iendEnd;
      const region = {
        id: archives.length,
        kind: "tail",
        label: "Trailing data after PNG IEND",
        offset: png.iendEnd,
        length,
        entries: [],
        zip: null
      };
      if (matchesBytesAt(bytes, png.iendEnd, [0x50, 0x4b, 0x03, 0x04])) {
        region.kind = "zip";
        region.label = "Appended ZIP after PNG IEND";
        region.zip = parseZipRegion(bytes, png.iendEnd);
        region.entries = region.zip?.entries || [];
      }
      archives.push(region);
    }
  }

  if (typeInfo.short === "JPEG") {
    Object.assign(metadata, parseJpeg(bytes));
  }

  if (typeInfo.short === "PDF") {
    Object.assign(metadata, parsePdf(bytes));
  }

  if (typeInfo.short === "ZIP") {
    const zip = parseZipRegion(bytes, 0);
    if (zip) {
      archives.push({
        id: archives.length,
        kind: "zip",
        label: "Primary ZIP archive",
        offset: 0,
        length: zip.length,
        entries: zip.entries,
        zip
      });
      metadata["Archive entries"] = String(zip.entries.length);
      metadata["Archive comment"] = zip.comment || "None";
    }
  }

  if (typeInfo.short === "ELF") Object.assign(metadata, parseElf(bytes));
  if (typeInfo.short === "PE") Object.assign(metadata, parsePe(bytes));
  if (typeInfo.short === "WAV") Object.assign(metadata, parseWav(bytes));
  if (typeInfo.short === "WEBP") Object.assign(metadata, parseWebp(bytes));
  if (typeInfo.short === "BMP") Object.assign(metadata, parseBmp(bytes));
  if (typeInfo.short === "SQLITE") Object.assign(metadata, parseSqlite(bytes));
  if (typeInfo.short === "OGG") Object.assign(metadata, parseOgg(bytes));
  if (typeInfo.short === "MP3") Object.assign(metadata, parseId3(bytes));
  if (typeInfo.short === "GZIP") Object.assign(metadata, parseGzip(bytes));
  if (typeInfo.short === "MP4") Object.assign(metadata, parseMp4(bytes));
  if (typeInfo.short === "PCAP") Object.assign(metadata, parsePcap(bytes));
  if (typeInfo.short === "PCAPNG") Object.assign(metadata, parsePcapng(bytes));
  if (typeInfo.short === "7Z") Object.assign(metadata, { "7-Zip version": `${bytes[6] ?? 0}.${bytes[7] ?? 0}` });
  if (typeInfo.short === "RAR") Object.assign(metadata, { "RAR generation": matchesBytesAt(bytes, 0, [0x52,0x61,0x72,0x21,0x1a,0x07,0x01,0x00]) ? "5.x" : "4.x" });
  if (typeInfo.short === "TEXT") Object.assign(metadata, parseText(bytes));

  if (!archives.length && typeInfo.short !== "ZIP") {
    const embeddedZipOffset = findSignature(bytes, [0x50, 0x4b, 0x03, 0x04], 1);
    if (embeddedZipOffset > 0) {
      const zip = parseZipRegion(bytes, embeddedZipOffset);
      if (zip) {
        archives.push({
          id: archives.length,
          kind: "zip",
          label: "Embedded ZIP region",
          offset: embeddedZipOffset,
          length: zip.length,
          entries: zip.entries,
          zip
        });
      }
    }
  }

  return { metadata, structures, archives };
}

function scanEmbeddedSignatures(bytes) {
  if (!bytes?.length) return [];
  const groups = new Map();
  embeddedSignaturePatterns.forEach((pattern) => {
    const first = pattern.bytes[0];
    if (!groups.has(first)) groups.set(first, []);
    groups.get(first).push(pattern);
  });

  const results = [];
  const perPattern = new Map();
  for (let offset = 0; offset < bytes.length && results.length < MAX_SIGNATURE_RESULTS; offset += 1) {
    const candidates = groups.get(bytes[offset]);
    if (!candidates) continue;
    for (const pattern of candidates) {
      const seen = perPattern.get(pattern.id) || 0;
      if (seen >= 16 || offset + pattern.bytes.length > bytes.length) continue;
      let matched = true;
      for (let index = 1; index < pattern.bytes.length; index += 1) {
        if (bytes[offset + index] !== pattern.bytes[index]) {
          matched = false;
          break;
        }
      }
      if (!matched || !validateEmbeddedSignature(pattern.id, bytes, offset)) continue;
      const contextStart = Math.max(0, offset - 4);
      const contextEnd = Math.min(bytes.length, offset + Math.max(pattern.bytes.length, 12));
      const primaryOffset = offset === 0 || (pattern.id === "ftyp" && offset === 4) || (pattern.id === "webp" && offset === 8);
      const structural = pattern.id === "zip-empty" || (pattern.id === "ftyp" && offset === 4) || (pattern.id === "webp" && offset === 8);
      results.push({
        ...pattern,
        offset,
        role: primaryOffset ? "primary" : structural ? "structural" : "embedded",
        context: bytesToHex(bytes.slice(contextStart, contextEnd))
      });
      perPattern.set(pattern.id, seen + 1);
    }
  }
  return results.sort((first, second) => first.offset - second.offset || first.name.localeCompare(second.name));
}

function validateEmbeddedSignature(id, bytes, offset) {
  if (id === "pe") {
    if (offset + 0x40 > bytes.length) return offset === 0;
    const relativePe = readUint32(bytes, offset + 0x3c, true);
    const peOffset = offset + relativePe;
    return relativePe >= 0x40 && peOffset + 4 <= bytes.length && matchesBytesAt(bytes, peOffset, [0x50, 0x45, 0x00, 0x00]);
  }
  if (id === "bmp") {
    if (offset + 18 > bytes.length) return false;
    const declaredSize = readUint32(bytes, offset + 2, true);
    const dibSize = readUint32(bytes, offset + 14, true);
    return declaredSize >= 26 && declaredSize <= bytes.length - offset && [12, 40, 52, 56, 108, 124].includes(dibSize);
  }
  if (id === "id3") {
    if (offset + 10 > bytes.length) return false;
    return bytes[offset + 3] !== 0xff && bytes[offset + 4] !== 0xff && [0, 1].includes(bytes[offset + 5] & 0x01);
  }
  if (id === "riff") return offset + 12 <= bytes.length;
  return true;
}

function buildByteMapData(bytes) {
  if (!bytes?.length) return { blocks: [], blockSize: 0, peakEntropy: 0, dominantByte: 0, nullRatio: 0 };
  const desiredBlocks = Math.min(BYTE_MAP_BLOCK_COUNT, Math.max(8, Math.ceil(bytes.length / 2048)));
  const blockSize = Math.max(1, Math.ceil(bytes.length / desiredBlocks));
  const blocks = [];
  const globalCounts = new Uint32Array(256);
  let nullCount = 0;
  let peakEntropy = 0;

  for (let start = 0; start < bytes.length; start += blockSize) {
    const end = Math.min(bytes.length, start + blockSize);
    const counts = new Uint32Array(256);
    let printable = 0;
    let high = 0;
    let zeros = 0;
    for (let index = start; index < end; index += 1) {
      const value = bytes[index];
      counts[value] += 1;
      globalCounts[value] += 1;
      if (value === 0) {
        zeros += 1;
        nullCount += 1;
      }
      if (value >= 32 && value <= 126) printable += 1;
      if (value >= 128) high += 1;
    }
    const length = Math.max(1, end - start);
    let entropy = 0;
    let dominantByte = 0;
    let dominantCount = 0;
    for (let value = 0; value < 256; value += 1) {
      const count = counts[value];
      if (!count) continue;
      const probability = count / length;
      entropy -= probability * Math.log2(probability);
      if (count > dominantCount) {
        dominantCount = count;
        dominantByte = value;
      }
    }
    peakEntropy = Math.max(peakEntropy, entropy);
    blocks.push({
      start,
      end,
      length,
      entropy,
      printableRatio: printable / length,
      highRatio: high / length,
      nullRatio: zeros / length,
      dominantByte,
      dominantRatio: dominantCount / length
    });
  }

  let dominantByte = 0;
  let dominantCount = 0;
  for (let value = 0; value < 256; value += 1) {
    if (globalCounts[value] > dominantCount) {
      dominantCount = globalCounts[value];
      dominantByte = value;
    }
  }

  return {
    blocks,
    blockSize,
    peakEntropy,
    dominantByte,
    dominantRatio: dominantCount / bytes.length,
    nullRatio: nullCount / bytes.length
  };
}

function detectFileType(bytes, file) {
  const patterns = [
    { signature: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], name: "PNG image", short: "PNG", category: "Forensics", finding: "PNG signature detected. Inspect chunks, text metadata, and data after IEND." },
    { signature: [0xff, 0xd8, 0xff], name: "JPEG image", short: "JPEG", category: "Forensics", finding: "JPEG signature detected. Inspect markers, EXIF/comment segments, and appended bytes." },
    { ascii: "GIF8", name: "GIF image", short: "GIF", category: "Forensics", finding: "GIF signature detected. Inspect frames, comments, and trailing content." },
    { signature: [0x25, 0x50, 0x44, 0x46], name: "PDF document", short: "PDF", category: "Forensics", finding: "PDF signature detected. Inspect metadata, objects, JavaScript indicators, and embedded files." },
    { signature: [0x50, 0x4b, 0x03, 0x04], name: "ZIP-compatible archive", short: "ZIP", category: "Forensics", finding: "ZIP-compatible signature detected. Inspect filenames, compression methods, comments, and nested artifacts." },
    { signature: [0x1f, 0x8b, 0x08], name: "GZIP compressed stream", short: "GZIP", category: "Forensics", finding: "GZIP stream detected. Inspect header flags, original filename, and decompressed content in a safe environment." },
    { signature: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], name: "7-Zip archive", short: "7Z", category: "Forensics", finding: "7-Zip archive detected. Inspect the archive table and nested content with an isolated extraction tool." },
    { signature: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00], name: "RAR archive", short: "RAR", category: "Forensics", finding: "RAR archive detected. Inspect filenames and nested artifacts with a safe extraction tool." },
    { signature: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00], name: "RAR 5 archive", short: "RAR", category: "Forensics", finding: "RAR 5 archive detected. Inspect filenames and nested artifacts with a safe extraction tool." },
    { signature: [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33, 0x00], name: "SQLite database", short: "SQLITE", category: "Database Forensics", finding: "SQLite database detected. Inspect schema, page size, user version, deleted records, and application tables." },
    { signature: [0x7f, 0x45, 0x4c, 0x46], name: "ELF executable", short: "ELF", category: "Reverse Engineering", finding: "ELF signature detected. Inspect architecture, strings, symbols, sections, and behavior in a sandbox." },
    { ascii: "MZ", name: "Windows PE executable", short: "PE", category: "Reverse Engineering", finding: "Windows executable signature detected. Inspect headers, imports, resources, and strings without executing it." },
    { ascii: "BM", name: "BMP image", short: "BMP", category: "Forensics", finding: "Bitmap image detected. Inspect dimensions, pixel offset, row padding, and bytes after the declared image size." },
    { ascii: "OggS", name: "Ogg media stream", short: "OGG", category: "Media Forensics", finding: "Ogg container detected. Inspect stream serials, codecs, comments, and hidden or concatenated streams." },
    { ascii: "ID3", name: "MP3 / ID3 audio", short: "MP3", category: "Media Forensics", finding: "ID3 metadata detected. Inspect text frames, comments, artwork, and trailing data." },
    { ascii: "RIFF", secondary: () => bytesToAscii(bytes.slice(8, 12)) === "WAVE", name: "WAV audio", short: "WAV", category: "Forensics", finding: "WAV container detected. Inspect chunks, metadata, spectrograms, and extra channels." },
    { ascii: "RIFF", secondary: () => bytesToAscii(bytes.slice(8, 12)) === "WEBP", name: "WebP image", short: "WEBP", category: "Forensics", finding: "WebP image container detected. Inspect RIFF chunks, metadata, animation frames, and trailing bytes." }
  ];

  for (const pattern of patterns) {
    const primary = pattern.signature
      ? matchesBytes(bytes, pattern.signature)
      : matchesAscii(bytes, pattern.ascii);
    if (primary && (!pattern.secondary || pattern.secondary())) return pattern;
  }

  const pcapMagic = bytes.length >= 4 ? readUint32(bytes, 0, false) : 0;
  if ([0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1].includes(pcapMagic)) {
    return { name: "PCAP capture", short: "PCAP", category: "Network Forensics", finding: "Packet capture signature detected. Inspect conversations, protocols, and transferred objects." };
  }
  if (pcapMagic === 0x0a0d0d0a) {
    return { name: "PCAPNG capture", short: "PCAPNG", category: "Network Forensics", finding: "PCAPNG section header detected. Inspect interfaces, packet blocks, comments, and transferred objects." };
  }
  if (bytes.length >= 12 && bytesToAscii(bytes.slice(4, 8)) === "ftyp") {
    return { name: "ISO Base Media / MP4", short: "MP4", category: "Media Forensics", finding: "ISO Base Media container detected. Inspect brands, tracks, metadata atoms, and appended content." };
  }

  const sample = bytes.slice(0, Math.min(bytes.length, 8192));
  if (file.type?.startsWith("text/") || printableRatio(sample) > 0.88) {
    return { name: "Text data", short: "TEXT", category: "Cryptography", finding: "Text-like content detected. Inspect encodings, ciphers, delimiters, and repeated patterns." };
  }

  return { name: "Unknown binary", short: "BIN", category: "Unknown", finding: "No known signature matched. Inspect the hex header, entropy, strings, and embedded signatures." };
}

function parsePng(bytes) {
  const metadata = {};
  const chunks = [];
  let offset = 8;
  let iendEnd = null;
  let width = null;
  let height = null;

  while (offset + 12 <= bytes.length) {
    const length = readUint32(bytes, offset, false);
    const type = bytesToAscii(bytes.slice(offset + 4, offset + 8));
    const dataStart = offset + 8;
    const dataEnd = dataStart + length;
    if (dataEnd + 4 > bytes.length) break;

    const data = bytes.slice(dataStart, dataEnd);
    chunks.push({ type, offset, length });

    if (type === "IHDR" && length >= 13) {
      width = readUint32(bytes, dataStart, false);
      height = readUint32(bytes, dataStart + 4, false);
      metadata["Bit depth"] = String(bytes[dataStart + 8]);
      metadata["Color type"] = String(bytes[dataStart + 9]);
    }

    if (type === "tEXt") {
      const separator = data.indexOf(0);
      if (separator !== -1) {
        metadata[bytesToLatin1(data.slice(0, separator))] = bytesToLatin1(data.slice(separator + 1));
      }
    }

    if (type === "iTXt") {
      const parsed = parseITxt(data);
      if (parsed) metadata[parsed.keyword] = parsed.value;
    }

    offset = dataEnd + 4;
    if (type === "IEND") {
      iendEnd = offset;
      break;
    }
  }

  const structure = {
    Dimensions: width !== null ? `${width} × ${height}` : "Unknown",
    "PNG chunks": chunks.map((chunk) => chunk.type).join(" → "),
    "PNG chunk count": String(chunks.length)
  };
  if (iendEnd !== null && iendEnd < bytes.length) {
    structure["Trailing bytes after IEND"] = String(bytes.length - iendEnd);
    structure["IEND end offset"] = `0x${iendEnd.toString(16)} (${iendEnd})`;
  }

  return { metadata, structure, chunks, iendEnd };
}

function parseITxt(data) {
  let cursor = 0;
  const readNull = () => {
    const end = data.indexOf(0, cursor);
    if (end === -1) return null;
    const part = data.slice(cursor, end);
    cursor = end + 1;
    return part;
  };

  const keywordBytes = readNull();
  if (!keywordBytes || cursor + 2 > data.length) return null;
  const keyword = bytesToLatin1(keywordBytes);
  const compressionFlag = data[cursor];
  cursor += 2;
  if (readNull() === null || readNull() === null) return null;
  const textBytes = data.slice(cursor);
  if (compressionFlag !== 0) return { keyword: `${keyword} (compressed)`, value: "Compressed iTXt value" };
  return { keyword, value: new TextDecoder().decode(textBytes) };
}

function parseJpeg(bytes) {
  const metadata = {};
  const markers = [];
  let offset = 2;
  let commentIndex = 1;

  while (offset + 4 <= bytes.length) {
    if (bytes[offset] !== 0xff) { offset += 1; continue; }
    const marker = bytes[offset + 1];
    offset += 2;
    if (marker === 0xd9 || marker === 0xda) break;
    if (marker === 0x00 || (marker >= 0xd0 && marker <= 0xd7)) continue;
    if (offset + 2 > bytes.length) break;
    const length = (bytes[offset] << 8) | bytes[offset + 1];
    if (length < 2 || offset + length > bytes.length) break;
    markers.push(`FF${marker.toString(16).padStart(2, "0").toUpperCase()}`);
    if (marker === 0xfe) {
      metadata[`JPEG comment ${commentIndex}`] = bytesToLatin1(bytes.slice(offset + 2, offset + length));
      commentIndex += 1;
    }
    if (marker === 0xe1) {
      const segment = bytes.slice(offset + 2, offset + length);
      if (bytesToAscii(segment.slice(0, 6)) === "Exif\u0000\u0000") metadata["EXIF segment"] = `${segment.length} bytes`;
    }
    offset += length;
  }
  metadata["JPEG markers"] = markers.join(", ");
  return metadata;
}

function parsePdf(bytes) {
  const text = bytesToLatin1(bytes.slice(0, Math.min(bytes.length, 5_000_000)));
  const metadata = {};
  const header = text.match(/%PDF-(\d\.\d)/);
  if (header) metadata["PDF version"] = header[1];
  const fields = ["Title", "Author", "Subject", "Creator", "Producer", "CreationDate", "ModDate"];
  for (const field of fields) {
    const match = text.match(new RegExp(`/${field}\\s*\\(([^)]{0,500})\\)`));
    if (match) metadata[field] = match[1];
  }
  metadata["Object count (approx.)"] = String((text.match(/\b\d+\s+\d+\s+obj\b/g) || []).length);
  metadata["JavaScript indicators"] = String((text.match(/\/JavaScript|\/JS\b/g) || []).length);
  metadata["Embedded file indicators"] = String((text.match(/\/EmbeddedFile|\/Filespec/g) || []).length);
  return metadata;
}

function parseElf(bytes) {
  const is64 = bytes[4] === 2;
  const little = bytes[5] === 1;
  return {
    "ELF class": is64 ? "64-bit" : bytes[4] === 1 ? "32-bit" : "Unknown",
    Endianness: little ? "Little-endian" : bytes[5] === 2 ? "Big-endian" : "Unknown",
    "OS ABI": String(bytes[7] ?? "Unknown"),
    "Machine": bytes.length >= 20 ? `0x${readUint16(bytes, 18, little).toString(16)}` : "Unknown"
  };
}

function parsePe(bytes) {
  const metadata = {};
  if (bytes.length < 0x40) return metadata;
  const peOffset = readUint32(bytes, 0x3c, true);
  metadata["PE header offset"] = `0x${peOffset.toString(16)} (${peOffset})`;
  if (peOffset + 24 <= bytes.length && bytesToAscii(bytes.slice(peOffset, peOffset + 4)) === "PE\u0000\u0000") {
    metadata.Machine = `0x${readUint16(bytes, peOffset + 4, true).toString(16)}`;
    metadata.Sections = String(readUint16(bytes, peOffset + 6, true));
    metadata.Timestamp = new Date(readUint32(bytes, peOffset + 8, true) * 1000).toISOString();
  }
  return metadata;
}

function parseWav(bytes) {
  const metadata = {};
  let offset = 12;
  const chunks = [];
  while (offset + 8 <= bytes.length) {
    const id = bytesToAscii(bytes.slice(offset, offset + 4));
    const length = readUint32(bytes, offset + 4, true);
    chunks.push(id);
    if (id === "fmt " && length >= 16) {
      metadata["Audio format"] = String(readUint16(bytes, offset + 8, true));
      metadata.Channels = String(readUint16(bytes, offset + 10, true));
      metadata["Sample rate"] = String(readUint32(bytes, offset + 12, true));
      metadata["Bits per sample"] = String(readUint16(bytes, offset + 22, true));
    }
    offset += 8 + length + (length % 2);
  }
  metadata["WAV chunks"] = chunks.join(" → ");
  return metadata;
}

function parsePcap(bytes) {
  const metadata = {};
  const magic = readUint32(bytes, 0, false);
  const little = magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1;
  metadata.Endianness = little ? "Little-endian" : "Big-endian";
  if (bytes.length >= 24) {
    metadata.Version = `${readUint16(bytes, 4, little)}.${readUint16(bytes, 6, little)}`;
    metadata.Snaplen = String(readUint32(bytes, 16, little));
    metadata.Linktype = String(readUint32(bytes, 20, little));
  }
  return metadata;
}

function parseText(bytes) {
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  return {
    Lines: String(text.split(/\r?\n/).length),
    Characters: String(text.length),
    "Ends with newline": /\r?\n$/.test(text) ? "Yes" : "No"
  };
}

function parseBmp(bytes) {
  if (bytes.length < 26) return {};
  const declaredSize = readUint32(bytes, 2, true);
  const pixelOffset = readUint32(bytes, 10, true);
  const dibSize = readUint32(bytes, 14, true);
  const metadata = {
    "Declared file size": formatFileSize(declaredSize),
    "Pixel data offset": `0x${pixelOffset.toString(16)} (${pixelOffset})`,
    "DIB header size": String(dibSize)
  };
  if (dibSize >= 40 && bytes.length >= 30) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    metadata.Dimensions = `${view.getInt32(18, true)} × ${Math.abs(view.getInt32(22, true))}`;
    metadata["Bits per pixel"] = String(readUint16(bytes, 28, true));
    metadata.Compression = String(readUint32(bytes, 30, true));
  }
  if (declaredSize && declaredSize < bytes.length) metadata["Trailing bytes"] = String(bytes.length - declaredSize);
  return metadata;
}

function parseWebp(bytes) {
  const metadata = {};
  if (bytes.length >= 16) {
    metadata["RIFF declared size"] = formatFileSize(readUint32(bytes, 4, true) + 8);
    metadata["First WebP chunk"] = bytesToAscii(bytes.slice(12, 16));
  }
  return metadata;
}

function parseSqlite(bytes) {
  if (bytes.length < 72) return {};
  let pageSize = readUint16(bytes, 16, false);
  if (pageSize === 1) pageSize = 65536;
  return {
    "Database page size": formatFileSize(pageSize),
    "Write version": String(bytes[18]),
    "Read version": String(bytes[19]),
    "Reserved bytes per page": String(bytes[20]),
    "File change counter": String(readUint32(bytes, 24, false)),
    "Database page count": String(readUint32(bytes, 28, false)),
    "Schema cookie": String(readUint32(bytes, 40, false)),
    "User version": String(readUint32(bytes, 60, false)),
    "Application ID": `0x${readUint32(bytes, 68, false).toString(16).padStart(8, "0")}`
  };
}

function parseOgg(bytes) {
  if (bytes.length < 27) return {};
  return {
    "Ogg stream version": String(bytes[4]),
    "Header type": `0x${bytes[5].toString(16).padStart(2, "0")}`,
    "Stream serial": String(readUint32(bytes, 14, true)),
    "Page sequence": String(readUint32(bytes, 18, true)),
    "Segment count": String(bytes[26])
  };
}

function parseId3(bytes) {
  if (bytes.length < 10) return {};
  const tagSize = ((bytes[6] & 0x7f) << 21) | ((bytes[7] & 0x7f) << 14) | ((bytes[8] & 0x7f) << 7) | (bytes[9] & 0x7f);
  return {
    "ID3 version": `2.${bytes[3]}.${bytes[4]}`,
    "ID3 flags": `0x${bytes[5].toString(16).padStart(2, "0")}`,
    "ID3 tag size": formatFileSize(tagSize + 10)
  };
}

function parseGzip(bytes) {
  if (bytes.length < 10) return {};
  const flags = bytes[3];
  const metadata = {
    "GZIP flags": `0x${flags.toString(16).padStart(2, "0")}`,
    "Modified time": readUint32(bytes, 4, true) ? new Date(readUint32(bytes, 4, true) * 1000).toISOString() : "Not set",
    "Compression hint": String(bytes[8]),
    "Origin OS": String(bytes[9])
  };
  let offset = 10;
  if (flags & 0x04 && offset + 2 <= bytes.length) offset += 2 + readUint16(bytes, offset, true);
  if (flags & 0x08 && offset < bytes.length) {
    const end = bytes.indexOf(0, offset);
    if (end > offset) metadata["Original filename"] = bytesToUtf8(bytes.slice(offset, end));
  }
  return metadata;
}

function parseMp4(bytes) {
  if (bytes.length < 16) return {};
  const firstBoxSize = readUint32(bytes, 0, false);
  const compatibleEnd = Math.min(bytes.length, Math.max(16, firstBoxSize));
  const brands = [];
  for (let offset = 16; offset + 4 <= compatibleEnd; offset += 4) brands.push(bytesToAscii(bytes.slice(offset, offset + 4)));
  return {
    "First box size": formatFileSize(firstBoxSize),
    "Major brand": bytesToAscii(bytes.slice(8, 12)),
    "Minor version": String(readUint32(bytes, 12, false)),
    "Compatible brands": brands.join(", ") || "None listed"
  };
}

function parsePcapng(bytes) {
  if (bytes.length < 28) return {};
  const little = readUint32(bytes, 8, false) === 0x4d3c2b1a;
  return {
    "Section byte order": little ? "Little-endian" : "Big-endian",
    "Section block length": String(readUint32(bytes, 4, little)),
    "PCAPNG version": `${readUint16(bytes, 12, little)}.${readUint16(bytes, 14, little)}`
  };
}

function parseZipRegion(bytes, baseOffset) {
  const eocdOffset = findEocd(bytes, baseOffset);
  if (eocdOffset === -1) return null;
  const entryCount = readUint16(bytes, eocdOffset + 10, true);
  const centralSize = readUint32(bytes, eocdOffset + 12, true);
  const centralRelativeOffset = readUint32(bytes, eocdOffset + 16, true);
  const commentLength = readUint16(bytes, eocdOffset + 20, true);
  const centralOffset = baseOffset + centralRelativeOffset;
  const archiveEnd = eocdOffset + 22 + commentLength;
  const comment = bytesToUtf8(bytes.slice(eocdOffset + 22, archiveEnd));
  const entries = [];
  let cursor = centralOffset;

  for (let index = 0; index < entryCount && cursor + 46 <= bytes.length; index += 1) {
    if (!matchesBytesAt(bytes, cursor, [0x50, 0x4b, 0x01, 0x02])) break;
    const method = readUint16(bytes, cursor + 10, true);
    const crc32 = readUint32(bytes, cursor + 16, true);
    const compressedSize = readUint32(bytes, cursor + 20, true);
    const uncompressedSize = readUint32(bytes, cursor + 24, true);
    const nameLength = readUint16(bytes, cursor + 28, true);
    const extraLength = readUint16(bytes, cursor + 30, true);
    const entryCommentLength = readUint16(bytes, cursor + 32, true);
    const localRelativeOffset = readUint32(bytes, cursor + 42, true);
    const nameStart = cursor + 46;
    const name = bytesToUtf8(bytes.slice(nameStart, nameStart + nameLength));
    entries.push({
      name,
      method,
      crc32,
      compressedSize,
      uncompressedSize,
      localOffset: baseOffset + localRelativeOffset,
      isDirectory: name.endsWith("/")
    });
    cursor = nameStart + nameLength + extraLength + entryCommentLength;
  }

  return {
    baseOffset,
    eocdOffset,
    centralOffset,
    centralSize,
    length: archiveEnd - baseOffset,
    comment,
    entries
  };
}

function findEocd(bytes, baseOffset) {
  const minimum = Math.max(baseOffset, bytes.length - 65557);
  for (let offset = bytes.length - 22; offset >= minimum; offset -= 1) {
    if (matchesBytesAt(bytes, offset, [0x50, 0x4b, 0x05, 0x06])) return offset;
  }
  return -1;
}

async function extractZipEntry(archive, entry) {
  if (entry.uncompressedSize > MAX_EXTRACTED_ENTRY_SIZE) {
    throw new Error(`Refusing to extract ${formatFileSize(entry.uncompressedSize)}. The per-entry safety limit is ${formatFileSize(MAX_EXTRACTED_ENTRY_SIZE)}.`);
  }
  if (entry.compressedSize > 0 && entry.uncompressedSize / entry.compressedSize > 250) {
    throw new Error("Refusing a suspicious compression ratio that may indicate a ZIP bomb.");
  }
  const offset = entry.localOffset;
  if (!matchesBytesAt(state.bytes, offset, [0x50, 0x4b, 0x03, 0x04])) throw new Error("Local ZIP header not found.");
  const nameLength = readUint16(state.bytes, offset + 26, true);
  const extraLength = readUint16(state.bytes, offset + 28, true);
  const dataStart = offset + 30 + nameLength + extraLength;
  const compressed = state.bytes.slice(dataStart, dataStart + entry.compressedSize);

  if (entry.method === 0) return compressed;
  if (entry.method === 8) return decompressDeflateRaw(compressed);
  throw new Error(`Compression method ${entry.method} is not supported by this browser build.`);
}

async function decompressDeflateRaw(bytes) {
  if (!("DecompressionStream" in window)) throw new Error("This browser does not support DecompressionStream.");
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

function buildFindings(parsed) {
  const findings = [{ level: "info", title: `${state.typeInfo.name} detected`, detail: state.typeInfo.finding }];
  const extension = getExtension(state.file?.name || "");
  const accepted = {
    PNG: [".png"], JPEG: [".jpg", ".jpeg"], GIF: [".gif"], PDF: [".pdf"],
    ZIP: [".zip", ".docx", ".xlsx", ".pptx", ".jar"], ELF: [".elf", ".bin", ""],
    PE: [".exe", ".dll"], WAV: [".wav"], WEBP: [".webp"], BMP: [".bmp"],
    GZIP: [".gz", ".gzip"], "7Z": [".7z"], RAR: [".rar"], SQLITE: [".sqlite", ".sqlite3", ".db"],
    OGG: [".ogg", ".oga", ".ogv"], MP3: [".mp3"], MP4: [".mp4", ".m4a", ".mov", ".m4v"],
    PCAP: [".pcap"], PCAPNG: [".pcapng"], TEXT: [".txt", ".log", ".csv", ".md", ".json", ""]
  };

  if (accepted[state.typeInfo.short] && extension && !accepted[state.typeInfo.short].includes(extension)) {
    findings.push({ level: "warning", title: "Extension mismatch", detail: `${extension} does not match the detected ${state.typeInfo.short} format.` });
  }
  if (state.entropy >= 7.5) findings.push({ level: "warning", title: "Very high entropy", detail: "The artifact may contain compressed, encrypted, or randomized data." });
  else if (state.entropy <= 4) findings.push({ level: "info", title: "Low entropy", detail: "The artifact contains substantial structured or repetitive data." });

  const metadataEntries = Object.entries(parsed.metadata);
  if (metadataEntries.length > 2) findings.push({ level: "success", title: "Metadata or structure extracted", detail: `${metadataEntries.length} fields are available for inspection.` });
  const interestingKeys = metadataEntries.filter(([key]) => /comment|hint|author|description|flag|secret|password|software|warning|note/i.test(key));
  if (interestingKeys.length) findings.push({ level: "warning", title: "Interesting metadata keys", detail: interestingKeys.map(([key]) => key).join(", ") });
  if (state.strings.some((value) => /https?:\/\//i.test(value))) findings.push({ level: "info", title: "URL-like strings found", detail: "Review extracted strings for external resources or callback addresses." });
  if (parsed.archives.length) findings.push({ level: "danger", title: "Embedded or appended archive region", detail: `${parsed.archives.length} archive or trailing-data region(s) detected.` });
  const embeddedSignatures = state.signatures.filter((signature) => signature.role === "embedded");
  if (embeddedSignatures.length) {
    const risky = embeddedSignatures.filter((signature) => ["Archive", "Executable"].includes(signature.category));
    findings.push({
      level: risky.length ? "warning" : "info",
      title: "Embedded file signatures mapped",
      detail: `${embeddedSignatures.length} non-primary signature${embeddedSignatures.length === 1 ? "" : "s"} detected: ${embeddedSignatures.slice(0, 6).map((signature) => `${signature.name} @ 0x${signature.offset.toString(16)}`).join(", ")}${embeddedSignatures.length > 6 ? "…" : ""}`
    });
  }
  const highEntropyBlocks = state.byteMap.blocks.filter((block) => block.entropy >= 7.45);
  if (highEntropyBlocks.length && state.byteMap.blocks.length > 1) {
    findings.push({
      level: "info",
      title: "Localized high-entropy regions",
      detail: `${highEntropyBlocks.length} of ${state.byteMap.blocks.length} mapped regions exceed 7.45 bits/byte. Review the Byte map for compressed or encrypted payload boundaries.`
    });
  }
  if (state.typeInfo.short === "PE" || state.typeInfo.short === "ELF") findings.push({ level: "warning", title: "Executable artifact", detail: "Do not run it directly. Use an isolated analysis environment." });
  return findings;
}

function discoverCandidatesFromSources() {
  const regex = /(?:flag|ctf|hackclub|stardance)\{[^}\r\n]{1,200}\}/gi;
  const sources = [
    ...state.strings.map((value) => ({ value, source: "Extracted strings" })),
    ...Object.entries(state.metadata).map(([key, value]) => ({ value: String(value), source: `Metadata: ${key}` }))
  ];
  for (const source of sources) {
    for (const match of source.value.matchAll(regex)) addCandidate(match[0], source.source, null);
  }
}

function discoverEncodedClues() {
  const base64Regex = /(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g;
  const sources = [...state.strings, ...Object.values(state.metadata).map(String)];
  for (const source of sources) {
    const candidates = source.match(base64Regex) || [];
    for (const candidate of candidates.slice(0, 30)) {
      const bytes = decodeBase64Bytes(candidate);
      if (!bytes) continue;
      const text = bytesToUtf8(bytes);
      if (printableRatio(bytes) > 0.82 && !elements.decoderInput.value) {
        elements.decoderMode.value = "base64";
        elements.decoderInput.value = candidate;
        updateDecoderControls();
      }
      const flags = text.match(/(?:flag|ctf|hackclub|stardance)\{[^}\r\n]{1,200}\}/gi) || [];
      flags.forEach((flag) => addCandidate(flag, "Decoded Base64 clue", null));
    }
  }
}

function addCandidate(value, source, evidenceId, verified = false) {
  const existing = state.candidates.get(value);
  if (existing) {
    if (verified) existing.verified = true;
    return existing;
  }
  const candidate = { value, source, evidenceId, verified, discoveredAt: new Date().toISOString() };
  state.candidates.set(value, candidate);
  recordReplay("candidate", "Flag candidate discovered", `${value} · ${source}`);
  return candidate;
}

function addEvidence({ type, source, title, value = "", preview = "", verified = false, manual = false }) {
  const signature = `${type}|${source}|${title}|${value}`;
  const duplicate = state.evidence.find((item) => item.signature === signature);
  if (duplicate) return duplicate;
  const item = {
    id: crypto.randomUUID ? crypto.randomUUID() : `ev-${Date.now()}-${Math.random()}`,
    signature,
    type,
    source,
    title,
    value: truncateEvidenceValue(value),
    preview: preview || String(value).slice(0, 300),
    verified,
    manual,
    timestamp: new Date().toISOString()
  };
  state.evidence.push(item);
  if (manual) state.manualEvidenceIds.add(item.id);
  recordReplay("evidence", `Evidence recorded: ${title}`, source);
  return item;
}

function recordReplay(type, title, detail = "") {
  state.replay.push({ id: `${Date.now()}-${Math.random()}`, type, title, detail, timestamp: new Date().toISOString() });
  renderReplay();
  updateInvestigatorHUD();
  if (!elements.caseboardOverlay.classList.contains("hidden")) renderCaseboard();
}

function activateTab(tabName, countInspection = true) {
  closeCommandPalette(true);
  document.querySelectorAll(".tab").forEach((tab) => tab.classList.toggle("active", tab.dataset.tab === tabName));
  document.querySelectorAll(".tab-panel").forEach((panel) => panel.classList.toggle("active", panel.id === `tab-${tabName}`));
  if (countInspection && state.file && ["metadata", "strings", "hex", "byte-map", "signatures", "archives", "findings", "evidence"].includes(tabName)) {
    completeStep(1);
    recordReplay("inspect", `Opened ${tabName} evidence`, state.file.name);
    elements.sessionStatus.textContent = "Evidence inspected. Extract an archive entry or transform a suspicious value.";
  }
  if (tabName === "byte-map") requestAnimationFrame(drawByteMap);
}

function renderAll() {
  renderOverview();
  renderMetadata();
  renderStrings();
  renderHex();
  renderByteMap();
  renderSignatures();
  renderArchives();
  renderFindings();
  renderEvidence();
  renderCandidates();
  renderDecoderHistory();
  renderReplay();
  renderTimeline();
  updateHints();
  updateSummary();
  updateChallengeUI();
  updateInvestigatorHUD();
  renderCaseboard();
}

function renderOverview() {
  const file = state.file;
  const type = state.typeInfo;
  elements.artifactTitle.textContent = file.name;
  elements.categoryBadge.textContent = type.category;
  elements.riskBadge.textContent = type.short === "PE" || type.short === "ELF" ? "Do not execute" : "Read-only";
  elements.riskBadge.className = type.short === "PE" || type.short === "ELF" ? "pill" : "pill pill-neutral";
  elements.fileName.textContent = file.name;
  elements.mimeType.textContent = file.type || "Unknown";
  elements.detectedFormat.textContent = type.name;
  elements.fileSize.textContent = formatFileSize(file.size);
  elements.printableRatio.textContent = `${(state.printable * 100).toFixed(1)}%`;
  elements.artifactRole.textContent = state.role;
  elements.fileHash.textContent = state.hash;
  elements.initialFinding.textContent = type.finding;
  elements.formatSummary.textContent = type.short;
  elements.categorySummary.textContent = type.category;
  elements.sizeSummary.textContent = formatFileSize(file.size);
  elements.mimeSummary.textContent = file.type || "Unknown MIME";
  elements.entropySummary.textContent = state.entropy.toFixed(2);
  elements.entropyLabel.textContent = describeEntropy(state.entropy);
}

function renderMetadata() {
  const entries = Object.entries({ ...state.metadata, ...state.structures });
  elements.metadataCount.textContent = String(entries.length);
  if (!entries.length) {
    elements.metadataList.className = "data-list empty-state";
    elements.metadataList.textContent = "No supported metadata was extracted.";
    return;
  }
  elements.metadataList.className = "data-list";
  elements.metadataList.innerHTML = "";
  for (const [key, value] of entries) {
    const row = document.createElement("div");
    row.className = "data-row";
    const keyElement = document.createElement("div");
    keyElement.className = "data-key";
    keyElement.textContent = key;
    const valueElement = document.createElement("div");
    valueElement.className = "data-value";
    valueElement.textContent = String(value);
    row.append(keyElement, valueElement);
    elements.metadataList.appendChild(row);
  }
}

function renderStrings() {
  elements.stringsCount.textContent = String(state.strings.length);
  filterStrings();
}

function filterStrings() {
  const query = elements.stringSearch.value.trim().toLowerCase();
  const interesting = elements.interestingOnly.checked;
  state.visibleStrings = state.strings.filter((value) => {
    if (query && !value.toLowerCase().includes(query)) return false;
    if (interesting && !isInterestingString(value)) return false;
    return true;
  });
  elements.stringsOutput.textContent = state.visibleStrings.length ? state.visibleStrings.join("\n") : "No matching strings.";
}

function isInterestingString(value) {
  return /flag\{|ctf\{|https?:\/\/|password|secret|token|key|comment|hint|PK\x03\x04|[A-Za-z0-9+/]{24,}={0,2}/i.test(value);
}

function renderHex() {
  elements.hexOutput.textContent = makeHexPreview(state.bytes, state.hexOffset, HEX_PAGE_SIZE);
}

function renderByteMap() {
  const map = state.byteMap;
  elements.byteMapBlockSize.textContent = map.blockSize ? formatFileSize(map.blockSize) : "—";
  elements.byteMapPeakEntropy.textContent = map.blocks.length ? `${map.peakEntropy.toFixed(2)} bits` : "—";
  elements.byteMapDominantByte.textContent = map.blocks.length ? `0x${map.dominantByte.toString(16).padStart(2, "0").toUpperCase()} · ${(map.dominantRatio * 100).toFixed(1)}%` : "—";
  elements.byteMapNullRatio.textContent = map.blocks.length ? `${(map.nullRatio * 100).toFixed(2)}%` : "—";
  if (document.getElementById("tab-byte-map")?.classList.contains("active")) requestAnimationFrame(drawByteMap);
}

function drawByteMap() {
  const canvas = elements.byteMapCanvas;
  const context = canvas?.getContext?.("2d");
  const blocks = state.byteMap.blocks;
  if (!canvas || !context || !blocks.length) return;
  const rect = canvas.getBoundingClientRect();
  if (rect.width < 40 || rect.height < 40) return;
  const ratio = Math.min(window.devicePixelRatio || 1, 2);
  canvas.width = Math.floor(rect.width * ratio);
  canvas.height = Math.floor(rect.height * ratio);
  context.setTransform(ratio, 0, 0, ratio, 0, 0);
  const width = rect.width;
  const height = rect.height;
  const left = 40;
  const right = 10;
  const top = 18;
  const bottom = 31;
  const plotWidth = width - left - right;
  const plotHeight = height - top - bottom;
  const signal = getComputedStyle(document.body).getPropertyValue("--case-signal-rgb").trim() || "111, 235, 255";
  const violet = getComputedStyle(document.body).getPropertyValue("--case-violet-rgb").trim() || "155, 135, 245";
  context.clearRect(0, 0, width, height);

  context.font = '9px "Cascadia Mono", monospace';
  context.textAlign = "right";
  context.textBaseline = "middle";
  for (let entropy = 0; entropy <= 8; entropy += 2) {
    const y = top + (1 - entropy / 8) * plotHeight;
    context.strokeStyle = `rgba(${signal}, 0.11)`;
    context.lineWidth = 1;
    context.beginPath();
    context.moveTo(left, y);
    context.lineTo(width - right, y);
    context.stroke();
    context.fillStyle = `rgba(${signal}, 0.48)`;
    context.fillText(String(entropy), left - 7, y);
  }

  const barWidth = Math.max(1, plotWidth / blocks.length);
  const points = [];
  blocks.forEach((block, index) => {
    const x = left + index * barWidth;
    const normalized = Math.max(0, Math.min(1, block.entropy / 8));
    const y = top + (1 - normalized) * plotHeight;
    const alpha = 0.17 + normalized * 0.48;
    const gradient = context.createLinearGradient(0, y, 0, top + plotHeight);
    gradient.addColorStop(0, `rgba(${signal}, ${alpha})`);
    gradient.addColorStop(1, `rgba(${violet}, ${0.08 + block.highRatio * 0.38})`);
    context.fillStyle = gradient;
    context.fillRect(x, y, Math.max(1, barWidth - 0.5), top + plotHeight - y);
    context.fillStyle = `rgba(96, 215, 167, ${0.08 + block.printableRatio * 0.45})`;
    context.fillRect(x, height - 20, Math.max(1, barWidth - 0.5), 4);
    context.fillStyle = `rgba(242, 125, 153, ${0.08 + block.nullRatio * 0.75})`;
    context.fillRect(x, height - 13, Math.max(1, barWidth - 0.5), 4);
    points.push({ x: x + barWidth / 2, y });
  });

  context.strokeStyle = `rgba(${signal}, 0.88)`;
  context.lineWidth = 1.3;
  context.beginPath();
  points.forEach((point, index) => index ? context.lineTo(point.x, point.y) : context.moveTo(point.x, point.y));
  context.stroke();

  state.signatures.filter((signature) => signature.role === "embedded").slice(0, 40).forEach((signature) => {
    const x = left + (signature.offset / Math.max(1, state.bytes.length)) * plotWidth;
    context.strokeStyle = "rgba(243, 186, 97, 0.58)";
    context.lineWidth = 1;
    context.beginPath();
    context.moveTo(x, top);
    context.lineTo(x, height - bottom + 5);
    context.stroke();
  });

  context.textAlign = "left";
  context.fillStyle = `rgba(${signal}, 0.48)`;
  context.fillText("0x0", left, height - 5);
  context.textAlign = "right";
  context.fillText(`0x${state.bytes.length.toString(16)}`, width - right, height - 5);
}

function byteMapBlockFromEvent(event) {
  const rect = elements.byteMapCanvas.getBoundingClientRect();
  const left = 40;
  const right = 10;
  const plotWidth = rect.width - left - right;
  const normalized = Math.max(0, Math.min(0.999999, (event.clientX - rect.left - left) / Math.max(1, plotWidth)));
  const index = Math.floor(normalized * state.byteMap.blocks.length);
  return { block: state.byteMap.blocks[index], index, rect };
}

function handleByteMapPointerMove(event) {
  const { block, index, rect } = byteMapBlockFromEvent(event);
  if (!block) return hideByteMapTooltip();
  elements.byteMapTooltip.innerHTML = `<strong>Region ${index + 1} / ${state.byteMap.blocks.length}</strong><span>Offset 0x${block.start.toString(16)}–0x${Math.max(block.start, block.end - 1).toString(16)}</span><span>Entropy ${block.entropy.toFixed(3)} bits</span><span>Printable ${(block.printableRatio * 100).toFixed(1)}% · Null ${(block.nullRatio * 100).toFixed(1)}%</span><span>Dominant 0x${block.dominantByte.toString(16).padStart(2, "0").toUpperCase()} (${(block.dominantRatio * 100).toFixed(1)}%)</span>`;
  elements.byteMapTooltip.classList.remove("hidden");
  const stage = elements.byteMapCanvas.parentElement.getBoundingClientRect();
  const left = Math.min(stage.width - 190, Math.max(8, event.clientX - stage.left + 12));
  const top = Math.min(stage.height - 105, Math.max(8, event.clientY - stage.top + 12));
  elements.byteMapTooltip.style.left = `${left}px`;
  elements.byteMapTooltip.style.top = `${top}px`;
}

function hideByteMapTooltip() {
  elements.byteMapTooltip?.classList.add("hidden");
}

function handleByteMapClick(event) {
  const { block } = byteMapBlockFromEvent(event);
  if (!block) return;
  elements.hexOffsetInput.value = `0x${block.start.toString(16)}`;
  state.hexOffset = block.start;
  activateTab("hex", true);
  renderHex();
  addEvidence({ type: "byte-map", source: state.file.name, title: `Mapped region at 0x${block.start.toString(16)}`, value: makeHexPreview(state.bytes, block.start, 128), preview: `Entropy ${block.entropy.toFixed(3)} bits · ${formatFileSize(block.length)}`, manual: true });
  renderEvidence();
}

function exportByteMapPng() {
  if (!state.file || !state.byteMap.blocks.length) {
    showToast("Load an artifact before exporting a byte map.");
    return;
  }
  drawByteMap();
  elements.byteMapCanvas.toBlob((blob) => {
    if (!blob) return showToast("The browser could not export the byte map.");
    downloadBlob(`${sanitizeFilename(state.file.name)}-byte-map.png`, blob);
    recordReplay("export", "Exported byte intelligence map", state.file.name);
  }, "image/png");
}

function renderSignatures() {
  const query = (elements.signatureSearch.value || "").trim().toLowerCase();
  const signatures = state.signatures.filter((signature) => {
    if (!query) return true;
    const haystack = `${signature.name} ${signature.category} ${signature.detail} ${signature.offset} 0x${signature.offset.toString(16)}`.toLowerCase();
    return haystack.includes(query);
  });
  elements.signatureCount.textContent = String(state.signatures.length);
  if (!signatures.length) {
    elements.signatureList.className = "signature-list empty-state";
    elements.signatureList.textContent = state.signatures.length ? "No signatures match this filter." : "No recognized file signatures were found.";
    return;
  }
  elements.signatureList.className = "signature-list";
  elements.signatureList.innerHTML = "";
  signatures.forEach((signature) => {
    const row = document.createElement("article");
    row.className = `signature-item ${signature.role}`;
    const name = document.createElement("div");
    name.className = "signature-name";
    const title = document.createElement("strong");
    title.textContent = signature.name;
    const category = document.createElement("small");
    category.textContent = `${signature.category} · ${signature.role === "primary" ? "primary structure" : signature.role === "structural" ? "container structure" : "embedded candidate"}`;
    name.append(title, category);
    const offset = document.createElement("div");
    offset.className = "signature-offset";
    const hex = document.createElement("strong");
    hex.textContent = `0x${signature.offset.toString(16).padStart(8, "0")}`;
    const decimal = document.createElement("small");
    decimal.textContent = `${signature.offset.toLocaleString()} bytes`;
    offset.append(hex, decimal);
    const context = document.createElement("div");
    context.className = "signature-context";
    context.title = signature.context;
    context.textContent = `${signature.detail} · ${signature.context}`;
    const button = document.createElement("button");
    button.className = "icon-button";
    button.type = "button";
    button.dataset.signatureOffset = String(signature.offset);
    button.textContent = "Inspect hex";
    row.append(name, offset, context, button);
    elements.signatureList.appendChild(row);
  });
}

function copySignatureMap() {
  if (!state.signatures.length) return showToast("No signatures to copy.");
  const text = state.signatures.map((signature) => `${signature.name}\t0x${signature.offset.toString(16)}\t${signature.role}\t${signature.detail}`).join("\n");
  copyText(text);
}

function renderArchives() {
  elements.signatureCount.textContent = String(state.signatures.length);
  elements.archiveCount.textContent = String(state.archives.length);
  if (!state.archives.length) {
    elements.archiveList.className = "archive-list empty-state";
    elements.archiveList.textContent = "No archive or trailing-data region was detected.";
    return;
  }
  elements.archiveList.className = "archive-list";
  elements.archiveList.innerHTML = "";

  state.archives.forEach((archive, archiveId) => {
    archive.id = archiveId;
    const card = document.createElement("article");
    card.className = "archive-card";
    const header = document.createElement("div");
    header.className = "archive-card-header";
    const copy = document.createElement("div");
    const title = document.createElement("h3");
    title.textContent = archive.label;
    const meta = document.createElement("p");
    meta.textContent = `Offset ${archive.offset} (0x${archive.offset.toString(16)}) · ${formatFileSize(archive.length)} · ${archive.entries.length} entries`;
    copy.append(title, meta);
    const badge = document.createElement("span");
    badge.className = "pill";
    badge.textContent = archive.kind.toUpperCase();
    header.append(copy, badge);
    card.appendChild(header);

    const actions = document.createElement("div");
    actions.className = "archive-actions";
    actions.innerHTML = `
      <button class="button button-ghost" type="button" data-archive-action="download-region" data-archive-id="${archiveId}">Download region</button>
      <button class="button button-ghost" type="button" data-archive-action="send-region" data-archive-id="${archiveId}">Send bytes to decoder</button>
    `;
    card.appendChild(actions);

    archive.entries.forEach((entry, entryIndex) => {
      const row = document.createElement("div");
      row.className = "archive-entry";
      const info = document.createElement("div");
      const name = document.createElement("strong");
      name.textContent = entry.name;
      const detail = document.createElement("small");
      detail.textContent = `${entry.isDirectory ? "Directory" : formatFileSize(entry.uncompressedSize)} · method ${entry.method} · compressed ${formatFileSize(entry.compressedSize)}`;
      info.append(name, detail);
      const entryActions = document.createElement("div");
      entryActions.className = "entry-actions";
      if (!entry.isDirectory) {
        entryActions.innerHTML = `
          <button class="icon-button" type="button" data-archive-action="download-entry" data-archive-id="${archiveId}" data-entry-index="${entryIndex}">Download</button>
          <button class="icon-button" type="button" data-archive-action="analyze-entry" data-archive-id="${archiveId}" data-entry-index="${entryIndex}">Analyze</button>
          <button class="icon-button" type="button" data-archive-action="decode-entry" data-archive-id="${archiveId}" data-entry-index="${entryIndex}">Decoder</button>
        `;
      }
      row.append(info, entryActions);
      card.appendChild(row);
    });

    elements.archiveList.appendChild(card);
  });
}

async function handleArchiveAction(action, archiveId, entryIndex) {
  const archive = state.archives[archiveId];
  if (!archive) return;
  try {
    if (action === "download-region") {
      const bytes = state.bytes.slice(archive.offset, archive.offset + archive.length);
      downloadBytes(`${sanitizeFilename(state.file.name)}-region-${archive.offset}.${archive.kind === "zip" ? "zip" : "bin"}`, bytes);
      addEvidence({ type: "carve", source: state.file.name, title: `Exported region at offset ${archive.offset}`, value: bytesToHex(bytes.slice(0, 64)), preview: `${formatFileSize(bytes.length)} exported`, manual: true });
      completeStep(2);
      return;
    }
    if (action === "send-region") {
      const bytes = state.bytes.slice(archive.offset, archive.offset + archive.length);
      setDecoderBinaryInput(bytes);
      addEvidence({ type: "carve", source: state.file.name, title: `Loaded region into decoder`, value: bytesToBase64(bytes), preview: `${formatFileSize(bytes.length)} from offset ${archive.offset}`, manual: true });
      completeStep(2);
      elements.decoderInput.scrollIntoView({ behavior: "smooth", block: "center" });
      return;
    }

    const entry = archive.entries[entryIndex];
    if (!entry) return;
    const bytes = await extractZipEntry(archive, entry);
    addEvidence({ type: "extraction", source: archive.label, title: `Extracted ${entry.name}`, value: bytesToBase64(bytes), preview: `${formatFileSize(bytes.length)} · SHA-256 pending`, manual: true });
    completeStep(2);
    recordReplay("extract", `Extracted ${entry.name}`, archive.label);

    if (action === "download-entry") {
      downloadBytes(entry.name.split("/").pop() || "entry.bin", bytes);
    }
    if (action === "analyze-entry") {
      const name = entry.name.split("/").pop() || "entry.bin";
      const file = new File([bytes], name, { type: guessMimeFromName(name) });
      await analyzeFile(file, { role: `Extracted entry: ${entry.name}`, preserveSession: true, parentSource: archive.label });
    }
    if (action === "decode-entry") {
      setDecoderBinaryInput(bytes);
      elements.decoderInput.scrollIntoView({ behavior: "smooth", block: "center" });
      showToast("Entry bytes loaded into the decoder as Base64.");
    }
  } catch (error) {
    console.error(error);
    showToast(error.message || "Archive extraction failed.");
  }
}

function setDecoderBinaryInput(bytes) {
  const ratio = printableRatio(bytes);
  if (ratio > 0.85) {
    elements.decoderInputEncoding.value = "text";
    elements.decoderInput.value = bytesToUtf8(bytes);
  } else {
    elements.decoderInputEncoding.value = "base64";
    elements.decoderInput.value = bytesToBase64(bytes);
  }
  elements.decoderMode.value = "xor";
  updateDecoderControls();
}

function renderFindings() {
  elements.findingsCount.textContent = String(state.findings.length);
  if (!state.findings.length) {
    elements.findingsList.className = "finding-list empty-state";
    elements.findingsList.textContent = "No findings generated.";
    return;
  }
  elements.findingsList.className = "finding-list";
  elements.findingsList.innerHTML = "";
  state.findings.forEach((finding) => {
    const item = document.createElement("article");
    item.className = `finding-item ${finding.level}`;
    const title = document.createElement("strong");
    title.textContent = finding.title;
    const detail = document.createElement("p");
    detail.textContent = finding.detail;
    item.append(title, detail);
    elements.findingsList.appendChild(item);
  });
}

function renderEvidence() {
  elements.evidenceCount.textContent = String(state.evidence.length);
  elements.evidenceSummary.textContent = String(state.evidence.length);
  elements.evidenceLabel.textContent = state.evidence.length ? "Provenance recorded" : "No evidence recorded";
  if (!state.evidence.length) {
    elements.evidenceList.className = "evidence-list empty-state";
    elements.evidenceList.textContent = "No evidence recorded yet.";
    return;
  }
  elements.evidenceList.className = "evidence-list";
  elements.evidenceList.innerHTML = "";
  state.evidence.slice().reverse().forEach((item) => {
    const row = document.createElement("article");
    row.className = `evidence-item${item.manual ? " evidence-manual" : ""}${item.verified ? " evidence-verified" : ""}`;
    const header = document.createElement("div");
    header.className = "evidence-item-header";
    const copy = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = item.title;
    const source = document.createElement("small");
    source.className = "evidence-source";
    source.textContent = `${item.source} · ${new Date(item.timestamp).toLocaleTimeString()}`;
    copy.append(title, source);
    const button = document.createElement("button");
    button.className = "icon-button";
    button.type = "button";
    button.dataset.evidenceCopy = item.id;
    button.textContent = "Copy";
    header.append(copy, button);
    const preview = document.createElement("p");
    preview.className = "mono";
    preview.textContent = item.preview || String(item.value).slice(0, 300);
    row.append(header, preview);
    elements.evidenceList.appendChild(row);
  });
}

function renderCandidates() {
  const candidates = [...state.candidates.values()];
  elements.candidateCount.textContent = String(candidates.length);
  if (!candidates.length) {
    elements.candidateList.className = "candidate-list empty-state";
    elements.candidateList.textContent = "No flag candidates discovered yet.";
    return;
  }
  elements.candidateList.className = "candidate-list";
  elements.candidateList.innerHTML = "";
  candidates.forEach((candidate) => {
    const item = document.createElement("div");
    item.className = "candidate-item";
    const copy = document.createElement("div");
    copy.style.minWidth = "0";
    copy.style.flex = "1";
    const value = document.createElement("div");
    value.className = "candidate-value";
    value.textContent = candidate.value;
    const meta = document.createElement("div");
    meta.className = `candidate-meta ${candidate.verified ? "candidate-verified" : "candidate-trust"}`;
    meta.textContent = candidate.verified ? `Verified · ${candidate.source}` : `Unverified candidate · ${candidate.source}`;
    copy.append(value, meta);
    const button = document.createElement("button");
    button.className = "icon-button";
    button.type = "button";
    button.dataset.candidate = candidate.value;
    button.textContent = "Use";
    item.append(copy, button);
    elements.candidateList.appendChild(item);
  });
}

function renderDecoderHistory() {
  if (!state.decoderHistory.length) {
    elements.decoderHistory.className = "history-list empty-state";
    elements.decoderHistory.textContent = "No decoder steps recorded.";
    return;
  }
  elements.decoderHistory.className = "history-list";
  elements.decoderHistory.innerHTML = "";
  state.decoderHistory.slice().reverse().forEach((step, index) => {
    const item = document.createElement("article");
    item.className = "history-item";
    const header = document.createElement("div");
    header.className = "history-item-header";
    const title = document.createElement("strong");
    title.textContent = `${step.operation} · step ${state.decoderHistory.length - index}`;
    const time = document.createElement("small");
    time.textContent = new Date(step.timestamp).toLocaleTimeString();
    header.append(title, time);
    const preview = document.createElement("p");
    preview.className = "mono";
    preview.textContent = step.display.slice(0, 300);
    item.append(header, preview);
    elements.decoderHistory.appendChild(item);
  });
}

function renderReplay() {
  if (!state.replay.length) {
    elements.replayList.className = "replay-list empty-state";
    elements.replayList.textContent = "No actions recorded yet.";
    return;
  }
  elements.replayList.className = "replay-list";
  elements.replayList.innerHTML = "";
  state.replay.slice().reverse().forEach((entry) => {
    const item = document.createElement("article");
    item.className = "replay-item";
    const header = document.createElement("div");
    header.className = "replay-item-header";
    const title = document.createElement("strong");
    title.textContent = entry.title;
    const time = document.createElement("small");
    time.textContent = new Date(entry.timestamp).toLocaleTimeString();
    header.append(title, time);
    const detail = document.createElement("p");
    detail.textContent = entry.detail;
    item.append(header, detail);
    elements.replayList.appendChild(item);
  });
}

function renderTimeline() {
  elements.timeline.innerHTML = "";
  const firstIncomplete = timelineSteps.findIndex((_, index) => !state.completedSteps.has(index));
  timelineSteps.forEach((step, index) => {
    const completed = state.completedSteps.has(index);
    const current = index === firstIncomplete;
    const row = document.createElement("div");
    row.className = completed ? "timeline-step completed" : current ? "timeline-step current" : "timeline-step locked";
    const number = document.createElement("div");
    number.className = "timeline-number";
    number.textContent = completed ? "✓" : String(index + 1);
    const copy = document.createElement("div");
    copy.className = "timeline-copy";
    const title = document.createElement("strong");
    title.textContent = step.title;
    const description = document.createElement("small");
    description.textContent = step.description;
    copy.append(title, description);
    const status = document.createElement("span");
    status.className = "timeline-status";
    status.textContent = completed ? "Completed" : current ? "Current" : "Locked";
    row.append(number, copy, status);
    elements.timeline.appendChild(row);
  });
  const progress = `${state.completedSteps.size} / ${timelineSteps.length}`;
  elements.progressText.textContent = progress;
  elements.progressSummary.textContent = progress;
}

function completeStep(index) {
  if (!timelineSteps[index] || state.completedSteps.has(index)) return;
  state.completedSteps.add(index);
  recordReplay("progress", `Completed: ${timelineSteps[index].title}`, timelineSteps[index].description);
  renderTimeline();
  updateHints();
  updateSummary();
  updateInvestigatorHUD();
}

function updateSummary() {
  const count = state.completedSteps.size;
  elements.progressLabel.textContent = [
    "Investigation not started",
    "Artifact identified",
    "Evidence inspected",
    "Hidden data extracted or decoded",
    "Flag verified"
  ][count] || "Investigation active";
}

function currentHints() {
  return state.challenge?.hints?.length ? state.challenge.hints.map((hint) => typeof hint === "string" ? hint : hint.text) : DEFAULT_HINTS;
}

function updateHints() {
  const hints = currentHints();
  if (state.completedSteps.size === timelineSteps.length) {
    elements.unlockHintButton.disabled = true;
    elements.hintText.textContent = "Investigation complete. Export the replay and evidence report.";
    return;
  }
  const available = Math.min(state.completedSteps.size, hints.length);
  if (state.revealedHints < available) {
    elements.unlockHintButton.disabled = false;
    if (state.revealedHints === 0) elements.hintText.textContent = "A contextual hint is available.";
    return;
  }
  elements.unlockHintButton.disabled = true;
  if (state.completedSteps.size === 0) elements.hintText.textContent = "Upload an artifact to unlock the first hint.";
}

function revealHint() {
  const hints = currentHints();
  const available = Math.min(state.completedSteps.size, hints.length);
  if (state.revealedHints >= available) return;
  state.revealedHints += 1;
  elements.hintText.innerHTML = hints.slice(0, state.revealedHints).map((hint, index) => `<p><strong>Hint ${index + 1}:</strong> ${escapeHtml(hint)}</p>`).join("");
  recordReplay("hint", `Unlocked hint ${state.revealedHints}`, hints[state.revealedHints - 1]);
  updateHints();
}

function updateDecoderControls() {
  const mode = elements.decoderMode.value;
  elements.keyControl.classList.toggle("hidden", mode !== "xor");
  elements.inputEncodingControl.classList.toggle("hidden", mode !== "xor");
  elements.outputEncodingControl.classList.toggle("hidden", mode !== "xor");
  elements.shiftControl.classList.toggle("hidden", mode !== "caesar");
}

function runDecoder() {
  const input = elements.decoderInput.value;
  if (!input.trim()) {
    setResult(elements.decoderOutput, "Enter a value to transform.", "error");
    return;
  }

  let result;
  try {
    result = transformValue(input);
  } catch (error) {
    console.error(error);
    setResult(elements.decoderOutput, error.message || "The operation failed.", "error");
    return;
  }

  if (!result || !result.bytes) {
    setResult(elements.decoderOutput, "The operation could not transform this input.", "error");
    return;
  }
  commitDecoderResult(result, input);
}

function commitDecoderResult(result, input, options = {}) {
  state.lastDecoderResult = result;
  setResult(elements.decoderOutput, result.display, "success");
  const step = {
    operation: result.operation,
    input,
    display: result.display,
    outputBase64: bytesToBase64(result.bytes),
    timestamp: new Date().toISOString(),
    source: options.source || "manual"
  };
  state.decoderHistory.push(step);
  const evidence = addEvidence({
    type: "decode",
    source: options.sourceLabel || `Decoder: ${result.operation}`,
    title: `${result.operation} output`,
    value: result.display,
    preview: result.display.slice(0, 300),
    manual: true
  });
  discoverCandidatesInText(result.display, options.sourceLabel || `Decoder: ${result.operation}`, evidence.id);
  renderCandidates();
  renderDecoderHistory();
  renderEvidence();
  completeStep(2);
  recordReplay("decode", `Ran ${result.operation}`, result.display.slice(0, 180));
  pushHeroTerminal(`decoder executed: ${result.operation}`, "success");
  elements.sessionStatus.textContent = state.candidates.size
    ? "Decoded evidence contains one or more candidates. Load a manifest before final verification."
    : "Transformation completed. Continue the decoder chain or inspect the output.";
}

function autoProbeInput() {
  const input = elements.decoderInput.value.trim();
  if (!input) {
    showToast("Paste suspicious text before running Auto-probe.");
    elements.decoderInput.focus();
    return;
  }

  const candidates = [];
  const seen = new Set();
  const add = (operation, bytes, display) => {
    if (!bytes || typeof display !== "string" || !display.length) return;
    const normalized = display.trim();
    if (!normalized || normalized === input || seen.has(normalized)) return;
    const score = scoreProbeOutput(normalized, input, bytes);
    if (score < 40) return;
    seen.add(normalized);
    candidates.push({ operation, bytes, display, score });
  };

  try { const bytes = decodeBase64Bytes(input); if (bytes) add("Base64 decode", bytes, bytesToDisplay(bytes)); } catch {}
  try { const bytes = decodeHexBytes(input); if (bytes) add("Hex to bytes", bytes, bytesToDisplay(bytes)); } catch {}
  try { const bytes = decodeBase32Bytes(input); if (bytes) add("Base32 decode", bytes, bytesToDisplay(bytes)); } catch {}
  try { const bytes = decodeBinaryBytes(input); if (bytes) add("Binary to bytes", bytes, bytesToDisplay(bytes)); } catch {}
  try { const bytes = decodeDecimalBytes(input); if (bytes) add("Decimal ASCII", bytes, bytesToDisplay(bytes)); } catch {}
  if (/%[0-9a-f]{2}|\+/i.test(input)) {
    try { const display = decodeURIComponent(input.replace(/\+/g, "%20")); add("URL decode", new TextEncoder().encode(display), display); } catch {}
  }

  const rot13 = rotateAscii(input, 13);
  add("ROT13", new TextEncoder().encode(rot13), rot13);
  const reversed = [...input].reverse().join("");
  add("Reverse text", new TextEncoder().encode(reversed), reversed);
  for (let shift = 1; shift <= 25; shift += 1) {
    const display = rotateAscii(input, shift);
    add(`Caesar shift ${shift}`, new TextEncoder().encode(display), display);
  }

  const ranked = candidates.sort((first, second) => second.score - first.score);
  const confidenceFloor = ranked.length ? Math.max(40, ranked[0].score - 45) : 40;
  state.autoProbeResults = ranked.filter((candidate) => candidate.score >= confidenceFloor).slice(0, 8);
  renderAutoProbeResults();
  recordReplay("probe", "Auto-probed decoder input", `${state.autoProbeResults.length} plausible transformations`);
  pushHeroTerminal(`auto-probe complete: ${state.autoProbeResults.length} candidates`, state.autoProbeResults.length ? "success" : "error");
}

function scoreProbeOutput(display, input, bytes) {
  const characters = [...display];
  const printable = characters.filter((character) => {
    const code = character.codePointAt(0);
    return character === "\n" || character === "\r" || character === "\t" || (code >= 32 && code <= 126);
  }).length / Math.max(1, characters.length);
  const flagLike = /(?:flag|ctf|hackclub|stardance)\{[^}\r\n]{1,200}\}/i.test(display);
  const commonWords = display.match(/\b(the|this|that|secret|password|token|key|hint|next|open|decode|archive|report|user|admin|file|data|case|note|payload)\b/gi) || [];
  const letters = display.match(/[a-z]/gi) || [];
  const vowels = display.match(/[aeiou]/gi) || [];
  const whitespaceRatio = (display.match(/\s/g) || []).length / Math.max(1, display.length);
  const vowelRatio = vowels.length / Math.max(1, letters.length);
  let score = printable * 42;

  if (flagLike) score += 80;
  if (commonWords.length) score += Math.min(30, 12 + commonWords.length * 6);
  if (/^[\x09\x0a\x0d\x20-\x7e]+$/.test(display)) score += 10;
  if (!display.includes("�")) score += 6;
  if (display.length >= 2 && display.length <= Math.max(4096, input.length * 4)) score += 6;
  if (letters.length >= 5 && vowelRatio >= 0.22 && vowelRatio <= 0.62) score += 10;
  if (whitespaceRatio >= 0.025 && whitespaceRatio <= 0.42) score += 8;

  const entropy = bytes.length ? calculateEntropy(bytes.slice(0, Math.min(bytes.length, 20000))) : 8;
  if (entropy < 6.8) score += 5;

  // Long unbroken alphanumeric outputs are often merely another encoding or
  // Caesar-shifted noise. Penalize them unless they contain a flag or words.
  if (!flagLike && !commonWords.length && display.length > 20 && /^[a-z0-9+/=_-]+$/i.test(display)) score -= 34;
  return Math.round(score);
}

function renderAutoProbeResults() {
  const results = state.autoProbeResults;
  if (!results.length) {
    elements.autoProbeResults.classList.remove("hidden");
    elements.autoProbeResults.innerHTML = '<div class="empty-state">No high-confidence common transformation was found. Try a manual decoder or provide an XOR key.</div>';
    return;
  }
  elements.autoProbeResults.classList.remove("hidden");
  elements.autoProbeResults.innerHTML = `
    <div class="auto-probe-header"><strong>Auto-probe ranked results</strong><span>Click a result to commit it to the evidence chain.</span></div>
    <div class="probe-list">
      ${results.map((result, index) => `<button class="probe-item" type="button" data-probe-index="${index}"><span class="probe-operation">${escapeHtml(result.operation)}</span><span class="probe-preview">${escapeHtml(result.display.replace(/\s+/g, " ").slice(0, 260))}</span><span class="probe-score">${result.score}</span></button>`).join("")}
    </div>`;
}

function applyProbeResult(index) {
  const result = state.autoProbeResults[index];
  if (!result) return;
  commitDecoderResult(result, elements.decoderInput.value, { source: "auto-probe", sourceLabel: `Auto-probe: ${result.operation}` });
  elements.autoProbeResults.classList.add("hidden");
  showToast(`${result.operation} committed to the replay.`);
}

function rotateAscii(input, shift) {
  return input.replace(/[a-zA-Z]/g, (character) => {
    const base = character <= "Z" ? 65 : 97;
    return String.fromCharCode(((character.charCodeAt(0) - base + shift + 2600) % 26) + base);
  });
}

function transformValue(input) {
  const mode = elements.decoderMode.value;
  if (mode === "base64") {
    const bytes = decodeBase64Bytes(input);
    return bytes ? { operation: "Base64 decode", bytes, display: bytesToDisplay(bytes) } : null;
  }
  if (mode === "hex") {
    const bytes = decodeHexBytes(input);
    return bytes ? { operation: "Hex to bytes", bytes, display: bytesToDisplay(bytes) } : null;
  }
  if (mode === "base32") {
    const bytes = decodeBase32Bytes(input);
    return bytes ? { operation: "Base32 decode", bytes, display: bytesToDisplay(bytes) } : null;
  }
  if (mode === "binary") {
    const bytes = decodeBinaryBytes(input);
    return bytes ? { operation: "Binary to bytes", bytes, display: bytesToDisplay(bytes) } : null;
  }
  if (mode === "decimal") {
    const bytes = decodeDecimalBytes(input);
    return bytes ? { operation: "Decimal ASCII", bytes, display: bytesToDisplay(bytes) } : null;
  }
  if (mode === "rot13") {
    const display = rotateAscii(input, 13);
    return { operation: "ROT13", bytes: new TextEncoder().encode(display), display };
  }
  if (mode === "caesar") {
    const shift = Number(elements.caesarShift.value || 0);
    const display = rotateAscii(input, shift);
    return { operation: `Caesar shift ${shift}`, bytes: new TextEncoder().encode(display), display };
  }
  if (mode === "url") {
    const display = decodeURIComponent(input.trim());
    return { operation: "URL decode", bytes: new TextEncoder().encode(display), display };
  }
  if (mode === "reverse") {
    const display = [...input].reverse().join("");
    return { operation: "Reverse text", bytes: new TextEncoder().encode(display), display };
  }
  if (mode === "xor") {
    const key = new TextEncoder().encode(elements.decoderKey.value);
    if (!key.length) throw new Error("XOR key is empty.");
    const inputBytes = parseDecoderInputBytes(input, elements.decoderInputEncoding.value);
    if (!inputBytes) return null;
    const output = new Uint8Array(inputBytes.length);
    for (let index = 0; index < inputBytes.length; index += 1) output[index] = inputBytes[index] ^ key[index % key.length];
    const outputMode = elements.decoderOutputEncoding.value;
    const display = outputMode === "hex" ? bytesToHex(output) : outputMode === "base64" ? bytesToBase64(output) : bytesToDisplay(output);
    return { operation: `Repeating-key XOR (${elements.decoderInputEncoding.value} → ${outputMode})`, bytes: output, display };
  }
  return null;
}

function parseDecoderInputBytes(input, encoding) {
  if (encoding === "text") return new TextEncoder().encode(input);
  if (encoding === "hex") return decodeHexBytes(input);
  if (encoding === "base64") return decodeBase64Bytes(input);
  return null;
}

function useDecoderOutputAsInput() {
  if (!state.lastDecoderResult) {
    showToast("Run a decoder operation first.");
    return;
  }
  elements.decoderInput.value = state.lastDecoderResult.display;
  showToast("Decoder output moved into the input field.");
}

function saveDecoderEvidence() {
  if (!state.lastDecoderResult) {
    showToast("Run a decoder operation first.");
    return;
  }
  addEvidence({ type: "manual", source: "Decoder workbench", title: "Saved decoder output", value: state.lastDecoderResult.display, preview: state.lastDecoderResult.display.slice(0, 300), manual: true });
  renderEvidence();
  showToast("Decoder output saved as evidence.");
}

function downloadDecoderOutput() {
  if (!state.lastDecoderResult) {
    showToast("Run a decoder operation first.");
    return;
  }
  downloadBytes("decoder-output.bin", state.lastDecoderResult.bytes);
}

function discoverCandidatesInText(text, source, evidenceId) {
  const matches = text.match(/(?:flag|ctf|hackclub|stardance)\{[^}\r\n]{1,200}\}/gi) || [];
  matches.forEach((value) => addCandidate(value, source, evidenceId));
}

async function verifyFlag() {
  const submitted = elements.flagInput.value.trim();
  if (!submitted) {
    setResult(elements.flagResult, "Enter a flag before verification.", "error");
    return;
  }

  addCandidate(submitted, "Manual submission", null);
  renderCandidates();

  if (!state.challenge) {
    setResult(elements.flagResult, "Candidate recorded, but no challenge manifest is loaded. The app will not claim that it is correct.", "error");
    recordReplay("verify", "Verification blocked", "No trusted challenge manifest loaded.");
    pushHeroTerminal("verification blocked: manifest missing", "error");
    return;
  }
  if (!state.artifactHashMatches) {
    setResult(elements.flagResult, "Verification blocked because the artifact does not match the manifest SHA-256.", "error");
    return;
  }
  if (state.challenge.flagFormat) {
    try {
      if (!new RegExp(state.challenge.flagFormat).test(submitted)) {
        setResult(elements.flagResult, "The submitted value does not match the challenge flag format.", "error");
        return;
      }
    } catch {
      // Invalid author regex should not break hash verification.
    }
  }

  const hash = await sha256Text(submitted);
  if (hash.toLowerCase() !== state.challenge.expectedFlagSha256.toLowerCase()) {
    setResult(elements.flagResult, "Hash mismatch. This is an unverified or incorrect candidate.", "error");
    recordReplay("verify", "Flag rejected", submitted);
    pushHeroTerminal("candidate rejected: hash mismatch", "error");
    return;
  }

  const candidate = addCandidate(submitted, "Manifest SHA-256 verification", null, true);
  candidate.verified = true;
  state.solvedAt = new Date();
  const evidence = addEvidence({ type: "verification", source: state.challenge.title, title: "Flag verified by SHA-256", value: submitted, preview: submitted, verified: true });
  candidate.evidenceId = evidence.id;
  setResult(elements.flagResult, "Correct flag. The manifest SHA-256 matched.", "success");
  completeStep(3);
  renderCandidates();
  renderEvidence();
  elements.sessionStatus.textContent = "Challenge solved. Export the full replay and evidence report.";
  recordReplay("verify", "Flag verified", submitted);
  pushHeroTerminal("case solved: trusted hash matched", "success");
}

async function loadChallengeManifest(file) {
  try {
    const data = JSON.parse(await file.text());
    validateManifest(data);
    state.challenge = data;
    state.revealedHints = 0;
    compareChallengeArtifactHash();
    updateChallengeUI();
    updateHints();
    recordReplay("manifest", `Loaded challenge manifest: ${data.title}`, file.name);
    showToast(`Challenge loaded: ${data.title}`);
  } catch (error) {
    console.error(error);
    showToast(error.message || "Invalid challenge manifest.");
  }
}

function validateManifest(data) {
  if (!data || typeof data !== "object") throw new Error("Manifest must be a JSON object.");
  if (data.schemaVersion !== 1) throw new Error("Unsupported manifest schemaVersion. Expected 1.");
  if (!data.id || !data.title) throw new Error("Manifest requires id and title.");
  if (!/^[a-f0-9]{64}$/i.test(data.expectedFlagSha256 || "")) throw new Error("expectedFlagSha256 must be a 64-character SHA-256 hex string.");
  if (data.artifactSha256 && !/^[a-f0-9]{64}$/i.test(data.artifactSha256)) throw new Error("artifactSha256 must be a 64-character SHA-256 hex string.");
}

function compareChallengeArtifactHash() {
  state.artifactHashMatches = true;
  const trustedHash = state.rootArtifactHash || state.hash;
  if (state.challenge?.artifactSha256 && trustedHash) {
    state.artifactHashMatches = state.challenge.artifactSha256.toLowerCase() === trustedHash.toLowerCase();
  }
  elements.artifactHashWarning.classList.toggle("hidden", state.artifactHashMatches);
  updateChallengeUI();
}

function updateChallengeUI() {
  if (!state.challenge) {
    elements.modePill.textContent = "Practice mode";
    elements.challengeTitle.textContent = "No challenge manifest loaded";
    elements.challengeSubtitle.textContent = "Candidates can be collected, but only a manifest can verify the final flag.";
    elements.clearChallengeButton.classList.add("hidden");
    elements.verificationMode.textContent = "Unverified practice";
    return;
  }
  elements.modePill.textContent = state.artifactHashMatches ? "Verified challenge mode" : "Manifest mismatch";
  elements.challengeTitle.textContent = state.challenge.title;
  elements.challengeSubtitle.textContent = `${state.challenge.category || "CTF"} · ${state.challenge.difficulty || "Unspecified"} · ${state.challenge.id}`;
  elements.clearChallengeButton.classList.remove("hidden");
  elements.verificationMode.textContent = state.artifactHashMatches ? "SHA-256 verification" : "Artifact mismatch";
}

function clearChallenge() {
  state.challenge = null;
  state.artifactHashMatches = true;
  state.revealedHints = 0;
  updateChallengeUI();
  updateHints();
  elements.artifactHashWarning.classList.add("hidden");
  showToast("Challenge manifest cleared.");
}

function openAuthorDialog() {
  closeCommandPalette(true);
  closeCaseboard(true);
  closeDiagnostics(true);
  rememberOverlayFocus();
  elements.authorArtifactHash.value = state.hash || "";
  elements.authorDialog.showModal();
  syncOverlayState();
}

async function exportAuthorManifest() {
  const flag = elements.authorFlag.value;
  if (!elements.authorTitle.value.trim() || !elements.authorId.value.trim() || !flag) {
    showToast("Title, challenge ID, and expected flag are required.");
    return;
  }
  const manifest = {
    schemaVersion: 1,
    id: slugify(elements.authorId.value),
    title: elements.authorTitle.value.trim(),
    category: elements.authorCategory.value.trim() || "CTF",
    difficulty: elements.authorDifficulty.value,
    artifactSha256: elements.authorArtifactHash.value.trim() || undefined,
    expectedFlagSha256: await sha256Text(flag),
    flagFormat: "^(?:flag|ctf|hackclub|stardance)\\{[^}]+\\}$",
    hints: elements.authorHints.value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean),
    createdAt: new Date().toISOString(),
    author: "@V01d_404"
  };
  Object.keys(manifest).forEach((key) => manifest[key] === undefined && delete manifest[key]);
  downloadTextFile(`${manifest.id}.ctflab.json`, JSON.stringify(manifest, null, 2), "application/json");
  elements.authorFlag.value = "";
  showToast("Challenge manifest exported without the plaintext flag.");
}

function concatBytes(...parts) {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  parts.forEach((part) => {
    output.set(part, offset);
    offset += part.length;
  });
  return output;
}

function u16le(value) {
  return Uint8Array.from([value & 0xff, (value >>> 8) & 0xff]);
}

function u32le(value) {
  return Uint8Array.from([value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff]);
}

function u32be(value) {
  return Uint8Array.from([(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff]);
}

function makePngChunk(type, data = new Uint8Array()) {
  const typeBytes = new TextEncoder().encode(type);
  return concatBytes(u32be(data.length), typeBytes, data, new Uint8Array(4));
}

function makeStoredZipEntry(name, data) {
  const nameBytes = new TextEncoder().encode(name);
  const local = concatBytes(
    Uint8Array.from([0x50, 0x4b, 0x03, 0x04]),
    u16le(20), u16le(0), u16le(0), u16le(0), u16le(0), u32le(0),
    u32le(data.length), u32le(data.length), u16le(nameBytes.length), u16le(0),
    nameBytes, data
  );
  const central = concatBytes(
    Uint8Array.from([0x50, 0x4b, 0x01, 0x02]),
    u16le(20), u16le(20), u16le(0), u16le(0), u16le(0), u16le(0), u32le(0),
    u32le(data.length), u32le(data.length), u16le(nameBytes.length), u16le(0), u16le(0),
    u16le(0), u16le(0), u32le(0), u32le(0), nameBytes
  );
  const eocd = concatBytes(
    Uint8Array.from([0x50, 0x4b, 0x05, 0x06]),
    u16le(0), u16le(0), u16le(1), u16le(1), u32le(central.length), u32le(local.length), u16le(0)
  );
  return concatBytes(local, central, eocd);
}

function createDemoArtifact(flag) {
  const clue = bytesToBase64(new TextEncoder().encode(flag));
  const clueText = new TextEncoder().encode(`CASE NOTE\nThe payload below is Base64.\n${clue}\n`);
  const zip = makeStoredZipEntry("clue.txt", clueText);
  const ihdr = concatBytes(u32be(1), u32be(1), Uint8Array.from([8, 6, 0, 0, 0]));
  const metadata = new TextEncoder().encode("Investigator\0V01d_404 // inspect bytes after IEND");
  return concatBytes(
    Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    makePngChunk("IHDR", ihdr),
    makePngChunk("tEXt", metadata),
    makePngChunk("IEND"),
    zip
  );
}

async function loadDemo() {
  const flag = "flag{follow_the_signature_map}";
  const bytes = createDemoArtifact(flag);
  const file = new File([bytes], "ghost-tail.png", { type: "image/png" });
  state.challenge = {
    schemaVersion: 1,
    id: "ghost-tail-demo",
    title: "Ghost Tail",
    category: "Forensics / Encoding",
    difficulty: "Medium",
    artifactSha256: await sha256Bytes(bytes),
    expectedFlagSha256: await sha256Text(flag),
    flagFormat: "^flag\\{[^}]+\\}$",
    hints: [
      "The primary PNG is not the whole file. Inspect the Signature map and bytes after IEND.",
      "Open Archives and extract or send clue.txt to the decoder.",
      "The recovered clue is Base64. Decode it, then verify the exact flag."
    ]
  };
  await analyzeFile(file, { role: "Built-in demo artifact", preserveSession: false });
  updateChallengeUI();
  activateTab("signatures", true);
  elements.sessionStatus.textContent = "Guided demo loaded. The Signature map shows an appended archive after the PNG terminator.";
  showToast("Ghost Tail demo loaded. Follow the signature at the appended offset.");
}

function updateCommandExplanation() {
  const command = elements.commandSelect.value;
  if (!command) {
    elements.commandExplanation.textContent = "Select a command to see what it does, why it helps, and its risk level.";
    elements.commandExplanation.className = "result-box";
    return;
  }
  const info = commandInformation[command];
  elements.commandExplanation.innerHTML = `<strong>Purpose</strong><p>${escapeHtml(info.purpose)}</p><strong>Why it is useful</strong><p>${escapeHtml(info.use)}</p><strong>Risk level</strong><p>${escapeHtml(info.risk)}</p>`;
}

function jumpHex() {
  const raw = elements.hexOffsetInput.value.trim().toLowerCase();
  const parsed = raw.startsWith("0x") ? Number.parseInt(raw.slice(2), 16) : Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed < 0 || !state.bytes) {
    showToast("Enter a valid decimal or hexadecimal offset.");
    return;
  }
  state.hexOffset = Math.min(parsed, Math.max(0, state.bytes.length - 1));
  renderHex();
  addEvidence({ type: "hex", source: state.file.name, title: `Inspected offset ${state.hexOffset}`, value: makeHexPreview(state.bytes, state.hexOffset, 128), preview: `0x${state.hexOffset.toString(16)}`, manual: true });
  completeStep(1);
}

function downloadFromOffset() {
  if (!state.bytes) return;
  const offset = state.hexOffset;
  downloadBytes(`${sanitizeFilename(state.file.name)}-from-${offset}.bin`, state.bytes.slice(offset));
  addEvidence({ type: "carve", source: state.file.name, title: `Exported bytes from offset ${offset}`, value: "", preview: `${formatFileSize(state.bytes.length - offset)} exported`, manual: true });
  completeStep(2);
}

function clearManualEvidence() {
  state.evidence = state.evidence.filter((item) => !state.manualEvidenceIds.has(item.id));
  state.manualEvidenceIds.clear();
  renderEvidence();
  showToast("Manual evidence cleared. Automatic and verified evidence was preserved.");
}

function exportEvidenceJson() {
  downloadTextFile(`${sanitizeFilename(state.file?.name || "session")}-evidence.json`, JSON.stringify({
    artifact: state.file ? { name: state.file.name, sha256: state.hash, format: state.typeInfo?.name, role: state.role } : null,
    challenge: state.challenge ? { id: state.challenge.id, title: state.challenge.title } : null,
    signatures: state.signatures,
    byteMap: {
      blockSize: state.byteMap.blockSize,
      peakEntropy: state.byteMap.peakEntropy,
      dominantByte: state.byteMap.dominantByte,
      dominantRatio: state.byteMap.dominantRatio,
      nullRatio: state.byteMap.nullRatio,
      blocks: state.byteMap.blocks
    },
    evidence: state.evidence,
    candidates: [...state.candidates.values()],
    decoderHistory: state.decoderHistory,
    replay: state.replay
  }, null, 2), "application/json");
}

function saveNotes() {
  if (!state.hash) return;
  try {
    localStorage.setItem(`ctf-replay-notes:${state.hash}`, elements.notesInput.value);
    elements.notesStatus.textContent = "Saved locally";
  } catch {
    elements.notesStatus.textContent = "Browser storage unavailable";
  }
}

function loadNotes() {
  if (!state.hash) return;
  try {
    elements.notesInput.value = localStorage.getItem(`ctf-replay-notes:${state.hash}`) || "";
    elements.notesStatus.textContent = elements.notesInput.value ? "Loaded from browser" : "Not saved";
  } catch {
    elements.notesInput.value = "";
    elements.notesStatus.textContent = "Browser storage unavailable";
  }
}

function copyReplay() {
  const text = state.replay.map((entry) => `${entry.timestamp} · ${entry.title}\n${entry.detail}`).join("\n\n");
  if (!text) showToast("No replay to copy.");
  else copyText(text);
}

function exportReport() {
  if (!state.file) return;
  const metadata = Object.entries({ ...state.metadata, ...state.structures }).map(([key, value]) => {
    const rendered = value && typeof value === "object" ? `\n\`\`\`json\n${JSON.stringify(value, null, 2)}\n\`\`\`` : String(value);
    return `- **${key}:** ${rendered}`;
  }).join("\n") || "No supported metadata.";
  const findings = state.findings.map((item) => `- **${item.title}:** ${item.detail}`).join("\n") || "No findings.";
  const signatures = state.signatures.map((item) => `- **${item.name}** — \`0x${item.offset.toString(16)}\` — ${item.role} — ${item.detail}`).join("\n") || "No recognized signatures.";
  const highEntropyRegions = state.byteMap.blocks
    .map((block, index) => ({ ...block, index }))
    .sort((first, second) => second.entropy - first.entropy)
    .slice(0, 8)
    .map((block) => `- Region ${block.index + 1}: \`0x${block.start.toString(16)}–0x${Math.max(block.start, block.end - 1).toString(16)}\` — ${block.entropy.toFixed(3)} bits/byte — ${(block.printableRatio * 100).toFixed(1)}% printable`)
    .join("\n") || "No byte-map regions.";
  const evidence = state.evidence.map((item, index) => `${index + 1}. **${item.title}** — ${item.source}\n   - ${item.preview}`).join("\n") || "No evidence.";
  const candidates = [...state.candidates.values()].map((item) => `- \`${item.value}\` — ${item.verified ? "VERIFIED" : "unverified"} — ${item.source}`).join("\n") || "No candidates.";
  const replay = state.replay.map((entry) => `- ${entry.timestamp} — **${entry.title}** — ${entry.detail}`).join("\n") || "No replay.";
  const decoders = state.decoderHistory.map((step, index) => `### Step ${index + 1}: ${step.operation}\n\n\`\`\`text\n${step.display}\n\`\`\``).join("\n\n") || "No decoder steps.";
  const report = `# CTF Replay Lab Investigation Report\n\n## Challenge\n\n${state.challenge ? `- **Title:** ${state.challenge.title}\n- **ID:** ${state.challenge.id}\n- **Mode:** Manifest-backed verification` : "Practice mode — no challenge manifest loaded."}\n\n## Current artifact\n\n- **Filename:** ${state.file.name}\n- **Role:** ${state.role}\n- **Detected format:** ${state.typeInfo.name}\n- **Category:** ${state.typeInfo.category}\n- **Size:** ${formatFileSize(state.file.size)}\n- **SHA-256:** ${state.hash}\n- **Root artifact:** ${state.rootArtifactName || state.file.name}\n- **Root artifact SHA-256:** ${state.rootArtifactHash || state.hash}\n- **Entropy:** ${state.entropy.toFixed(4)}\n- **Started:** ${state.startedAt?.toISOString() || "Unknown"}\n- **Solved:** ${state.solvedAt?.toISOString() || "Not verified"}\n\n## Metadata and structure\n\n${metadata}\n\n## Findings\n\n${findings}\n\n## Evidence provenance\n\n${evidence}\n\n## Candidate status\n\n${candidates}\n\n## Decoder replay\n\n${decoders}\n\n## Action replay\n\n${replay}\n\n## Investigator notes\n\n${elements.notesInput.value || "No notes recorded."}\n\n---\nGenerated locally by CTF Replay Lab · @V01d_404\n`;
  downloadTextFile(`${sanitizeFilename(state.file.name)}-ctf-replay-report.md`, report, "text/markdown");
  recordReplay("export", "Exported investigation report", state.file.name);
}

function updateSummaryCardsAfterEvidence() {
  elements.evidenceSummary.textContent = String(state.evidence.length);
  elements.evidenceLabel.textContent = state.evidence.length ? "Provenance recorded" : "No evidence recorded";
}

function copyVisibleStrings() {
  if (!state.visibleStrings.length) showToast("No visible strings to copy.");
  else copyText(state.visibleStrings.join("\n"));
}

function setResult(element, message, status = "") {
  element.textContent = message;
  element.className = `result-box${status ? ` ${status}` : ""}`;
}

function makeHexPreview(bytes, startOffset, maximumBytes) {
  if (!bytes) return "No hex preview available.";
  const start = Math.min(Math.max(0, startOffset), bytes.length);
  const end = Math.min(bytes.length, start + maximumBytes);
  const lines = [];
  for (let offset = start; offset < end; offset += 16) {
    const slice = bytes.slice(offset, Math.min(offset + 16, end));
    const hex = Array.from(slice).map((byte) => byte.toString(16).padStart(2, "0")).join(" ").padEnd(47, " ");
    const ascii = Array.from(slice).map((byte) => byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : ".").join("");
    lines.push(`${offset.toString(16).padStart(8, "0")}  ${hex}  |${ascii}|`);
  }
  if (end < bytes.length) lines.push(`\n… showing ${start}–${end - 1} of ${bytes.length} bytes`);
  return lines.join("\n");
}

function extractStrings(bytes, minimumLength = 4, maximum = 1500) {
  const results = [];
  let current = "";
  for (let index = 0; index < bytes.length; index += 1) {
    const byte = bytes[index];
    if (byte >= 32 && byte <= 126) current += String.fromCharCode(byte);
    else {
      if (current.length >= minimumLength) {
        results.push(current);
        if (results.length >= maximum) break;
      }
      current = "";
    }
  }
  if (current.length >= minimumLength && results.length < maximum) results.push(current);

  const utf16 = [];
  current = "";
  for (let index = 0; index + 1 < bytes.length && utf16.length < 300; index += 2) {
    if (bytes[index + 1] === 0 && bytes[index] >= 32 && bytes[index] <= 126) current += String.fromCharCode(bytes[index]);
    else {
      if (current.length >= minimumLength) utf16.push(`[UTF-16LE] ${current}`);
      current = "";
    }
  }
  return [...new Set([...results, ...utf16])].slice(0, maximum);
}

function prepareStringScanBytes(bytes) {
  if (bytes.length <= MAX_STRING_SCAN_BYTES) return bytes;
  const firstLength = 8 * 1024 * 1024;
  const lastLength = 4 * 1024 * 1024;
  const combined = new Uint8Array(firstLength + lastLength);
  combined.set(bytes.slice(0, firstLength), 0);
  combined.set(bytes.slice(bytes.length - lastLength), firstLength);
  return combined;
}

function truncateEvidenceValue(value) {
  const text = String(value ?? "");
  if (text.length <= MAX_EVIDENCE_VALUE) return text;
  return `${text.slice(0, MAX_EVIDENCE_VALUE)}\n[truncated by CTF Replay Lab]`;
}

function calculateEntropy(bytes) {
  if (!bytes.length) return 0;
  const counts = new Uint32Array(256);
  bytes.forEach((byte) => counts[byte] += 1);
  let entropy = 0;
  for (const count of counts) {
    if (!count) continue;
    const probability = count / bytes.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function describeEntropy(value) {
  if (value >= 7.5) return "Very high · compressed/encrypted-like";
  if (value >= 6.5) return "High · dense binary data";
  if (value >= 4.5) return "Moderate · mixed structure";
  return "Low · structured or repetitive";
}

function printableRatio(bytes) {
  if (!bytes.length) return 0;
  let printable = 0;
  bytes.forEach((byte) => {
    if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126)) printable += 1;
  });
  return printable / bytes.length;
}

function decodeBase64Bytes(value) {
  try {
    let normalized = value.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
    if (!normalized || normalized.length % 4 === 1) return null;
    normalized += "=".repeat((4 - normalized.length % 4) % 4);
    const binary = atob(normalized);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch { return null; }
}

function decodeHexBytes(value) {
  const normalized = value.replace(/0x/gi, "").replace(/[^0-9a-f]/gi, "");
  if (!normalized || normalized.length % 2 !== 0) return null;
  const bytes = new Uint8Array(normalized.length / 2);
  for (let index = 0; index < normalized.length; index += 2) bytes[index / 2] = Number.parseInt(normalized.slice(index, index + 2), 16);
  return bytes;
}

function decodeBase32Bytes(value) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const normalized = value.toUpperCase().replace(/[\s=-]+/g, "");
  if (!normalized || /[^A-Z2-7]/.test(normalized)) return null;
  let buffer = 0;
  let bits = 0;
  const output = [];
  for (const character of normalized) {
    const index = alphabet.indexOf(character);
    if (index < 0) return null;
    buffer = (buffer << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      output.push((buffer >> bits) & 0xff);
      buffer &= (1 << bits) - 1;
    }
  }
  return output.length ? Uint8Array.from(output) : null;
}

function decodeBinaryBytes(value) {
  const normalized = value.replace(/0b/gi, "").replace(/[\s,_-]+/g, "");
  if (!normalized || /[^01]/.test(normalized) || normalized.length % 8 !== 0) return null;
  const output = new Uint8Array(normalized.length / 8);
  for (let index = 0; index < normalized.length; index += 8) {
    output[index / 8] = Number.parseInt(normalized.slice(index, index + 8), 2);
  }
  return output;
}

function decodeDecimalBytes(value) {
  const tokens = value.trim().split(/[\s,;|]+/).filter(Boolean);
  if (!tokens.length || tokens.some((token) => !/^\d{1,3}$/.test(token))) return null;
  const numbers = tokens.map(Number);
  if (numbers.some((number) => number < 0 || number > 255)) return null;
  return Uint8Array.from(numbers);
}

function bytesToDisplay(bytes) {
  const text = bytesToUtf8(bytes);
  return printableRatio(bytes) >= 0.75 ? text : `${bytesToHex(bytes)}\n\n[Binary output · Base64]\n${bytesToBase64(bytes)}`;
}

function bytesToUtf8(bytes) { return new TextDecoder("utf-8", { fatal: false }).decode(bytes); }
function bytesToAscii(bytes) { return Array.from(bytes).map((byte) => String.fromCharCode(byte)).join(""); }
function bytesToLatin1(bytes) { return Array.from(bytes).map((byte) => String.fromCharCode(byte)).join(""); }
function bytesToHex(bytes) { return Array.from(bytes).map((byte) => byte.toString(16).padStart(2, "0")).join(""); }
function bytesToBase64(bytes) {
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  return btoa(binary);
}

function matchesBytes(bytes, signature) { return matchesBytesAt(bytes, 0, signature); }
function matchesBytesAt(bytes, offset, signature) {
  if (offset < 0 || offset + signature.length > bytes.length) return false;
  return signature.every((value, index) => bytes[offset + index] === value);
}
function matchesAscii(bytes, value) {
  if (bytes.length < value.length) return false;
  for (let index = 0; index < value.length; index += 1) if (bytes[index] !== value.charCodeAt(index)) return false;
  return true;
}
function findSignature(bytes, signature, start = 0) {
  outer: for (let offset = start; offset <= bytes.length - signature.length; offset += 1) {
    for (let index = 0; index < signature.length; index += 1) if (bytes[offset + index] !== signature[index]) continue outer;
    return offset;
  }
  return -1;
}
function readUint16(bytes, offset, littleEndian) {
  if (offset + 2 > bytes.length) return 0;
  return littleEndian ? bytes[offset] | (bytes[offset + 1] << 8) : (bytes[offset] << 8) | bytes[offset + 1];
}
function readUint32(bytes, offset, littleEndian) {
  if (offset + 4 > bytes.length) return 0;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return view.getUint32(offset, littleEndian);
}

async function calculateSHA256(arrayBuffer) {
  return bytesToHex(await digestSha256(new Uint8Array(arrayBuffer)));
}
async function sha256Text(value) { return sha256Bytes(new TextEncoder().encode(value)); }
async function sha256Bytes(bytes) {
  return bytesToHex(await digestSha256(bytes));
}

async function digestSha256(value) {
  const bytes = value instanceof Uint8Array
    ? value
    : ArrayBuffer.isView(value)
      ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
      : new Uint8Array(value);
  try {
    if (globalThis.crypto?.subtle) {
      const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
      return new Uint8Array(digest);
    }
  } catch {
    // Fall through to the local implementation for file:// or restricted contexts.
  }
  return sha256Fallback(bytes);
}

function sha256Fallback(bytes) {
  const constants = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];
  const hash = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ];
  const bitLength = bytes.length * 8;
  const paddedLength = Math.ceil((bytes.length + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLength);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(paddedLength - 8, Math.floor(bitLength / 0x100000000), false);
  view.setUint32(paddedLength - 4, bitLength >>> 0, false);
  const words = new Uint32Array(64);
  const rotateRight = (value, amount) => (value >>> amount) | (value << (32 - amount));

  for (let offset = 0; offset < paddedLength; offset += 64) {
    for (let index = 0; index < 16; index += 1) words[index] = view.getUint32(offset + index * 4, false);
    for (let index = 16; index < 64; index += 1) {
      const first = words[index - 15];
      const second = words[index - 2];
      const sigma0 = rotateRight(first, 7) ^ rotateRight(first, 18) ^ (first >>> 3);
      const sigma1 = rotateRight(second, 17) ^ rotateRight(second, 19) ^ (second >>> 10);
      words[index] = (words[index - 16] + sigma0 + words[index - 7] + sigma1) >>> 0;
    }

    let [a, b, c, d, e, f, g, h] = hash;
    for (let index = 0; index < 64; index += 1) {
      const bigSigma1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
      const choice = (e & f) ^ (~e & g);
      const temp1 = (h + bigSigma1 + choice + constants[index] + words[index]) >>> 0;
      const bigSigma0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
      const majority = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (bigSigma0 + majority) >>> 0;
      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    hash[0] = (hash[0] + a) >>> 0;
    hash[1] = (hash[1] + b) >>> 0;
    hash[2] = (hash[2] + c) >>> 0;
    hash[3] = (hash[3] + d) >>> 0;
    hash[4] = (hash[4] + e) >>> 0;
    hash[5] = (hash[5] + f) >>> 0;
    hash[6] = (hash[6] + g) >>> 0;
    hash[7] = (hash[7] + h) >>> 0;
  }

  const output = new Uint8Array(32);
  const outputView = new DataView(output.buffer);
  hash.forEach((value, index) => outputView.setUint32(index * 4, value, false));
  return output;
}

function formatFileSize(bytes) {
  if (bytes === 0) return "0 Bytes";
  const units = ["Bytes", "KB", "MB", "GB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** index).toFixed(2)} ${units[index]}`;
}
function getExtension(filename) { const index = filename.lastIndexOf("."); return index > 0 ? filename.slice(index).toLowerCase() : ""; }
function guessMimeFromName(name) {
  const extension = getExtension(name);
  return ({ ".txt": "text/plain", ".json": "application/json", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".pdf": "application/pdf", ".zip": "application/zip" })[extension] || "application/octet-stream";
}
function sanitizeFilename(filename) { return filename.replace(/[^a-z0-9._-]+/gi, "_"); }
function slugify(value) { return value.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, ""); }
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" })[character]);
}

async function copyText(value) {
  try { await navigator.clipboard.writeText(value); showToast("Copied to clipboard."); }
  catch { showToast("Clipboard access was blocked."); }
}
function downloadBytes(filename, bytes) {
  const blob = new Blob([bytes], { type: "application/octet-stream" });
  downloadBlob(filename, blob);
}
function downloadTextFile(filename, content, type = "text/plain") { downloadBlob(filename, new Blob([content], { type: `${type};charset=utf-8` })); }
function downloadBlob(filename, blob) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

let toastTimer = null;
function showToast(message) {
  elements.toast.textContent = message;
  elements.toast.classList.add("visible");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => elements.toast.classList.remove("visible"), 2600);
}
