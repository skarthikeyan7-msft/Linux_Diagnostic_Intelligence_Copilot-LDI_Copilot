// Linux Diagnostic Intelligence Copilot - LDI Copilot frontend
// Vanilla JS, no build step, no external CDN dependencies (including the
// markdown renderer below) - this app is designed to work fully offline,
// consistent with the Ollama local-model option.
"use strict";

const state = {
  selectedFile: null,
  jobId: null,
  pollTimer: null,
  jobResult: null,   // {summary, digest, findings, timeline, facts}
  providers: {},
  savedAiSettings: null,
  autoSynthesizeNext: false, // set true right before submitting a fresh analysis; consumed (and reset) the next time results load
  analyzing: false,  // true only while a job is actively in flight (right now) - not used for the Analyzing tab's own visibility, see hasProgressContent
  hasProgressContent: false, // true once there is a progress log worth showing (set on starting OR loading any job); stays true across navigating away to Results and back - only a fresh "Run analysis"/"Start a new analysis" clears it, so the completed run's log remains visible until a genuinely new analysis begins
  activeMainTab: "upload",
  terminalProgressCount: 0, // number of progress lines already mirrored into the activity terminal for the current job
  ollamaLogCount: 0,        // same idea, for Ollama's own subprocess log lines
  ollamaPollTimer: null,
  sarData: null,   // raw /api/jobs/:id/sar_series payload for the currently loaded job - kept client-side so the time-range picker can re-render charts instantly without re-fetching
  sarRange: { from: null, to: null }, // epoch-ms bounds (null = unbounded) currently applied to the Performance charts
};

const $ = (id) => document.getElementById(id);

// --------------------------------------------------------------------------
// Tiny dependency-free Markdown -> HTML renderer (subset: headers, bold,
// italic, inline code, fenced code blocks, lists, tables, blockquotes,
// links, hr). Covers everything digest.md / the AI report actually emit.
// --------------------------------------------------------------------------
function escapeHtml(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function renderInline(text) {
  let t = escapeHtml(text);
  t = t.replace(/`([^`]+)`/g, "<code>$1</code>");
  t = t.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  t = t.replace(/(^|[\s(])\*([^*\s][^*]*?)\*(?=[\s).,;:!?]|$)/g, "$1<em>$2</em>");
  t = t.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
  return t;
}

function markdownToHtml(md) {
  const lines = (md || "").replace(/\r\n/g, "\n").split("\n");
  const out = [];
  let i = 0;
  let inList = null; // 'ul' | 'ol' | null

  function closeList() {
    if (inList) { out.push(`</${inList}>`); inList = null; }
  }

  while (i < lines.length) {
    const line = lines[i];

    // Fenced code block
    if (/^```/.test(line)) {
      closeList();
      const codeLines = [];
      i++;
      while (i < lines.length && !/^```/.test(lines[i])) { codeLines.push(lines[i]); i++; }
      i++; // skip closing fence
      out.push(`<pre><code>${escapeHtml(codeLines.join("\n"))}</code></pre>`);
      continue;
    }

    // Headers
    let m = line.match(/^(#{1,6})\s+(.*)$/);
    if (m) {
      closeList();
      const level = m[1].length;
      out.push(`<h${level}>${renderInline(m[2])}</h${level}>`);
      i++;
      continue;
    }

    // Horizontal rule
    if (/^(---+|\*\*\*+)\s*$/.test(line) && !/^\|/.test(lines[i + 1] || "")) {
      closeList();
      out.push("<hr>");
      i++;
      continue;
    }

    // Table: header row + separator row (|---|---|)
    if (/^\|.*\|\s*$/.test(line) && /^\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)+\|?\s*$/.test(lines[i + 1] || "")) {
      closeList();
      const headerCells = line.split("|").slice(1, -1).map((c) => c.trim());
      out.push("<table><thead><tr>" + headerCells.map((c) => `<th>${renderInline(c)}</th>`).join("") + "</tr></thead><tbody>");
      i += 2;
      while (i < lines.length && /^\|.*\|\s*$/.test(lines[i])) {
        const cells = lines[i].split("|").slice(1, -1).map((c) => c.trim());
        out.push("<tr>" + cells.map((c) => `<td>${renderInline(c)}</td>`).join("") + "</tr>");
        i++;
      }
      out.push("</tbody></table>");
      continue;
    }

    // Blockquote
    if (/^>\s?/.test(line)) {
      closeList();
      const quoteLines = [];
      while (i < lines.length && /^>\s?/.test(lines[i])) { quoteLines.push(lines[i].replace(/^>\s?/, "")); i++; }
      out.push(`<blockquote>${renderInline(quoteLines.join(" "))}</blockquote>`);
      continue;
    }

    // Unordered list item
    m = line.match(/^(\s*)[-*]\s+(.*)$/);
    if (m) {
      if (inList !== "ul") { closeList(); out.push("<ul>"); inList = "ul"; }
      out.push(`<li>${renderInline(m[2])}</li>`);
      i++;
      continue;
    }

    // Ordered list item
    m = line.match(/^(\s*)\d+\.\s+(.*)$/);
    if (m) {
      if (inList !== "ol") { closeList(); out.push("<ol>"); inList = "ol"; }
      out.push(`<li>${renderInline(m[2])}</li>`);
      i++;
      continue;
    }

    // Blank line
    if (line.trim() === "") { closeList(); i++; continue; }

    // Paragraph (collect contiguous plain lines)
    closeList();
    const paraLines = [line];
    i++;
    while (i < lines.length && lines[i].trim() !== "" && !/^(#{1,6})\s|^```|^\||^>|^(\s*)[-*]\s|^(\s*)\d+\.\s|^(---+|\*\*\*+)\s*$/.test(lines[i])) {
      paraLines.push(lines[i]);
      i++;
    }
    out.push(`<p>${renderInline(paraLines.join(" "))}</p>`);
  }
  closeList();
  return out.join("\n");
}

// --------------------------------------------------------------------------
// Top-level tabs: Provide Bundle / Analyzing / Results are always visible
// and clickable - not a forced linear wizard. The focus + AI config panel
// lives permanently in the Provide Bundle tab's DOM and is never moved;
// hidden (display:none) tabs stay fully queryable via getElementById, so
// starting a second analysis from Step 1 never hits stale/null field
// references the way physically relocating the panel would. Submitting
// an analysis / finishing one still auto-advances the active tab for a
// guided feel, but the user can always click back and forth manually.
// --------------------------------------------------------------------------
function activateMainTab(tabName) {
  document.querySelectorAll(".main-tab-btn").forEach((b) => b.classList.toggle("active", b.dataset.mainTab === tabName));
  $("uploadSection").classList.toggle("hidden", tabName !== "upload");
  $("progressSection").classList.toggle("hidden", tabName !== "progress");
  $("resultsSection").classList.toggle("hidden", tabName !== "results");
  state.activeMainTab = tabName;
  updatePlaceholders();
}

function updatePlaceholders() {
  $("progressPlaceholder").classList.toggle("hidden", state.hasProgressContent);
  $("progressContent").classList.toggle("hidden", !state.hasProgressContent);
  $("resultsPlaceholder").classList.toggle("hidden", !!state.jobResult);
  $("resultsContent").classList.toggle("hidden", !state.jobResult);
}

function initMainTabs() {
  document.querySelectorAll(".main-tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => activateMainTab(btn.dataset.mainTab));
  });
}

// --------------------------------------------------------------------------
// Activity terminal - a persistent, always-visible (regardless of which
// main tab is active) timestamped log of background progress across
// every stage: bundle selection, the mechanical scan's progress lines,
// AI synthesis start/streaming completion, downloads, and resets. This
// is deliberately separate from the Analyzing tab's own progress-log
// (which still shows full detail when you're specifically on that tab)
// - the terminal's job is cross-cutting visibility from anywhere.
// --------------------------------------------------------------------------
function logTerminal(message, level) {
  const body = $("terminalBody");
  if (!body) return;
  const time = new Date().toLocaleTimeString([], { hour12: false });
  const line = document.createElement("div");
  line.className = `term-line term-${level || "info"}`;
  line.innerHTML = `<span class="term-ts">[${escapeHtml(time)}]</span>${escapeHtml(message)}`;
  body.appendChild(line);
  body.scrollTop = body.scrollHeight;
}

function initTerminal() {
  logTerminal("LDI Copilot ready. Waiting for a diagnostic bundle…", "info");
  $("btnClearTerminal").addEventListener("click", () => {
    $("terminalBody").innerHTML = "";
    logTerminal("Terminal cleared.", "info");
  });
}

// --------------------------------------------------------------------------
// Small reusable confirm modal (used by the Ollama install-confirmation
// flow below; kept generic in case something else needs a confirm step
// later). Resolves true/false - never rejects, so callers can always
// `await` it directly without a try/catch just for the dialog itself.
// --------------------------------------------------------------------------
function showConfirmModal(title, body, confirmLabel) {
  return new Promise((resolve) => {
    const overlay = $("confirmModalOverlay");
    $("confirmModalTitle").textContent = title;
    $("confirmModalBody").textContent = body;
    const confirmBtn = $("confirmModalConfirm");
    const cancelBtn = $("confirmModalCancel");
    confirmBtn.textContent = confirmLabel || "Confirm";

    const cleanup = (result) => {
      overlay.classList.add("hidden");
      confirmBtn.removeEventListener("click", onConfirm);
      cancelBtn.removeEventListener("click", onCancel);
      overlay.removeEventListener("click", onOverlayClick);
      resolve(result);
    };
    const onConfirm = () => cleanup(true);
    const onCancel = () => cleanup(false);
    const onOverlayClick = (e) => { if (e.target === overlay) cleanup(false); };

    confirmBtn.addEventListener("click", onConfirm);
    cancelBtn.addEventListener("click", onCancel);
    overlay.addEventListener("click", onOverlayClick);
    overlay.classList.remove("hidden");
  });
}

// --------------------------------------------------------------------------
// Stop the whole server (topbar "⏹ Stop project" button) - the in-app
// equivalent of running stop.sh/stop.bat/stop.ps1. Always confirms first
// (this has no undo - any in-progress analysis is lost, and the page
// becomes unusable afterward) via the same themed modal used for the
// Ollama install flow above.
// --------------------------------------------------------------------------
async function stopProject() {
  const confirmed = await showConfirmModal(
    "Stop LDI Copilot?",
    "This shuts down the server process itself (and any Ollama instance it's managing) - not just this browser tab. Any analysis currently in progress will be lost. You'll need to restart it from a terminal (run.sh/run.bat/run.ps1) to use it again.",
    "Stop project",
  );
  if (!confirmed) return;

  logTerminal("⏹ Stopping the server…", "info");
  try {
    await fetch("/api/shutdown", { method: "POST" });
  } catch {
    // Expected: the connection drops mid-response as the process exits
    // right after sending it - not a failure from the user's point of
    // view, so this is deliberately swallowed rather than shown as an
    // error. Either way, show the "stopped" overlay below.
  }
  $("shutdownOverlay").classList.remove("hidden");
  if (state.ollamaPollTimer) clearInterval(state.ollamaPollTimer);
  if (state.pollTimer) clearInterval(state.pollTimer);
}

// --------------------------------------------------------------------------
// Ollama lifecycle control - the terminal's toolbar (status badge +
// Start/Stop/Refresh) gives direct manual control, and runSynthesis()
// calls ensureOllamaRunning() automatically whenever Ollama is the
// selected provider, so clicking "Generate log analysis" starts
// Ollama on demand if it isn't already up - no separate manual step
// needed. See backend/ai/ollama_manager.py for the server-side design
// (never spawns a duplicate instance; only stops one it started itself).
// --------------------------------------------------------------------------
function renderOllamaBadge(status) {
  const badge = $("ollamaStatusBadge");
  const labels = {
    unknown: "🦙 Ollama: checking…",
    stopped: "🦙 Ollama: stopped",
    starting: "🦙 Ollama: starting…",
    running: "🦙 Ollama: running",
    error: "🦙 Ollama: error",
  };
  const cls = status ? status.status : "unknown";
  badge.className = `ollama-status-badge status-${cls}`;
  badge.textContent = labels[cls] || labels.unknown;
  badge.title = status && status.error ? status.error : "";
  // Enable/disable based on whether Ollama is actually running/starting,
  // not on status.managed (whether THIS app happens to be the one that
  // spawned it). Stop is safe to offer either way - the backend already
  // no-ops with a clear reason if it isn't managed by this app (e.g. an
  // externally-running instance) instead of actually terminating it, so
  // disabling it outright here just hid that useful feedback and left
  // the control looking permanently broken.
  const isActive = cls === "running" || cls === "starting";
  $("btnStartOllama").disabled = isActive;
  $("btnStopOllama").disabled = !isActive;
}

function mirrorOllamaLogs(status) {
  if (!status || !status.log_lines) return;
  if (status.log_lines.length > state.ollamaLogCount) {
    status.log_lines.slice(state.ollamaLogCount).forEach((line) => logTerminal(`🦙 ${line}`, "info"));
    state.ollamaLogCount = status.log_lines.length;
  }
}

async function fetchOllamaStatus() {
  const resp = await fetch("/api/ollama/status");
  return resp.json();
}

async function refreshOllamaStatus() {
  const status = await fetchOllamaStatus();
  renderOllamaBadge(status);
  mirrorOllamaLogs(status);
  return status;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Used both by the manual "Start" button and automatically from
// runSynthesis()/chat/testConnectivity when Ollama is the selected
// provider. Resolves once Ollama is confirmed reachable; rejects with a
// human-readable message if it fails to start, times out, or the user
// declines an install prompt - callers must not proceed to an actual
// synthesis call in that case. `model` (optional) is whichever model
// the caller has selected - used only if Ollama turns out to need
// installing, so the model pulled afterward actually matches what the
// user is about to use instead of always defaulting to llama3.1.
async function ensureOllamaRunning(model) {
  let status = await refreshOllamaStatus();
  if (status.status === "running") return status;

  if (!status.installed) {
    const modelToPull = (model || "llama3.1").trim() || "llama3.1";
    const confirmed = await showConfirmModal(
      "Ollama isn't installed",
      `Ollama isn't installed on this machine yet. Install it now and pull the "${modelToPull}" model?\n\nThis runs Ollama's official installer, then downloads the model (can be several GB depending on which one) - it may take a few minutes on a slower connection. Progress will show in the activity terminal.`,
      "Install",
    );
    if (!confirmed) {
      throw new Error("Ollama installation was skipped. Pick a different AI provider, or click Start again to install it later.");
    }
    await installAndPullOllama(modelToPull);
    status = await refreshOllamaStatus();
    if (status.status === "running") return status;
    // Falls through to the normal start-and-poll flow below in the rare
    // case installAndPullOllama() finished but readiness hasn't caught
    // up to this exact instant yet.
  }

  logTerminal("🦙 Ollama isn't running yet — starting it now…", "info");
  await fetch("/api/ollama/start", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });

  const deadline = Date.now() + 65000; // a little past the backend's own ~60s readiness ceiling
  while (Date.now() < deadline) {
    await sleep(1000);
    status = await refreshOllamaStatus();
    if (status.status === "running") return status;
    if (status.status === "error") throw new Error(status.error || "Ollama failed to start.");
  }
  throw new Error("Timed out waiting for Ollama to start.");
}

// Streams backend/app.py's POST /api/ollama/install SSE response into
// the activity terminal live - the install + model pull together can
// take several minutes, so this gives real progress instead of a
// silent wait. Throws if the backend reports a final error; resolves
// (no return value) on success, with Ollama already started as part of
// the same server-side flow.
async function installAndPullOllama(model) {
  logTerminal(`🦙 Installing Ollama and pulling model "${model}"…`, "info");
  const resp = await fetch("/api/ollama/install", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model }),
  });
  if (!resp.ok || !resp.body) {
    const detail = await resp.json().catch(() => ({}));
    throw new Error(detail.detail || `Install request failed (HTTP ${resp.status})`);
  }
  const reader = resp.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let finalError = null;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const events = buffer.split("\n\n");
    buffer = events.pop(); // keep any incomplete trailing event
    for (const evt of events) {
      const line = evt.trim();
      if (!line.startsWith("data:")) continue;
      const parsed = JSON.parse(line.slice(5).trim());
      if (parsed.log) {
        logTerminal(`🦙 ${parsed.log}`, parsed.ok === false ? "error" : "info");
      }
      if (parsed.done && parsed.error) {
        finalError = parsed.error;
      }
    }
  }
  if (finalError) throw new Error(finalError);
}

async function startOllama() {
  $("btnStartOllama").disabled = true;
  try {
    const { payload } = collectAiPayload();
    const model = payload.provider === "ollama" ? payload.model : null;
    await ensureOllamaRunning(model);
    logTerminal("✅ Ollama is running.", "success");
  } catch (err) {
    logTerminal(`❌ ${err.message}`, "error");
  } finally {
    // Re-render from the real current status instead of blindly
    // re-enabling Start - otherwise Start stays clickable even after
    // Ollama is confirmed running, which is the bug this fixes.
    await refreshOllamaStatus();
  }
}

async function stopOllama() {
  $("btnStopOllama").disabled = true;
  try {
    const resp = await fetch("/api/ollama/stop", { method: "POST" });
    const result = await resp.json();
    if (result.stopped) {
      logTerminal("🛑 Ollama stopped.", "success");
    } else {
      logTerminal(`ℹ️ ${result.reason || "Ollama was not stopped."}`, "warn");
    }
  } catch (err) {
    logTerminal(`⚠ Failed to stop Ollama: ${err.message}`, "warn");
  }
  await refreshOllamaStatus();
}

function initOllamaControls() {
  $("btnStartOllama").addEventListener("click", startOllama);
  $("btnStopOllama").addEventListener("click", stopOllama);
  $("btnRefreshOllama").addEventListener("click", refreshOllamaStatus);
  refreshOllamaStatus();
  // Light periodic refresh so the badge/log stay accurate even if the
  // user starts/stops Ollama from outside this app (e.g. the desktop
  // tray icon) while this page is open.
  state.ollamaPollTimer = setInterval(refreshOllamaStatus, 15000);
}

// --------------------------------------------------------------------------
// Session-based auth (local accounts and/or Microsoft Entra ID SSO -
// backend/auth.py, backend/users.py, backend/entra_auth.py) - shows
// "signed in as <username>" (with a badge for HOW they signed in) + a
// logout link + an Audit Log link in the topbar when this instance has
// session-based auth active. A 401 from /api/auth/me is expected and
// silently ignored whenever session auth isn't in use (--auth-token/
// --no-auth/loopback), so this never shows anything misleading in those
// cases.
// --------------------------------------------------------------------------
async function initWhoami() {
  try {
    const resp = await fetch("/api/auth/me");
    if (!resp.ok) return;
    const data = await resp.json();
    const pill = $("whoamiPill");
    const methodLabel = data.auth_method === "entra" ? "Microsoft Entra ID" : "local account";
    pill.innerHTML = `👤 ${escapeHtml(data.username)} <span class="muted small" title="Signed in via ${escapeHtml(methodLabel)}">(${escapeHtml(methodLabel)})</span> <a id="btnAuditLog" href="/audit.html">Audit log</a> · <a id="btnLogout">Sign out</a>`;
    pill.classList.remove("hidden");
    document.getElementById("btnLogout").addEventListener("click", async () => {
      await fetch("/api/auth/logout", { method: "POST" });
      window.location.href = "/login.html";
    });
  } catch {
    // Network error or session auth not in use - nothing to show.
  }
}

// Fetches this machine's detected CPU/memory capacity (v4.9.1) so the
// "Parallel scanning workers" dropdown can show real, machine-specific
// context (e.g. flagging which numeric choices exceed this machine's own
// CPU core count) instead of listing bare numbers with no frame of
// reference for whether they're realistic.
async function initSystemInfo() {
  const note = $("workersCpuNote");
  try {
    const resp = await fetch("/api/system-info");
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const info = await resp.json();
    const cpu = info.cpu_count;
    note.textContent = `This machine reports ${cpu} logical CPU core(s)` + (info.available_memory_mb ? ` and ~${Math.round(info.available_memory_mb / 1024)} GB available memory` : "") + `. "Auto" would currently pick up to ${info.default_max_workers} worker(s) for a large-enough bundle.`;

    const select = $("optWorkers");
    Array.from(select.options).forEach((opt) => {
      const n = parseInt(opt.value, 10);
      if (!Number.isFinite(n) || n <= 1) return;
      if (n > cpu) {
        opt.textContent = `${n} (${Math.round((n / cpu) * 10) / 10}x this machine's ${cpu} cores — oversubscribed)`;
      } else if (n === cpu) {
        opt.textContent = `${n} (= this machine's core count)`;
      }
    });
  } catch {
    note.textContent = "Could not detect this machine's CPU core count - \"Auto\" still works, it just can't be previewed here.";
  }
}

// --------------------------------------------------------------------------
// Upload / dropzone
// --------------------------------------------------------------------------
function initDropzone() {
  const dz = $("dropzone");
  const fileInput = $("fileInput");

  const setFile = (file) => {
    state.selectedFile = file;
    $("serverPath").value = "";
    $("dropzoneFile").textContent = `${file.name} (${humanSize(file.size)})`;
    $("dropzoneFile").classList.remove("hidden");
    updateAnalyzeEnabled();
  };

  dz.addEventListener("click", (e) => { if (e.target.tagName !== "INPUT") fileInput.click(); });
  fileInput.addEventListener("change", () => { if (fileInput.files[0]) setFile(fileInput.files[0]); });

  ["dragenter", "dragover"].forEach((evt) =>
    dz.addEventListener(evt, (e) => { e.preventDefault(); dz.classList.add("dragover"); })
  );
  ["dragleave", "drop"].forEach((evt) =>
    dz.addEventListener(evt, (e) => { e.preventDefault(); dz.classList.remove("dragover"); })
  );
  dz.addEventListener("drop", (e) => {
    if (e.dataTransfer.files && e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]);
  });

  $("serverPath").addEventListener("input", () => {
    if ($("serverPath").value.trim()) {
      state.selectedFile = null;
      fileInput.value = "";
      $("dropzoneFile").classList.add("hidden");
    }
    updateAnalyzeEnabled();
  });
}

function updateAnalyzeEnabled() {
  $("btnAnalyze").disabled = !(state.selectedFile || $("serverPath").value.trim());
}

function humanSize(n) {
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(1)}${units[i]}`;
}

// --------------------------------------------------------------------------
// Scope mode (full / range / around)
// --------------------------------------------------------------------------
function initScopeToggle() {
  document.querySelectorAll('input[name="scopeMode"]').forEach((radio) => {
    radio.addEventListener("change", () => {
      $("scopeRangeFields").classList.toggle("hidden", radio.value !== "range" || !radio.checked);
      $("scopeAroundFields").classList.toggle("hidden", radio.value !== "around" || !radio.checked);
    });
  });
}

function getScopeMode() {
  return document.querySelector('input[name="scopeMode"]:checked').value;
}

// --------------------------------------------------------------------------
// Analyze flow
// --------------------------------------------------------------------------
async function startAnalysis() {
  const fd = new FormData();
  const bundleLabel = state.selectedFile ? state.selectedFile.name : $("serverPath").value.trim();
  if (state.selectedFile) fd.append("file", state.selectedFile);
  else fd.append("server_path", bundleLabel);

  const focusText = $("focusInput").value.trim();
  fd.append("focus", focusText);
  fd.append("min_severity", $("optMinSeverity").value);
  fd.append("top_per_category", $("optTopPerCategory").value);
  // "" (Auto) is deliberately NOT appended at all - the backend's
  // workers Form field defaults to None (auto-detect) when omitted;
  // sending an empty string would fail FastAPI's int|None parsing.
  const workersVal = $("optWorkers").value;
  if (workersVal) fd.append("workers", workersVal);

  const checkedFocusAreas = Array.from(document.querySelectorAll(".focus-area-cb:checked")).map((cb) => cb.value);
  // Always sent explicitly (even "all checked", even "" if the user
  // unchecked everything) so the backend can tell "user didn't touch
  // this control" (field absent - default to everything) apart from
  // "user deliberately unchecked everything" (empty string - show
  // nothing) without any ambiguity.
  fd.append("focus_areas", checkedFocusAreas.join(","));

  const pcapFile = $("pcapInput").files[0];
  if (pcapFile) {
    fd.append("pcap_file", pcapFile);
    logTerminal(`🌐 Attaching packet capture: ${pcapFile.name} (metadata-only analysis)`, "info");
  }

  const mode = getScopeMode();
  if (mode === "range") {
    if ($("optStart").value.trim()) fd.append("start", $("optStart").value.trim());
    if ($("optEnd").value.trim()) fd.append("end", $("optEnd").value.trim());
  } else if (mode === "around") {
    fd.append("around", $("optAround").value.trim());
    fd.append("window", $("optWindow").value);
  }

  // If AI settings are already filled in, automatically generate the
  // root-cause report as soon as the mechanical scan finishes - the
  // whole point of moving AI config into Step 1. Consumed (and reset)
  // the next time results load, so it never fires again for this job
  // and never fires when merely revisiting a "Recent analysis".
  state.autoSynthesizeNext = true;

  state.analyzing = true;
  state.hasProgressContent = true;
  state.terminalProgressCount = 0;
  activateMainTab("progress");
  $("progressError").classList.add("hidden");
  $("progressLog").innerHTML = "";

  logTerminal(`▶ Starting analysis: ${bundleLabel || "(no bundle specified)"}`, "info");
  logTerminal(focusText ? `🎯 Focus: ${focusText}` : "🎯 No focus specified - general full-bundle analysis", "info");

  let resp;
  try {
    resp = await fetch("/api/analyze", { method: "POST", body: fd });
  } catch (err) {
    showProgressError(`Network error: ${err.message}`);
    return;
  }
  if (!resp.ok) {
    const detail = await resp.json().catch(() => ({}));
    showProgressError(detail.detail || `Request failed (HTTP ${resp.status})`);
    return;
  }
  const data = await resp.json();
  state.jobId = data.job_id;
  pollJob();
}

function showProgressError(msg) {
  $("progressError").textContent = msg;
  $("progressError").classList.remove("hidden");
  state.analyzing = false;
  updatePlaceholders();
  logTerminal(`❌ ${msg}`, "error");
}

function pollJob() {
  clearInterval(state.pollTimer);
  state.pollTimer = setInterval(async () => {
    let resp;
    try {
      resp = await fetch(`/api/jobs/${state.jobId}`);
    } catch (err) {
      return; // transient network hiccup - keep polling
    }
    if (!resp.ok) return;
    const job = await resp.json();
    renderProgressLog(job.progress);
    if (job.progress.length > state.terminalProgressCount) {
      job.progress.slice(state.terminalProgressCount).forEach((line) => logTerminal(line, "info"));
      state.terminalProgressCount = job.progress.length;
    }
    if (job.status === "done") {
      clearInterval(state.pollTimer);
      await loadResults();
    } else if (job.status === "error") {
      clearInterval(state.pollTimer);
      showProgressError(job.error || "Analysis failed for an unknown reason.");
    }
  }, 800);
}

function renderProgressLog(lines) {
  const el = $("progressLog");
  el.innerHTML = lines.map((l) => `<div class="line">${escapeHtml(l)}</div>`).join("");
  el.scrollTop = el.scrollHeight;
}

async function loadResults(jobIdOverride) {
  const jobId = jobIdOverride || state.jobId;
  state.jobId = jobId;
  const [jobResp, digestResp, findingsResp, timelineResp, factsResp] = await Promise.all([
    fetch(`/api/jobs/${jobId}`),
    fetch(`/api/jobs/${jobId}/digest`),
    fetch(`/api/jobs/${jobId}/findings`),
    fetch(`/api/jobs/${jobId}/timeline`),
    fetch(`/api/jobs/${jobId}/facts`),
  ]);
  const job = await jobResp.json();
  const digest = await digestResp.text();
  const findings = await findingsResp.json();
  const timeline = await timelineResp.json();
  const facts = await factsResp.json();

  state.jobResult = { job, digest, findings, timeline, facts };

  const isFreshRun = state.autoSynthesizeNext;
  if (isFreshRun && job.summary) {
    logTerminal(`✅ Analysis complete — ${job.summary.num_findings} findings, ${job.summary.num_files} files, ${job.summary.elapsed_seconds.toFixed(1)}s`, "success");
  } else {
    logTerminal(`📂 Loaded results for job ${jobId}`, "info");
  }

  state.analyzing = false;
  // The Analyzing tab's progress log stays populated with this job's
  // history from here on - navigating away to Results (below) and back
  // to "2. Analyzing" must keep showing it, not revert to the "no
  // analysis running" placeholder, until a genuinely new analysis starts
  // (startAnalysis()) or the user explicitly resets (resetToUpload()).
  // Also covers picking a job from "Recent analyses", which never goes
  // through the live polling loop that would otherwise populate this.
  state.hasProgressContent = true;
  renderProgressLog(job.progress || []);
  activateMainTab("results");
  activateTab("ai"); // always land on the AI report for fresh results

  renderSummaryCards(job.summary, facts);
  renderFocusCallout(job.summary);
  renderClusterStatus(job.summary, facts);
  $("digestRender").innerHTML = markdownToHtml(digest);
  renderFindings(findings);
  renderTimeline(timeline);
  loadSarSeries(jobId);
  renderFactPanels(facts);

  // Reset AI tab for the (possibly new) job
  $("aiRender").innerHTML = "";
  $("aiError").classList.add("hidden");
  $("btnDownloadReport").classList.add("hidden");
  $("chatSection").classList.add("hidden");
  $("chatThread").innerHTML = "";
  renderRedactionCallout(null);
  const existingReport = await fetch(`/api/jobs/${jobId}/ai_report`).then((r) => r.text()).catch(() => "");
  if (existingReport) {
    $("aiRender").innerHTML = markdownToHtml(existingReport);
    $("btnDownloadReport").classList.remove("hidden");
    $("btnSynthesize").textContent = "Regenerate log analysis";
    $("chatSection").classList.remove("hidden");
    await restoreChatHistory(jobId);
    const existingRedaction = await fetch(`/api/jobs/${jobId}/redaction`).then((r) => r.json()).catch(() => null);
    renderRedactionCallout(existingRedaction);
  } else {
    $("btnSynthesize").textContent = "Generate log analysis";
  }

  // Auto-chain: if AI settings were filled in back in Step 1, kick off
  // synthesis automatically now that the mechanical scan is done -
  // this only fires once per fresh "Run analysis" submission, and never
  // when merely revisiting a Recent analysis that already has a report.
  if (state.autoSynthesizeNext) {
    state.autoSynthesizeNext = false;
    if (!existingReport) {
      const { missing } = collectAiPayload();
      if (missing.length === 0) {
        runSynthesis();
      }
    }
  }

  loadRecentJobs();
}

function renderSummaryCards(summary, facts) {
  if (!summary) { $("summaryCards").innerHTML = ""; return; }
  const cards = [
    { label: "Type", value: summary.kind },
    { label: "Files scanned", value: summary.num_files.toLocaleString() },
    { label: "Lines scanned", value: summary.num_lines.toLocaleString() },
    { label: "Findings", value: summary.num_findings.toLocaleString() },
    { label: "Duration", value: `${summary.elapsed_seconds.toFixed(1)}s` },
  ];
  const mem = facts.memory || {};
  if (mem.available_pct !== undefined && mem.available_pct !== null) {
    cards.push({ label: "Memory available", value: `${mem.available_pct}%` });
  }
  $("summaryCards").innerHTML = cards
    .map((c) => `<div class="summary-card"><div class="value">${escapeHtml(String(c.value))}</div><div class="label">${escapeHtml(c.label)}</div></div>`)
    .join("");
}

function renderFocusCallout(summary) {
  const el = $("focusCallout");
  const focus = summary && summary.focus;
  if (!focus || !focus.text) {
    el.classList.add("hidden");
    el.innerHTML = "";
    return;
  }
  const kwHtml = focus.keywords && focus.keywords.length
    ? ` &nbsp;·&nbsp; keywords: ${focus.keywords.map((k) => `<code>${escapeHtml(k)}</code>`).join(", ")}`
    : "";
  el.innerHTML = `🎯 <strong>Focused on:</strong> "${escapeHtml(focus.text)}" &nbsp;·&nbsp; ${focus.num_matching_findings} finding(s) matched${kwHtml}`;
  el.classList.remove("hidden");
}

// `data` is the {summary, legend} object emitted by the backend's
// synthesize() SSE stream (and persisted at GET /api/jobs/{id}/redaction) -
// or null/undefined when the most recent report used a local provider
// (Ollama) or had redaction turned off, in which case the callout hides.
// Renders the token->original mapping grouped by kind (hostnames/IPv4/
// IPv6/emails) inside a collapsible <details> so it doesn't dominate the
// page when there are many redacted values, matching the always-visible
// one-line summary engineers need at a glance plus the full mapping on
// demand.
function renderRedactionCallout(data) {
  const el = $("redactionCallout");
  const legend = data && data.legend;
  if (!legend || !legend.length) {
    el.classList.add("hidden");
    el.innerHTML = "";
    return;
  }
  const hosts = legend.filter((e) => e.token.startsWith("HOST-"));
  // IPv6/email prefixes must be checked BEFORE the plain "IP-" test below
  // (v4.9.1) - "IPV6-1" does not start with "IP-" (the "V" breaks the
  // match), so these are already mutually exclusive by construction, but
  // filtering ipv6/email first keeps this readable regardless.
  const ipv6s = legend.filter((e) => e.token.startsWith("IPV6-"));
  const emails = legend.filter((e) => e.token.startsWith("EMAIL-"));
  const ips = legend.filter((e) => e.token.startsWith("IP-"));
  const parts = [];
  if (hosts.length) parts.push(`${hosts.length} hostname(s)`);
  if (ips.length) parts.push(`${ips.length} IPv4 address(es)`);
  if (ipv6s.length) parts.push(`${ipv6s.length} IPv6 address(es)`);
  if (emails.length) parts.push(`${emails.length} email address(es)`);
  const renderGroup = (title, items) => (items.length
    ? `<div class="redaction-group"><h5>${escapeHtml(title)}</h5>${items.map((e) => `<code>${escapeHtml(e.token)}=${escapeHtml(e.original)}</code>`).join("")}</div>`
    : "");
  el.innerHTML = `
    <div class="redaction-summary">🔒 <strong>Redacted ${escapeHtml(parts.join(" and "))} before sending.</strong> Local-only mapping - never sent to the AI provider:</div>
    <details class="redaction-details">
      <summary>View mapping (${legend.length} value(s))</summary>
      <div class="redaction-columns">${renderGroup("Hostnames", hosts)}${renderGroup("IPv4 Addresses", ips)}${renderGroup("IPv6 Addresses", ipv6s)}${renderGroup("Email Addresses", emails)}</div>
    </details>`;
  el.classList.remove("hidden");
}

function renderClusterStatus(summary, facts) {
  const el = $("crmClusterStatus");
  if (!summary || summary.kind !== "crm_report" || !facts.cluster_health) {
    el.classList.add("hidden");
    return;
  }
  const ch = facts.cluster_health;
  const parts = [];
  if (ch.nodes_detected) parts.push(`<strong>Nodes:</strong> ${escapeHtml(ch.nodes_detected.join(", "))}`);
  if (ch.offline_or_unclean_nodes && ch.offline_or_unclean_nodes.length) {
    parts.push(`<strong>⚠ Offline/unclean:</strong> ${escapeHtml(ch.offline_or_unclean_nodes.join(", "))}`);
  }
  if (ch.failed_resource_actions_raw) parts.push(`<strong>⚠ Failed Resource Actions detected</strong> — see Findings tab`);
  if (!parts.length) { el.classList.add("hidden"); return; }
  el.innerHTML = parts.join(" &nbsp;·&nbsp; ");
  el.classList.remove("hidden");
}

// --------------------------------------------------------------------------
// Findings tab
// --------------------------------------------------------------------------
function renderFindings(findings) {
  const hasFocus = findings.some((f) => Object.prototype.hasOwnProperty.call(f, "focus_match"));
  $("findingsFocusOnlyRow").classList.toggle("hidden", !hasFocus);

  const byCat = {};
  for (const f of findings) {
    (byCat[f.category] = byCat[f.category] || []).push(f);
  }
  const sevRank = { CRITICAL: 3, ERROR: 2, WARNING: 1, INFO: 0 };
  const cats = Object.keys(byCat).sort((a, b) => {
    const maxA = Math.max(...byCat[a].map((f) => sevRank[f.severity] || 0));
    const maxB = Math.max(...byCat[b].map((f) => sevRank[f.severity] || 0));
    return maxB - maxA;
  });

  const renderList = (filterText) => {
    const ft = (filterText || "").toLowerCase();
    const focusOnly = hasFocus && $("findingsFocusOnly").checked;
    const html = cats
      .map((cat) => {
        const items = byCat[cat]
          .slice()
          .sort((a, b) => (sevRank[b.severity] || 0) - (sevRank[a.severity] || 0) || b.count - a.count)
          .filter((f) => !ft || cat.toLowerCase().includes(ft) || f.message.toLowerCase().includes(ft))
          .filter((f) => !focusOnly || f.focus_match);
        if (!items.length) return "";
        const rows = items
          .map(
            (f) => `<div class="finding-item ${f.focus_match ? "focus-match" : ""}">
              <div class="msg">${f.focus_match ? "🎯 " : ""}<span class="sev-badge sev-${f.severity}">${f.severity}</span> (${f.count}×) ${escapeHtml(f.message)}</div>
              ${f.examples.slice(0, 2).map((ex) => `<div class="ex">${escapeHtml(ex.file)}:${ex.line}</div>`).join("")}
            </div>`
          )
          .join("");
        return `<div class="finding-group"><div class="finding-cat-head"><span>${escapeHtml(cat)}</span><span class="muted">${items.length} shown</span></div>${rows}</div>`;
      })
      .join("");
    if (html) {
      $("findingsList").innerHTML = html;
    } else if (focusOnly) {
      $("findingsList").innerHTML = `<p class="muted">No findings matched your focus text${ft ? ` and filter "${escapeHtml(ft)}"` : ""}. Uncheck "Show only findings matching my focus" to see everything.</p>`;
    } else {
      $("findingsList").innerHTML = `<p class="muted">No findings match "${escapeHtml(ft)}".</p>`;
    }
  };

  renderList("");
  $("findingsFilter").oninput = (e) => renderList(e.target.value);
  $("findingsFocusOnly").onchange = () => renderList($("findingsFilter").value);
}

// --------------------------------------------------------------------------
// Timeline tab
// --------------------------------------------------------------------------
// Dedicated Results tabs for each of the 8 always-on analyzer categories
// (💥 Crash, 🥾 Boot, 🛡️ Security, 📦 Packages, 🔗 Cascade, 🐳 Containers,
// 🌐 Network - SAR/Performance has its own richer chart-based tab above).
// Every category runs unconditionally on every analysis (see
// backend/engine/analyzer_core.py's run_structured_checks()) - these
// panels exist purely to surface whatever it found (or didn't) directly
// in the UI, rather than only inside the Digest/AI report text. Each
// renderer shares the same "nothing found" fallback wording so it's
// never ambiguous whether an empty tab means "no problem detected" vs.
// "this broke."
// --------------------------------------------------------------------------
const NO_FACT_DATA_MSG = "No relevant data found from the sosreport or supportconfig.";

function factPanelEmpty(msg) {
  return `<p class="fact-panel-empty">${escapeHtml(msg || NO_FACT_DATA_MSG)}</p>`;
}

function factCard(title, bodyHtml) {
  return `<div class="fact-card"><h4>${escapeHtml(title)}</h4>${bodyHtml}</div>`;
}

function factKv(pairs) {
  const items = pairs.filter(([, v]) => v !== undefined && v !== null && v !== "");
  if (!items.length) return "";
  return `<div class="fact-kv">${items.map(([label, value]) => `<div class="kv-item"><div class="label">${escapeHtml(label)}</div><div class="value">${escapeHtml(String(value))}</div></div>`).join("")}</div>`;
}

function factTable(headers, rows) {
  if (!rows.length) return "";
  const thead = `<tr>${headers.map((h) => `<th>${escapeHtml(h)}</th>`).join("")}</tr>`;
  const tbody = rows.map((r) => `<tr>${r.map((c) => `<td>${escapeHtml(String(c ?? ""))}</td>`).join("")}</tr>`).join("");
  return `<table>${thead}${tbody}</table>`;
}

function factLink(url, label) {
  if (!url) return "";
  return `<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(label || url)}</a>`;
}

function renderCrashPanel(crash) {
  if (!crash || Object.keys(crash).length === 0) return factPanelEmpty();
  let html = "";
  if (crash.abrt_reports && crash.abrt_reports.length) {
    html += crash.abrt_reports.map((r) => factCard(
      `ABRT crash report — ${r.executable || r.dir}`,
      factKv([["Crash time", r.crash_time], ["Reason", r.reason], ["Command line", r.cmdline], ["UID", r.uid], ["Directory", r.dir]])
      + (r.backtrace ? `<pre>${escapeHtml(r.backtrace)}</pre>` : ""),
    )).join("");
  }
  if (crash.vmcore_files && crash.vmcore_files.length) {
    html += factCard("Kernel vmcore files", factTable(["Path", "Size"], crash.vmcore_files.map((v) => [v.path, v.size_human])));
  }
  if (crash.kdump_configured !== undefined) {
    html += factCard("kdump configuration", factKv([["Configured", crash.kdump_configured ? "Yes" : "No"], ["Path", crash.kdump_path]]));
  }
  if (crash.kernel_oops_signature_count) {
    html += factCard("Kernel oops/panic signatures", factKv([["Count found in dmesg/kernel log", crash.kernel_oops_signature_count]]));
  }
  return html || factPanelEmpty();
}

function renderBootPanel(boot) {
  if (!boot || Object.keys(boot).length === 0) return factPanelEmpty();
  let html = "";
  if (boot.startup_breakdown_raw || boot.total_boot_seconds !== undefined) {
    html += factCard("Startup breakdown", factKv([["Raw systemd-analyze output", boot.startup_breakdown_raw], ["Total boot time (s)", boot.total_boot_seconds]]));
  }
  if (boot.slowest_units && boot.slowest_units.length) {
    html += factCard("Slowest units", factTable(["Unit", "Seconds"], boot.slowest_units.map((u) => [u.unit, u.seconds])));
  }
  if (boot.critical_chain_raw) {
    html += factCard("Critical chain", `<pre>${escapeHtml(boot.critical_chain_raw)}</pre>`);
  }
  return html || factPanelEmpty();
}

function renderSecurityPanel(sec) {
  if (!sec || Object.keys(sec).length === 0) return factPanelEmpty();
  let html = "";
  if (sec.selinux_status || sec.selinux_mode) {
    html += factCard("SELinux status", factKv([["Status", sec.selinux_status], ["Mode", sec.selinux_mode]]));
  }
  if (sec.apparmor_profiles_enforce !== undefined || sec.apparmor_profiles_complain !== undefined) {
    html += factCard("AppArmor status", factKv([["Profiles in enforce mode", sec.apparmor_profiles_enforce], ["Profiles in complain mode", sec.apparmor_profiles_complain]]));
  }
  if (sec.selinux_top_denials && sec.selinux_top_denials.length) {
    html += factCard(`SELinux denials (${sec.selinux_denial_total} total)`, factTable(
      ["Source context", "Target context", "Class", "Count"],
      sec.selinux_top_denials.map((d) => [d.scontext, d.tcontext, d.tclass, d.count]),
    ));
  }
  if (sec.apparmor_top_denials && sec.apparmor_top_denials.length) {
    html += factCard(`AppArmor denials (${sec.apparmor_denial_total} total)`, factTable(
      ["Profile", "Operation", "Count"],
      sec.apparmor_top_denials.map((d) => [d.profile, d.operation, d.count]),
    ));
  }
  return html || factPanelEmpty();
}

function renderPackagesPanel(pkg) {
  if (!pkg || Object.keys(pkg).length === 0) return factPanelEmpty();
  let html = "";
  html += factCard("Package change summary", factKv([
    ["Total dated packages found", pkg.total_dated_packages],
    ["Most recent change", pkg.most_recent_change ? `${pkg.most_recent_change.package} (${pkg.most_recent_change.when})` : null],
    ["Changes in the 7 days before capture", pkg.recent_changes_7d_count],
  ]));
  if (pkg.recent_changes_7d && pkg.recent_changes_7d.length) {
    html += factCard("Changed in the 7 days before capture", factTable(
      ["Package", "When", "Action"],
      pkg.recent_changes_7d.map((c) => [c.package, c.when, c.action]),
    ));
  }
  return html || factPanelEmpty();
}

function renderCascadePanel(cascade) {
  if (!cascade || Object.keys(cascade).length === 0) return factPanelEmpty();
  let html = "";
  if (cascade.cascade_events_found) {
    html += factCard("Cascade events found", factKv([["Total dependency-failure/OnFailure/unit-failed events", cascade.cascade_events_found]]));
  }
  if (cascade.cascades && cascade.cascades.length) {
    html += cascade.cascades.map((c) => factCard(
      `Cascade: ${c.likely_trigger} → ${c.cascaded_units.length} unit(s)`,
      factKv([["Start", c.start_ts], ["End", c.end_ts], ["Likely trigger", c.likely_trigger]])
      + `<p class="muted small">Cascaded units: ${c.cascaded_units.map(escapeHtml).join(", ")}</p>`,
    )).join("");
  }
  if (cascade.dependency_failures_untimed && cascade.dependency_failures_untimed.length) {
    html += factCard("Dependency failures (no timestamp available)", `<p class="muted small">${cascade.dependency_failures_untimed.map(escapeHtml).join(", ")}</p>`);
  }
  return html || factPanelEmpty();
}

function renderContainersPanel(containers) {
  if (!containers || Object.keys(containers).length === 0) return factPanelEmpty();
  let html = "";
  if (containers.total_containers_seen) {
    html += factCard("Container summary", factKv([["Total containers seen", containers.total_containers_seen]]));
  }
  if (containers.exited_nonzero && containers.exited_nonzero.length) {
    html += factCard("Exited with non-zero code", factTable(
      ["Name", "Exit code", "Note"],
      containers.exited_nonzero.map((c) => [c.name, c.exit_code, c.note]),
    ));
  }
  if (containers.currently_restarting && containers.currently_restarting.length) {
    html += factCard("Currently restart-looping", factTable(
      ["Name", "Exit code"],
      containers.currently_restarting.map((c) => [c.name, c.exit_code]),
    ));
  }
  return html || factPanelEmpty();
}

function renderNetworkPanel(net) {
  if (!net || Object.keys(net).length === 0) {
    return factPanelEmpty("No relevant data found from the sosreport or supportconfig. (Network capture is not part of a standard sosreport/supportconfig bundle — attach a .pcap/.pcapng file in Step 1 to enable this analysis.)");
  }
  if (net.error) return factPanelEmpty(net.error);
  let html = factCard("Capture summary", factKv([
    ["Total packets", net.total_packets], ["Total bytes", net.total_bytes_human],
    ["Duration (s)", net.duration_seconds], ["Packets/sec", net.packets_per_second],
    ["Possible port-scan pattern", net.possible_port_scan_pattern ? "Yes — worth a look" : "No"],
  ]));
  if (net.protocol_counts) {
    html += factCard("Protocol mix", factTable(["Protocol", "Packets"], Object.entries(net.protocol_counts)));
  }
  if (net.top_talkers && net.top_talkers.length) {
    html += factCard("Top talkers", factTable(["Source", "Destination", "Bytes"], net.top_talkers.map((t) => [t.src, t.dst, t.bytes_human])));
  }
  html += factCard("TCP anomaly counts", factKv([
    ["SYN", net.tcp_syn], ["SYN-ACK", net.tcp_synack], ["RST", net.tcp_reset], ["Suspected retransmits", net.tcp_retransmits_suspected],
  ]));
  if (net.dns_top_queries && net.dns_top_queries.length) {
    html += factCard("Top DNS queries", factTable(["Query", "Count"], net.dns_top_queries.map((q) => [q.qname, q.count])));
  }
  return html;
}

function renderOsKnowledgePanel(osk) {
  if (!osk || Object.keys(osk).length === 0) {
    return factPanelEmpty("No relevant data found from the sosreport or supportconfig. (No OS-release identification file — /etc/os-release, /etc/redhat-release, or the supportconfig equivalent — could be found or parsed in this bundle.)");
  }
  const det = osk.detected || {};
  const links = [
    osk.docs_hub_link ? factLink(osk.docs_hub_link, "Official docs for this version") : "",
    osk.cve_search_link ? factLink(osk.cve_search_link, "Vendor security-advisory / CVE search") : "",
  ].filter(Boolean).join("  ·  ");
  let html = factCard("Detected OS", factKv([
    ["Name", det.pretty_name || det.name],
    ["Family", osk.family_label],
    ["Version", det.version],
    ["Identified from", osk.source_file],
  ]) + (osk.lifecycle_hint ? `<p class="muted small" style="margin-top:8px">🕒 ${escapeHtml(osk.lifecycle_hint)}</p>` : "")
    + (links ? `<p class="muted small">${links}</p>` : ""));

  if (osk.version_notes && osk.version_notes.length) {
    html += factCard("What's different about this major version (quick orientation, not exhaustive)", `<ul>${osk.version_notes.map((n) => `<li>${escapeHtml(n)}</li>`).join("")}</ul>`);
  }
  if (osk.known_issues && osk.known_issues.length) {
    html += osk.known_issues.map((ki) => factCard(
      `⚠️ ${ki.title}`,
      `<p>${escapeHtml(ki.detail)}</p>` + (ki.doc_link ? `<p class="muted small">${factLink(ki.doc_link, "Reference")}</p>` : ""),
    )).join("");
  }
  return html;
}

function renderConfigAnomaliesPanel(cfg) {
  if (!cfg || (!(cfg.anomalies || []).length && !(cfg.files_checked || []).length)) {
    return factPanelEmpty("No relevant data found from the sosreport or supportconfig. (None of the configuration files this project currently checks — sysctl, limits.conf, fstab, corosync.conf, multipath.conf, chrony/ntp.conf, resolv.conf, selinux config — were found in this bundle.)");
  }
  let html = "";
  if (cfg.anomalies && cfg.anomalies.length) {
    html += cfg.anomalies.map((a) => factCard(
      a.title,
      `<span class="sev-badge sev-${a.severity}">${escapeHtml(a.severity)}</span><span class="muted small">${escapeHtml(a.file)}</span>`
      + `<p style="margin-top:8px">${escapeHtml(a.detail)}</p>`
      + (a.doc_link ? `<p class="muted small">${factLink(a.doc_link, "Reference")}</p>` : ""),
    )).join("");
  } else {
    html += factCard("Result", `<p>✅ Checked ${cfg.files_checked.length} configuration file(s) present in this bundle — no anomalies found among the known-risky/known-inconsistent settings this project currently checks for.</p>`);
  }
  if (cfg.files_checked && cfg.files_checked.length) {
    html += factCard("Files checked", `<p class="muted small">${cfg.files_checked.map((f) => escapeHtml(f)).join(", ")}</p>`);
  }
  return html;
}

function renderFactPanels(facts) {
  $("factPanel-crash_analysis").innerHTML = renderCrashPanel(facts.crash_analysis);
  $("factPanel-boot_performance").innerHTML = renderBootPanel(facts.boot_performance);
  $("factPanel-security_mac").innerHTML = renderSecurityPanel(facts.security_mac);
  $("factPanel-package_drift").innerHTML = renderPackagesPanel(facts.package_drift);
  $("factPanel-systemd_cascade").innerHTML = renderCascadePanel(facts.systemd_cascade);
  $("factPanel-container_logs").innerHTML = renderContainersPanel(facts.container_logs);
  $("factPanel-network_capture").innerHTML = renderNetworkPanel(facts.network_capture);
  $("factPanel-os_knowledge").innerHTML = renderOsKnowledgePanel(facts.os_knowledge);
  $("factPanel-config_anomalies").innerHTML = renderConfigAnomaliesPanel(facts.config_anomalies);
}

// --------------------------------------------------------------------------
function renderTimeline(timeline) {
  if (!timeline.length) {
    $("timelineList").innerHTML = '<p class="muted">No dated CRITICAL/high-signal events were found to place on a timeline.</p>';
    return;
  }
  $("timelineList").innerHTML = timeline
    .map(
      (ev) => `<div class="timeline-item ${ev.focus_match ? "focus-match" : ""}">
        <div class="timeline-ts">${escapeHtml(ev.ts)} <span class="sev-badge sev-${ev.severity}">${ev.severity}</span> ${escapeHtml(ev.category)}${ev.focus_match ? " 🎯" : ""}</div>
        <div class="timeline-text">${escapeHtml(ev.text)}</div>
        <div class="timeline-file">${escapeHtml(ev.file)}:${ev.line}</div>
      </div>`
    )
    .join("");
}

// --------------------------------------------------------------------------
// Performance (SAR) sub-tab - dependency-free <canvas> line charts, one
// card per metric group. Consistent with the project's zero-external-
// dependency philosophy (own markdown renderer, own everything here too).
// --------------------------------------------------------------------------
const CHART_COLORS = ["#4da3ff", "#f2c94c", "#6fcf97", "#ff5470", "#bb86fc", "#ff8a4c"];

// Draws one or more named value-series (each an array of {ts, value})
// sharing a single time axis onto `canvas`, auto-scaling both axes.
// Optional `hoverT` (an x-axis timestamp) draws a crosshair + a marker dot
// on the nearest point of every series and returns that hover info so the
// caller (buildChartCard's mousemove handler) can render a text tooltip;
// omit it (or pass null) for a plain static draw. The computed axis layout
// is stashed on the canvas element itself so the mousemove handler can
// convert a raw pixel position back into a timestamp without redoing all
// the min/max/scale math on every mouse event.
function drawLineChart(canvas, namedSeries, hoverT) {
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  const w = Math.max(rect.width, 300);
  const h = Math.max(rect.height, 140);
  canvas.width = w * dpr;
  canvas.height = h * dpr;
  const ctx = canvas.getContext("2d");
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);

  const allPoints = namedSeries.flatMap((s) => s.points);
  if (!allPoints.length) {
    ctx.fillStyle = "#8b94a7";
    ctx.font = "12px sans-serif";
    ctx.fillText("No data points", 10, h / 2);
    canvas._chartLayout = null;
    return null;
  }
  const padL = 46, padR = 10, padT = 10, padB = 22;
  const plotW = w - padL - padR;
  const plotH = h - padT - padB;

  const xs = allPoints.map((p) => p.t);
  const ys = allPoints.map((p) => p.v);
  const xMin = Math.min(...xs), xMax = Math.max(...xs);
  let yMin = Math.min(0, ...ys), yMax = Math.max(...ys);
  if (yMax === yMin) yMax = yMin + 1;
  yMax += (yMax - yMin) * 0.08; // small headroom so the peak isn't flush against the top edge

  const xOf = (t) => padL + (xMax === xMin ? 0 : ((t - xMin) / (xMax - xMin)) * plotW);
  const yOf = (v) => padT + plotH - ((v - yMin) / (yMax - yMin)) * plotH;

  // Stashed so the mousemove handler in buildChartCard() can convert a raw
  // canvas-relative pixel position back into a timestamp/plot-area test
  // without duplicating this layout math (and without going stale, since
  // this is rewritten on every draw - including the tab-activation redraw
  // that fixes up charts first drawn while their tab was still hidden).
  canvas._chartLayout = { padL, padR, padT, padB, w, h, plotW, plotH, xMin, xMax, yMin, yMax };

  // Gridlines + y-axis labels (4 bands)
  ctx.strokeStyle = "#2a313f";
  ctx.fillStyle = "#8b94a7";
  ctx.font = "10.5px sans-serif";
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const v = yMin + ((yMax - yMin) * i) / 4;
    const y = yOf(v);
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(w - padR, y);
    ctx.stroke();
    ctx.fillText(v >= 100 ? v.toFixed(0) : v.toFixed(1), 2, y + 3);
  }
  // x-axis start/end time labels (VM-local wall clock, HH:MM)
  const fmtT = (t) => {
    const d = new Date(t);
    return `${String(d.getUTCHours()).padStart(2, "0")}:${String(d.getUTCMinutes()).padStart(2, "0")}`;
  };
  ctx.fillText(fmtT(xMin), padL, h - 6);
  ctx.fillText(fmtT(xMax), w - padR - 30, h - 6);

  namedSeries.forEach((s, idx) => {
    if (!s.points.length) return;
    ctx.strokeStyle = s.color || CHART_COLORS[idx % CHART_COLORS.length];
    ctx.lineWidth = 1.6;
    ctx.beginPath();
    s.points.forEach((p, i) => {
      const x = xOf(p.t), y = yOf(p.v);
      if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    });
    ctx.stroke();
  });

  if (hoverT == null) return null;

  // Hover pass: nearest point per series (by timestamp) gets a filled dot;
  // a dashed vertical crosshair marks the hovered x position. Returned so
  // the caller can render a text tooltip alongside it.
  const hoverInfo = { t: hoverT, x: xOf(hoverT), items: [] };
  namedSeries.forEach((s, idx) => {
    if (!s.points.length) return;
    let nearest = s.points[0];
    let bestDiff = Math.abs(nearest.t - hoverT);
    for (const p of s.points) {
      const diff = Math.abs(p.t - hoverT);
      if (diff < bestDiff) {
        bestDiff = diff;
        nearest = p;
      }
    }
    const color = s.color || CHART_COLORS[idx % CHART_COLORS.length];
    const mx = xOf(nearest.t), my = yOf(nearest.v);
    ctx.beginPath();
    ctx.arc(mx, my, 3.4, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.fill();
    ctx.beginPath();
    ctx.arc(mx, my, 3.4, 0, Math.PI * 2);
    ctx.strokeStyle = "#0e1117";
    ctx.lineWidth = 1;
    ctx.stroke();
    hoverInfo.items.push({ label: s.label, color, v: nearest.v, t: nearest.t });
  });
  ctx.save();
  ctx.setLineDash([3, 3]);
  ctx.strokeStyle = "#c7ccd6";
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(hoverInfo.x, padT);
  ctx.lineTo(hoverInfo.x, padT + plotH);
  ctx.stroke();
  ctx.restore();
  return hoverInfo;
}

// facts.json timestamps from the engine are naive VM-local wall-clock
// strings (e.g. "2026-07-10T14:10:01", no timezone suffix) - parsed here
// as if they were UTC purely so Date's internals give us a consistent,
// timezone-independent numeric axis to plot against; never displayed as
// "UTC" anywhere (labels always say "VM-local", per the detected zone
// note shown above the charts).
function seriesPoints(rows, valueKey, filter) {
  return rows
    .filter((r) => (filter ? filter(r) : true) && typeof r[valueKey] === "number")
    .map((r) => ({ t: Date.parse(r.ts.endsWith("Z") ? r.ts : r.ts + "Z"), v: r[valueKey] }))
    .filter((p) => Number.isFinite(p.t));
}

// Same as seriesPoints(), plus an optional client-side [fromMs, toMs]
// time-range clip (either bound may be null/undefined for "unbounded") -
// this is what lets the Performance tab's date/time range picker
// re-render already-fetched chart data instantly on every change,
// without a round-trip back to the server (the full series for the
// whole bundle was already downloaded once by loadSarSeries()).
function seriesPointsRanged(rows, valueKey, fromMs, toMs, filter) {
  return seriesPoints(rows, valueKey, filter).filter(
    (p) => (fromMs == null || p.t >= fromMs) && (toMs == null || p.t <= toMs)
  );
}

// Full HH:MM:SS (vs. the axis labels' HH:MM) for the hover tooltip's time
// line - same "treat as UTC" convention as drawLineChart's fmtT, so it
// matches the VM-local wall clock printed by `sar` on the analyzed host.
function fmtFullTime(t) {
  const d = new Date(t);
  return `${String(d.getUTCHours()).padStart(2, "0")}:${String(d.getUTCMinutes()).padStart(2, "0")}:${String(d.getUTCSeconds()).padStart(2, "0")}`;
}

// Rounds to 2 decimal places without forcing trailing zeros, so a hovered
// value reads "45.2" or "100" rather than "45.20"/"100.00".
function formatChartValue(v) {
  return Number.isFinite(v) ? String(Math.round(v * 100) / 100) : String(v);
}

function buildLegendHtml(namedSeries) {
  return namedSeries
    .map((s, i) => `<span><span class="swatch" style="background:${s.color || CHART_COLORS[i % CHART_COLORS.length]}"></span>${escapeHtml(s.label)}</span>`)
    .join("");
}

// Wires the shared hover-crosshair/tooltip behavior onto any chart
// canvas (a per-card canvas, or the single reusable modal canvas) - the
// series to draw is resolved lazily via getNamedSeries() rather than a
// fixed value, since the SAME modal canvas gets reused across many
// different charts over its lifetime (see openChartModal()). Returns
// hideHover so a caller can also invoke it directly (e.g. when closing
// the modal, to leave its canvas in a clean redrawn state next time).
function attachChartHover(canvas, tooltip, getNamedSeries) {
  const hideHover = () => {
    tooltip.classList.add("hidden");
    drawLineChart(canvas, getNamedSeries());
  };
  canvas.addEventListener("mousemove", (ev) => {
    const layout = canvas._chartLayout;
    if (!layout) return;
    const rect = canvas.getBoundingClientRect();
    const mx = ev.clientX - rect.left;
    const my = ev.clientY - rect.top;
    if (mx < layout.padL || mx > layout.w - layout.padR || layout.plotW <= 0) {
      hideHover();
      return;
    }
    const hoverT = layout.xMin + ((mx - layout.padL) / layout.plotW) * (layout.xMax - layout.xMin);
    const info = drawLineChart(canvas, getNamedSeries(), hoverT);
    if (!info || !info.items.length) {
      tooltip.classList.add("hidden");
      return;
    }
    tooltip.innerHTML =
      `<div class="tt-time">${fmtFullTime(info.items[0].t)}</div>` +
      info.items
        .map((it) => `<div class="tt-row"><span class="swatch" style="background:${it.color}"></span>${escapeHtml(it.label)}: <strong>${formatChartValue(it.v)}</strong></div>`)
        .join("");
    tooltip.classList.remove("hidden");
    // Position near the cursor, measured after the content above is set so
    // offsetWidth/Height reflect the tooltip's real rendered size; flips to
    // the left/below once it would overflow the canvas's right/top edge.
    const ttW = tooltip.offsetWidth, ttH = tooltip.offsetHeight;
    let left = mx + 14;
    if (left + ttW > layout.w) left = mx - ttW - 14;
    let top = my - ttH - 12;
    if (top < 0) top = my + 14;
    tooltip.style.left = `${Math.max(0, left)}px`;
    tooltip.style.top = `${Math.max(0, top)}px`;
  });
  canvas.addEventListener("mouseleave", hideHover);
  return hideHover;
}

// Opens the click-to-expand detail view (v4.11.0) for any chart card -
// same series, drawn much larger with the identical hover/tooltip
// behavior, for a closer look than a ~160px-tall grid card allows.
function openChartModal(title, statsText, namedSeries) {
  const overlay = $("chartModalOverlay");
  $("chartModalTitle").textContent = title;
  $("chartModalStats").textContent = statsText;
  $("chartModalLegend").innerHTML = buildLegendHtml(namedSeries);
  const canvas = $("chartModalCanvas");
  canvas._namedSeries = namedSeries;
  overlay.classList.remove("hidden");
  requestAnimationFrame(() => drawLineChart(canvas, namedSeries));
}

// One-time wiring for the single reusable chart-detail modal - hover
// behavior, close affordances (✕ button, click outside, Escape key),
// and a resize redraw since the modal's canvas width depends on
// viewport size like any other chart canvas.
function initChartModal() {
  const overlay = $("chartModalOverlay");
  const canvas = $("chartModalCanvas");
  const tooltip = $("chartModalTooltip");
  attachChartHover(canvas, tooltip, () => canvas._namedSeries || []);
  const close = () => {
    overlay.classList.add("hidden");
    canvas._namedSeries = null;
  };
  $("chartModalClose").addEventListener("click", close);
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) close();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !overlay.classList.contains("hidden")) close();
  });
  window.addEventListener("resize", () => {
    if (!overlay.classList.contains("hidden") && canvas._namedSeries) drawLineChart(canvas, canvas._namedSeries);
  });
}

function buildChartCard(title, statsText, namedSeries) {
  const card = document.createElement("div");
  card.className = "chart-card";
  const legend = buildLegendHtml(namedSeries);
  card.innerHTML =
    `<div class="chart-card-head"><h4>${escapeHtml(title)}</h4><button type="button" class="btn-expand-chart" title="Expand for a larger, more detailed view">⛶ Expand</button></div>` +
    `<div class="chart-stats">${escapeHtml(statsText)}</div><div class="chart-canvas-wrap"><canvas></canvas><div class="chart-tooltip hidden"></div></div><div class="chart-legend">${legend}</div>`;
  const canvas = card.querySelector("canvas");
  const tooltip = card.querySelector(".chart-tooltip");
  // Read back by activateTab()'s redraw-on-activate fix, since the very
  // first draw below can happen while the Performance tab (and therefore
  // this canvas's real width) is still hidden - see drawLineChart's comment.
  canvas._namedSeries = namedSeries;
  requestAnimationFrame(() => drawLineChart(canvas, namedSeries));
  attachChartHover(canvas, tooltip, () => namedSeries);
  card.querySelector(".btn-expand-chart").addEventListener("click", () => openChartModal(title, statsText, namedSeries));
  return card;
}

// --------------------------------------------------------------------------
// Performance (SAR) charts: per-metric-group card builders. Deliberately
// organized by table type (matching how `sar`'s own manpage documents
// each one) rather than one fully generic "chart every numeric column"
// pass - a real `sar -A` capture has ~40 distinct column names across
// CPU/memory/disk/network/load/swap/paging, and a naive dump of all of
// them would produce dozens of near-duplicate single-line charts with
// no organizing structure. Each builder takes the raw rows for its
// metric group plus the currently-applied [fromMs, toMs] range (either
// may be null for "unbounded") and returns an array of
// {title, stats, named} card specs - named being the namedSeries array
// buildChartCard()/openChartModal() already expect.
// --------------------------------------------------------------------------

function buildCpuCardSpecs(rows, fromMs, toMs) {
  const specs = [];
  const overall = rows.filter((r) => r.CPU === "all" || r.CPU === undefined);

  const used = overall.filter((r) => typeof r["%idle"] === "number").map((r) => ({ ts: r.ts, used: 100 - r["%idle"] }));
  const usedPts = seriesPointsRanged(used, "used", fromMs, toMs);
  if (usedPts.length) {
    specs.push({ title: "📊 CPU used - overall (%)", stats: `${usedPts.length} samples`, named: [{ label: "% used", points: usedPts, color: CHART_COLORS[0] }] });
  }

  // %usr/%sys/%iowait/%steal/%nice - sysstat's own CPU-time breakdown;
  // whichever of these columns this capture actually has (varies by
  // sysstat version/switches) is charted, others are simply absent.
  const breakdownCols = [["%usr", "user"], ["%sys", "system"], ["%iowait", "iowait"], ["%steal", "steal"], ["%nice", "nice"]];
  const breakdownNamed = breakdownCols
    .map(([col, label], i) => ({ label: `${label} (${col})`, points: seriesPointsRanged(overall, col, fromMs, toMs), color: CHART_COLORS[i % CHART_COLORS.length] }))
    .filter((s) => s.points.length);
  if (breakdownNamed.length) {
    specs.push({ title: "📊 CPU breakdown (%)", stats: `${overall.length} samples · ${breakdownNamed.length} component(s)`, named: breakdownNamed });
  }

  // Per-core rows only exist when the capture used `-P ALL` - one line
  // per logical CPU (up to however many the box has, e.g. 64 on a real
  // customer system) for the deepest possible view of core imbalance.
  const perCore = rows.filter((r) => r.CPU !== undefined && r.CPU !== "all");
  if (perCore.length) {
    const cores = Array.from(new Set(perCore.map((r) => r.CPU))).sort((a, b) => (Number(a) - Number(b)) || String(a).localeCompare(String(b)));
    const named = cores
      .map((core, i) => {
        const coreRows = perCore
          .filter((r) => r.CPU === core)
          .map((r) => ({ ts: r.ts, used: typeof r["%idle"] === "number" ? 100 - r["%idle"] : undefined }));
        return { label: `CPU${core}`, points: seriesPointsRanged(coreRows, "used", fromMs, toMs), color: CHART_COLORS[i % CHART_COLORS.length] };
      })
      .filter((s) => s.points.length);
    if (named.length) {
      specs.push({ title: `📊 CPU used by core (%)`, stats: `${named.length} core(s) - per-core (-P ALL) breakdown`, named });
    }
  }
  return specs;
}

function buildMemoryCardSpecs(rows, fromMs, toMs) {
  const specs = [];
  const pctPts = seriesPointsRanged(rows, "%memused", fromMs, toMs);
  if (pctPts.length) {
    specs.push({ title: "🧠 Memory used (%)", stats: `${pctPts.length} samples`, named: [{ label: "%memused", points: pctPts, color: CHART_COLORS[2] }] });
  }

  // kbmemused/kbcached/kbbuffers/kbcommit are printed in KB by sar;
  // divided by 1024 here so the chart reads in the friendlier MB unit
  // at real-world multi-GB scale.
  const mbCols = [["kbmemused", "used"], ["kbcached", "cached"], ["kbbuffers", "buffers"], ["kbcommit", "committed"]];
  const mbRows = rows.map((r) => {
    const out = { ts: r.ts };
    for (const [col] of mbCols) if (typeof r[col] === "number") out[col] = r[col] / 1024;
    return out;
  });
  const mbNamed = mbCols
    .map(([col, label], i) => ({ label: `${label} (MB)`, points: seriesPointsRanged(mbRows, col, fromMs, toMs), color: CHART_COLORS[i % CHART_COLORS.length] }))
    .filter((s) => s.points.length);
  if (mbNamed.length) {
    specs.push({ title: "🧠 Memory used / cached / buffers (MB)", stats: `${rows.length} samples`, named: mbNamed });
  }

  const commitPts = seriesPointsRanged(rows, "%commit", fromMs, toMs);
  if (commitPts.length) {
    specs.push({ title: "🧠 Memory commit (%)", stats: `${commitPts.length} samples`, named: [{ label: "%commit", points: commitPts, color: CHART_COLORS[4] }] });
  }
  return specs;
}

// sysstat has renamed disk throughput columns across major versions
// (bread/s+bwrtn/s -> rd_sec/s+wr_sec/s -> rkB/s+wkB/s) - see
// _SAR_HEADER_HINTS in analyzer_core.py for the same version-drift
// story on the analysis side. Tried in the order most-modern-first;
// whichever pair this capture actually has is what gets charted.
const _DISK_THROUGHPUT_COL_PAIRS = [["rkB/s", "wkB/s"], ["bread/s", "bwrtn/s"], ["rd_sec/s", "wr_sec/s"]];

function buildDiskCardSpecs(rows, fromMs, toMs) {
  const specs = [];
  const hasDev = rows.some((r) => r.DEV !== undefined);
  const throughputPair = _DISK_THROUGHPUT_COL_PAIRS.find(([r]) => rows.some((row) => typeof row[r] === "number"));

  if (hasDev) {
    const byDev = {};
    rows.forEach((r) => {
      if (r.DEV) (byDev[r.DEV] = byDev[r.DEV] || []).push(r);
    });
    // Generous cap - a real box rarely has more than a dozen block
    // devices worth separately charting; guards against a pathological
    // capture with hundreds of LVM/multipath sub-devices.
    const devs = Object.keys(byDev).slice(0, 12);
    const tpsNamed = devs
      .map((d, i) => ({ label: d, points: seriesPointsRanged(byDev[d], "tps", fromMs, toMs), color: CHART_COLORS[i % CHART_COLORS.length] }))
      .filter((s) => s.points.length);
    if (tpsNamed.length) {
      specs.push({ title: "💽 Disk transactions/sec (by device)", stats: `${devs.length} device(s)`, named: tpsNamed });
    }
    if (throughputPair) {
      const [readCol, writeCol] = throughputPair;
      const named = devs
        .flatMap((d, i) => [
          { label: `${d} read`, points: seriesPointsRanged(byDev[d], readCol, fromMs, toMs), color: CHART_COLORS[(i * 2) % CHART_COLORS.length] },
          { label: `${d} write`, points: seriesPointsRanged(byDev[d], writeCol, fromMs, toMs), color: CHART_COLORS[(i * 2 + 1) % CHART_COLORS.length] },
        ])
        .filter((s) => s.points.length);
      if (named.length) {
        specs.push({ title: `💽 Disk throughput (${readCol} / ${writeCol}, by device)`, stats: `${devs.length} device(s)`, named });
      }
    }
  } else {
    const tpsPts = seriesPointsRanged(rows, "tps", fromMs, toMs);
    if (tpsPts.length) {
      specs.push({ title: "💽 Disk transactions/sec", stats: `${tpsPts.length} samples`, named: [{ label: "tps", points: tpsPts, color: CHART_COLORS[1] }] });
    }
    if (throughputPair) {
      const [readCol, writeCol] = throughputPair;
      const named = [
        { label: readCol, points: seriesPointsRanged(rows, readCol, fromMs, toMs), color: CHART_COLORS[0] },
        { label: writeCol, points: seriesPointsRanged(rows, writeCol, fromMs, toMs), color: CHART_COLORS[3] },
      ].filter((s) => s.points.length);
      if (named.length) {
        specs.push({ title: `💽 Disk throughput (${readCol} / ${writeCol})`, stats: `${rows.length} samples`, named });
      }
    }
  }
  return specs;
}

function buildNetworkCardSpecs(rows, fromMs, toMs) {
  const specs = [];
  const byIface = {};
  rows.forEach((r) => {
    if (r.IFACE) (byIface[r.IFACE] = byIface[r.IFACE] || []).push(r);
  });
  const ifaces = Object.keys(byIface).slice(0, 10);
  const mk = (col, labelSuffix) =>
    ifaces
      .map((iface, i) => ({ label: `${iface} ${labelSuffix}`, points: seriesPointsRanged(byIface[iface], col, fromMs, toMs), color: CHART_COLORS[i % CHART_COLORS.length] }))
      .filter((s) => s.points.length);

  const rx = mk("rxkB/s", "rx");
  if (rx.length) specs.push({ title: "🌐 Network received (kB/s)", stats: `${ifaces.length} interface(s)`, named: rx });
  const tx = mk("txkB/s", "tx");
  if (tx.length) specs.push({ title: "🌐 Network transmitted (kB/s)", stats: `${ifaces.length} interface(s)`, named: tx });
  const pktNamed = [...mk("rxpck/s", "rx pkt/s"), ...mk("txpck/s", "tx pkt/s")];
  if (pktNamed.length) specs.push({ title: "🌐 Network packets/sec", stats: `${ifaces.length} interface(s)`, named: pktNamed });
  return specs;
}

function buildLoadCardSpecs(rows, fromMs, toMs) {
  const specs = [];
  const avgCols = [["ldavg-1", "1 min"], ["ldavg-5", "5 min"], ["ldavg-15", "15 min"]];
  const avgNamed = avgCols
    .map(([col, label], i) => ({ label, points: seriesPointsRanged(rows, col, fromMs, toMs), color: CHART_COLORS[i % CHART_COLORS.length] }))
    .filter((s) => s.points.length);
  if (avgNamed.length) specs.push({ title: "⚖️ Load average", stats: `${rows.length} samples`, named: avgNamed });

  const qCols = [["runq-sz", "run queue size"], ["plist-sz", "process count"]];
  const qNamed = qCols
    .map(([col, label], i) => ({ label, points: seriesPointsRanged(rows, col, fromMs, toMs), color: CHART_COLORS[(i + 3) % CHART_COLORS.length] }))
    .filter((s) => s.points.length);
  if (qNamed.length) specs.push({ title: "⚖️ Run queue / process count", stats: `${rows.length} samples`, named: qNamed });
  return specs;
}

function buildSwapCardSpecs(rows, fromMs, toMs) {
  const specs = [];
  const pctPts = seriesPointsRanged(rows, "%swpused", fromMs, toMs);
  if (pctPts.length) specs.push({ title: "💤 Swap used (%)", stats: `${pctPts.length} samples`, named: [{ label: "%swpused", points: pctPts, color: CHART_COLORS[5] }] });

  const mbCols = [["kbswpfree", "free"], ["kbswpused", "used"]];
  const mbRows = rows.map((r) => {
    const out = { ts: r.ts };
    for (const [col] of mbCols) if (typeof r[col] === "number") out[col] = r[col] / 1024;
    return out;
  });
  const mbNamed = mbCols
    .map(([col, label], i) => ({ label: `${label} (MB)`, points: seriesPointsRanged(mbRows, col, fromMs, toMs), color: CHART_COLORS[i % CHART_COLORS.length] }))
    .filter((s) => s.points.length);
  if (mbNamed.length) specs.push({ title: "💤 Swap free / used (MB)", stats: `${rows.length} samples`, named: mbNamed });
  return specs;
}

function buildPagingCardSpecs(rows, fromMs, toMs) {
  const specs = [];
  const cols = [["pgpgin/s", "page in"], ["pgpgout/s", "page out"], ["fault/s", "fault"], ["majflt/s", "major fault"]];
  const named = cols
    .map(([col, label], i) => ({ label, points: seriesPointsRanged(rows, col, fromMs, toMs), color: CHART_COLORS[i % CHART_COLORS.length] }))
    .filter((s) => s.points.length);
  if (named.length) specs.push({ title: "📄 Paging activity (per sec)", stats: `${rows.length} samples`, named });
  return specs;
}

// Order here drives the on-screen card order too - CPU/memory/disk first
// (the three an RCA investigation reaches for most), then network/load/
// swap/paging.
const SAR_GROUP_BUILDERS = [
  ["cpu", buildCpuCardSpecs],
  ["memory", buildMemoryCardSpecs],
  ["disk_io", buildDiskCardSpecs],
  ["network", buildNetworkCardSpecs],
  ["load", buildLoadCardSpecs],
  ["swap", buildSwapCardSpecs],
  ["paging", buildPagingCardSpecs],
];

// Scans every metric group's full (unfiltered) series for its overall
// min/max timestamp - used to pre-fill the range pickers with the
// bundle's actual captured span, and to restore that span on "Full
// range".
function computeSarTimeBounds(sar) {
  let min = Infinity, max = -Infinity;
  const series = sar.series || {};
  Object.values(series).forEach((rows) => {
    rows.forEach((r) => {
      const t = Date.parse(r.ts && r.ts.endsWith("Z") ? r.ts : `${r.ts}Z`);
      if (Number.isFinite(t)) {
        if (t < min) min = t;
        if (t > max) max = t;
      }
    });
  });
  return Number.isFinite(min) && Number.isFinite(max) ? { min, max } : null;
}

// datetime-local inputs have no timezone of their own - formatting with
// UTC getters (not local getters) keeps this consistent with the
// project-wide convention (see seriesPoints() above) of treating every
// VM-local wall-clock timestamp AS IF it were UTC purely for a stable,
// timezone-independent numeric axis.
function epochToLocalInputValue(t) {
  const d = new Date(t);
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}

// Inverse of epochToLocalInputValue() - parses a datetime-local input's
// value by hand (rather than `new Date(value)`, which would apply the
// BROWSER's own local timezone to a string with no offset) so a typed/
// picked range boundary lines up exactly with the same "treat as UTC"
// axis every chart point already uses.
function inputValueToEpoch(v) {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/.exec(v || "");
  if (!m) return null;
  const [, y, mo, d, h, mi, s] = m;
  return Date.UTC(+y, +mo - 1, +d, +h, +mi, +(s || 0));
}

// Pure render pass over the already-fetched state.sarData, filtered to
// state.sarRange - called on initial load AND every time the range
// picker changes, with no server round-trip (the full series was
// already downloaded once).
function renderPerfCharts() {
  const sar = state.sarData;
  if (!sar) return;
  const grid = $("chartGrid");
  grid.innerHTML = "";
  const series = sar.series || {};
  const { from, to } = state.sarRange || {};
  let cardCount = 0;
  for (const [group, builder] of SAR_GROUP_BUILDERS) {
    const rows = series[group];
    if (!rows || !rows.length) continue;
    for (const spec of builder(rows, from, to)) {
      grid.appendChild(buildChartCard(spec.title, spec.stats, spec.named));
      cardCount += 1;
    }
  }
  const note = $("perfRangeNote");
  if (!cardCount) {
    note.textContent = "No chart-able samples in the selected range — try \"Full range\".";
  } else if (from != null || to != null) {
    note.textContent = `Showing ${cardCount} chart(s) filtered to the selected range.`;
  } else {
    note.textContent = `Showing ${cardCount} chart(s) across the full captured range.`;
  }
}

// One-time wiring for the range-picker toolbar (Apply/Full/Zoom-to-peak)
// - called once from the DOMContentLoaded handler, not per job load;
// state.sarData/state.sarRange carry the per-job data these handlers
// act on.
function initPerfToolbar() {
  $("btnPerfRangeApply").addEventListener("click", () => {
    state.sarRange = { from: inputValueToEpoch($("perfRangeFrom").value), to: inputValueToEpoch($("perfRangeTo").value) };
    renderPerfCharts();
  });
  $("btnPerfRangeFull").addEventListener("click", () => {
    state.sarRange = { from: null, to: null };
    const bounds = state.sarData && computeSarTimeBounds(state.sarData);
    if (bounds) {
      $("perfRangeFrom").value = epochToLocalInputValue(bounds.min);
      $("perfRangeTo").value = epochToLocalInputValue(bounds.max);
    }
    renderPerfCharts();
  });
  $("btnPerfRangePeak").addEventListener("click", (ev) => {
    const peakTs = ev.currentTarget.dataset.peakTs;
    if (!peakTs) return;
    const t = Date.parse(peakTs.endsWith("Z") ? peakTs : `${peakTs}Z`);
    if (!Number.isFinite(t)) return;
    const pad = 30 * 60 * 1000; // ±30 minutes around the peak CPU sample
    state.sarRange = { from: t - pad, to: t + pad };
    $("perfRangeFrom").value = epochToLocalInputValue(t - pad);
    $("perfRangeTo").value = epochToLocalInputValue(t + pad);
    renderPerfCharts();
  });
}

async function loadSarSeries(jobId) {
  let sar = {};
  try {
    sar = await fetch(`/api/jobs/${jobId}/sar_series`).then((r) => r.json());
  } catch {
    sar = {};
  }
  state.sarData = sar;
  state.sarRange = { from: null, to: null };

  const groups = sar.metric_groups_found || [];
  if (!groups.length) {
    // no_samples_reason (v4.11.0) distinguishes "sar data was found and
    // read, but held nothing but a system-restart marker" (a real case -
    // a sysstat spool file captured moments after a fresh reboot) from
    // plain "no sar data in this bundle at all" - worth telling apart
    // rather than showing the same generic message either way.
    const ph = $("perfPlaceholder");
    if (sar.no_samples_reason) {
      ph.textContent = `ℹ️ ${sar.no_samples_reason}`;
    } else if (sar.restart_events && sar.restart_events.length) {
      ph.textContent = `No SAR performance charts to show, but sar/sadc directly recorded a system restart at ${sar.restart_events.join(", ")}.`;
    } else {
      ph.textContent = "No SAR performance data was found in this bundle (sysstat/sar wasn't captured, or this bundle predates the incident window). Everything else in this analysis is unaffected.";
    }
    ph.classList.remove("hidden");
    $("perfContent").classList.add("hidden");
    $("chartRangeToolbar").classList.add("hidden");
    return;
  }
  $("perfPlaceholder").classList.add("hidden");
  $("perfContent").classList.remove("hidden");
  $("chartRangeToolbar").classList.remove("hidden");

  const tz = sar.vm_timezone;
  $("perfTzNote").textContent = tz
    ? `🕒 Timestamps below are VM-local time (${tz.label}) - not your own timezone or the customer's, unless they happen to match.`
    : "🕒 The VM's timezone could not be determined - timestamps below are shown exactly as `sar` printed them on the analyzed host.";
  const s = sar.summary || {};
  const bits = [];
  if (s.cpu_pct_used_avg != null) bits.push(`CPU avg ${s.cpu_pct_used_avg}% / peak ${s.cpu_pct_used_peak}%`);
  if (s.mem_pct_used_avg != null) bits.push(`Mem avg ${s.mem_pct_used_avg}% / peak ${s.mem_pct_used_peak}%`);
  if (s.load1_avg != null) bits.push(`Load(1m) avg ${s.load1_avg} / peak ${s.load1_peak}`);
  if (s.disk_tps_avg != null) bits.push(`Disk avg ${s.disk_tps_avg} tps / peak ${s.disk_tps_peak} tps`);
  if (s.busiest_iface) bits.push(`Busiest NIC: ${s.busiest_iface} (${s.busiest_iface_rxkbps_avg} kB/s avg rx)`);
  $("perfSummaryNote").textContent = bits.join("  ·  ");

  // Un-rendered binary sadc spool siblings (v4.11.0) - real performance
  // data sadc already collected but couldn't be safely decoded (see
  // check_sar_performance()'s docstring in analyzer_core.py). Shown as
  // a standalone callout here (rather than folded into perfSummaryNote)
  // since it's actionable guidance, not just another stat.
  const spoolNote = $("perfBinarySpoolNote");
  if (sar.binary_only_spool_files && sar.binary_only_spool_files.length) {
    const files = sar.binary_only_spool_files;
    spoolNote.textContent = `ℹ️ ${files.length} additional raw sysstat binary spool file(s) found that couldn't be decoded directly (${files.slice(0, 3).join(", ")}${files.length > 3 ? ", ..." : ""}) - these hold real interval data sadc already collected. Ask for sar -A -f <file> or sadf -x -- -A -f <file> output from the original system to see it.`;
    spoolNote.classList.remove("hidden");
  } else {
    spoolNote.classList.add("hidden");
  }

  // Pre-fill the range pickers with the bundle's actual captured span,
  // so the user sees exactly what's available before narrowing it.
  const bounds = computeSarTimeBounds(sar);
  if (bounds) {
    $("perfRangeFrom").value = epochToLocalInputValue(bounds.min);
    $("perfRangeTo").value = epochToLocalInputValue(bounds.max);
  } else {
    $("perfRangeFrom").value = "";
    $("perfRangeTo").value = "";
  }

  const peakBtn = $("btnPerfRangePeak");
  const peakTs = s.cpu_pct_used_peak_ts;
  peakBtn.classList.toggle("hidden", !peakTs);
  peakBtn.dataset.peakTs = peakTs || "";

  renderPerfCharts();
}

// --------------------------------------------------------------------------
// Tabs
// --------------------------------------------------------------------------
function activateTab(tabName) {
  document.querySelectorAll(".tab-btn").forEach((b) => b.classList.toggle("active", b.dataset.tab === tabName));
  document.querySelectorAll(".tab-panel").forEach((p) => p.classList.toggle("hidden", p.id !== `tab-${tabName}`));
  if (tabName === "performance") {
    // Chart canvases are laid out at their container's real pixel width,
    // but the Performance tab starts hidden (display:none) - so the very
    // first draw (requestAnimationFrame at chart-card creation, before the
    // user has ever clicked here) can see a zero-width container and fall
    // back to a fixed 300px layout. Redraw now that the tab is genuinely
    // visible so both the rendered scale and the hover-tooltip's pixel<->
    // timestamp math (which depends on this same width) are accurate.
    document.querySelectorAll("#chartGrid canvas").forEach((c) => {
      if (c._namedSeries) drawLineChart(c, c._namedSeries);
    });
  }
}

function initTabs() {
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => activateTab(btn.dataset.tab));
  });
}

// --------------------------------------------------------------------------
// AI provider config + synthesis (SSE via fetch, since EventSource can't POST)
// --------------------------------------------------------------------------
// Renamed from "sosreport-rca-ai-settings" for the v2.0.0 rebrand + the
// auth_type restructuring - old localStorage entries under the previous
// key used a different (pre-auth_type) shape and are intentionally left
// orphaned rather than migrated, to avoid loading stale/incompatible
// saved settings under the new schema.
const AI_SETTINGS_KEY = "ldi-copilot-ai-settings";

async function initAiProviders() {
  const resp = await fetch("/api/providers");
  state.providers = await resp.json();
  const sel = $("aiProvider");
  sel.innerHTML = Object.entries(state.providers)
    .map(([key, p]) => `<option value="${key}">${escapeHtml(p.label)}${p.local ? " 🔒" : ""}</option>`)
    .join("");
  sel.addEventListener("change", () => renderAuthTypeSelector(sel.value));
  $("aiAuthType").addEventListener("change", () => renderAiFields(sel.value, $("aiAuthType").value));

  state.savedAiSettings = loadAiSettings();
  if (state.savedAiSettings && state.savedAiSettings.provider && state.providers[state.savedAiSettings.provider]) {
    sel.value = state.savedAiSettings.provider;
  } else if (state.providers.ollama) {
    // Ollama is the recommended default: fully offline, safest choice
    // for customer diagnostic data, and nothing to configure besides
    // picking a model - explicit rather than relying on dict/option
    // order alone.
    sel.value = "ollama";
  }
  renderAuthTypeSelector(sel.value);
}

function updateConfidentialityUI(providerKey) {
  const p = state.providers[providerKey];
  const isLocal = !!(p && p.local);
  $("confidentialityPanel").classList.toggle("hidden", isLocal);
  $("ollamaPrivacyNote").classList.toggle("hidden", !isLocal);
  if (!isLocal && p) {
    $("confidentialityProviderName").textContent = p.label.replace(/\s*—.*$/, "");
  }
}

function fieldLabel(field) {
  const labels = {
    api_key: "API key", model: "Model", endpoint: "Endpoint URL",
    deployment: "Deployment name", base_url: "Base URL",
    tenant_id: "Directory (tenant) ID", client_id: "Application (client) ID",
    client_secret: "Client secret",
  };
  return labels[field] || field;
}

// Azure OpenAI is the only provider with more than one auth_types entry
// today (API Key vs. Microsoft Entra ID) - the dropdown only shows up
// for providers where there's an actual choice to make; providers with
// exactly one auth_type still work correctly since a single <option>
// is auto-selected as the <select>'s value even while its row is hidden.
function renderAuthTypeSelector(providerKey) {
  const p = state.providers[providerKey];
  if (!p) return;
  const saved = state.savedAiSettings;
  const authTypes = Object.entries(p.auth_types);
  const sel = $("aiAuthType");
  sel.innerHTML = authTypes.map(([key, cfg]) => `<option value="${key}">${escapeHtml(cfg.label)}</option>`).join("");
  $("authTypeRow").classList.toggle("hidden", authTypes.length <= 1);
  const wanted = (saved && saved.provider === providerKey && saved.auth_type) || p.default_auth_type;
  if (authTypes.some(([key]) => key === wanted)) sel.value = wanted;
  updateConfidentialityUI(providerKey);
  renderAiFields(providerKey, sel.value);
}

function renderAiFields(providerKey, authType) {
  const p = state.providers[providerKey];
  if (!p) return;
  const authCfg = p.auth_types[authType] || p.auth_types[p.default_auth_type];
  const saved = state.savedAiSettings || {};
  const sameSaved = saved.provider === providerKey && saved.auth_type === authType ? saved : {};

  $("aiFields").innerHTML = authCfg.fields.map((f) => renderAiFieldHtml(f, p, sameSaved)).join("");

  // Only fields named "model" with a curated known_models list get the
  // dropdown + "Check available models" treatment (Azure OpenAI's
  // "deployment" field is user-defined and stays plain text).
  if (authCfg.fields.includes("model") && p.known_models && p.known_models.length) {
    wireModelSelect(providerKey);
  }
}

function renderAiFieldHtml(f, p, saved) {
  if (f === "model" && p.known_models && p.known_models.length) {
    return renderModelFieldHtml(p, saved);
  }
  const isSecret = f === "api_key" || f === "client_secret";
  const value = saved[f] || (f === "base_url" ? p.default_base_url || "" : "");
  return `<div class="field-row">
    <label for="ai_${f}">${fieldLabel(f)}</label>
    <input type="${isSecret ? "password" : "text"}" id="ai_${f}" value="${escapeHtml(String(value))}">
  </div>`;
}

// Model field: a <select> of curated known models (from PROVIDERS[..].known_models)
// plus a "Custom / other model…" fallback (curated lists can't be
// exhaustive, and new models ship often). "Check available models"
// queries /api/models with the credentials currently filled in and
// disables (greys out, via the native disabled attribute) any known
// option the live check didn't confirm - see checkModelAvailability().
function renderModelFieldHtml(p, saved) {
  const savedModel = saved.model || "";
  const isCustom = !!savedModel && !p.known_models.includes(savedModel);
  const selected = savedModel || p.default_model;
  const options = p.known_models
    .map((m) => `<option value="${escapeHtml(m)}" ${!isCustom && m === selected ? "selected" : ""}>${escapeHtml(m)}</option>`)
    .join("");
  return `<div class="field-row">
    <label for="ai_model">Model <span class="muted small">(${escapeHtml(p.model_hint || "")})</span></label>
    <select id="ai_model">
      ${options}
      <option value="__custom__" ${isCustom ? "selected" : ""}>Custom / other model…</option>
    </select>
    <div class="field-row ${isCustom ? "" : "hidden"}" id="aiModelCustomRow" style="margin-top:6px;">
      <input type="text" id="ai_model_custom" placeholder="Enter exact model name" value="${isCustom ? escapeHtml(savedModel) : ""}">
    </div>
    <div class="model-check-row">
      <button type="button" id="btnCheckModels" class="btn btn-ghost btn-sm">🔎 Check available models</button>
      <span id="modelCheckStatus" class="muted small"></span>
    </div>
  </div>`;
}

function wireModelSelect(providerKey) {
  const sel = $("ai_model");
  if (!sel) return;
  sel.addEventListener("change", () => {
    $("aiModelCustomRow").classList.toggle("hidden", sel.value !== "__custom__");
  });
  const btn = $("btnCheckModels");
  if (btn) btn.addEventListener("click", () => checkModelAvailability(providerKey));
}

// Reads a field's current value, routing "model" through the
// select/custom-input pair instead of a plain ai_model text box.
function getFieldValue(f) {
  if (f === "model") {
    const sel = $("ai_model");
    if (!sel) return "";
    if (sel.value === "__custom__") {
      const custom = $("ai_model_custom");
      return custom ? custom.value.trim() : "";
    }
    return sel.value;
  }
  const el = $(`ai_${f}`);
  return el ? el.value.trim() : "";
}

async function checkModelAvailability(providerKey) {
  const p = state.providers[providerKey];
  if (!p) return;
  const authType = $("aiAuthType").value;
  const authCfg = p.auth_types[authType] || p.auth_types[p.default_auth_type];
  const payload = { provider: providerKey };
  authCfg.fields.forEach((f) => {
    if (f !== "model") payload[f] = getFieldValue(f);
  });

  const statusEl = $("modelCheckStatus");
  statusEl.textContent = "Checking…";
  logTerminal(`🔎 Checking available models for ${p.label}…`, "info");
  try {
    const resp = await fetch("/api/models", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();
    const sel = $("ai_model");
    if (data.available && sel) {
      let disabledCount = 0;
      Array.from(sel.options).forEach((opt) => {
        if (opt.value === "__custom__") return;
        const isAvailable = data.available.includes(opt.value);
        opt.disabled = !isAvailable;
        if (!isAvailable) disabledCount++;
      });
      const selectedDisabled = sel.selectedOptions[0] && sel.selectedOptions[0].disabled;
      statusEl.textContent = `✅ ${data.available.length} model(s) confirmed available` + (selectedDisabled ? " — ⚠ your current selection may be unavailable" : "");
      logTerminal(`✅ ${p.label}: ${data.available.length} model(s) available${disabledCount ? `, ${disabledCount} known model(s) greyed out` : ""}`, "success");
    } else {
      statusEl.textContent = `⚠ ${data.error || "Could not verify - showing known models"}`;
      logTerminal(`⚠ Could not verify live model availability for ${p.label}: ${data.error || "unknown reason"}`, "warn");
    }
  } catch (err) {
    statusEl.textContent = "⚠ Check failed (network error)";
    logTerminal(`⚠ Model availability check failed: ${err.message}`, "warn");
  }
}

function loadAiSettings() {
  try {
    return JSON.parse(localStorage.getItem(AI_SETTINGS_KEY) || "null");
  } catch {
    return null;
  }
}

function saveAiSettingsIfRequested() {
  if (!$("aiRemember").checked) {
    localStorage.removeItem(AI_SETTINGS_KEY);
    state.savedAiSettings = null;
    return;
  }
  const providerKey = $("aiProvider").value;
  const authType = $("aiAuthType").value;
  const p = state.providers[providerKey];
  const authCfg = p.auth_types[authType] || p.auth_types[p.default_auth_type];
  const settings = { provider: providerKey, auth_type: authType };
  authCfg.fields.forEach((f) => { settings[f] = getFieldValue(f); });
  localStorage.setItem(AI_SETTINGS_KEY, JSON.stringify(settings));
  state.savedAiSettings = settings;
}

function collectAiPayload() {
  const providerKey = $("aiProvider").value;
  const p = state.providers[providerKey];
  const authType = $("aiAuthType").value;
  const payload = {
    provider: providerKey,
    auth_type: authType,
    extra_context: $("aiExtraContext").value,
    focus_text: $("focusInput") ? $("focusInput").value.trim() : "",
    redact: $("aiRedact").checked,
  };
  const missing = [];
  if (!p) {
    missing.push("provider");
    return { payload, missing };
  }
  const authCfg = p.auth_types[authType] || p.auth_types[p.default_auth_type];
  authCfg.fields.forEach((f) => {
    const val = getFieldValue(f);
    if (!val) missing.push(fieldLabel(f));
    payload[f] = val;
  });
  return { payload, missing };
}

async function runSynthesis() {
  const { payload, missing } = collectAiPayload();
  const provider = state.providers[payload.provider];
  const isLocal = !!(provider && provider.local);

  $("aiError").classList.add("hidden");
  if (missing.length) {
    $("aiError").textContent = `Missing required field(s): ${missing.join(", ")}`;
    $("aiError").classList.remove("hidden");
    return;
  }
  if (!isLocal && !$("aiConfirmExternal").checked) {
    $("aiError").textContent = "Please check \"I confirm I'm authorized to share this bundle's data with an external AI provider\" above before generating with a non-local provider.";
    $("aiError").classList.remove("hidden");
    return;
  }

  saveAiSettingsIfRequested();
  $("btnSynthesize").disabled = true;
  $("btnSynthesize").textContent = "Generating…";
  $("aiRender").innerHTML = '<p class="muted">Waiting for the model to respond…</p>';
  $("btnDownloadReport").classList.add("hidden");
  // A (re)generate always starts a brand-new conversation server-side
  // (see backend/app.py synthesize()) - clear any previous follow-up
  // chat thread from the UI so it doesn't look like it still applies.
  $("chatSection").classList.add("hidden");
  $("chatThread").innerHTML = "";
  renderRedactionCallout(null);

  if (payload.provider === "ollama") {
    try {
      await ensureOllamaRunning(payload.model);
    } catch (err) {
      $("aiError").textContent = `Ollama startup failed: ${err.message}`;
      $("aiError").classList.remove("hidden");
      logTerminal(`❌ Ollama startup failed: ${err.message}`, "error");
      $("btnSynthesize").disabled = false;
      $("btnSynthesize").textContent = "Generate log analysis";
      return;
    }
  }

  const providerLabel = (state.providers[payload.provider] || {}).label || payload.provider;
  const authCfg = ((state.providers[payload.provider] || {}).auth_types || {})[payload.auth_type];
  logTerminal(`🤖 Requesting AI root-cause report from ${providerLabel}${authCfg ? ` (${authCfg.label})` : ""}…`, "info");

  let accumulated = "";
  try {
    const resp = await fetch(`/api/jobs/${state.jobId}/synthesize`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!resp.ok || !resp.body) {
      const detail = await resp.json().catch(() => ({}));
      throw new Error(detail.detail || `Request failed (HTTP ${resp.status})`);
    }
    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const events = buffer.split("\n\n");
      buffer = events.pop(); // keep any incomplete trailing event
      for (const evt of events) {
        const line = evt.trim();
        if (!line.startsWith("data:")) continue;
        const parsed = JSON.parse(line.slice(5).trim());
        if (parsed.error) throw new Error(parsed.error);
        if (parsed.redaction) {
          logTerminal(`🔒 ${parsed.redaction.summary}`, "info");
          renderRedactionCallout(parsed.redaction);
        }
        if (parsed.delta) {
          accumulated += parsed.delta;
          $("aiRender").innerHTML = markdownToHtml(accumulated);
        }
        if (parsed.done) {
          $("btnDownloadReport").classList.remove("hidden");
          $("chatSection").classList.remove("hidden");
        }
      }
    }
    logTerminal(`✅ AI report generated (${accumulated.length.toLocaleString()} chars)`, "success");
  } catch (err) {
    $("aiError").textContent = `Generation failed: ${err.message}`;
    $("aiError").classList.remove("hidden");
    logTerminal(`❌ AI generation failed: ${err.message}`, "error");
  } finally {
    $("btnSynthesize").disabled = false;
    $("btnSynthesize").textContent = accumulated ? "Regenerate log analysis" : "Generate log analysis";
  }
}

// --------------------------------------------------------------------------
// Interactive follow-up chat on the generated report (Results -> AI tab).
// Backed by POST/GET/DELETE /api/jobs/{id}/chat - see backend/app.py. The
// report itself (rendered above via #aiRender) is the conversation's
// first "assistant" turn server-side; this thread only ever shows the
// follow-up exchanges layered on top of it.
// --------------------------------------------------------------------------
function appendChatMessage(role, content, pending) {
  const div = document.createElement("div");
  div.className = `chat-message ${role}${pending ? " pending" : ""}`;
  div.innerHTML = `<div class="chat-role">${role === "user" ? "You" : "AI"}</div><div class="chat-body">${markdownToHtml(content)}</div>`;
  $("chatThread").appendChild(div);
  $("chatThread").scrollTop = $("chatThread").scrollHeight;
  return div;
}

async function restoreChatHistory(jobId) {
  try {
    const data = await fetch(`/api/jobs/${jobId}/chat`).then((r) => r.json());
    (data.messages || []).forEach((m) => appendChatMessage(m.role === "user" ? "user" : "assistant", m.content, false));
  } catch {
    // Non-fatal - the report itself still renders fine without history.
  }
}

async function sendChatMessage() {
  const message = $("chatInput").value.trim();
  if (!message) return;
  const { payload, missing } = collectAiPayload();
  $("chatError").classList.add("hidden");
  if (missing.length) {
    $("chatError").textContent = `Missing required AI field(s): ${missing.join(", ")} - check "Edit focus & AI settings".`;
    $("chatError").classList.remove("hidden");
    return;
  }

  appendChatMessage("user", message, false);
  $("chatInput").value = "";
  const pendingEl = appendChatMessage("assistant", "_thinking…_", true);
  $("btnSendChat").disabled = true;

  if (payload.provider === "ollama") {
    try {
      await ensureOllamaRunning(payload.model);
    } catch (err) {
      pendingEl.remove();
      $("chatError").textContent = `Ollama startup failed: ${err.message}`;
      $("chatError").classList.remove("hidden");
      $("btnSendChat").disabled = false;
      return;
    }
  }

  let accumulated = "";
  try {
    const resp = await fetch(`/api/jobs/${state.jobId}/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...payload, message }),
    });
    if (!resp.ok || !resp.body) {
      const detail = await resp.json().catch(() => ({}));
      throw new Error(detail.detail || `Request failed (HTTP ${resp.status})`);
    }
    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    pendingEl.classList.remove("pending");
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const events = buffer.split("\n\n");
      buffer = events.pop();
      for (const evt of events) {
        const line = evt.trim();
        if (!line.startsWith("data:")) continue;
        const parsed = JSON.parse(line.slice(5).trim());
        if (parsed.error) throw new Error(parsed.error);
        if (parsed.delta) {
          accumulated += parsed.delta;
          pendingEl.querySelector(".chat-body").innerHTML = markdownToHtml(accumulated);
          $("chatThread").scrollTop = $("chatThread").scrollHeight;
        }
      }
    }
    logTerminal(`💬 AI follow-up reply generated (${accumulated.length.toLocaleString()} chars)`, "success");
  } catch (err) {
    pendingEl.querySelector(".chat-body").innerHTML = `<em>Failed to respond: ${escapeHtml(err.message)}</em>`;
    pendingEl.classList.remove("pending");
    logTerminal(`❌ Chat follow-up failed: ${err.message}`, "error");
  } finally {
    $("btnSendChat").disabled = false;
  }
}

async function resetChat() {
  if (!state.jobId) return;
  try {
    await fetch(`/api/jobs/${state.jobId}/chat`, { method: "DELETE" });
  } catch {
    // best-effort - clear the visible thread regardless
  }
  $("chatThread").innerHTML = "";
  $("chatError").classList.add("hidden");
  logTerminal("🔄 Chat conversation reset (report above is unaffected).", "info");
}

// --------------------------------------------------------------------------
// AI connectivity test - a lightweight "does this provider/credential
// combination actually work?" check, separate from a full synthesis run.
// Sends only the tiny fixed test prompt defined server-side
// (_CONNECTIVITY_TEST_MESSAGES in backend/app.py) - never any bundle
// data - so it carries none of the confidentiality considerations a
// real synthesis call does, and doesn't require the external-send
// confirmation checkbox.
// --------------------------------------------------------------------------
async function testConnectivity() {
  const { payload, missing } = collectAiPayload();
  const statusEl = $("connectivityStatus");
  const btn = $("btnTestConnectivity");

  if (missing.length) {
    statusEl.textContent = `⚠ Fill in: ${missing.join(", ")}`;
    return;
  }

  const providerLabel = (state.providers[payload.provider] || {}).label || payload.provider;
  btn.disabled = true;
  statusEl.textContent = "Testing…";
  logTerminal(`🔌 Testing connectivity to ${providerLabel}…`, "info");

  if (payload.provider === "ollama") {
    try {
      await ensureOllamaRunning(payload.model);
    } catch (err) {
      statusEl.textContent = `❌ ${err.message}`;
      logTerminal(`❌ Ollama startup failed: ${err.message}`, "error");
      btn.disabled = false;
      return;
    }
  }

  try {
    const resp = await fetch("/api/test-connection", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const result = await resp.json();
    if (result.ok) {
      statusEl.textContent = `✅ Connected (replied: "${result.sample}")`;
      logTerminal(`✅ ${providerLabel} connectivity OK (replied: "${result.sample}")`, "success");
    } else {
      const errMsg = result.error || "Connection failed";
      const shortMsg = errMsg.split("\n\n")[0];
      statusEl.textContent = `❌ ${shortMsg}` + (errMsg.length > shortMsg.length ? " (see activity log for more detail)" : "");
      logTerminal(`❌ ${providerLabel} connectivity failed: ${errMsg}`, "error");
    }
  } catch (err) {
    statusEl.textContent = `❌ ${err.message}`;
    logTerminal(`❌ Connectivity test request failed: ${err.message}`, "error");
  } finally {
    btn.disabled = false;
  }
}

function downloadReport() {
  const digest = state.jobResult ? state.jobResult.digest : "";
  const aiText = $("aiRender").innerText || "";
  const disclaimer = "> ⚠️ **AI-generated content may be incorrect or incomplete.** Always verify findings against the evidence digest and your own judgment before acting on this report.";
  const content = `# AI Root Cause Report\n\n${disclaimer}\n\n${aiText}\n\n---\n\n# Full Evidence Digest\n\n${digest}`;
  const blob = new Blob([content], { type: "text/markdown" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  const filename = `ldi-copilot-report-${state.jobId || "analysis"}.md`;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
  logTerminal(`⬇ Downloaded report as ${filename}`, "success");
}

// --------------------------------------------------------------------------
// Recent jobs panel
// --------------------------------------------------------------------------
async function loadRecentJobs() {
  const resp = await fetch("/api/jobs");
  const jobs = await resp.json();
  $("recentList").innerHTML = jobs
    .map((j) => {
      const statusLabel = j.status === "done" ? (j.summary ? j.summary.kind : "done") : j.status;
      return `<div class="recent-item" data-id="${j.id}">
        <div class="name">${escapeHtml(j.name)}</div>
        <div class="meta"><span>${escapeHtml(statusLabel)}</span><span>${escapeHtml(new Date(j.created_at).toLocaleTimeString())}</span></div>
      </div>`;
    })
    .join("") || '<p class="muted small">No analyses yet this session.</p>';

  document.querySelectorAll(".recent-item").forEach((item) => {
    item.addEventListener("click", async () => {
      $("recentPanel").classList.add("hidden");
      await loadResults(item.dataset.id);
    });
  });
}

// --------------------------------------------------------------------------
// Wire everything up
// --------------------------------------------------------------------------
function resetToUpload() {
  activateMainTab("upload");
  state.selectedFile = null;
  state.jobId = null;
  state.autoSynthesizeNext = false;
  $("fileInput").value = "";
  $("serverPath").value = "";
  $("dropzoneFile").classList.add("hidden");
  $("pcapInput").value = "";
  $("pcapFileName").classList.add("hidden");
  // Deliberately NOT clearing focusInput / AI provider settings - a
  // support engineer often analyzes a second bundle (e.g. another
  // node's crm_report) for the very same investigation, and retyping
  // the focus + API key every time would be needless friction.
  updateAnalyzeEnabled();
  logTerminal("🔄 Ready for a new analysis.", "info");
}

document.addEventListener("DOMContentLoaded", () => {
  initTerminal();
  initOllamaControls();
  initDropzone();
  initScopeToggle();
  initTabs();
  initMainTabs();
  initAiProviders();
  initWhoami();
  initSystemInfo();
  initPerfToolbar();
  initChartModal();
  loadRecentJobs();
  updatePlaceholders();

  $("btnAnalyze").addEventListener("click", startAnalysis);
  $("btnNewAnalysis").addEventListener("click", resetToUpload);
  $("btnSynthesize").addEventListener("click", runSynthesis);
  $("btnTestConnectivity").addEventListener("click", testConnectivity);
  $("btnDownloadReport").addEventListener("click", downloadReport);
  $("btnEditFocusAi").addEventListener("click", () => activateMainTab("upload"));
  $("btnRecent").addEventListener("click", () => { $("recentPanel").classList.toggle("hidden"); loadRecentJobs(); });
  $("btnCloseRecent").addEventListener("click", () => $("recentPanel").classList.add("hidden"));
  $("btnStopProject").addEventListener("click", stopProject);
  $("btnSendChat").addEventListener("click", sendChatMessage);
  $("btnResetChat").addEventListener("click", resetChat);
  $("chatInput").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendChatMessage();
    }
  });
  $("pcapInput").addEventListener("change", () => {
    const f = $("pcapInput").files[0];
    $("pcapFileName").textContent = f ? `Selected: ${f.name} (${humanSize(f.size)})` : "";
    $("pcapFileName").classList.toggle("hidden", !f);
  });
});
