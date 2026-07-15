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
// runSynthesis() when Ollama is the selected provider. Resolves once
// Ollama is confirmed reachable; rejects with a human-readable message
// if it fails to start or times out - callers must not proceed to an
// actual synthesis call in that case.
async function ensureOllamaRunning() {
  let status = await refreshOllamaStatus();
  if (status.status === "running") return status;

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

async function startOllama() {
  $("btnStartOllama").disabled = true;
  try {
    await ensureOllamaRunning();
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
// Renders the token->original mapping grouped by kind (hostnames vs IPs)
// inside a collapsible <details> so it doesn't dominate the page when
// there are many redacted values, matching the always-visible one-line
// summary engineers need at a glance plus the full mapping on demand.
function renderRedactionCallout(data) {
  const el = $("redactionCallout");
  const legend = data && data.legend;
  if (!legend || !legend.length) {
    el.classList.add("hidden");
    el.innerHTML = "";
    return;
  }
  const hosts = legend.filter((e) => e.token.startsWith("HOST-"));
  const ips = legend.filter((e) => e.token.startsWith("IP-"));
  const parts = [];
  if (hosts.length) parts.push(`${hosts.length} hostname(s)`);
  if (ips.length) parts.push(`${ips.length} IP address(es)`);
  const renderGroup = (title, items) => (items.length
    ? `<div class="redaction-group"><h5>${escapeHtml(title)}</h5>${items.map((e) => `<code>${escapeHtml(e.token)}=${escapeHtml(e.original)}</code>`).join("")}</div>`
    : "");
  el.innerHTML = `
    <div class="redaction-summary">🔒 <strong>Redacted ${escapeHtml(parts.join(" and "))} before sending.</strong> Local-only mapping - never sent to the AI provider:</div>
    <details class="redaction-details">
      <summary>View mapping (${legend.length} value(s))</summary>
      <div class="redaction-columns">${renderGroup("Hostnames", hosts)}${renderGroup("IP Addresses", ips)}</div>
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
// Deliberately simple (no zoom/pan/tooltips) - this is a diagnostic
// glance, not a full charting library; findings.json/facts.json retain
// the exact numbers for anything requiring precision.
function drawLineChart(canvas, namedSeries) {
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
    return;
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

function buildChartCard(title, statsText, namedSeries) {
  const card = document.createElement("div");
  card.className = "chart-card";
  const legend = namedSeries
    .map((s, i) => `<span><span class="swatch" style="background:${s.color || CHART_COLORS[i % CHART_COLORS.length]}"></span>${escapeHtml(s.label)}</span>`)
    .join("");
  card.innerHTML = `<h4>${escapeHtml(title)}</h4><div class="chart-stats">${escapeHtml(statsText)}</div><canvas></canvas><div class="chart-legend">${legend}</div>`;
  requestAnimationFrame(() => drawLineChart(card.querySelector("canvas"), namedSeries));
  return card;
}

async function loadSarSeries(jobId) {
  let sar = {};
  try {
    sar = await fetch(`/api/jobs/${jobId}/sar_series`).then((r) => r.json());
  } catch {
    sar = {};
  }
  const groups = sar.metric_groups_found || [];
  if (!groups.length) {
    $("perfPlaceholder").classList.remove("hidden");
    $("perfContent").classList.add("hidden");
    return;
  }
  $("perfPlaceholder").classList.add("hidden");
  $("perfContent").classList.remove("hidden");

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

  const grid = $("chartGrid");
  grid.innerHTML = "";
  const series = sar.series || {};

  if (series.cpu) {
    const rows = series.cpu.filter((r) => (r.CPU === "all" || r.CPU === undefined));
    const used = rows.filter((r) => typeof r["%idle"] === "number").map((r) => ({ ts: r.ts, used: 100 - r["%idle"] }));
    grid.appendChild(buildChartCard("📊 CPU used (%)", `${used.length} samples`, [
      { label: "% used", points: seriesPoints(used, "used"), color: CHART_COLORS[0] },
    ]));
    const iowait = seriesPoints(rows, "%iowait");
    if (iowait.length) {
      grid.appendChild(buildChartCard("⏳ I/O wait (%)", `${iowait.length} samples`, [
        { label: "%iowait", points: iowait, color: CHART_COLORS[3] },
      ]));
    }
  }
  if (series.memory) {
    grid.appendChild(buildChartCard("🧠 Memory used (%)", `${series.memory.length} samples`, [
      { label: "%memused", points: seriesPoints(series.memory, "%memused"), color: CHART_COLORS[2] },
    ]));
  }
  if (series.disk_io) {
    grid.appendChild(buildChartCard("💽 Disk transactions/sec", `${series.disk_io.length} samples`, [
      { label: "tps", points: seriesPoints(series.disk_io, "tps"), color: CHART_COLORS[1] },
    ]));
  }
  if (series.load) {
    grid.appendChild(buildChartCard("⚖️ Load average (1 min)", `${series.load.length} samples`, [
      { label: "ldavg-1", points: seriesPoints(series.load, "ldavg-1"), color: CHART_COLORS[4] },
    ]));
  }
  if (series.network) {
    const byIface = {};
    series.network.forEach((r) => {
      if (typeof r["rxkB/s"] !== "number" || !r.IFACE) return;
      (byIface[r.IFACE] = byIface[r.IFACE] || []).push(r);
    });
    const namedSeries = Object.keys(byIface)
      .slice(0, 6)
      .map((iface, i) => ({ label: iface, points: seriesPoints(byIface[iface], "rxkB/s"), color: CHART_COLORS[i % CHART_COLORS.length] }));
    if (namedSeries.length) {
      grid.appendChild(buildChartCard("🌐 Network received (kB/s)", `${Object.keys(byIface).length} interface(s)`, namedSeries));
    }
  }
}

// --------------------------------------------------------------------------
// Tabs
// --------------------------------------------------------------------------
function activateTab(tabName) {
  document.querySelectorAll(".tab-btn").forEach((b) => b.classList.toggle("active", b.dataset.tab === tabName));
  document.querySelectorAll(".tab-panel").forEach((p) => p.classList.toggle("hidden", p.id !== `tab-${tabName}`));
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
      await ensureOllamaRunning();
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
      await ensureOllamaRunning();
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
      await ensureOllamaRunning();
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
      statusEl.textContent = `❌ ${result.error || "Connection failed"}`;
      logTerminal(`❌ ${providerLabel} connectivity failed: ${result.error || "unknown error"}`, "error");
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
