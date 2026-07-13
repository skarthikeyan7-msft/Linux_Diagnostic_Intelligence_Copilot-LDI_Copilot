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
  analyzing: false,  // true while a job is in flight; drives the Analyzing tab's placeholder vs. progress log
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
  $("progressPlaceholder").classList.toggle("hidden", state.analyzing);
  $("progressContent").classList.toggle("hidden", !state.analyzing);
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
// selected provider, so clicking "Generate root-cause report" starts
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
  $("btnStopOllama").disabled = !(status && status.managed);
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
    $("btnStartOllama").disabled = false;
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
  activateMainTab("results");
  activateTab("ai"); // always land on the AI report for fresh results

  renderSummaryCards(job.summary, facts);
  renderFocusCallout(job.summary);
  renderClusterStatus(job.summary, facts);
  $("digestRender").innerHTML = markdownToHtml(digest);
  renderFindings(findings);
  renderTimeline(timeline);

  // Reset AI tab for the (possibly new) job
  $("aiRender").innerHTML = "";
  $("aiError").classList.add("hidden");
  $("btnDownloadReport").classList.add("hidden");
  const existingReport = await fetch(`/api/jobs/${jobId}/ai_report`).then((r) => r.text()).catch(() => "");
  if (existingReport) {
    $("aiRender").innerHTML = markdownToHtml(existingReport);
    $("btnDownloadReport").classList.remove("hidden");
    $("btnSynthesize").textContent = "Regenerate root-cause report";
  } else {
    $("btnSynthesize").textContent = "Generate root-cause report";
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

  if (payload.provider === "ollama") {
    try {
      await ensureOllamaRunning();
    } catch (err) {
      $("aiError").textContent = `Ollama startup failed: ${err.message}`;
      $("aiError").classList.remove("hidden");
      logTerminal(`❌ Ollama startup failed: ${err.message}`, "error");
      $("btnSynthesize").disabled = false;
      $("btnSynthesize").textContent = "Generate root-cause report";
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
        }
        if (parsed.delta) {
          accumulated += parsed.delta;
          $("aiRender").innerHTML = markdownToHtml(accumulated);
        }
        if (parsed.done) {
          $("btnDownloadReport").classList.remove("hidden");
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
    $("btnSynthesize").textContent = accumulated ? "Regenerate root-cause report" : "Generate root-cause report";
  }
}

function downloadReport() {
  const digest = state.jobResult ? state.jobResult.digest : "";
  const aiText = $("aiRender").innerText || "";
  const content = `# AI Root Cause Report\n\n${aiText}\n\n---\n\n# Full Evidence Digest\n\n${digest}`;
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
  $("btnDownloadReport").addEventListener("click", downloadReport);
  $("btnEditFocusAi").addEventListener("click", () => activateMainTab("upload"));
  $("btnRecent").addEventListener("click", () => { $("recentPanel").classList.toggle("hidden"); loadRecentJobs(); });
  $("btnCloseRecent").addEventListener("click", () => $("recentPanel").classList.add("hidden"));
});
