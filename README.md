# Linux Diagnostic Intelligence Copilot - LDI Copilot

[![Version](https://img.shields.io/badge/version-4.2.0-blue)](CHANGELOG.md) [![status](https://img.shields.io/badge/status-personal%20tool-informational)]() [![privacy](https://img.shields.io/badge/data-stays%20local-brightgreen)]()

AI-powered analysis of **sosreport** (Red Hat), **supportconfig** (SUSE), and **crm_report/hb_report** (Pacemaker/Corosync HA cluster) diagnostic bundles — running locally in your browser — to deliver automated issue detection, root cause analysis, and remediation guidance.

Describe the specific issue you're investigating, pick an AI model (and how you want to authenticate to it), drop in an archive, and get a **focused**, evidence-cited root-cause report — instead of a generic exhaustive dump. Every bundle is automatically analyzed across **performance (SAR), crash/coredump artifacts, boot timing, SELinux/AppArmor, recent package changes, systemd failure cascades, container correlation, and (optionally) a standalone packet capture** — no need to tell it what kind of problem you're chasing. Built on the same mechanical evidence-scanning engine as the [`sosreport-rca`](../sosreport-rca) CLI tool, extended with full `crm_report` support, investigation-focused steering, Microsoft Entra ID authentication for Azure OpenAI, a persistent tabbed UI, a full-height activity terminal with one-click Ollama control, automatic redaction of sensitive identifiers when using a non-local AI provider, and an interactive follow-up chat on every generated report.

See [CHANGELOG.md](CHANGELOG.md) for release history — this project follows [Semantic Versioning](https://semver.org/) and is tagged (`vX.Y.Z`) with a matching GitHub Release per version. See **[SECURITY.md](SECURITY.md)** for this project's full data-handling and confidentiality guidance — read this before using it with customer data at team scale.

> **Formerly `sosreport-rca-webapp`.** Renamed and rebranded as **LDI Copilot** as of v2.0.0 — same project, same history, new identity.

## Why a webapp on top of the CLI tool

The CLI (`sosreport-rca`) is great for scripting/automation. This project wraps the same analysis engine in a browser UI so you can:
- **Tell it what you're actually investigating** — e.g. "find root cause of NC and IP cluster resource restart issue" — and get an answer to that question specifically, instead of every unrelated warning in the bundle competing for attention
- Drag-and-drop a bundle instead of remembering CLI flags
- **Choose which AI model does the reasoning, and how to authenticate to it** — **Ollama (local, fully offline) is the default** — or OpenAI, Anthropic (Claude), Azure OpenAI (API key **or** Microsoft Entra ID app registration) — pick from a dropdown of known models (with a live "Check available models" option that greys out anything not actually available to your credentials), configured up front so the AI report generates automatically as soon as analysis finishes
- **Never have to remember to start Ollama** — clicking "Generate log analysis" with Ollama selected starts `ollama serve` automatically if it isn't already running, with progress visible in the activity terminal; a toolbar also gives direct manual Start/Stop/Refresh control any time
- **Move freely between Provide Bundle / Analyzing / Results** at any time via a persistent top tab bar, instead of being forced through a linear wizard
- **Watch background progress from a full-height activity terminal docked along the entire right edge** — bundle selection, scan progress, AI synthesis, Ollama start/stop, downloads — without needing to be on a specific tab
- **Reduce exposure automatically when using a public AI model** — known hostnames and IP addresses are redacted from the evidence digest before it's sent to any non-local provider, with an explicit confirmation required before any external send (see [SECURITY.md](SECURITY.md))
- Get a live, readable dashboard (summary cards, cluster status, findings by category, chronological timeline) instead of a markdown file
- Analyze `crm_report`/`hb_report` bundles too, with per-node attribution across a multi-node cluster
- Keep everything on your machine — the server binds to `127.0.0.1` only by default, and bundle data is only ever sent off-box if you explicitly choose a cloud AI provider for the synthesis step

## Quick start

Requirements: Python 3.10+ (uses only the standard library plus `dpkt` for the engine; FastAPI/uvicorn for the server). Runs on **Windows, Linux, and macOS** — pick the launcher matching whatever shell you're already in; all three do exactly the same thing (create/reuse a local `.venv`, install dependencies, start the server, open your browser):

| Shell | Command |
|---|---|
| **PowerShell** (Windows PowerShell 5.1, or `pwsh` 7+ on Windows/Linux/macOS) | `.\run.ps1` |
| **Command Prompt (cmd.exe)** | `.\run.bat` |
| **bash** (Linux, macOS, WSL, Git Bash) | `./run.sh` (first: `chmod +x run.sh`) |

Stop any of them with `Ctrl+C`.

> **Command Prompt users:** always type `.\run.bat` (or `call run.bat`), not a bare `run.bat`. Many Windows machines — including Microsoft-managed corporate devices — have the `NoDefaultCurrentDirectoryInExePath` security policy enabled, which blocks cmd.exe from finding a bare `run.bat` in the current folder at all (`'run.bat' is not recognized...`) even when you're sitting right in this directory. The explicit `.\` prefix sidesteps that policy entirely and always works.

Options (same three flags on every launcher, just spelled per that shell's own convention):
```powershell
.\run.ps1 -Port 9000            # use a different port
.\run.ps1 -NoBrowser             # don't auto-open a browser tab
.\run.ps1 -HostAddress 0.0.0.0   # allow LAN access (not recommended - see Privacy below)
```
```bat
.\run.bat --port 9000
.\run.bat --no-browser
.\run.bat --host 0.0.0.0
```
```bash
./run.sh --port 9000
./run.sh --no-browser
./run.sh --host 0.0.0.0
```

### Manual setup (alternative to the run scripts)

Windows (PowerShell or cmd):
```powershell
cd backend
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python app.py
```

Linux / macOS / WSL (bash):
```bash
cd backend
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python app.py
```

## Using it

The top of the page has three always-clickable tabs — **1. Provide Bundle**, **2. Analyzing**, **3. Results** — so you can jump back to tweak settings or check a previous tab at any time; nothing forces a strict linear flow.

1. **Provide a bundle** (tab 1) — drag & drop an archive (`.tar.xz`, `.tgz`, `.tar.bz2`, `.zip`, …), or paste a path already on disk (file or an already-extracted folder). Format (sosreport/supportconfig/crm_report) is auto-detected — and so is everything inside it (SAR, crash artifacts, boot timing, security, package changes, systemd cascades, container logs). Optionally attach a standalone **packet capture** (`.pcap`/`.pcapng`) alongside it for network-level metadata analysis.
2. **Say what you're investigating** — in the "🎯 What are you investigating?" box, describe the specific issue, e.g. *"find root cause of NC and IP cluster resource restart issue"*. This steers both the mechanical scan (a dedicated Focused Findings section, keyword-tagged results) and the AI report (which answers that question directly and demotes unrelated findings to a short closing section). Leave it blank for a generic full-bundle analysis.
3. **Configure your AI model** — right below, in the same panel: pick a provider, then (for Azure OpenAI) pick an **authentication type** — API Key or Microsoft Entra ID — and fill in the fields for that choice. Optionally check "Remember these settings on this device". Filling this in now means a full AI-reasoned report generates **automatically** as soon as the scan finishes — no extra click. This panel lives permanently on tab 1; use the "✏️ Edit focus & AI settings" shortcut on the Results tab to jump straight back to it.
4. **(Optional) scope the analysis** — expand "Advanced options" to restrict the scan to a specific date/time range or a time ± window, or narrow which **analysis focus areas** (SAR, crash, boot, security, packages, cascade, containers, network) actually show up in the digest/report. Useful when you already know roughly when an incident happened, or which axes matter for this investigation.
5. **Run analysis** — the view auto-advances to tab 2 to show live progress, then to tab 3 once done. Results open on the **AI Root Cause Report** tab by default, streaming in automatically if you configured a model in step 3 (or click "Generate log analysis" there if you didn't). A disclaimer is always shown above the report — ⚠️ AI-generated content may be incorrect or incomplete; verify against the evidence before acting. Other tabs: a **📊 Performance** sub-tab with SAR charts (when SAR data was found), the full evidence **Digest**, a filterable **Findings** list (with a "show only findings matching my focus 🎯" toggle), and a cross-file **Timeline**.
6. **Ask follow-up questions** — once a report is generated, an "💬 Ask a follow-up" thread appears below it. Type a custom instruction and the model replies in the context of the report it just gave you, without re-running the mechanical scan.
7. **Regenerate or refine** — click "✏️ Edit focus & AI settings" to jump back to tab 1, tweak the focus text or switch AI providers/auth type, then return to tab 3 and click Generate again to regenerate (this also resets the follow-up chat thread) without re-running the mechanical scan.
8. **Download** the combined AI report + evidence digest as a single Markdown file.

Recent analyses from the current server session are listed under "Recent analyses" (top right) so you can revisit results without re-uploading.

### The activity terminal

The panel docked along the entire right edge of the page is a persistent, timestamped activity log — visible no matter which of the three tabs you're on. It mirrors background progress from every stage: bundle selection, the mechanical scan's own progress lines, AI synthesis start/completion, Ollama start/stop, model-availability checks, downloads, and resets. Its header has an Ollama status badge plus **Start**/**Stop**/**⟳ (refresh)** buttons for direct manual control, and a **Clear** button to wipe the log. It's session-only (not persisted), purely a live "what's happening" view.

### Ollama auto-start

Since Ollama is the default AI provider, clicking **"Generate log analysis"** with Ollama selected will automatically start `ollama serve` if it isn't already running — no need to remember to start it yourself first. Progress (including Ollama's own startup log lines) streams into the activity terminal while it comes up. You can also start/stop/check it manually any time via the terminal's toolbar — the **Start** button disables itself while Ollama is running/starting, and **Stop** becomes enabled at that point (it's a no-op with a clear message in the terminal if Ollama is running but wasn't started by LDI Copilot itself — e.g. the desktop app — rather than actually terminating an instance it didn't launch).

### Testing AI connectivity before a full analysis

The **"🔌 Test AI connectivity"** button (right below the model picker in tab 1) sends a tiny fixed test message — never any bundle data — to the currently configured provider/credentials and reports success or failure inline, plus in the activity terminal. Useful for confirming an API key, endpoint, or Ollama model actually works before running a full analysis and waiting on a real synthesis call. For Ollama it starts the service first (same as Generate); for paid providers it consumes a negligible number of tokens, not a full report's worth.

### A note on focused analysis

The mechanical engine's keyword matching is intentionally simple (it just tags findings that literally contain your focus words), while the AI layer does the actual causal reasoning across the *entire* evidence base — so it can, for example, connect a flapping NIC (`NIC Link is Down`) to a restart of a resource named `rsc_ip_cluster` even though "NIC" and "IP" don't share a literal keyword. If you ask about "NC and IP" and the mechanical Focused Findings section looks sparse, that's expected — the AI report is where the deeper connection gets made. Use the Findings tab's focus filter to see exactly what was keyword-matched, and the Digest/Timeline to see everything else the AI had available to reason over.

## Multi-analyzer deep-dive (v4.0.0)

Every bundle is **automatically** analyzed across all of the below — there's no "pick an analysis type" step, because SAR/crash/security/etc. data (when present) lives inside the *same* sosreport/supportconfig/crm_report bundle as everything else; each is just a dedicated parser that only adds a digest section when it actually finds something relevant:

- **📊 Performance (SAR)** — parses sysstat's pre-rendered `sar` text tables (CPU/memory/disk I/O/network/load) into both a condensed text summary *and* dependency-free `<canvas>` line charts on a new **Performance** sub-tab (Results → Performance). Every timestamp is explicitly labeled with the analyzed **VM's own detected timezone** (from `/etc/timezone`, the captured `date` output, or `/etc/localtime`) so you never confuse "the time I'm reading this in" with "the time it happened on the customer's box" — a common source of confusion when the analyst and the customer are in different timezones.
- **💥 Crash / Coredump analysis** — correlates ABRT crash reports (`var/spool/abrt/ccpp-*`, already-human-readable backtraces ABRT captured at crash time), kdump/kexec configuration, and vmcore presence/size. Deliberately scoped to what's realistically available in a bundle — full raw-core-file-plus-gdb symbolication needs matching debug symbols and would mean shelling out to `gdb`, which this analysis engine deliberately never does (keeps the tool dependency-free and portable across Windows/Linux/macOS).
- **🥾 Boot performance** — `systemd-analyze`'s own startup breakdown, slowest-unit ("blame") ranking, and critical-chain tree, when captured.
- **🛡️ Security (SELinux/AppArmor)** — enforcing/permissive status, AppArmor profile counts, and a *structured* denial breakdown (by SELinux scontext/tcontext/tclass, or AppArmor profile/operation) — more actionable than a flat list of near-identical raw log lines.
- **📦 Recent package changes** — installed-package timestamps (and yum/dnf transaction history, where available) surfaced with a dedicated "changed in the 7 days before capture" view — a very common real "what changed right before this broke" question.
- **🔗 Service failure cascade** — looks for `Dependency failed for X` / `Triggering OnFailure=` evidence and groups near-simultaneous multi-unit failures, since a cluster of units failing within a few seconds usually shares one root cause rather than being N independent problems.
- **🐳 Container correlation** — Docker/Podman `ps` snapshots correlated with host-level OOM evidence; flags containers that exited with a signal consistent with an OOM-kill (exit code 137) or are stuck restart-looping.
- **🌐 Network capture (pcap)** — optional: attach a standalone `.pcap`/`.pcapng` (Step 1, "Attach a packet capture") for packet/byte counts, top talkers, protocol mix, TCP anomaly counts (resets, suspected retransmissions, a rough port-scan heuristic), and a DNS query summary. **Metadata only, never raw payload content** — see [SECURITY.md](SECURITY.md) for the full privacy stance behind this design choice, and why it's held to a stricter standard than the rest of the digest.

**Analysis focus areas** (Step 1 → Advanced options) let you narrow which of the sections above actually render in the digest/AI report — useful once you already know a given axis isn't relevant to this investigation. Every analyzer still *runs* regardless (they're cheap, and the full structured data stays available in `facts.json`/the API either way) — the toggles only control what's emphasized in what you and the AI actually read. All checked by default.

### Interactive follow-up chat

The generated report isn't the end of the conversation — **Results → AI Root Cause Report** now has an "💬 Ask a follow-up" thread below the report. Type a custom instruction (*"focus more on the network side"*, *"explain the timeline gap between 14:02 and 14:05"*, *"give me a shorter executive summary for my manager"*) and the model replies **in the context of the report it just gave you**, not as a fresh, disconnected question. Each exchange appends to the same conversation; "Reset conversation" clears the follow-up thread without discarding the report itself or re-running the mechanical scan. History is capped in length so an extended back-and-forth doesn't let request size/cost/latency grow unbounded — the original report is always preserved regardless of how many follow-ups you send.

## AI provider setup

Pick whichever you have access to — no code changes needed, it's a dropdown in the UI (tab 1, or jump there any time via "✏️ Edit focus & AI settings" on the Results tab). **Ollama is selected by default** — the safest choice for customer diagnostic data, since nothing ever leaves your machine.

| Provider | Authentication | What you need | Notes |
|---|---|---|---|
| **Ollama (local)** — *default* | None | [Ollama](https://ollama.com) installed, with a model pulled (`ollama pull llama3.1`) | 🔒 **Fully offline** — the bundle's evidence digest never leaves your machine. Best choice for sensitive customer data. LDI Copilot starts `ollama serve` for you automatically if it isn't already running. Model is a dropdown of common Ollama model names, plus "Custom / other model…" |
| **OpenAI** | API Key | API key from platform.openai.com | Model is a dropdown of known models (`gpt-4o`, `gpt-4o-mini`, `gpt-4.1`, `gpt-4-turbo`, `gpt-3.5-turbo`, `o3`, `o3-mini`, `o1`), plus a "Custom / other model…" option for anything newer |
| **Anthropic (Claude)** | API Key | API key from console.anthropic.com | Model is a dropdown of known Claude models, plus "Custom / other model…" |
| **Azure OpenAI** | API Key | API key + resource endpoint URL + **deployment name** (not the base model name) | Deployment name is whatever you named it when you deployed the model in Azure AI Foundry / Azure OpenAI Studio — always free text (deployment names are user-defined, so there's no fixed list to offer) |
| **Azure OpenAI** | Microsoft Entra ID | Directory (tenant) ID + Application (client) ID + client secret, from an app registration, plus the same endpoint + deployment name | For enterprise environments where API keys are locked down by policy. The app registration needs the **Cognitive Services OpenAI User** RBAC role (or equivalent) assigned on the target Azure OpenAI resource — see below. |

**API key / secret handling:** credentials are entered in the browser and sent directly from your local backend to the provider you chose (or, for Entra ID, to `login.microsoftonline.com` to exchange for a short-lived access token, then to your Azure OpenAI endpoint), for that one request only. They are never written to disk unless you explicitly check "Remember these settings on this device" (which stores them in your browser's `localStorage`, not on any server).

**Non-local providers require an extra confirmation.** When you pick anything other than Ollama, a confidentiality panel appears with a redaction toggle (checked by default) and a required "I confirm I'm authorized to share this bundle's data with an external AI provider" checkbox — see [SECURITY.md](SECURITY.md) for the full design and its limitations.

### Checking which models are actually available

For OpenAI, Anthropic, and Ollama, the Model field is a dropdown seeded with a curated list of known model names. Fill in your credentials (API key, or for Ollama the base URL if it's not the default `http://localhost:11434`) and click **"🔎 Check available models"** to query the provider live:
- **OpenAI** — lists models your API key's account actually has access to (`GET /v1/models`).
- **Anthropic** — lists models available to your API key via Anthropic's Models API.
- **Ollama** — lists whatever's actually pulled locally (`GET /api/tags`) — the most precise availability signal of the three, since a model is either on disk or it isn't.

Any known model the live check didn't confirm is **greyed out** (disabled) in the dropdown rather than removed, so you can still see what exists in the curated list even if your current credentials don't have access to it. The check is best-effort and non-blocking: if it fails (no credentials yet, invalid key, offline, network error), every option simply stays selectable and a short status message explains why. Your current selection is never silently changed by a check — if it becomes greyed out, you'll see a warning next to it instead. Not available for Azure OpenAI, since deployment names are user-defined and can't be enumerated this way.

### Setting up Microsoft Entra ID authentication for Azure OpenAI

1. In the Azure Portal, register an application under **Microsoft Entra ID → App registrations → New registration**. Note its **Application (client) ID** and **Directory (tenant) ID**.
2. Under that app registration's **Certificates & secrets**, create a new **client secret**. Copy its value immediately (it's only shown once).
3. On your **Azure OpenAI resource** (not the app registration), go to **Access control (IAM) → Add role assignment**, and grant the app registration the **Cognitive Services OpenAI User** role (or a custom role with equivalent `Microsoft.CognitiveServices/accounts/OpenAI/*` permissions).
4. In LDI Copilot, choose **Azure OpenAI** as the provider and **Microsoft Entra ID** as the authentication type, then fill in the Tenant ID, Client ID, Client secret, your Azure OpenAI endpoint URL, and the deployment name.
5. A fresh access token is requested from `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` on every "Generate report" click (scope `https://cognitiveservices.azure.com/.default`) — tokens are not cached, so there's no stale-token expiry to worry about, and no token is ever written to disk.

If authentication succeeds but the chat call still fails, double-check step 3 — a valid token with insufficient RBAC on the target resource surfaces as an HTTP 403 from the chat-completions call, not a login failure.

## Privacy & data handling

**See [SECURITY.md](SECURITY.md) for the full picture** — recommended team deployment model (one instance per engineer, not a shared server), exactly what data leaves the machine and when, the redaction feature and its limitations, a provider risk ordering, retention guidance, and an explicit list of what this tool does *not* provide (encryption at rest, audit logging, RBAC, DLP, formal compliance certification).

Summary:
- The server binds to `127.0.0.1` (localhost) by default — nothing on your network can reach it unless you explicitly pass `-HostAddress 0.0.0.0`, which isn't recommended given what these bundles contain.
- Uploaded archives and their extracted contents/analysis output are kept under `backend/data/jobs/<job_id>/` for the lifetime of the server process. Delete a job's data any time via the API (`DELETE /api/jobs/{id}`) or just delete the folder; nothing is auto-uploaded anywhere.
- The AI synthesis step sends the **evidence digest** (system/cluster names, log excerpts, IPs, timestamps, etc. — not the raw uploaded archive) to whichever provider you pick, with known hostnames/IPs redacted by default for non-local providers. Use **Ollama** (the default) if the bundle must never leave the machine.
- The frontend has zero external/CDN dependencies (including its own small Markdown renderer) so the UI itself works with no internet access — only the AI synthesis step (for non-Ollama providers) and the optional "Check available models" call need connectivity.

## Architecture

```
ldi-copilot/
├── run.ps1                    # one-command launcher (PowerShell / pwsh - Windows, Linux, macOS)
├── run.bat                    # one-command launcher (Windows Command Prompt)
├── run.sh                     # one-command launcher (bash - Linux, macOS, WSL, Git Bash)
├── CHANGELOG.md
├── SECURITY.md                 # data-handling / confidentiality guidance - read before team rollout
├── backend/
│   ├── app.py                 # FastAPI server: job management, REST API, static file serving,
│   │                          # /api/models live-availability endpoint, /api/ollama/* lifecycle,
│   │                          # /api/jobs/{id}/chat (interactive follow-up), /api/jobs/{id}/sar_series
│   ├── requirements.txt        # fastapi, uvicorn, python-multipart, dpkt (pcap parsing)
│   ├── engine/
│   │   ├── analyzer_core.py   # mechanical scanning engine (extraction, detection, pattern
│   │   │                      # matching, fact-checks, timeline, digest, focus-keyword
│   │   │                      # tagging) - sosreport + supportconfig + crm_report, with a
│   │   │                      # run_analysis() library API. v4.0.0 added 7 new fact-checks
│   │   │                      # (SAR/perf, crash/coredump, boot, SELinux/AppArmor, package
│   │   │                      # drift, systemd cascade, container correlation), VM-timezone
│   │   │                      # detection, and focus-area digest-section gating
│   │   └── pcap_analyzer.py   # standalone .pcap/.pcapng metadata analyzer (dpkt-based) -
│   │                          # packet/byte counts, top talkers, protocol mix, TCP/DNS
│   │                          # summaries; never parses/stores raw payload content
│   ├── ai/
│   │   ├── providers.py       # OpenAI / Anthropic / Azure OpenAI (API key + Entra ID) /
│   │   │                      # Ollama streaming clients, known_models registry, and
│   │   │                      # list_models() live-availability checks
│   │   ├── prompts.py         # focus-aware RCA synthesis system prompt + evidence-digest user prompt
│   │   ├── redaction.py       # hostname/IPv4 redaction for non-local providers, with a
│   │   │                      # local-only legend
│   │   └── ollama_manager.py  # starts/stops/monitors a local `ollama serve` process on demand
│   └── data/jobs/<id>/         # per-analysis uploaded file(s) + extracted tree + output (gitignored)
├── frontend/
│   ├── index.html             # persistent top-level tabs (Provide Bundle/Analyzing/Results),
│   │                          # focus+AI config panel permanently inlined in tab 1, optional
│   │                          # pcap upload slot + analysis focus-area toggles, full-height
│   │                          # right-edge activity terminal with Ollama toolbar, Performance
│   │                          # sub-tab, interactive chat thread
│   ├── app.js                 # upload, polling, rendering, SSE streaming, tiny MD renderer,
│   │                          # top-level tab switching, auth-type-aware AI config, model
│   │                          # dropdown + availability checks, activity-terminal logging,
│   │                          # Ollama start/stop/status polling, auto-chained synthesis,
│   │                          # dependency-free <canvas> SAR charts, interactive chat thread
│   └── styles.css
└── samples/                    # synthetic test fixtures (fake_sosreport, fake_supportconfig,
                                 # fake_crm_report, fake_crm_report_multi) - safe, fictional
                                 # data for trying the app
```

**Request flow:** browser uploads a bundle (+ optional focus text + optional pcap + optional AI config incl. auth type, all collected in tab 1) → FastAPI saves it and starts a background thread running `run_analysis(..., focus=..., focus_areas=..., pcap_path=...)` → browser polls job status (mirroring new progress lines into the activity terminal as they arrive), tab auto-advances to "2. Analyzing" → once done, browser fetches the digest/findings/facts/timeline/sar_series JSON, tab auto-advances to "3. Results" and renders the dashboard (including Performance-tab charts, if SAR data was found), opening on the AI Root Cause Report tab → if AI settings were filled in, the browser automatically POSTs the provider credentials (+ auth type, + redact flag) + focus text + the job's digest to `/api/jobs/{id}/synthesize` (first calling `/api/ollama/start` and polling `/api/ollama/status` if Ollama was selected and isn't already running) → the endpoint redacts known hostnames/IPs from the digest first if the provider isn't local, emits a local-only redaction-legend SSE event, and (for Entra ID) exchanges the tenant/client/secret for a bearer token before streaming the model's response back via Server-Sent Events, seeding the interactive-chat conversation with that report as its first turn. Follow-up messages go to `/api/jobs/{id}/chat`, replaying the same conversation history rather than starting fresh each time. The focus+AI panel never moves in the DOM — the Results tab's "Edit focus & AI settings" button just switches the active top-level tab back to it, so a second analysis from tab 1 always finds its fields intact.

## Focused analysis

Point the tool at one specific problem instead of getting a generic report:
- The "🎯 What are you investigating?" field in tab 1 accepts free text like *"find root cause of NC and IP cluster resource restart issue"*.
- `extract_focus_keywords()` tokenizes this into meaningful identifiers (filtering generic words like "find"/"root"/"cause"/"issue"), and every finding/timeline event gets tagged `focus_match: true/false`. Matching treats `_`/`-` as separators, so short identifiers like `ip`/`nc` correctly match inside real resource names such as `rsc_ip_cluster`/`rsc_nc_share`.
- `digest.md` gets a `## 🎯 Focused Findings` section ahead of the full category breakdown, listing only keyword-matched evidence.
- The AI synthesis prompt restructures around the focus: the Executive Summary and Root Cause Analysis sections answer the stated focus directly, and the model is explicitly instructed to reason *beyond* the literal keyword matches (e.g. connecting a flapping NIC to an IP-resource restart) since mechanical keyword matching alone cannot make that causal leap. Anything unrelated to the focus is demoted to a short closing "Other Observations" section instead of competing for attention.
- The Findings tab's "Show only findings matching my focus 🎯" toggle lets you flip between the focused view and the full exhaustive list at any time, without re-running anything.

## crm_report / hb_report support

Detects the crmsh `crm report` layout (`analysis.txt`, `cib.xml`, `members.txt`, `crm_mon.txt`, per-node subdirectories named by hostname) and adds:
- Per-node categorization (a `pacemaker.log`/`corosync.log` inside any node's subfolder is recognized regardless of which node it's under)
- A dedicated **Cluster Status** summary: nodes detected, offline/unclean nodes (parsed from `crm_mon.txt`), and Failed Resource Actions
- `analysis.txt` (crm_report's own built-in CRIT:/ERROR:/WARNING: scan) is surfaced verbatim as an independent cross-check against this tool's own findings
- The AI synthesis prompt is specifically primed to use per-node evidence (e.g. CPU/memory exhaustion, kernel soft-lockups, or NIC flaps on the affected node) to explain *why* a fencing/STONITH event or resource restart happened, not just report that it happened

## Limitations

- This is heuristic pattern-matching plus structured fact-checks, not a certified rules engine (e.g. Red Hat Insights, SUSE's SCA tool). Treat the digest as a strong evidence base for the AI/human review step, not an infallible verdict.
- Focus-keyword matching is intentionally literal/simple; it cannot make causal leaps between differently-worded evidence on its own (that's the AI synthesis step's job) — if the Focused Findings section looks sparse, check the AI report and the full Digest/Timeline before concluding there's no relevant evidence.
- Microsoft Entra ID auth requires network access to `login.microsoftonline.com` and your Azure OpenAI endpoint; it is not usable fully offline the way Ollama is.
- The redaction feature is a best-effort mitigation, not a guarantee — it only catches known hostnames (from this analysis's own facts) and IPv4 addresses. It does not find customer/company names in free text, usernames, IPv6 addresses, or other identifiers. See [SECURITY.md](SECURITY.md) for the full picture.
- Single-user, single-machine tool: job state is in-memory and does not survive a server restart (uploaded files/analysis output on disk do persist under `backend/data/jobs/` until deleted). Not designed to be deployed as a shared, centrally-reachable server for a team — see [SECURITY.md](SECURITY.md) for the recommended one-instance-per-engineer model.
- No authentication on the local server itself — appropriate for local personal use; do not expose this server beyond localhost.
- **SAR analysis** parses pre-rendered SAR *text* tables wherever a bundle stores them: sosreport's dedicated `sos_commands/sar/*` capture, sosreport's raw `var/log/sa/*` spool directory (checked too, but only the text files in it if any exist — the binary `saDD` files there are correctly skipped, not decoded), supportconfig's `sar/` directory (matched by directory membership, not filename, since supportconfig names files by date/day-of-month rather than anything containing "sar"), and crm_report's `sysstats.txt`. It does **not** decode raw binary sar data, which would require shelling out to the `sar`/`sadf` binary - a dependency this tool deliberately avoids so it stays portable across Windows/Linux/macOS without needing sysstat installed on the analysis machine itself. If sysstat wasn't installed on the customer's box, or no sar data was included in the capture at all, there's simply nothing to show — the Performance tab will say so rather than erroring.
- **Crash/coredump analysis** is scoped to already-textual artifacts a bundle realistically contains (ABRT reports, kdump config, vmcore file presence/size) — it does **not** symbolize a raw core file with `gdb` (that needs matching debug symbols and a Linux environment, and sosreport/supportconfig don't normally include the actual core file anyway, since it's typically huge).
- **VM timezone detection** is best-effort (checks `/etc/timezone`, the captured `date` output, then `/etc/localtime`) and returns "unknown" rather than guessing when none of these signals are present — never silently assumes UTC.
- **Packet capture (pcap) analysis** requires you to separately obtain and attach a capture — sosreport/supportconfig/crm_report essentially never embed one themselves (too large, too privacy-sensitive for a general-purpose collector to grab automatically). It's metadata-only by design; see [SECURITY.md](SECURITY.md) for why.
- The **interactive chat** follow-up history is capped in length (see `_CHAT_MAX_FOLLOWUP_TURNS` in `backend/app.py`) to bound request size/cost/latency on long back-and-forths — the original report is always preserved, only older follow-up exchanges age out.
