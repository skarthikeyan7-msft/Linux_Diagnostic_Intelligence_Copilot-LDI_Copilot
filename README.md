# LDI Copilot — Linux Diagnostic Intelligence Copilot

[![Version](https://img.shields.io/badge/version-2.0.0-blue)](CHANGELOG.md) [![status](https://img.shields.io/badge/status-personal%20tool-informational)]() [![privacy](https://img.shields.io/badge/data-stays%20local-brightgreen)]()

AI-powered analysis of **sosreport** (Red Hat), **supportconfig** (SUSE), and **crm_report/hb_report** (Pacemaker/Corosync HA cluster) diagnostic bundles — running locally in your browser — to deliver automated issue detection, root cause analysis, and remediation guidance.

Describe the specific issue you're investigating, pick an AI model (and how you want to authenticate to it), drop in an archive, and get a **focused**, evidence-cited root-cause report — instead of a generic exhaustive dump. Built on the same mechanical evidence-scanning engine as the [`sosreport-rca`](../sosreport-rca) CLI tool, extended with full `crm_report` support, investigation-focused steering, Microsoft Entra ID authentication for Azure OpenAI, and a persistent tabbed UI.

See [CHANGELOG.md](CHANGELOG.md) for release history — this project follows [Semantic Versioning](https://semver.org/) and is tagged (`vX.Y.Z`) with a matching GitHub Release per version.

> **Formerly `sosreport-rca-webapp`.** Renamed and rebranded as of v2.0.0 — same project, same history, new identity.

## Why a webapp on top of the CLI tool

The CLI (`sosreport-rca`) is great for scripting/automation. This project wraps the same analysis engine in a browser UI so you can:
- **Tell it what you're actually investigating** — e.g. "find root cause of NC and IP cluster resource restart issue" — and get an answer to that question specifically, instead of every unrelated warning in the bundle competing for attention
- Drag-and-drop a bundle instead of remembering CLI flags
- **Choose which AI model does the reasoning, and how to authenticate to it** — OpenAI, Anthropic (Claude), Azure OpenAI (API key **or** Microsoft Entra ID app registration), or a fully local Ollama model — configured up front, so the AI report generates automatically as soon as analysis finishes
- **Move freely between Provide Bundle / Analyzing / Results** at any time via a persistent top tab bar, instead of being forced through a linear wizard
- Get a live, readable dashboard (summary cards, cluster status, findings by category, chronological timeline) instead of a markdown file
- Analyze `crm_report`/`hb_report` bundles too, with per-node attribution across a multi-node cluster
- Keep everything on your machine — the server binds to `127.0.0.1` only by default, and bundle data is only ever sent off-box if you explicitly choose a cloud AI provider for the synthesis step

## Quick start

Requirements: Python 3.10+ on Windows (uses only the standard library for the engine; FastAPI/uvicorn for the server).

```powershell
.\run.ps1
```

This creates a local `.venv`, installs dependencies, starts the server, and opens `http://127.0.0.1:8756` in your browser. Stop it with `Ctrl+C`.

Options:
```powershell
.\run.ps1 -Port 9000            # use a different port
.\run.ps1 -NoBrowser             # don't auto-open a browser tab
.\run.ps1 -HostAddress 0.0.0.0   # allow LAN access (not recommended - see Privacy below)
```

### Manual setup (alternative to run.ps1)
```powershell
cd backend
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python app.py
```

## Using it

The top of the page has three always-clickable tabs — **1. Provide Bundle**, **2. Analyzing**, **3. Results** — so you can jump back to tweak settings or check a previous tab at any time; nothing forces a strict linear flow.

1. **Provide a bundle** (tab 1) — drag & drop an archive (`.tar.xz`, `.tgz`, `.tar.bz2`, `.zip`, …), or paste a path already on disk (file or an already-extracted folder). Format (sosreport/supportconfig/crm_report) is auto-detected.
2. **Say what you're investigating** — in the "🎯 What are you investigating?" box, describe the specific issue, e.g. *"find root cause of NC and IP cluster resource restart issue"*. This steers both the mechanical scan (a dedicated Focused Findings section, keyword-tagged results) and the AI report (which answers that question directly and demotes unrelated findings to a short closing section). Leave it blank for a generic full-bundle analysis.
3. **Configure your AI model** — right below, in the same panel: pick a provider, then (for Azure OpenAI) pick an **authentication type** — API Key or Microsoft Entra ID — and fill in the fields for that choice. Optionally check "Remember these settings on this device". Filling this in now means a full AI-reasoned report generates **automatically** as soon as the scan finishes — no extra click. This panel lives permanently on tab 1; use the "✏️ Edit focus & AI settings" shortcut on the Results tab to jump straight back to it.
4. **(Optional) scope the analysis** — expand "Advanced options" to restrict the scan to a specific date/time range or a time ± window, instead of the whole archive. Useful when you already know roughly when an incident happened.
5. **Run analysis** — the view auto-advances to tab 2 to show live progress, then to tab 3 once done. Results open on the **AI Root Cause Report** tab by default, streaming in automatically if you configured a model in step 3 (or click "Generate root-cause report" there if you didn't). Other tabs: the full evidence **Digest**, a filterable **Findings** list (with a "show only findings matching my focus 🎯" toggle), and a cross-file **Timeline**.
6. **Regenerate or refine** — click "✏️ Edit focus & AI settings" to jump back to tab 1, tweak the focus text or switch AI providers/auth type, then return to tab 3 and click Generate again to regenerate without re-running the mechanical scan.
7. **Download** the combined AI report + evidence digest as a single Markdown file.

Recent analyses from the current server session are listed under "Recent analyses" (top right) so you can revisit results without re-uploading.

### A note on focused analysis

The mechanical engine's keyword matching is intentionally simple (it just tags findings that literally contain your focus words), while the AI layer does the actual causal reasoning across the *entire* evidence base — so it can, for example, connect a flapping NIC (`NIC Link is Down`) to a restart of a resource named `rsc_ip_cluster` even though "NIC" and "IP" don't share a literal keyword. If you ask about "NC and IP" and the mechanical Focused Findings section looks sparse, that's expected — the AI report is where the deeper connection gets made. Use the Findings tab's focus filter to see exactly what was keyword-matched, and the Digest/Timeline to see everything else the AI had available to reason over.

## AI provider setup

Pick whichever you have access to — no code changes needed, it's a dropdown in the UI (tab 1, or jump there any time via "✏️ Edit focus & AI settings" on the Results tab).

| Provider | Authentication | What you need | Notes |
|---|---|---|---|
| **OpenAI** | API Key | API key from platform.openai.com | Model field defaults to `gpt-4o`; use any chat-completions-capable model name |
| **Anthropic (Claude)** | API Key | API key from console.anthropic.com | Model field defaults to a Claude Sonnet model name |
| **Azure OpenAI** | API Key | API key + resource endpoint URL + **deployment name** (not the base model name) | Deployment name is whatever you named it when you deployed the model in Azure AI Foundry / Azure OpenAI Studio |
| **Azure OpenAI** | Microsoft Entra ID | Directory (tenant) ID + Application (client) ID + client secret, from an app registration, plus the same endpoint + deployment name | For enterprise environments where API keys are locked down by policy. The app registration needs the **Cognitive Services OpenAI User** RBAC role (or equivalent) assigned on the target Azure OpenAI resource — see below. |
| **Ollama (local)** | None | [Ollama](https://ollama.com) installed and running locally (`ollama serve`), with a model pulled (`ollama pull llama3.1`) | 🔒 **Fully offline** — the bundle's evidence digest never leaves your machine. Best choice for sensitive infrastructure data. |

**API key / secret handling:** credentials are entered in the browser and sent directly from your local backend to the provider you chose (or, for Entra ID, to `login.microsoftonline.com` to exchange for a short-lived access token, then to your Azure OpenAI endpoint), for that one request only. They are never written to disk unless you explicitly check "Remember these settings on this device" (which stores them in your browser's `localStorage`, not on any server).

### Setting up Microsoft Entra ID authentication for Azure OpenAI

1. In the Azure Portal, register an application under **Microsoft Entra ID → App registrations → New registration**. Note its **Application (client) ID** and **Directory (tenant) ID**.
2. Under that app registration's **Certificates & secrets**, create a new **client secret**. Copy its value immediately (it's only shown once).
3. On your **Azure OpenAI resource** (not the app registration), go to **Access control (IAM) → Add role assignment**, and grant the app registration the **Cognitive Services OpenAI User** role (or a custom role with equivalent `Microsoft.CognitiveServices/accounts/OpenAI/*` permissions).
4. In LDI Copilot, choose **Azure OpenAI** as the provider and **Microsoft Entra ID** as the authentication type, then fill in the Tenant ID, Client ID, Client secret, your Azure OpenAI endpoint URL, and the deployment name.
5. A fresh access token is requested from `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` on every "Generate report" click (scope `https://cognitiveservices.azure.com/.default`) — tokens are not cached, so there's no stale-token expiry to worry about, and no token is ever written to disk.

If authentication succeeds but the chat call still fails, double-check step 3 — a valid token with insufficient RBAC on the target resource surfaces as an HTTP 403 from the chat-completions call, not a login failure.

## Privacy & data handling

- The server binds to `127.0.0.1` (localhost) by default — nothing on your network can reach it unless you explicitly pass `-HostAddress 0.0.0.0`, which isn't recommended given what these bundles contain.
- Uploaded archives and their extracted contents/analysis output are kept under `backend/data/jobs/<job_id>/` for the lifetime of the server process. Delete a job's data any time via the API (`DELETE /api/jobs/{id}`) or just delete the folder; nothing is auto-uploaded anywhere.
- The AI synthesis step sends the **evidence digest** (system/cluster names, log excerpts, IPs, timestamps, etc. — not the raw uploaded archive) to whichever provider you pick. Use **Ollama** if the bundle must never leave the machine.
- The frontend has zero external/CDN dependencies (including its own small Markdown renderer, and the Microsoft logo mark which is drawn as an inline SVG) so the UI itself works with no internet access — only the AI synthesis step (for non-Ollama providers) needs connectivity.

## Architecture

```
ldi-copilot/
├── run.ps1                    # one-command launcher (venv + deps + server)
├── CHANGELOG.md
├── backend/
│   ├── app.py                 # FastAPI server: job management, REST API, static file serving
│   ├── requirements.txt
│   ├── engine/
│   │   └── analyzer_core.py   # mechanical scanning engine (extraction, detection, pattern
│   │                          # matching, fact-checks, timeline, digest, focus-keyword
│   │                          # tagging) - sosreport + supportconfig + crm_report, with a
│   │                          # run_analysis() library API
│   ├── ai/
│   │   ├── providers.py       # OpenAI / Anthropic / Azure OpenAI (API key + Entra ID) /
│   │   │                      # Ollama streaming clients
│   │   └── prompts.py         # focus-aware RCA synthesis system prompt + evidence-digest user prompt
│   └── data/jobs/<id>/         # per-analysis uploaded file + extracted tree + output (gitignored)
├── frontend/
│   ├── index.html             # persistent top-level tabs (Provide Bundle/Analyzing/Results),
│   │                          # focus+AI config panel permanently inlined in tab 1
│   ├── app.js                 # upload, polling, rendering, SSE streaming, tiny MD renderer,
│   │                          # top-level tab switching, auth-type-aware AI config, auto-chained synthesis
│   └── styles.css
└── samples/                    # synthetic test fixtures (fake_sosreport, fake_supportconfig,
                                 # fake_crm_report, fake_crm_report_multi) - safe, fictional
                                 # data for trying the app
```

**Request flow:** browser uploads a bundle (+ optional focus text + optional AI config incl. auth type, all collected in tab 1) → FastAPI saves it and starts a background thread running `run_analysis(..., focus=...)` → browser polls job status, tab auto-advances to "2. Analyzing" → once done, browser fetches the digest/findings/facts/timeline JSON, tab auto-advances to "3. Results" and renders the dashboard, opening on the AI Root Cause Report tab → if AI settings were filled in, the browser automatically POSTs the provider credentials (+ auth type) + focus text + the job's digest to `/api/jobs/{id}/synthesize`, which (for Entra ID) first exchanges the tenant/client/secret for a bearer token, then streams the model's response back via Server-Sent Events. The focus+AI panel never moves in the DOM — the Results tab's "Edit focus & AI settings" button just switches the active top-level tab back to it, so a second analysis from tab 1 always finds its fields intact.

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
- Single-user, single-machine tool: job state is in-memory and does not survive a server restart (uploaded files/analysis output on disk do persist under `backend/data/jobs/` until deleted).
- No authentication on the local server itself — appropriate for local personal use; do not expose this server beyond localhost.
