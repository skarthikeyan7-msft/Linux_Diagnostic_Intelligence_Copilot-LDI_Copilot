# sosreport-rca-webapp

A local, browser-based AI agent for deep root-cause analysis of **sosreport** (Red Hat), **supportconfig** (SUSE), and **crm_report/hb_report** (Pacemaker/Corosync HA cluster) diagnostic bundles.

Drop an archive in the browser, pick an AI model, and get a ranked, evidence-cited root-cause report — built on the same mechanical evidence-scanning engine as the [`sosreport-rca`](../sosreport-rca) CLI tool, extended with full `crm_report` support and wrapped in a local web UI with pluggable AI providers.

![type](https://img.shields.io/badge/status-personal%20tool-informational) ![privacy](https://img.shields.io/badge/data-stays%20local-brightgreen)

## Why a webapp on top of the CLI tool

The CLI (`sosreport-rca`) is great for scripting/automation. This project wraps the same analysis engine in a browser UI so you can:
- Drag-and-drop a bundle instead of remembering CLI flags
- **Choose which AI model does the reasoning** — OpenAI, Anthropic (Claude), Azure OpenAI, or a fully local Ollama model — per analysis, right from the UI
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

1. **Provide a bundle** — drag & drop an archive (`.tar.xz`, `.tgz`, `.tar.bz2`, `.zip`, …), or paste a path already on disk (file or an already-extracted folder). Format (sosreport/supportconfig/crm_report) is auto-detected.
2. **(Optional) scope the analysis** — expand "Analysis options" to restrict the scan to a specific date/time range or a time ± window, instead of the whole archive. Useful when you already know roughly when an incident happened.
3. **Run analysis** — watch live progress, then review the results dashboard: summary cards, cluster status (for `crm_report`), the full evidence **Digest**, a filterable **Findings** list by category/severity, and a cross-file **Timeline**.
4. **Generate an AI root-cause report** — go to the "AI Root Cause Report" tab, pick a provider, fill in credentials, and click Generate. The evidence digest is sent to the model as context; the model reasons over it (root cause vs. cascading symptoms vs. noise) and streams back a structured report.
5. **Download** the combined AI report + evidence digest as a single Markdown file.

Recent analyses from the current server session are listed under "Recent analyses" (top right) so you can revisit results without re-uploading.

## AI provider setup

Pick whichever you have access to — no code changes needed, it's a dropdown in the UI.

| Provider | What you need | Notes |
|---|---|---|
| **OpenAI** | API key from platform.openai.com | Model field defaults to `gpt-4o`; use any chat-completions-capable model name |
| **Anthropic (Claude)** | API key from console.anthropic.com | Model field defaults to a Claude Sonnet model name |
| **Azure OpenAI** | API key + resource endpoint URL + **deployment name** (not the base model name) | Deployment name is whatever you named it when you deployed the model in Azure AI Foundry / Azure OpenAI Studio |
| **Ollama (local)** | [Ollama](https://ollama.com) installed and running locally (`ollama serve`), with a model pulled (`ollama pull llama3.1`) | 🔒 **Fully offline** — the bundle's evidence digest never leaves your machine. Best choice for sensitive infrastructure data. |

**API key handling:** keys are entered in the browser and sent directly from your local backend to the provider you chose, for that one request only. They are never written to disk unless you explicitly check "Remember these settings on this device" (which stores them in your browser's `localStorage`, not on any server).

## Privacy & data handling

- The server binds to `127.0.0.1` (localhost) by default — nothing on your network can reach it unless you explicitly pass `-HostAddress 0.0.0.0`, which isn't recommended given what these bundles contain.
- Uploaded archives and their extracted contents/analysis output are kept under `backend/data/jobs/<job_id>/` for the lifetime of the server process. Delete a job's data any time via the API (`DELETE /api/jobs/{id}`) or just delete the folder; nothing is auto-uploaded anywhere.
- The AI synthesis step sends the **evidence digest** (system/cluster names, log excerpts, IPs, timestamps, etc. — not the raw uploaded archive) to whichever provider you pick. Use **Ollama** if the bundle must never leave the machine.
- The frontend has zero external/CDN dependencies (including its own small Markdown renderer) so the UI itself works with no internet access — only the AI synthesis step (for non-Ollama providers) needs connectivity.

## Architecture

```
sosreport-rca-webapp/
├── run.ps1                    # one-command launcher (venv + deps + server)
├── backend/
│   ├── app.py                 # FastAPI server: job management, REST API, static file serving
│   ├── requirements.txt
│   ├── engine/
│   │   └── analyzer_core.py   # mechanical scanning engine (extraction, detection, pattern
│   │                          # matching, fact-checks, timeline, digest) - sosreport +
│   │                          # supportconfig + crm_report, with a run_analysis() library API
│   ├── ai/
│   │   ├── providers.py       # OpenAI / Anthropic / Azure OpenAI / Ollama streaming clients
│   │   └── prompts.py         # RCA synthesis system prompt + evidence-digest user prompt
│   └── data/jobs/<id>/         # per-analysis uploaded file + extracted tree + output (gitignored)
├── frontend/
│   ├── index.html
│   ├── app.js                 # upload, polling, rendering, SSE streaming, tiny MD renderer
│   └── styles.css
└── samples/                    # synthetic test fixtures (fake_sosreport, fake_supportconfig,
                                 # fake_crm_report) - safe, fictional data for trying the app
```

**Request flow:** browser uploads a bundle → FastAPI saves it and starts a background thread running `run_analysis()` → browser polls job status → once done, browser fetches the digest/findings/facts/timeline JSON and renders the dashboard → on "Generate root-cause report", the browser POSTs provider credentials + the job's digest to `/api/jobs/{id}/synthesize`, which streams the model's response back via Server-Sent Events.

## crm_report / hb_report support

Detects the crmsh `crm report` layout (`analysis.txt`, `cib.xml`, `members.txt`, `crm_mon.txt`, per-node subdirectories named by hostname) and adds:
- Per-node categorization (a `pacemaker.log`/`corosync.log` inside any node's subfolder is recognized regardless of which node it's under)
- A dedicated **Cluster Status** summary: nodes detected, offline/unclean nodes (parsed from `crm_mon.txt`), and Failed Resource Actions
- `analysis.txt` (crm_report's own built-in CRIT:/ERROR:/WARNING: scan) is surfaced verbatim as an independent cross-check against this tool's own findings
- The AI synthesis prompt is specifically primed to use per-node evidence (e.g. CPU/memory exhaustion or kernel soft-lockups on the node that got fenced) to explain *why* a fencing/STONITH event happened, not just report that it happened

## Limitations

- This is heuristic pattern-matching plus structured fact-checks, not a certified rules engine (e.g. Red Hat Insights, SUSE's SCA tool). Treat the digest as a strong evidence base for the AI/human review step, not an infallible verdict.
- Single-user, single-machine tool: job state is in-memory and does not survive a server restart (uploaded files/analysis output on disk do persist under `backend/data/jobs/` until deleted).
- No authentication — appropriate for local personal use; do not expose this server beyond localhost.
