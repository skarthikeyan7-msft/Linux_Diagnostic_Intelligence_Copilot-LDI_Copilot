# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-07-13

### Added
- **Focused analysis**: a new "What are you investigating?" field, front and center in Step 1, lets you describe the specific issue you want root-caused (e.g. "find root cause of NC and IP cluster resource restart issue") instead of always getting a generic exhaustive report.
  - The mechanical engine (`backend/engine`) extracts keywords from the focus text and tags every finding/timeline event with `focus_match`. The digest gains a dedicated `## 🎯 Focused Findings` section ahead of the full category breakdown, and matches are marked with 🎯 throughout.
  - Keyword matching treats `_`/`-` as separators (not just whitespace), so it correctly matches short identifiers like `ip`/`nc` embedded in real-world Pacemaker resource names such as `rsc_ip_cluster` or `rsc_nc_share`.
  - The AI synthesis prompt (`backend/ai/prompts.py`) is restructured around the stated focus when one is given: the executive summary and root-cause section answer the focus directly, evidence outside the focus is demoted to a short closing "Other Observations" section, and the model is explicitly told to reason beyond the mechanical keyword matches (e.g. connecting a flapping NIC to an IP-resource restart even though "NIC" and "IP" share no literal keyword).
- **AI model selection moved to Step 1**: the provider/model/API-key configuration panel that used to live at the end (in the AI Root Cause Report tab) now lives in Step 1, alongside the new focus field. Fill it in before running analysis and a full AI-reasoned report is generated **automatically** as soon as the mechanical scan finishes - no extra click needed. Leave it blank to just get the mechanical evidence digest and configure AI later; the same panel relocates into the AI tab afterward so it can still be filled in or tweaked to regenerate without re-running the scan.
- Results now open on the **AI Root Cause Report** tab by default (previously Digest), since that's normally the first thing you want to read.
- A "🎯 Focused on: ..." callout summarizing the stated focus and match count appears above the results tabs.
- The Findings tab gained a "Show only findings matching my focus 🎯" toggle (checked by default when a focus was used) to cut through unrelated noise (e.g. an unrelated STONITH/fencing resource's routine warnings) when investigating one specific resource or subsystem.
- `run_analysis()` / the CLI gained a `focus` parameter / `--focus` flag for the same capability outside the browser UI.
- New synthetic test fixture `samples/fake_crm_report_multi`: a 2-node cluster with two independent problems (an Azure STONITH resource with unrelated API rate-limit noise, and a genuine NIC-flap-induced restart of `rsc_ip_cluster`/`rsc_nc_share`) - used to validate that focus steering correctly promotes the relevant evidence and demotes the unrelated one.

### Changed
- `backend/ai/prompts.py`: `build_messages()` now accepts a `focus_text` parameter; `/api/jobs/{id}/synthesize` accepts an optional `focus_text` override and otherwise reuses the focus text supplied at analysis time.
- `POST /api/analyze` accepts a new optional `focus` form field, stored on the job and threaded through to the mechanical scan.

## [1.0.0] - 2026-07-11

### Added
- Initial release: local browser-based AI agent for root-cause analysis of sosreport, supportconfig, and crm_report/hb_report diagnostic bundles.
- `backend/engine`: mechanical scanning engine (extraction, format detection, pattern matching, structured fact-checks, cross-file timeline, evidence digest) extended from the standalone `sosreport-rca` CLI tool with full crm_report support (per-node categorization, cluster status facts, analysis.txt cross-check) and refactored into an importable `run_analysis()` library API.
- `backend/ai`: pluggable AI provider clients (OpenAI, Anthropic Claude, Azure OpenAI, local Ollama) behind one streaming chat interface, plus the root-cause-synthesis prompt template.
- `backend/app.py`: local FastAPI server - upload/analyze jobs with background execution and progress polling, results API (digest/findings/facts/inventory/timeline), and an AI synthesis endpoint streaming the model's report via Server-Sent Events.
- Dependency-free vanilla HTML/CSS/JS frontend: drag-and-drop upload, time-window scoping controls, results dashboard, AI provider/model picker with optional per-device credential storage, and a small built-in Markdown renderer (zero CDN dependencies).
- `samples/`: synthetic `fake_sosreport`, `fake_supportconfig`, and `fake_crm_report` fixtures.
- `run.ps1`: one-command local launcher (venv + deps + server + browser).

[1.1.0]: https://github.com/skarthikeyan7-msft/sosreport-rca-webapp/releases/tag/v1.1.0
[1.0.0]: https://github.com/skarthikeyan7-msft/sosreport-rca-webapp/releases/tag/v1.0.0
