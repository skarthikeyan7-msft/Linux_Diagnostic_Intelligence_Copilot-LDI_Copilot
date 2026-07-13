# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-07-13

### Changed - BREAKING
- **Project renamed and rebranded**: `sosreport-rca-webapp` is now **LDI Copilot (Linux Diagnostic Intelligence Copilot)**. Same project, same commit history, new identity — the GitHub repository, page title, header branding, `localStorage` settings key, and downloaded-report filename all reflect the new name. Old `localStorage` entries under the previous settings key are intentionally left orphaned rather than migrated (their shape changed anyway - see the `auth_type` restructuring below).
- **AI provider registry restructured around authentication type**: every provider's config now lives under `auth_types: {key: {label, fields}}` instead of a flat `fields` list. This is a breaking change to the `/api/providers` response shape and the payload accepted by `/api/jobs/{id}/synthesize` (both now expect/return an `auth_type` alongside `provider`) - not backward compatible with v1.x API callers.
- **UI navigation restructured as persistent top-level tabs**: "Provide Bundle", "Analyzing", and "Results" are now always-visible, freely-clickable tabs at the top of the page instead of a forced linear 3-step wizard. The focus + AI settings panel that used to physically relocate between step 1 and the results view now lives permanently in the "Provide Bundle" tab; the Results tab's AI section gained a "✏️ Edit focus & AI settings" button that jumps back to it instead.

### Added
- **Microsoft Entra ID authentication for Azure OpenAI**: choose "Microsoft Entra ID" as the authentication type (alongside the existing API Key option) and authenticate via an app registration (service principal) - Tenant ID, Client ID, and Client secret - instead of an API key. Uses the standard OAuth2 client-credentials flow against `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` (scope `https://cognitiveservices.azure.com/.default`), then calls Azure OpenAI with an `Authorization: Bearer` header. A fresh token is requested per synthesis call; nothing is cached or written to disk. See the README for full app-registration/RBAC setup steps.
- An **Authentication Type** dropdown appears in the AI config panel whenever the selected provider offers more than one option (currently just Azure OpenAI); other providers are unaffected and still show only their relevant fields.
- Empty-state placeholders on the "Analyzing" and "Results" tabs so visiting them before starting/completing an analysis shows a helpful message instead of a blank panel.
- A small Microsoft logo mark (inline SVG, no external asset) next to the app name in the header.

### Fixed
- Fixed a design flaw in the previous panel-relocation mechanism where starting a second analysis from "Provide Bundle" after visiting "Results" could reference stale/detached DOM nodes; the new architecture (panel never moves, tabs just show/hide) eliminates that class of bug entirely.

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

[2.0.0]: https://github.com/skarthikeyan7-msft/ldi-copilot/releases/tag/v2.0.0
[1.1.0]: https://github.com/skarthikeyan7-msft/ldi-copilot/releases/tag/v1.1.0
[1.0.0]: https://github.com/skarthikeyan7-msft/ldi-copilot/releases/tag/v1.0.0
