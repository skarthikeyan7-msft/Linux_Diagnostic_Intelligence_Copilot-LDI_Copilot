# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.3.0] - 2026-07-16

### Added
- **HTTPS/TLS support (`--https`)**: the server can now serve over TLS instead of plain HTTP. Without `--ssl-certfile`/`--ssl-keyfile`, a self-signed certificate is auto-generated once (`backend/certs.py`, new `cryptography` dependency) and reused across restarts under `certs/` (gitignored) - covering `localhost`/`127.0.0.1`/`::1` plus whatever `--host` was requested. Browsers show a one-time "connection isn't private" warning for it, as expected for any self-signed certificate; supply your own trusted certificate via `--ssl-certfile`/`--ssl-keyfile` to avoid that warning entirely. All three launchers (`run.sh`/`run.bat`/`run.ps1`) gained matching `--https`/`--ssl-certfile`/`--ssl-keyfile` passthrough flags.
- **Shared-secret auth gate for non-loopback hosts**: the moment `--host` is anything other than `127.0.0.1`/`localhost`/`::1`, every request (every API route and the page itself, except `/api/health`) now requires an HTTP Basic Auth credential (`backend/auth.py`) - any username, one shared password. A random password is generated and printed once at startup unless `--auth-token` is passed explicitly (to pin a stable one) or `--no-auth` (to disable the gate - only appropriate when network-level access is already restricted, e.g. VPN-only). Requires zero frontend code, since browsers cache a successful Basic Auth credential per-origin and automatically attach it to the page's own subsequent `fetch()` calls. All three launchers gained matching `--auth-token`/`--no-auth` passthrough flags. Built in response to a request to expose a single instance to a globally-distributed support team over the internet - see the new "Sharing with a team" section in README.md and "Running one shared instance instead" in SECURITY.md for exactly what this does and does not protect against (notably: no per-user isolation - every authenticated user of a shared instance sees every job on it).
- **Redaction mapping now shown directly on the Results page**: previously the "🔒 Redacted N hostname(s)/IP address(es)..." summary and its token↔real-value legend were only ever logged to the activity terminal, easy to miss and lost once the terminal scrolled. A new callout now renders right above the AI report itself (between the focus-area summary and the report), with the summary always visible and the full mapping available in a collapsible detail view. Persisted server-side per job (`GET /api/jobs/{id}/redaction`) so it's still shown correctly after navigating away and back, or reopening the job later from "Recent analyses" - not just during the initial streamed generation.

### Fixed
- **Auth middleware silently not applying**: initial implementation called `app.add_middleware(...)` directly inside `main()`, which had no effect on the actually-served app - `uvicorn.run("app:app", ...)` resolves that string by re-importing `app.py` under the module name `app`, a separate module object from the `__main__` copy that runs `main()` (this is what lets `--reload` re-import fresh on file changes). Caught before release by a dedicated live-process test suite that starts the real server as a subprocess and checks actual HTTP responses rather than only unit-testing the function in isolation; fixed by handing the computed token across via an environment variable that both module copies read identically at import time, since `os.environ` (unlike a module-level Python object) is shared process-wide.

## [4.2.4] - 2026-07-16

### Added
- **Proactive `--host` validation before starting the server**: `backend/app.py` now attempts a real (ephemeral-port) bind against the requested `--host` value *before* handing off to uvicorn, catching the exact failure mode reported from a real Azure RHEL 8 VM - passing a cloud VM's public IP, which is NAT'd at the platform edge and never actually assigned to the VM's own network interface. Instead of the raw, context-free `[Errno 99] Cannot assign requested address`, the server now exits immediately with a clear explanation of *why* (cloud public IPs are never locally bindable, regardless of platform) and two concrete fixes (SSH tunnel to keep the safe localhost-only default, or `--host 0.0.0.0` + a properly-scoped cloud firewall rule). Skips the check entirely (zero overhead, zero risk of false positives) for `0.0.0.0`/`127.0.0.1`/`localhost`/`::`/`::1`, so the overwhelmingly common default case is completely unaffected. Verified with a dedicated test suite (8 cases, including the exact reported Azure IP) plus live end-to-end runs confirming normal startup, `--host 0.0.0.0`, and the rejected-bad-IP path all behave correctly.


- **README troubleshooting note for cloud VM users** (Azure/AWS/GCP): documents why passing a cloud VM's *public* IP to `--host`/`-HostAddress` always fails with `[Errno 99] Cannot assign requested address` (cloud public IPs are NAT'd at the platform level and are never actually configured on the VM's own network interface, so the OS can't bind to them) - reported from a real Azure RHEL 8 VM. Recommends binding to `0.0.0.0` (or, more safely, using an SSH tunnel and keeping the default localhost-only bind - `ssh -L 8756:127.0.0.1:8756 user@vm-ip`) instead, plus a reminder to scope any cloud firewall rule to a specific source IP rather than the whole internet, and to review [SECURITY.md](SECURITY.md) before exposing this beyond localhost with real customer bundle data.

## [4.2.2] - 2026-07-15

### Fixed
- **`run.sh` failed outright on RHEL 8.x** with a confusing pip error (`Could not find a version that satisfies the requirement fastapi>=0.110 ... from versions: ... 0.83.0`) instead of a clear diagnosis. Root cause: RHEL/CentOS/Alma/Rocky 8's default `python3` is Python 3.6 (long past upstream end-of-life), and the launcher used whatever `python3`/`python` it found on `PATH` without checking its version at all - pip's own version-resolution then silently filtered out every FastAPI release that had already dropped Python 3.6 support, surfacing as an opaque "no matching distribution" error with no indication the real problem was the interpreter, not the package.
- All three launchers (`run.sh`, `run.ps1`, `run.bat`) now validate the resolved Python meets the minimum version (3.10+) *before* touching pip at all, and fail with a clear, actionable message (including the exact `dnf install python3.11` / `apt install python3.11` remediation) if not:
  - `run.sh` now probes `python3.10` through `python3.13` (newest first) *ahead of* the bare `python3`/`python` names - RHEL/CentOS/Fedora commonly have a newer versioned interpreter installed *alongside* an old default, and this ensures it's preferred automatically without any configuration.
  - `run.ps1`/`run.bat` prefer the official Windows `py` launcher's version-selection flags (`py -3.11`, etc.) for the same reason, falling back to bare `python3`/`python`.
  - An explicit `$PYTHON`/`%PYTHON%`/`$env:PYTHON` override is still respected even if it turns out too old (fails loudly naming that specific override, rather than silently substituting something else).
  - A pre-existing `.venv` built against a too-old Python (e.g. from a previous failed run) is now detected and automatically recreated with a valid interpreter, instead of being silently reused and hitting the same pip error again.
- Verified via a dedicated bash test suite using fake versioned-python stubs (no valid interpreter found -> clear RHEL guidance; old + new both present -> newer one auto-selected; explicit `$PYTHON` override validation; stale-venv auto-recreation) plus live functional runs of all three launchers on this machine.

## [4.2.1] - 2026-07-15

### Fixed
- **"2. Analyzing" tab lost its content after moving to Results**: navigating to "3. Results" once a scan finished, then clicking back to "2. Analyzing", showed the "No analysis is currently running" placeholder instead of the just-completed scan's progress log - even though that log's content was still sitting in the DOM. Root cause: the placeholder-vs-content toggle was driven by `state.analyzing` (true only while a scan is actively in flight right now), which flips to `false` the moment results load. Fixed with a new, separately-tracked `state.hasProgressContent` flag that stays `true` from the moment a scan starts until a genuinely *new* one begins (`startAnalysis()`) - so the completed run's log now stays visible when navigating back to "2. Analyzing" at any point, exactly as long as the user hasn't started another analysis yet. Also fixed the same gap for jobs opened via "Recent analyses" (which never went through the live-polling code path that used to populate this log at all) - `loadResults()` now always renders the loaded job's progress history.

## [4.2.0] - 2026-07-15

### Fixed
- **supportconfig SAR detection**: `check_sar_performance()` required the *filename* to contain the substring "sar", but real-world supportconfig bundles name files inside their `sar/` directory by date/day-of-month only (e.g. `sar/15`) - never containing the word "sar" itself. Every supportconfig SAR file was silently missed. Fixed by matching on directory *membership* (an exact path segment equal to `sar`) in addition to the filename check.
- **sosreport SAR detection**: `sos_commands/sar/*` (pre-rendered text) was already checked, but the raw sysstat spool directory (`var/log/sa/*`) sosreport also copies in wholesale was not - occasionally this contains pre-rendered `sarDD`/`sadDD` text reports alongside the (correctly still-unparsed) binary `saDD` files. Now checked too, with `is_probably_text()` filtering out the binary files before attempting to parse them as text (never decodes raw binary sar data - see README/SECURITY.md).

### Changed
- **Scan progress reporting now names the current file**: the periodic "...scanned N/Total files, M distinct findings so far" progress line only ever printed *after* a file finished, so a single very large/slow file (which can legitimately take minutes) produced a long silent gap with no indication of which file was responsible. The check now fires *before* each file starts, and the message includes that file's path: `...scanning var/log/audit/audit.log (19/912 files, 1905 distinct findings so far)`.

## [4.1.0] - 2026-07-15

### Added
- **Cross-platform launchers**: new `run.sh` (bash - Linux/macOS/WSL/Git Bash) and `run.bat` (Windows Command Prompt) mirror `run.ps1`'s behavior (create/reuse `.venv`, install dependencies, start the server, open the browser). `run.ps1` itself is now also portable to `pwsh` (PowerShell 7+) on Linux/macOS, auto-detecting the correct venv layout (`Scripts\python.exe` vs `bin/python`) via the `$IsWindows` automatic variable. All three accept equivalent `--host`/`--port`/`--no-browser` (or PowerShell-cased) flags. Verified working end-to-end via Git Bash (`run.sh`) and Command Prompt (`run.bat`).
- **README documentation** for a real, easy-to-hit gotcha discovered while testing `run.bat`: many Windows machines (including Microsoft-managed corporate devices) have the `NoDefaultCurrentDirectoryInExePath` security policy enabled, which makes cmd.exe unable to find a *bare* `run.bat` typed in the current folder (even at a real interactive prompt) - always use `.\run.bat` (or `call run.bat`) instead, which works unconditionally.

### Changed
- Confirmed (via a fresh audit) that the Python backend itself was already fully cross-platform - the only platform-specific code paths (`ollama_manager.py`'s Windows-only `subprocess.CREATE_NO_WINDOW` flag, and `analyzer_core.py`'s Windows-path-sanitizing archive extraction fix from v4.0.0) were already correctly guarded behind `sys.platform`/`os.name` checks and are no-ops on Linux/macOS.

### Removed
- **Microsoft logo watermark** removed from the bottom-right corner of the UI (`frontend/index.html`'s `.ms-logo-corner` block and its CSS in `frontend/styles.css`) - this is an independent personal tool, not an official Microsoft product, and shouldn't visually imply otherwise. Can be added back locally if desired; not part of the shipped UI going forward.

## [4.0.0] - 2026-07-15

### Added - BREAKING (major version: new analyzer suite + interactive chat)
- **Seven new mechanical analyzers**, wired into `run_structured_checks()`/`build_digest()` and run automatically on every analysis (auto-detected - no analysis-type picker):
  - **📊 Performance (SAR)** (`check_sar_performance`) - parses sysstat's pre-rendered `sar` text tables (CPU/memory/disk I/O/network/load) into time series + a condensed summary. New `detect_vm_timezone()` utility labels every SAR timestamp with the analyzed VM's own detected timezone (`/etc/timezone`, captured `date` output, or `/etc/localtime`) so analyst/customer timezone confusion can't happen. New **Performance** sub-tab (Results) renders dependency-free `<canvas>` line charts per metric group, backed by a new `GET /api/jobs/{id}/sar_series` endpoint.
  - **💥 Crash / Coredump analysis** (`check_crash_analysis`) - ABRT report correlation (backtrace/reason/cmdline/executable/time), kdump configuration, vmcore presence/size, kernel oops/panic signature counts. Scoped to already-textual bundle artifacts, not raw-core-plus-gdb symbolication.
  - **🥾 Boot performance** (`check_boot_performance`) - `systemd-analyze` startup breakdown, slowest-unit ("blame") ranking, and critical-chain tree, when captured.
  - **🛡️ Security (SELinux/AppArmor)** (`check_security_mac`) - enforcing/permissive status, AppArmor profile counts, and structured denial breakdowns by SELinux scontext/tcontext/tclass or AppArmor profile/operation.
  - **📦 Recent package changes** (`check_package_drift`) - installed-package timestamps plus yum/dnf transaction history where available, with a dedicated "changed in the 7 days before capture" view.
  - **🔗 Service failure cascade** (`check_systemd_cascade`) - detects `Dependency failed for X`/`Triggering OnFailure=` evidence and clusters near-simultaneous multi-unit failures into a likely-trigger → cascaded-units view.
  - **🐳 Container correlation** (`check_container_logs`) - Docker/Podman `ps` snapshot parsing, flags non-zero exit codes (with a SIGKILL/SIGTERM/SIGSEGV note) and restart-looping containers, correlated with host-level OOM evidence in dmesg/messages.
  - Each ships its own conditionally-rendered digest section (only appears if relevant data was found), and a new **"Analysis focus areas"** checkbox row (Step 1 → Advanced options) lets you narrow which sections actually render (every check still runs regardless -`facts.json`/the API always has the full data). Wired end-to-end: frontend checkboxes → `focus_areas` form field → `run_analysis(focus_areas=...)` → `build_digest()` section gating.
- **TCPdump/pcap analyzer** (`backend/engine/pcap_analyzer.py`, new `dpkt` dependency) - optional standalone packet-capture upload (Step 1, second upload slot) analyzed as **metadata only**: packet/byte counts, top talkers, protocol mix, TCP anomaly counts (resets, suspected retransmissions, a rough port-scan heuristic), DNS query summary, packets/sec timing. **Raw payload content is never parsed, stored, or sent anywhere** - see `SECURITY.md` for the full privacy rationale. New `pcap_path` param on `run_analysis()`; new `pcap_file` upload field on `POST /api/analyze`.
- **Interactive follow-up chat** on the Results → AI Root Cause Report tab: a persistent chat thread below the generated report lets you send custom instructions ("focus more on the network side", "explain the timeline gap between 14:02 and 14:05") and get a reply **in the context of the same conversation** (not a fresh disconnected question). New `POST /api/jobs/{id}/chat` (streams via SSE, replays capped conversation history), `GET /api/jobs/{id}/chat` (restore on reload), `DELETE /api/jobs/{id}/chat` (reset follow-ups without discarding the report). `synthesize()` now seeds `JOBS[id]["conversation"]` with the system+digest+report turn on every (re)generate.
- **Windows-path-sanitization fix in archive extraction**: `safe_extract_tar`/`safe_extract_zip` now sanitize Windows-illegal characters (`< > : " | ? *`) in archive member names before extracting - discovered via the crash analyzer, since real-world ABRT crash-report directories are named like `ccpp-2026-07-10-11:15:22-9999`, which would otherwise silently fail to extract at all on this tool's own (Windows) runtime, making the crash analyzer see nothing for the most common real-world case. Extraction now succeeds (with the sanitized name) instead of being silently dropped into `extraction_skipped.json`.

### Changed - BREAKING
- `run_analysis()` gained new optional parameters `focus_areas` and `pcap_path`; `_DigestArgs`/`build_digest()` gained `enabled_sections`. Fully backward compatible for existing callers (both default to "everything enabled", matching pre-v4.0.0 behavior) - flagged as breaking only because of the size of the new public surface area on the library API.
- `backend/requirements.txt` gained `dpkt>=1.9.8` - the project's first runtime dependency beyond FastAPI/uvicorn/python-multipart.

## [3.1.2] - 2026-07-14

### Changed
- Renamed the "Generate root-cause report" / "Regenerate root-cause report" button to **"Generate log analysis"** / **"Regenerate log analysis"** (Step 1's focus+AI panel drives the Results/AI tab's button in all states: initial, post-generation, and error-recovery).

## [3.1.1] - 2026-07-14

### Fixed
- **OpenAI/Azure OpenAI "reasoning" model support**: `stream_openai()` and `stream_azure_openai()` hardcoded `temperature: 0.2` on every request, which OpenAI's reasoning model family (o1, o3, o3-mini, o4-mini, ...) - and Azure OpenAI deployments of them - reject outright with `HTTP 400: Unsupported value: 'temperature' does not support 0.2 with this model. Only the default (1) value is supported.` Since Azure deployment names are user-defined, there's no reliable way to detect a reasoning-model deployment by name ahead of time. Fixed by reacting to the actual API error instead: both functions now retry once without `temperature` whenever this specific error occurs, letting the API fall back to its own default (1). Safe to retry cleanly - the API rejects invalid parameters before streaming any content, so the retry never duplicates output. Verified via a mocked-HTTP unit test asserting exactly two calls (temperature included, then removed) and a successful result from the retry.

## [3.1.0] - 2026-07-14

### Fixed
- **Activity terminal Ollama Start/Stop buttons**: Start stayed enabled (looked "stuck on") even while Ollama was confirmed running, and Stop was permanently disabled whenever Ollama was reachable but not started by LDI Copilot itself (the common case when using the Ollama desktop app), making it look broken. Root cause was twofold: `renderOllamaBadge()` gated Stop's disabled state on `status.managed` (whether *this app* spawned the process) instead of whether Ollama was actually running, and `startOllama()`'s `finally` block unconditionally re-enabled Start regardless of the outcome. Both buttons now reflect actual Ollama state (running/starting → Start disabled, Stop enabled; otherwise the reverse) - Stop remains safe to click in the "not managed by this app" case, since the backend already no-ops with a clear reason instead of terminating an instance it didn't launch.

### Added
- **"🔌 Test AI connectivity" button** in the focus+AI panel (Step 1): sends a tiny fixed test message (never any bundle/job data) to the currently configured provider/credentials and reports success or failure inline plus in the activity terminal - useful for confirming an API key, endpoint, or Ollama model actually works before running a full analysis. Starts Ollama first (like Generate) when Ollama is selected. New `POST /api/test-connection` endpoint; validation logic shared with `/synthesize` via a new `_validate_provider_auth()` helper.
- **AI-generated content disclaimer**: a persistent "⚠️ AI-generated content may be incorrect or incomplete" notice above every AI Root Cause Report, and prepended to the downloaded `.md` report so it travels with the file if shared outside the app.

## [3.0.0] - 2026-07-13

### Changed - BREAKING
- **Reclassified as a major version.** The v2.2.0 changes below (shipped minutes earlier) introduce enough breaking behavior change to warrant a major version rather than minor:
  - **Default AI provider changed from OpenAI to Ollama.** Anyone relying on the previous default (no saved settings + no explicit provider chosen) will now get a local Ollama call instead of a cloud OpenAI call.
  - **A new mandatory external-send confirmation gate** now blocks any non-local `synthesize` call from the UI until the user explicitly checks "I confirm I'm authorized to share this bundle's data with an external AI provider" - a previously unconfirmed workflow (fill in credentials, click Generate) no longer completes silently for non-Ollama providers.
  - **Redaction is now applied by default** (`redact: true`) for all non-local providers - external providers receive a modified (token-substituted) evidence digest by default where they previously received the raw digest, a meaningful change in what data actually leaves the machine for existing API integrations.
- No functional code changes in this release beyond the version bump itself and this changelog/README entry - see the [2.2.0] entry immediately below for the full technical changelog of what shipped (Ollama auto-start/control, redaction, default-provider change, layout, SECURITY.md).

## [2.2.0] - 2026-07-13

### Added
- **Ollama auto-start**: clicking "Generate root-cause report" with Ollama selected now automatically starts `ollama serve` if it isn't already running, streaming its startup log into the activity terminal. The terminal's header also gained a toolbar with an Ollama status badge and manual **Start**/**Stop**/**⟳ Refresh** buttons. `backend/ai/ollama_manager.py` (new) never spawns a duplicate instance if Ollama is already reachable (e.g. via the Ollama desktop app), and Stop only ever terminates a process this app itself spawned - it will never touch an externally-managed instance. New endpoints: `POST /api/ollama/start`, `POST /api/ollama/stop`, `GET /api/ollama/status`.
- **Sensitive-data redaction for non-local providers**: whenever a non-Ollama provider is selected, the evidence digest has its known hostnames/node names (from this analysis's own facts) and IPv4 addresses replaced with stable, meaningless tokens (`HOST-1`, `IP-1`, …) before being sent externally. A local-only "legend" mapping tokens back to real values is logged to the activity terminal - this mapping is never part of the outbound request. Controlled by a new "🔒 Redact known hostnames & IP addresses before sending" checkbox (checked by default), implemented in `backend/ai/redaction.py` (new) and wired through a new optional `redact` field on `POST /api/jobs/{id}/synthesize` (default `true`).
- **Explicit external-send confirmation gate**: a required "I confirm I'm authorized to share this bundle's data with an external AI provider" checkbox must be checked before generating a report with any non-local provider - enforced at click-time, not just as a passive warning.
- **`SECURITY.md`**: new document covering the recommended one-instance-per-engineer deployment model for team rollout, exactly what data leaves the machine and when, the redaction feature's guarantees and limitations, a provider risk ordering (Ollama > org-governed Azure OpenAI via Entra ID > public consumer APIs), retention/cleanup guidance, and an explicit list of what this tool does not provide (encryption at rest, audit logging, RBAC, DLP, compliance certification).

### Changed
- **Ollama is now the default AI provider** - selected automatically when no saved settings exist, and listed first in the provider dropdown. It remains the only fully-offline option and requires no credentials.
- **Layout widened**: the main content panel is noticeably wider, and the activity terminal now docks flush along the *entire* right edge of the viewport (full height, no floating-card margin or rounded outer corners) instead of a smaller floating sidebar card.

## [2.1.1] - 2026-07-13

### Changed
- The Microsoft logo watermark in the bottom-right corner now includes a "Microsoft" text label next to the mark, styled as a standard logo+wordmark lockup, instead of the logo mark alone.

## [2.1.0] - 2026-07-13

### Added
- **Activity terminal**: a persistent, timestamped log panel on the right side of the page, visible no matter which of the three main tabs (Provide Bundle / Analyzing / Results) is active. Mirrors background progress across every stage - bundle selection, the mechanical scan's own progress lines (as they arrive from polling), AI synthesis start/streaming completion, model-availability checks, downloads, and resets - with level-based coloring (info/success/warn/error) and a "Clear" button. Complements, rather than replaces, the existing detailed progress log inside the Analyzing tab.
- **Model dropdown with live availability checking**: the free-text "Model" field for OpenAI, Anthropic, and Ollama (Azure OpenAI's "deployment" field is unaffected - deployment names are user-defined) is now a `<select>` populated from a curated `known_models` list per provider, plus a "Custom / other model…" fallback for anything not yet in the list. A new **"🔎 Check available models"** button calls the new `POST /api/models` endpoint, which live-queries the provider (OpenAI `GET /v1/models`, Anthropic's Models API, or Ollama's `GET /api/tags` for whatever's actually pulled locally) and **greys out (disables)** any known model not confirmed available - without silently changing your current selection. The check is best-effort and non-blocking: missing credentials, invalid keys, or network failures simply leave every option selectable with an explanatory status message, never a hard error.
- `backend/ai/providers.py` gained `list_models()` / `list_models_openai()` / `list_models_anthropic()` / `list_models_ollama()` and a `KNOWN_MODELS` registry; `backend/app.py` gained `POST /api/models` (always returns HTTP 200 with `{available, error}`, never raises, for a failed live check).

### Changed
- **Microsoft logo relocated**: moved from the header (next to the app name) to a small fixed watermark in the bottom-right corner of the viewport.
- **Project name standardized** to "Linux Diagnostic Intelligence Copilot - LDI Copilot" in prominent branding spots (page title, README, source file headers); the compact "LDI Copilot" form remains in the header nav, console/log output, and buttons.
- Two-column page layout: main content on the left, the new activity terminal on the right (stacks vertically below on narrow viewports).

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

[4.3.0]: https://github.com/skarthikeyan7-msft/Linux_Diagnostic_Intelligence_Copilot-LDI_Copilot/releases/tag/v4.3.0
[4.2.4]: https://github.com/skarthikeyan7-msft/Linux_Diagnostic_Intelligence_Copilot-LDI_Copilot/releases/tag/v4.2.4
[4.2.3]: https://github.com/skarthikeyan7-msft/Linux_Diagnostic_Intelligence_Copilot-LDI_Copilot/releases/tag/v4.2.3
[4.2.2]: https://github.com/skarthikeyan7-msft/Linux_Diagnostic_Intelligence_Copilot-LDI_Copilot/releases/tag/v4.2.2
[4.2.1]: https://github.com/skarthikeyan7-msft/Linux_Diagnostic_Intelligence_Copilot-LDI_Copilot/releases/tag/v4.2.1
[4.2.0]: https://github.com/skarthikeyan7-msft/Linux_Diagnostic_Intelligence_Copilot-LDI_Copilot/releases/tag/v4.2.0
[4.1.0]: https://github.com/skarthikeyan7-msft/Linux_Diagnostic_Intelligence_Copilot-LDI_Copilot/releases/tag/v4.1.0
[4.0.0]: https://github.com/skarthikeyan7-msft/Linux_Diagnostic_Intelligence_Copilot-LDI_Copilot/releases/tag/v4.0.0
[3.1.2]: https://github.com/skarthikeyan7-msft/Linux_Diagnostic_Intelligence_Copilot-LDI_Copilot/releases/tag/v3.1.2
[3.1.1]: https://github.com/skarthikeyan7-msft/Linux_Diagnostic_Intelligence_Copilot-LDI_Copilot/releases/tag/v3.1.1
[3.1.0]: https://github.com/skarthikeyan7-msft/Linux_Diagnostic_Intelligence_Copilot-LDI_Copilot/releases/tag/v3.1.0
[3.0.0]: https://github.com/skarthikeyan7-msft/Linux_Diagnostic_Intelligence_Copilot-LDI_Copilot/releases/tag/v3.0.0
[2.2.0]: https://github.com/skarthikeyan7-msft/Linux_Diagnostic_Intelligence_Copilot-LDI_Copilot/releases/tag/v2.2.0
[2.1.1]: https://github.com/skarthikeyan7-msft/Linux_Diagnostic_Intelligence_Copilot-LDI_Copilot/releases/tag/v2.1.1
[2.1.0]: https://github.com/skarthikeyan7-msft/Linux_Diagnostic_Intelligence_Copilot-LDI_Copilot/releases/tag/v2.1.0
[2.0.0]: https://github.com/skarthikeyan7-msft/Linux_Diagnostic_Intelligence_Copilot-LDI_Copilot/releases/tag/v2.0.0
[1.1.0]: https://github.com/skarthikeyan7-msft/Linux_Diagnostic_Intelligence_Copilot-LDI_Copilot/releases/tag/v1.1.0
[1.0.0]: https://github.com/skarthikeyan7-msft/Linux_Diagnostic_Intelligence_Copilot-LDI_Copilot/releases/tag/v1.0.0
