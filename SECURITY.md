# Security & confidential customer data handling

LDI Copilot is built to analyze real customer Linux VM diagnostics (sosreport, supportconfig, crm_report/hb_report) — bundles that routinely contain hostnames, internal IPs, usernames, and sometimes application-specific data. This document describes, honestly and specifically, what the tool technically does and does not do with that data, so you can make an informed decision about using it for customer work and about sharing it with your team.

> **This is not a compliance attestation.** It describes technical behavior only. Before using this tool with customer data at team scale, confirm with your own organization's data-governance, privacy, and compliance contacts that this usage pattern is acceptable for the customer engagements you support. Nothing here should be read as a claim that this tool satisfies any specific regulatory framework, certification, or internal Microsoft policy.

## Recommended deployment model: one instance per engineer

**LDI Copilot is a single-user, localhost-only tool by design** — not a shared, centrally-hosted service:
- The server binds to `127.0.0.1` by default; nothing on your network can reach it unless you explicitly pass `--host 0.0.0.0` (or `.\run.ps1 -HostAddress 0.0.0.0` / `.\run.bat --host 0.0.0.0` / `./run.sh --host 0.0.0.0`), which is **strongly discouraged** for exactly this reason.
- Job state (uploaded bundles, extracted files, analysis output) lives in-memory and under `backend/data/jobs/<id>/` **on the machine running the server** — there is no shared database, no multi-tenant job store, and no per-user accounts, regardless of the auth gate described below.

**The recommended way to roll this out to your entire CSS team is for each engineer to clone the repo and run their own local instance on their own machine** (`.\run.ps1` / `.\run.bat` / `./run.sh`, whichever matches their shell — the tool runs on Windows, Linux, and macOS), the same way they'd run a local dev tool. This means:
- No single point of failure or single repository of customer bundles across the team.
- No new network-accessible attack surface — each instance is exactly as exposed as the engineer's own laptop already is.
- No additional authentication/authorization system needs to be built or trusted, because there isn't a shared service to authenticate against.

This remains the recommended default. If your situation genuinely calls for one shared instance instead (e.g. a globally-distributed support team without per-engineer VMs), read "Running one shared instance instead" below — it is a materially different, riskier architecture, and the mitigations described there reduce but don't eliminate that risk.

## Running one shared instance instead (if you can't avoid it)

As of v4.4.0, if you do run a single instance reachable by more than one person, layered controls are available and (except accounts/Entra ID, which need one-time setup) turn on **automatically** the moment `--host` is anything other than a loopback address:

- **Per-user accounts** (`backend/users.py`, `backend/auth.py`'s `SessionCookieMiddleware`) - real individual sign-in. Provision each teammate with `python backend/manage_users.py add <username>` (prompts for a password, hashed with `hashlib.scrypt` - a memory-hard KDF, never stored or logged in plaintext). The moment at least one account exists, everyone signs in individually at a login page instead of sharing one secret; access for one person can be revoked (`manage_users.py remove <username>`) without affecting anyone else, and failed logins lock an account out after 5 attempts within 15 minutes. This does **not** create per-user data isolation - see below.
- **Microsoft Entra ID SSO** (v4.10.0, `backend/entra_auth.py`, `backend/app.py`'s `/api/auth/entra/*` endpoints) - **the recommended control for teams already in Microsoft 365/Azure AD**. Teammates sign in with their existing organizational Microsoft account via a standard OAuth2 Authorization Code + PKCE flow (RFC 7636) - see "Microsoft Entra ID SSO: security properties" below for the full technical detail. Configured via `--entra-tenant-id`/`--entra-client-id`/`--entra-client-secret`/`--entra-redirect-uri` (or the matching `LDI_COPILOT_ENTRA_*` environment variables, to avoid the client secret appearing in shell history/process list) - all four required together. Can be enabled **alongside** local accounts; the login page offers whichever is actually configured. Restricting *who* can sign in is delegated entirely to Entra ID's own "Assignment required?" app setting (Enterprise applications → your app → Properties) rather than a second, separately-maintained allow-list in this project - one source of truth for who's allowed in, not two that can drift apart.
- Establishing a session via **either** local accounts or Entra ID produces the exact same kind of session cookie - everything downstream (the auth gate itself, `/api/auth/me`, the audit log) treats a session uniformly regardless of which door the user came in through.
- **A shared-secret auth gate** (`backend/auth.py`'s `BasicAuthMiddleware`, the original v4.3.0 control) - every request requires a single shared HTTP Basic Auth credential. Used automatically as a zero-setup fallback whenever neither accounts nor Entra ID is configured yet, or explicitly via `--auth-token` (which always takes priority over accounts/Entra ID, for cases where individual provisioning is overkill). `--no-auth` disables every gate entirely - only if network-level access is already restricted, e.g. VPN-only.
- **`--https`** — TLS via a self-signed certificate (auto-generated and reused under `certs/`, gitignored) or your own certificate via `--ssl-certfile`/`--ssl-keyfile`. Without this, a shared instance sends account/token credentials, Entra ID tokens, and every bundle/report over plain HTTP, readable by anyone positioned on the network path between a user and the server. Entra ID SSO in particular effectively requires this, since Microsoft's own redirect-URI validation strongly prefers `https://` for anything beyond `localhost`.
- **`--require-auth`** — forces whichever gate would apply on a non-loopback host to also apply on `127.0.0.1`, for testing the login flow locally.
- **Sign-in audit log** (v4.10.0, `backend/audit.py`) - every login attempt (success or failure, local account or Entra ID) and every logout is recorded to `backend/data/audit.log` (gitignored, rotates at 5MB keeping 5 backups) - see "Sign-in audit log" below for exactly what is and isn't covered.

**What this combination does and does not give you:**
- ✅ Blocks a stranger who finds the address/port from reaching the tool or any data on it at all.
- ✅ With accounts or Entra ID specifically: individual identity and revocability - you know *who* signed in (not just that *someone* did), and can cut off one person (removing their local account, or removing their Entra ID app assignment) without resetting a secret everyone else also has to update.
- ✅ With Entra ID SSO specifically: no separate password for this tool at all - teammates use the same organizational account/MFA/Conditional Access policies your org already enforces everywhere else, and leaving the org (Entra ID account disabled) automatically revokes access here too, with no separate step in this tool.
- ✅ Encrypts traffic between each user and the server (with `--https`), so credentials/tokens and bundle data aren't sent in the clear.
- ✅ A durable, reviewable **sign-in** history (v4.10.0) - who signed in, how, when, from what IP, and whether it succeeded; see "Sign-in audit log" below for exactly what this covers.
- ❌ Does **not** give per-user *data* isolation, even with accounts/Entra ID. Every authenticated user - regardless of mode - sees the exact same job list (`GET /api/jobs`) and can open, chat about, or delete any job on the instance, including bundles a different teammate uploaded. If your team analyzes different customers' data on the same shared instance, every team member with access can see every customer's bundle.
- ❌ The audit log covers **sign-in/sign-out only** - it does **not** correlate a signed-in identity to specific *job-level* actions (who analyzed which specific bundle, downloaded which report, etc.). See "Sign-in audit log" below for the precise boundary.
- ❌ Does **not** give RBAC (every authenticated user has identical capability - see above) or per-user rate limiting/quotas against a shared AI provider budget.
- ❌ Is not a substitute for real network-layer controls. Combine it with a cloud firewall rule scoped to your team's known IP ranges/VPN CIDR (not `0.0.0.0/0`) whenever possible - every auth gate here is a safety net behind that, not instead of it.

If any of the ❌ items above are unacceptable for the customer engagements you support, go back to one-instance-per-engineer instead.

Example for a globally-distributed team on one Azure VM, with Entra ID SSO plus a firewall rule:
```bash
export LDI_COPILOT_ENTRA_CLIENT_SECRET="the-secret-value"
./run.sh --host 0.0.0.0 --https \
  --entra-tenant-id <directory-tenant-id> --entra-client-id <application-client-id> \
  --entra-redirect-uri https://<vm-address>:8756/api/auth/entra/callback
```
Then scope the cloud NSG/security group rule for that port to your team's IP ranges, and share the URL with your team - each person signs in with their existing Microsoft account, nothing else to distribute or leak. See README.md's "Sharing with a team over the internet" section for the full Azure Portal app-registration walkthrough.

## Microsoft Entra ID SSO: security properties

v4.10.0's "Sign in with Microsoft" option implements the OAuth2 Authorization Code flow with PKCE (RFC 7636) - the standard, Microsoft-recommended pattern for a confidential web client authenticating a real person through a browser (a different flow from the machine-to-machine client-credentials grant `backend/ai/providers.py` uses to *call* Azure OpenAI on the analysis side - see that module's docstring):

- **PKCE** is used even though this is a confidential client (it holds a client secret) - defense-in-depth against authorization-code interception, per current Microsoft/IETF best-practice guidance for all app types, not just public/mobile clients.
- **`state` parameter**: single-use (consumed on first use, a replay of the same callback URL fails), time-limited (10 minutes), cryptographically random - this is the CSRF protection, preventing an attacker from tricking a victim's browser into completing an OAuth flow the attacker initiated for their own account.
- **ID token signature verification**: the returned ID token's RS256 signature is verified against Microsoft's own published signing keys (JWKS), fetched from Entra ID's own discovery endpoint - via `PyJWT` (the one new dependency this feature adds; every other module in this project remains stdlib-only where a stdlib facility already suffices). A token that isn't genuinely signed by Microsoft for your tenant/app is rejected outright, regardless of what claims it contains.
- **`iss` (issuer) and `aud` (audience) claim checks**: a validly-*signed* token for a different tenant or a different app registration is still rejected - these are exact string matches, not fuzzy ones.
- **Session identical to local accounts**: on success, the exact same kind of session cookie local-account login produces is created - no separate, parallel auth path exists downstream of a successful sign-in.
- **No new outbound network destination beyond Microsoft's own identity platform** (`login.microsoftonline.com`) - the same host Entra ID API-key/token flows in `backend/ai/providers.py` already talk to for Azure OpenAI, not a new third party.
- **Restricting *who* can sign in** is intentionally left to Entra ID's own "Assignment required?" app setting (see the setup steps in README.md), not a second allow-list maintained inside this project - avoids two access-control lists that could silently drift out of sync with each other.

## Sign-in audit log

v4.10.0 adds `backend/audit.py`: every login attempt (success or failure, local account **or** Entra ID) and every logout is recorded as one JSON line to `backend/data/audit.log` (gitignored, same as `users.json`) - `{time, event, username, auth_method, ip, user_agent, detail}`. Rotates at 5MB, keeping 5 backups, via stdlib `logging.handlers.RotatingFileHandler` (no hand-rolled rotation logic, no new dependency).

- View it in-app at `/audit.html` (linked next to your username in the topbar once signed in) or read the file directly - it's plain JSON-lines, `grep`/log-shipping-tool friendly without needing this project's own viewer.
- `GET /api/audit` (the API the in-app viewer calls) is gated by whichever auth mode is already active, same as every other route - there is **no separate "admin-only" restriction** on top of that, consistent with this project's no-RBAC design (see "What this combination does and does not give you" above). Anyone who can reach the app at all can view its sign-in history.
- **Scope, precisely**: this is a **sign-in/sign-out** audit trail, not a job-action audit trail. It answers "who has been signing in to this instance, and did anyone fail to get in" - it does **not** answer "who analyzed customer X's bundle" or "who downloaded this report." Correlating identity to specific job actions would require instrumenting every job-related endpoint individually, which this version does not do.
- IP address is read directly from the TCP connection (`request.client.host`) - deliberately does **not** trust an `X-Forwarded-For` header, since this project's documented deployment model is a direct bind (see "Recommended deployment model" above), not behind a trusted reverse proxy that could be relied on to set that header correctly. If you do put a trusted proxy in front of this server yourself, that proxy's own access log is the right place to capture the true client IP for that setup.

Do **not** run a shared instance with `--no-auth` unless network-level access is independently locked down (VPN-only, or a firewall rule scoped to known IPs) — without either an auth gate or a network restriction, this would be an unauthenticated multi-tenant service holding multiple customers' diagnostic data on the open internet.

## What data leaves the machine, and when

Nothing leaves the machine **except** the evidence digest sent to an AI provider for root-cause synthesis, and only when you explicitly click "Generate root-cause report" (or it auto-runs because you pre-filled AI settings before starting analysis):

- **Ollama (local, fully offline) — the default provider as of v2.2.0.** The model runs on your own machine; the evidence digest never leaves it. If Ollama isn't already running, LDI Copilot starts it for you (`ollama serve`), visible in the activity terminal.
- **OpenAI / Anthropic / Azure OpenAI / Mistral AI / DeepSeek / GitHub Models (v4.7.0+)** — the evidence digest (not the raw uploaded archive) is sent to that provider's API over HTTPS, for that one request. Credentials are used only for that request and are never written to disk unless you explicitly opt in to "Remember these settings on this device" (browser `localStorage` only). GitHub Models is a single gateway that can route to several underlying model publishers (OpenAI, Meta, Microsoft, Mistral AI, DeepSeek, and more) through one GitHub personal access token — from a data-flow perspective it's still "your digest goes to one more API over HTTPS for one request," same as the others in this list.

The raw uploaded archive itself is **never** sent anywhere — only the mechanically-produced Markdown digest (pattern-matched findings, structured fact-checks, a chronological timeline) is ever transmitted, and only to the provider you explicitly chose.

The v4.0.0 mechanical analyzers (SAR/performance, crash/coredump, boot performance, SELinux/AppArmor, package drift, systemd failure cascades, container correlation, and the pcap metadata analyzer below) introduce **no new data flows** — they're all local, offline text/binary parsing of files already inside the bundle (or the optional attached capture), folded into the same digest described above. Nothing about them changes when/what gets sent externally.

The interactive follow-up chat (Results → AI tab, "Ask a follow-up") continues the **same conversation** as the original report: each follow-up message you type is sent to whichever provider generated that report, along with the existing conversation history (the original system prompt + digest + report, plus recent follow-ups, capped in length — see the code comments in `backend/app.py`'s `/api/jobs/{id}/chat` for the exact cap). It does not re-send the raw archive, and redaction (if applicable) was already applied to the digest in that first turn.

## Redaction: reducing exposure even when using a public AI model

As of v2.2.0, whenever a **non-local** provider is selected, LDI Copilot automatically redacts the evidence digest before sending it. As of **v4.11.0**, this covers four categories:
- **Known hostnames/node names** — pulled from **three** sources as of v4.9.2, with the first source gaining two additional supportconfig-specific fallbacks in v4.11.0:
  1. This analysis's own facts (sosreport/supportconfig's captured hostname, or crm_report's detected cluster node names) — as of v4.9.1, also matches a known hostname when it appears **fully-qualified** (e.g. `ue2op1dbsp01.corp.contoso.com`), not just standalone. As of v4.11.0, a supportconfig bundle whose `basic-environment.txt` doesn't happen to include a `/bin/hostname` section (a real, confirmed case — see "A real incident" below) falls back to `hostnamectl status`'s `Static hostname:` line, then to `summary.xml`'s own `<hostname>` tag (which holds the **full FQDN**, tracked as a distinct fact from the short hostname).
  2. **(v4.9.2)** A content-based sniffer that reads the hostname field rsyslog/journald embed in nearly every log line, so hostname redaction works even for a bundle with none of the dedicated system-info files the first source depends on (see "A real incident: hostnames leaked despite redaction" below).
  3. **(v4.9.2)** A cluster-peer "sibling" detector — once one cluster node's hostname is confirmed (e.g. `ue2op1dbsp01`), any other identifier sharing its exact prefix elsewhere in the bundle (e.g. `ue2op1dbsp02`) is also treated as a known hostname, since HA-cluster nodes overwhelmingly follow a shared-prefix-plus-incrementing-node-number naming convention, and a peer's name legitimately appears only in free-text log messages (fencing/membership notices), never in the local hostname field itself.

  All matches are replaced with stable tokens (`HOST-1`, `HOST-2`, …) — substituted **longest-known-hostname-first** (as of v4.11.0, fixing a real bug — see below), so a full FQDN is always redacted as one complete token before any shorter hostname that happens to be its own prefix is considered, rather than leaving the FQDN's unique subdomain suffix exposed after only the short label matched.
- **IPv4 addresses** are replaced with stable tokens (`IP-1`, `IP-2`, …), consistently per unique address, so the AI can still reason about repetition (e.g. "the same node appears in three unrelated log lines") without ever seeing the real identifier. Not allow-list based — every syntactically valid IPv4 address in the digest is caught, regardless of whether this analysis already "knew" about it from elsewhere.
- **IPv6 addresses** (new in v4.9.1 — previously not handled at all) are replaced with `IPV6-1`, `IPV6-2`, … using the same not-allow-list-based, catch-every-valid-address approach as IPv4. Handles compressed (`::`) forms and IPv4-mapped addresses (`::ffff:192.168.1.1`).
- **Email addresses** (new in v4.9.1) are replaced with `EMAIL-1`, `EMAIL-2`, … — e.g. admin/on-call contact addresses that occasionally appear in NTP/mail/monitoring config excerpts.
- A **local-only legend** mapping each token back to its real value is shown in the activity terminal **and** (as of v4.3.0) in a dedicated callout on the Results page itself, right above the AI report — this mapping is generated *after* redaction, persists with the job so it's still visible after navigating away and back, and is never part of the outbound request.
- The checkbox controlling this ("🔒 Redact known hostnames & IP addresses before sending") is **checked by default** whenever a non-local provider is selected, and hidden entirely for Ollama (nothing to redact — nothing leaves the machine). This default is not persisted/remembered across page loads or provider switches — it always starts checked whenever the confidentiality panel becomes relevant, so it can never be silently "stuck" off from an earlier session.
- Every provider added since redaction shipped (Mistral AI, DeepSeek, GitHub Models — see "AI providers" below) is registered with the same `local: False` marker as OpenAI/Anthropic/Azure OpenAI, so redaction automatically applies to them too; adding a new provider that omits this marker entirely also fails safe (treated as non-local, i.e. redaction still applies), not the other way around.

### A real incident: supportconfig hostname never detected at all (fixed in v4.11.0)

A real, freshly captured SLES15 supportconfig bundle exposed a second real hostname-redaction gap, distinct from the v4.9.2 incident below: `check_system_info()`'s supportconfig branch looked for a hostname **only** inside `basic-environment.txt`'s `/bin/hostname` section — but that section simply wasn't present in this bundle (only `/bin/date`, `/bin/uname -a`, and `/etc/os-release` were captured there). With no hostname ever identified, `collect_known_hostnames()` had nothing to redact against for source #1 — even though the box's real FQDN hostname appeared verbatim in `boot.txt`, `messages.txt`, `fs-files.txt`, `shell_history.txt`, `systemd-status.txt`, and `summary.xml`.

A related second bug was found in the same investigation: known hostnames were substituted in plain alphabetical order, not by length. Since a short hostname (`SLES15SP6`) sorts alphabetically *before* its own longer FQDN form, it was substituted to `HOST-1` first — after which the FQDN's own matching text no longer existed verbatim, so the FQDN pattern found nothing left to replace, silently leaving the customer's real, unique cloud-provider subdomain suffix (e.g. `.2hgdthpdov5unbb0h1dsbld3xb.xx.internal.cloudapp.net`) exposed in the outbound report.

**Fixed in v4.11.0** by adding two fallback hostname sources for supportconfig (`hostnamectl status`'s `Static hostname:` line, then `summary.xml`'s `<hostname>` tag for the full FQDN) and by sorting known hostnames longest-first before substitution. Verified directly against the real bundle: both the short hostname and the full FQDN are now correctly identified and redacted as two independent, non-overlapping tokens.

**Important — this does not undo an exposure that already happened**, the same caveat as every other redaction-gap fix in this document: if a report was generated from a supportconfig bundle before upgrading to v4.11.0 where `basic-environment.txt` didn't have a `/bin/hostname` section, that bundle's real hostname/FQDN was sent to whichever provider generated that report; upgrading only protects *future* analyses.

### A real incident: hostnames leaked despite redaction (fixed in v4.9.2)

A real customer bundle — a raw copy of `/var/log` with none of the dedicated system-info files (`sos_commands/`, `installed-rpms`, `basic-environment.txt`) that hostname detection depended on — was correctly detected as `kind="unknown"`. That classification is otherwise harmless (it just means SAR/boot/package-drift analyzers don't populate for that bundle), but it had an unnoticed side effect: `collect_known_hostnames()` had **zero** input to work from, so hostname redaction was a complete, silent no-op for that bundle. Two real hostnames from a live Pacemaker/SAP HANA HA cluster then appeared verbatim in an Azure OpenAI-generated report, even though redaction was enabled.

**Fixed in v4.9.2** by adding a content-based hostname detector (source #2 and #3 above) that no longer depends on any bundle-kind-specific file existing at all — it works directly from the log content itself, the same way a human reading the log would recognize the hostname. Verified end-to-end against a reconstruction of the exact reported scenario (a raw `/var/log`-shaped bundle with a compressed `pacemaker.log`, two HA cluster node hostnames, `kind="unknown"`) — both hostnames are now correctly redacted before the digest would reach any non-local AI provider.

**Important — this does not undo an exposure that already happened.** If a report was generated *before* upgrading to v4.9.2, whatever hostnames were in it were already sent to whichever provider generated that report; upgrading only protects *future* analyses. If you've generated reports from bundles with no `sos_commands/`/`installed-rpms`/`basic-environment.txt` (i.e. anything that showed `kind="unknown"` in the activity log), treat any hostnames in those specific historical reports as already disclosed to that provider, and re-run the analysis under v4.9.2 if you need a properly-redacted version going forward.

**Limitations — read before relying on this for genuinely sensitive engagements:**
- This is a **best-effort mitigation, not a guarantee**. Hostname redaction is still fundamentally **allow-list based** — nothing in this project guesses that an arbitrary string is a hostname purely because it looks like one; it always requires either a dedicated system-info file (source #1) or a repeating/pattern-matched signal from the log content itself (sources #2/#3). A hostname or peer name that doesn't follow the classic rsyslog line format AND doesn't share a detected node's naming convention (e.g. a single one-off mention in unrelated free text, or a completely differently-named third node in a larger cluster) may still not be caught. A peer/hostname mentioned **only** inside a large freeform verbatim block — specifically, crm_report's own "Built-in Analysis (analysis.txt, verbatim)" digest section — is subject to the same caveat, though any IPv4/IPv6/email addresses in that same block still are caught (those three categories are detected by shape, not by an allow-list).
- Still does **not** find or redact: customer/company names mentioned in free text, usernames, application-specific identifiers, MAC addresses, file paths containing customer names, or anything else that isn't one of the four categories above.
- If a bundle is sensitive enough that *any* residual identifying detail reaching a public AI provider would be unacceptable, **use Ollama** (fully offline) instead of relying on redaction with a cloud provider — this is the recommended default provider for exactly this reason.

## Packet captures (.pcap/.pcapng): metadata only, never payload content

As of v4.0.0, you can optionally attach a standalone packet capture alongside a bundle for network-level analysis (`backend/engine/pcap_analyzer.py`). This is held to a **stricter standard than the rest of the digest**, because raw packet payloads can contain credentials, session tokens, cookies, or other highly sensitive content that the hostname/IP redaction described above was never designed to parse or scrub from arbitrary binary payload data:

- **Only metadata is ever extracted:** packet/byte counts, source/destination IP pairs ("top talkers"), protocol mix (TCP/UDP/ICMP/…), TCP-layer anomaly counts (resets, suspected retransmissions, a rough SYN-vs-SYN-ACK port-scan heuristic), DNS query names, and packets-per-second timing.
- **Raw payload bytes/strings are never read into memory as analysis output, never written to `facts.json`/the digest, and never sent to any AI provider.** The parser (`dpkt`) only inspects packet headers (Ethernet/IP/TCP/UDP/ICMP/DNS) for the fields listed above — application-layer payload content (HTTP bodies, TLS application data, plaintext protocol payloads, etc.) is never decoded or surfaced.
- IP addresses and DNS names **are** included in the summary (that's the point of a "top talkers"/"DNS summary" view) and flow through the same hostname/IP redaction as the rest of the digest when a non-local AI provider is selected — see "Redaction" above.
- The pcap is stored on disk under the same per-job folder as the bundle (`backend/data/jobs/<job_id>/upload/`) and is subject to the same retention/cleanup guidance below — deleting the job deletes the capture too.
- `dpkt` (the one new dependency this feature adds) is a pure-Python pcap/pcapng parser with no network access of its own; it never phones home or uploads anything itself.

If your organization's policy is stricter than "metadata only" for packet captures specifically, don't attach one — every other part of this tool works identically without it.

## OS knowledge base and config-anomaly checks (v4.7.0+): no new network calls

`backend/engine/os_knowledge.py` adds an OS/version knowledge base and a config-file anomaly scanner (see CHANGELOG.md for what these check). Both are **pure, offline, local parsing** with the same guarantees as every other mechanical analyzer:

- The "known issues" and "official docs" reference links shown in the UI/digest are **hardcoded strings baked into this file at development time** (each one verified to resolve before being added) — the tool never fetches, pings, or validates them at analysis time, and never sends any bundle content to them. Clicking a link in the UI is the only way one of these URLs is ever actually requested, and that's a normal outbound browser navigation you control, not something LDI Copilot does on your behalf.
- Both checks read only files already inside the bundle you provided (`/etc/os-release`, `sysctl.conf`, `corosync.conf`, etc.) and produce structured findings that flow into the same digest/redaction pipeline as every other analyzer above — no separate data path, no new destination.

## Parallel scanning (v4.9.0): local worker processes only, no new data flow

For large bundles, the line-by-line scan spreads across multiple local **processes** on the same machine (see CHANGELOG.md for how worker count is chosen). This is a pure performance optimization — every worker process runs the exact same file-scanning code as the single-process path, reading only files already inside the bundle on local disk. No network calls, no data leaves the machine, and no additional destination is introduced — the only thing that changes is how many CPU cores work through the file list at once. Forcing `workers=1` (Advanced options, or `--workers 1` on the CLI) restores the original single-process behavior exactly, if you ever want to rule out a parallelism-related difference.

## Installing Ollama itself (v4.5.0+): what runs, and only with your say-so

If Ollama isn't installed yet, both the launcher scripts (`run.sh`/`run.bat`/`run.ps1`) and the browser's Ollama **Start** button (`backend/ai/ollama_manager.py`) can install it for you - but only after an explicit confirmation each time (a `[y/N]` prompt in the launcher, a confirm dialog in the browser), never automatically, and this choice is never remembered anywhere - declining once doesn't suppress being asked again later.

What actually runs, always going straight to Ollama's own official distribution channels (this project never bundles, mirrors, or hosts the Ollama binary itself):
- **Linux:** `curl -fsSL https://ollama.com/install.sh | sh` - Ollama's own published install script.
- **Windows:** `winget install --id Ollama.Ollama` if `winget` is available, otherwise downloading `https://ollama.com/download/OllamaSetup.exe` directly from ollama.com and launching it for you to complete.
- **macOS:** `brew install ollama` via Homebrew, if installed - otherwise you're pointed at a manual download; a macOS `.dmg` app install isn't driven automatically.

After installation, pulling a model runs the exact CLI command you'd otherwise type yourself: `ollama pull <model>`. Both installation and the model pull need outbound internet access to ollama.com's CDN and are genuinely multi-gigabyte downloads for some models - progress streams live into the activity terminal (or the launcher's own console output) rather than running silently.

## An explicit confirmation gate before any external send

Before generating a report with any non-local provider, you must check **"I confirm I'm authorized to share this bundle's data with an external AI provider"** — this is enforced at generate-time (not just as a passive warning), so sending data externally is always a deliberate, acknowledged action rather than an accidental default.

## Provider risk ordering (least to most exposure)

1. **Ollama (local, fully offline)** — nothing leaves the machine. The default provider as of v2.2.0. Best choice for any bundle you're not fully comfortable sending to a third party.
2. **Azure OpenAI via Microsoft Entra ID, using your organization's own Azure tenant/subscription** — data is processed within your org's own governed Azure environment rather than a public consumer API. If your organization already has an approved Azure OpenAI deployment for handling customer-derived data, this is generally a better fit for CSS work than a personal API key with a public provider.
3. **OpenAI / Anthropic / Mistral AI / DeepSeek / GitHub Models public consumer APIs, or Azure OpenAI via a personal API key** — treat these as "public AI model" in every sense: only use them for customer data if your organization has explicitly cleared that practice, and use the redaction toggle every time.

This ordering reflects data-locality and organizational-governance properties only — it is not a statement about model quality or accuracy for RCA purposes.

## Retention and cleanup

- Uploaded archives and analysis output persist under `backend/data/jobs/<job_id>/` for the lifetime of the server process (and on disk after that, until deleted).
- Delete a specific job's data any time via `DELETE /api/jobs/{id}` (or by deleting its folder directly).
- Recommended practice for customer engagements: delete a job's data once you've captured what you need from the report, rather than accumulating a long-lived local archive of customer bundles.
- Job metadata (which bundles were analyzed, when) is in-memory only and does not survive a server restart; the underlying files on disk are unaffected by a restart and must be cleaned up separately.

## Sharing this repository with your team

The GitHub repository itself is private. To share it with your CSS team:
- Add teammates as collaborators (or, for larger rollouts, transfer/mirror it into a team-owned GitHub organization with its own access controls) via the repository's **Settings → Collaborators and teams**.
- Each teammate then clones the repo and runs their **own** local instance (`.\run.ps1` / `.\run.bat` / `./run.sh`) — see "Recommended deployment model" above. Nothing about cloning the repo shares any customer data; customer bundles and analysis output are never committed to the repository (`backend/data/` is gitignored) and should stay that way.

## What this tool does **not** provide

Be clear-eyed about the gaps before treating this as a complete solution for handling regulated or highly sensitive customer data:
- No encryption at rest for uploaded bundles or analysis output on disk.
- No **job-level** audit logging - v4.10.0 adds a **sign-in** audit log (who signed in, how, when, from what IP, success/failure - see "Sign-in audit log" above), but nothing correlates a signed-in identity to specific job actions (who analyzed which specific bundle, downloaded which report, etc.).
- No per-user data isolation - the optional auth gates (shared-secret, per-user accounts, or Microsoft Entra ID SSO - see "Running one shared instance instead") block unauthenticated outsiders, but every authenticated user of a shared instance has identical access to every job on it, regardless of which auth mode is active.
- No data-loss-prevention (DLP) scanning beyond the hostname/IP/email redaction described above.
- No formal compliance certification of any kind.

If your team's work requires any of the above, treat this tool as a productivity aid layered on top of your organization's existing data-handling controls and policies — not a replacement for them.
