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

As of v4.4.0, if you do run a single instance reachable by more than one person, layered controls are available and (except accounts, which need one-time setup) turn on **automatically** the moment `--host` is anything other than a loopback address:

- **Per-user accounts** (`backend/users.py`, `backend/auth.py`'s `SessionCookieMiddleware`) - **the recommended control**. Provision each teammate with `python backend/manage_users.py add <username>` (prompts for a password, hashed with `hashlib.scrypt` - a memory-hard KDF, never stored or logged in plaintext). The moment at least one account exists, everyone signs in individually at a login page instead of sharing one secret; access for one person can be revoked (`manage_users.py remove <username>`) without affecting anyone else, and failed logins lock an account out after 5 attempts within 15 minutes. This does **not** create per-user data isolation - see below.
- **A shared-secret auth gate** (`backend/auth.py`'s `BasicAuthMiddleware`, the original v4.3.0 control) - every request requires a single shared HTTP Basic Auth credential. Used automatically as a zero-setup fallback whenever no accounts are configured yet, or explicitly via `--auth-token` (which always takes priority over accounts, for cases where individual provisioning is overkill). `--no-auth` disables every gate entirely - only if network-level access is already restricted, e.g. VPN-only.
- **`--https`** — TLS via a self-signed certificate (auto-generated and reused under `certs/`, gitignored) or your own certificate via `--ssl-certfile`/`--ssl-keyfile`. Without this, a shared instance sends account/token credentials and every bundle/report over plain HTTP, readable by anyone positioned on the network path between a user and the server.
- **`--require-auth`** — forces whichever gate would apply on a non-loopback host to also apply on `127.0.0.1`, for testing the login flow locally.

**What this combination does and does not give you:**
- ✅ Blocks a stranger who finds the address/port from reaching the tool or any data on it at all.
- ✅ With accounts specifically: individual identity and revocability - you know *who* signed in (not just that *someone* did), and can cut off one person without resetting a secret everyone else also has to update.
- ✅ Encrypts traffic between each user and the server (with `--https`), so credentials and bundle data aren't sent in the clear.
- ❌ Does **not** give per-user *data* isolation, even with accounts. Every authenticated user - regardless of mode - sees the exact same job list (`GET /api/jobs`) and can open, chat about, or delete any job on the instance, including bundles a different teammate uploaded. If your team analyzes different customers' data on the same shared instance, every team member with access can see every customer's bundle.
- ❌ Does **not** give audit logging (who analyzed what, when - accounts mode knows who's *logged in*, but nothing correlates that identity to specific job actions), RBAC, or per-user rate limiting/quotas against a shared AI provider budget.
- ❌ Is not a substitute for real network-layer controls. Combine it with a cloud firewall rule scoped to your team's known IP ranges/VPN CIDR (not `0.0.0.0/0`) whenever possible - every auth gate here is a safety net behind that, not instead of it.

If any of the ❌ items above are unacceptable for the customer engagements you support, go back to one-instance-per-engineer instead.

Example for a globally-distributed team on one Azure VM, with individual accounts plus a firewall rule:
```bash
python backend/manage_users.py add alice
python backend/manage_users.py add bob
./run.sh --host 0.0.0.0 --https
```
Then scope the cloud NSG/security group rule for that port to your team's IP ranges, and share the URL with your team - each person signs in with their own account, nothing else to distribute or leak.

Do **not** run a shared instance with `--no-auth` unless network-level access is independently locked down (VPN-only, or a firewall rule scoped to known IPs) — without either an auth gate or a network restriction, this would be an unauthenticated multi-tenant service holding multiple customers' diagnostic data on the open internet.

## What data leaves the machine, and when

Nothing leaves the machine **except** the evidence digest sent to an AI provider for root-cause synthesis, and only when you explicitly click "Generate root-cause report" (or it auto-runs because you pre-filled AI settings before starting analysis):

- **Ollama (local, fully offline) — the default provider as of v2.2.0.** The model runs on your own machine; the evidence digest never leaves it. If Ollama isn't already running, LDI Copilot starts it for you (`ollama serve`), visible in the activity terminal.
- **OpenAI / Anthropic / Azure OpenAI** — the evidence digest (not the raw uploaded archive) is sent to that provider's API over HTTPS, for that one request. Credentials are used only for that request and are never written to disk unless you explicitly opt in to "Remember these settings on this device" (browser `localStorage` only).

The raw uploaded archive itself is **never** sent anywhere — only the mechanically-produced Markdown digest (pattern-matched findings, structured fact-checks, a chronological timeline) is ever transmitted, and only to the provider you explicitly chose.

The v4.0.0 mechanical analyzers (SAR/performance, crash/coredump, boot performance, SELinux/AppArmor, package drift, systemd failure cascades, container correlation, and the pcap metadata analyzer below) introduce **no new data flows** — they're all local, offline text/binary parsing of files already inside the bundle (or the optional attached capture), folded into the same digest described above. Nothing about them changes when/what gets sent externally.

The interactive follow-up chat (Results → AI tab, "Ask a follow-up") continues the **same conversation** as the original report: each follow-up message you type is sent to whichever provider generated that report, along with the existing conversation history (the original system prompt + digest + report, plus recent follow-ups, capped in length — see the code comments in `backend/app.py`'s `/api/jobs/{id}/chat` for the exact cap). It does not re-send the raw archive, and redaction (if applicable) was already applied to the digest in that first turn.

## Redaction: reducing exposure even when using a public AI model

As of v2.2.0, whenever a **non-local** provider is selected, LDI Copilot automatically redacts the evidence digest before sending it:
- **Known hostnames/node names** (pulled from this analysis's own facts — e.g. the sosreport/supportconfig's captured hostname, or crm_report's detected cluster node names) are replaced with stable tokens (`HOST-1`, `HOST-2`, …).
- **IPv4 addresses** are replaced with stable tokens (`IP-1`, `IP-2`, …), consistently per unique address, so the AI can still reason about repetition (e.g. "the same node appears in three unrelated log lines") without ever seeing the real identifier.
- A **local-only legend** mapping each token back to its real value is shown in the activity terminal **and** (as of v4.3.0) in a dedicated callout on the Results page itself, right above the AI report — this mapping is generated *after* redaction, persists with the job so it's still visible after navigating away and back, and is never part of the outbound request.
- The checkbox controlling this ("🔒 Redact known hostnames & IP addresses before sending") is **checked by default** whenever a non-local provider is selected, and hidden entirely for Ollama (nothing to redact — nothing leaves the machine).

**Limitations — read before relying on this for genuinely sensitive engagements:**
- This is a **best-effort mitigation, not a guarantee**. It only catches the two most mechanically reliable categories (known hostnames from this analysis's own facts, and IPv4 addresses). It does **not** find or redact: customer/company names mentioned in free text, usernames, email addresses, application-specific identifiers, IPv6 addresses, MAC addresses, file paths containing customer names, or anything else that isn't one of the two categories above.
- If a bundle is sensitive enough that *any* residual identifying detail reaching a public AI provider would be unacceptable, **use Ollama** (fully offline) instead of relying on redaction with a cloud provider.

## Packet captures (.pcap/.pcapng): metadata only, never payload content

As of v4.0.0, you can optionally attach a standalone packet capture alongside a bundle for network-level analysis (`backend/engine/pcap_analyzer.py`). This is held to a **stricter standard than the rest of the digest**, because raw packet payloads can contain credentials, session tokens, cookies, or other highly sensitive content that the hostname/IP redaction described above was never designed to parse or scrub from arbitrary binary payload data:

- **Only metadata is ever extracted:** packet/byte counts, source/destination IP pairs ("top talkers"), protocol mix (TCP/UDP/ICMP/…), TCP-layer anomaly counts (resets, suspected retransmissions, a rough SYN-vs-SYN-ACK port-scan heuristic), DNS query names, and packets-per-second timing.
- **Raw payload bytes/strings are never read into memory as analysis output, never written to `facts.json`/the digest, and never sent to any AI provider.** The parser (`dpkt`) only inspects packet headers (Ethernet/IP/TCP/UDP/ICMP/DNS) for the fields listed above — application-layer payload content (HTTP bodies, TLS application data, plaintext protocol payloads, etc.) is never decoded or surfaced.
- IP addresses and DNS names **are** included in the summary (that's the point of a "top talkers"/"DNS summary" view) and flow through the same hostname/IP redaction as the rest of the digest when a non-local AI provider is selected — see "Redaction" above.
- The pcap is stored on disk under the same per-job folder as the bundle (`backend/data/jobs/<job_id>/upload/`) and is subject to the same retention/cleanup guidance below — deleting the job deletes the capture too.
- `dpkt` (the one new dependency this feature adds) is a pure-Python pcap/pcapng parser with no network access of its own; it never phones home or uploads anything itself.

If your organization's policy is stricter than "metadata only" for packet captures specifically, don't attach one — every other part of this tool works identically without it.

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
3. **OpenAI / Anthropic public consumer APIs, or Azure OpenAI via a personal API key** — treat these as "public AI model" in every sense: only use them for customer data if your organization has explicitly cleared that practice, and use the redaction toggle every time.

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
- No audit logging of who analyzed what, when - per-user accounts (v4.4.0+) know who's *logged in*, but nothing correlates that identity to specific job actions.
- No per-user data isolation - the optional auth gates (shared-secret or per-user accounts, see "Running one shared instance instead") block unauthenticated outsiders, but every authenticated user of a shared instance has identical access to every job on it, regardless of which auth mode is active.
- No data-loss-prevention (DLP) scanning beyond the hostname/IP redaction described above.
- No formal compliance certification of any kind.

If your team's work requires any of the above, treat this tool as a productivity aid layered on top of your organization's existing data-handling controls and policies — not a replacement for them.
