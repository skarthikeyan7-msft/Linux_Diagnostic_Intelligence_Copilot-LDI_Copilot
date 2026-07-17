"""
Sensitive-data redaction for the evidence digest before it's sent to a
non-local AI provider (OpenAI, Anthropic, Azure OpenAI, Mistral,
DeepSeek, GitHub Models, ...). This is the technical control behind the
"safest place to share, even with a public AI model" goal: hostnames,
IPv4/IPv6 addresses, and email addresses that identify a specific
customer's infrastructure or personnel are replaced with stable,
meaningless tokens before the request leaves the machine, while
preserving the *pattern* of repetition an AI model needs for causal
reasoning (e.g. "the same node appears in three unrelated log lines" is
still visible - it's just called HOST-1 instead of its real name).

This is a best-effort mitigation, not a guarantee - see the
"Limitations" section below and SECURITY.md. It does NOT attempt to
find every possible sensitive token (customer/company names in
free-text comments, application-specific identifiers, MAC addresses,
etc.) - it covers the categories that are both common in sosreport/
supportconfig/crm_report evidence AND mechanically reliable to detect:

  - IPv4 addresses (any syntactically valid one - not allow-list based,
    so this catches every IPv4 address in the digest regardless of
    whether this analysis already "knows" about it).
  - IPv6 addresses (v4.9.1 - previously MISSING entirely; see
    "Limitations" below for why this was a real, if narrow, gap).
  - Email addresses (v4.9.1 - classic PII, e.g. admin contact addresses
    sometimes present in NTP/mail/monitoring config excerpts).
  - Already-known hostnames/node names pulled from this job's own facts
    (system_info.hostname, cluster_health.nodes_detected) - this one IS
    allow-list based (a hostname can't be recognized by shape alone the
    way an IP address can - "web01" is indistinguishable from an
    ordinary word without already knowing it's this bundle's hostname),
    so it only catches occurrences of a hostname this analysis has
    already confidently identified elsewhere in the SAME bundle.

Limitations (read before treating this as a guarantee for
maximum-sensitivity data):
  - Hostname redaction is allow-list based (see above) - a peer/node
    name that appears ONLY inside a large freeform verbatim block (e.g.
    crm_report's own analysis.txt cross-check, embedded verbatim in the
    digest) but was never independently identified via
    collect_known_hostnames()'s own sources will NOT be caught. IPv4/
    IPv6 addresses and email addresses inside that same block ARE still
    caught, since those two categories are detected by shape, not by an
    allow-list.
  - Does not attempt customer/company names, physical addresses, MAC
    addresses, or application-specific account identifiers.
  - For bundles with the highest sensitivity requirements, the fully
    offline Ollama provider (which never leaves the machine at all, so
    none of this redaction logic is even needed) remains the
    recommended choice over any redaction-then-send approach - see the
    "Ollama (local, fully offline) — recommended default" provider
    label and SECURITY.md.
"""
import ipaddress
import re

_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")

# IPv6 candidate-then-validate approach (v4.9.1): IPv6's textual grammar
# (multiple valid compressed-zero forms via "::", optional embedded
# IPv4-mapped suffix like "::ffff:192.168.1.1", etc.) is notoriously
# error-prone to hand-write as a single precise regex. Instead, this
# regex only finds plausible CANDIDATES (a delimited run of hex digits/
# colons/dots, requiring at least one colon so plain IPv4 addresses and
# ordinary numbers are never even considered), then the stdlib
# `ipaddress` module - already a hard dependency-free, always-available
# choice consistent with this project's stdlib-only philosophy used
# elsewhere (see determine_worker_count()'s memory detection) - makes
# the actual correctness decision. This is far more robust than a
# hand-rolled IPv6 regex while staying just as dependency-free.
_IPV6_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9:._-])(?=[A-Fa-f0-9:.]*:)[A-Fa-f0-9:.]{2,45}(?![A-Za-z0-9:._-])")

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def _is_ipv6(token):
    try:
        return isinstance(ipaddress.ip_address(token), ipaddress.IPv6Address)
    except ValueError:
        return False


def collect_known_hostnames(facts):
    """Pull every hostname/node identifier this analysis already knows
    about out of the job's facts, so redact_text() can replace exact
    occurrences of them. Sourced from:
    - facts.system_info.hostname (sosreport/supportconfig - single host)
    - facts.cluster_health.nodes_detected (crm_report - list of nodes)
    - facts.detected_hostnames_from_logs (v4.9.2 - engine-side
      sniff_syslog_hostnames(): a generic, content-based fallback that
      finds the hostname field rsyslog embeds in nearly every log line,
      regardless of bundle 'kind'. This is what closes a real, live gap:
      a bundle detected as kind="unknown" (e.g. a raw copy of /var/log,
      with none of the dedicated system-info files the two sources
      above depend on) previously had NO hostname source at all here,
      so hostname redaction was a complete no-op for it even though the
      real hostname appeared in nearly every scanned log line - exactly
      what let it leak, unredacted, into a real AI-generated report.
      Also useful for sosreport/supportconfig/crm_report bundles as a
      way to additionally catch a cluster PEER's hostname mentioned
      only in this node's own logs.)
    The first two sources are a closed, already-confident allow-list
    from dedicated system-info files. The third is a frequency-gated
    heuristic (see its own docstring for why that keeps it reliable) -
    deliberately NOT a raw, ungated free-text guess, which would be far
    more error-prone (false positives on ordinary words, false
    negatives on unusual naming schemes)."""
    names = set()
    system_info = (facts or {}).get("system_info") or {}
    hostname = system_info.get("hostname")
    if hostname:
        # first whitespace-delimited token - the raw field can carry
        # trailing shell-prompt artifacts in some supportconfig captures
        first_token = hostname.split()[0] if hostname.split() else None
        if first_token:
            names.add(first_token)
    cluster_health = (facts or {}).get("cluster_health") or {}
    for node in cluster_health.get("nodes_detected") or []:
        if node:
            names.add(node)
    for node in (facts or {}).get("detected_hostnames_from_logs") or []:
        if node:
            names.add(node)
    return sorted(n for n in names if len(n) >= 2)  # skip anything too short to safely match


def redact_text(text, hostnames=None):
    """Returns (redacted_text, legend) where legend is a list of
    {"token": "...", "original": "..."} dicts - for local-only display
    so the engineer can still map HOST-1/IP-1/IPV6-1/EMAIL-1 back to the
    real value while reading the AI's report, without that mapping ever
    being part of the outbound request itself.

    Order matters here: hostnames first (longest/most specific strings,
    including matching a known short hostname when it appears as the
    leading label of a longer FQDN - see the boundary pattern below),
    then email addresses, then IPv6 (before IPv4 - an IPv4-mapped IPv6
    address like "::ffff:192.168.1.1" contains a syntactically valid
    IPv4 substring, so replacing the whole IPv6 token FIRST means the
    IPv4 pass never sees a leftover fragment to double-process), then
    plain IPv4."""
    if not text:
        return text, []

    legend = []
    result = text

    # Hostnames first (longer, more specific strings) so a hostname
    # that happens to contain digits isn't partially eaten by a later
    # pass. Boundary excludes only [A-Za-z0-9_-] (NOT "."), so a known
    # short hostname is still matched when it appears as the leading
    # label of a longer FQDN (e.g. known host "ue2op1dbsp01" is matched
    # inside "ue2op1dbsp01.corp.contoso.com", not just as a standalone
    # token) - a real gap fixed in v4.9.1: the previous boundary treated
    # "." as "still part of the same identifier", which silently
    # skipped every FQDN-qualified occurrence of an otherwise-known
    # hostname.
    for i, host in enumerate(hostnames or [], start=1):
        token = f"HOST-{i}"
        pattern = re.compile(r"(?<![A-Za-z0-9_-])" + re.escape(host) + r"(?![A-Za-z0-9_-])")
        new_result, count = pattern.subn(token, result)
        if count:
            legend.append({"token": token, "original": host})
            result = new_result

    # Email addresses (v4.9.1) - classic PII, and cheap/low-false-positive
    # to detect by shape alone (no allow-list needed). Deduplicated, in
    # order of first appearance, same convention as IPs below.
    seen_emails = {}
    def _sub_email(m):
        addr = m.group(0)
        if addr not in seen_emails:
            seen_emails[addr] = f"EMAIL-{len(seen_emails) + 1}"
            legend.append({"token": seen_emails[addr], "original": addr})
        return seen_emails[addr]
    result = _EMAIL_RE.sub(_sub_email, result)

    # IPv6 addresses (v4.9.1 - previously not handled AT ALL, a real gap
    # for any dual-stack or IPv6-only environment). Candidate regex finds
    # plausible tokens; ipaddress.ip_address() (stdlib) makes the actual
    # validity call, which correctly handles every compressed/"::"/
    # IPv4-mapped form without a hand-rolled monster regex.
    seen_ipv6 = {}
    def _sub_ipv6(m):
        candidate = m.group(0)
        if not _is_ipv6(candidate):
            return candidate  # not actually a valid IPv6 address - leave untouched
        if candidate not in seen_ipv6:
            seen_ipv6[candidate] = f"IPV6-{len(seen_ipv6) + 1}"
            legend.append({"token": seen_ipv6[candidate], "original": candidate})
        return seen_ipv6[candidate]
    result = _IPV6_CANDIDATE_RE.sub(_sub_ipv6, result)

    # Then IPv4 addresses, in order of first appearance, deduplicated.
    # Not allow-list based - this catches every syntactically valid IPv4
    # address regardless of whether this analysis already "knows" about
    # it (e.g. an address seen only in a raw log line or a verbatim
    # embedded block like crm_report's own analysis.txt cross-check).
    seen_ips = {}
    def _sub_ip(m):
        ip = m.group(0)
        if ip not in seen_ips:
            seen_ips[ip] = f"IP-{len(seen_ips) + 1}"
            legend.append({"token": seen_ips[ip], "original": ip})
        return seen_ips[ip]
    result = _IPV4_RE.sub(_sub_ip, result)

    return result, legend


def build_redaction_summary(legend):
    """Short, human-readable line for the activity terminal describing
    what was redacted - local-only, never transmitted."""
    if not legend:
        return "No hostnames, IP addresses, or email addresses were found to redact."
    hosts = sum(1 for e in legend if e["token"].startswith("HOST-"))
    ips = sum(1 for e in legend if e["token"].startswith("IP-"))
    ipv6s = sum(1 for e in legend if e["token"].startswith("IPV6-"))
    emails = sum(1 for e in legend if e["token"].startswith("EMAIL-"))
    parts = []
    if hosts:
        parts.append(f"{hosts} hostname(s)")
    if ips:
        parts.append(f"{ips} IPv4 address(es)")
    if ipv6s:
        parts.append(f"{ipv6s} IPv6 address(es)")
    if emails:
        parts.append(f"{emails} email address(es)")
    mapping = ", ".join(f"{e['token']}={e['original']}" for e in legend)
    return f"Redacted {' and '.join(parts)} before sending. Local-only mapping: {mapping}"
