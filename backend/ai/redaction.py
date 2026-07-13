"""
Sensitive-data redaction for the evidence digest before it's sent to a
non-local AI provider (OpenAI, Anthropic, Azure OpenAI). This is the
technical control behind the "safest place to share, even with a public
AI model" goal: hostnames and IP addresses that identify a specific
customer's infrastructure are replaced with stable, meaningless tokens
before the request leaves the machine, while preserving the *pattern*
of repetition an AI model needs for causal reasoning (e.g. "the same
node appears in three unrelated log lines" is still visible - it's just
called HOST-1 instead of its real name).

This is a best-effort mitigation, not a guarantee - see the "Limitations"
note in build_redaction_report()/SECURITY.md. It does NOT attempt to
find every possible sensitive token (customer names in free-text
comments, application-specific identifiers, etc.) - only the two most
common and most mechanically reliable categories: IPv4 addresses and
already-known hostnames/node names pulled from this job's own facts.
"""
import re

_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


def collect_known_hostnames(facts):
    """Pull every hostname/node identifier this analysis already knows
    about out of the job's facts, so redact_text() can replace exact
    occurrences of them. Sourced from:
    - facts.system_info.hostname (sosreport/supportconfig - single host)
    - facts.cluster_health.nodes_detected (crm_report - list of nodes)
    Deliberately does NOT try to guess arbitrary hostnames out of free
    text via regex - that's much more error-prone (false positives on
    ordinary words, false negatives on unusual naming schemes) than
    matching identifiers this analysis has already confidently
    identified elsewhere."""
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
    return sorted(n for n in names if len(n) >= 2)  # skip anything too short to safely match


def redact_text(text, hostnames=None):
    """Returns (redacted_text, legend) where legend is a list of
    {"token": "...", "original": "..."} dicts - for local-only display
    so the engineer can still map HOST-1/IP-1 back to the real value
    while reading the AI's report, without that mapping ever being
    part of the outbound request itself."""
    if not text:
        return text, []

    legend = []
    result = text

    # Hostnames first (longer, more specific strings) so a hostname
    # that happens to contain digits isn't partially eaten by the IP
    # pass afterward.
    for i, host in enumerate(hostnames or [], start=1):
        token = f"HOST-{i}"
        pattern = re.compile(r"(?<![A-Za-z0-9_.-])" + re.escape(host) + r"(?![A-Za-z0-9_.-])")
        new_result, count = pattern.subn(token, result)
        if count:
            legend.append({"token": token, "original": host})
            result = new_result

    # Then IPv4 addresses, in order of first appearance, deduplicated.
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
        return "No hostnames or IP addresses were found to redact."
    hosts = sum(1 for e in legend if e["token"].startswith("HOST-"))
    ips = sum(1 for e in legend if e["token"].startswith("IP-"))
    parts = []
    if hosts:
        parts.append(f"{hosts} hostname(s)")
    if ips:
        parts.append(f"{ips} IP address(es)")
    mapping = ", ".join(f"{e['token']}={e['original']}" for e in legend)
    return f"Redacted {' and '.join(parts)} before sending. Local-only mapping: {mapping}"
