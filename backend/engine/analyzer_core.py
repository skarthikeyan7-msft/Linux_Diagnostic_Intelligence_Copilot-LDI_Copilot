#!/usr/bin/env python3
"""
sosreport / supportconfig deep-triage analyzer
================================================
Mechanical evidence-gathering engine for Red Hat "sos report" (sosreport)
archives and SUSE "supportconfig" archives.

It extracts the archive, walks and categorizes EVERY file, streams every
text file line-by-line looking for known failure signatures (kernel
panics, OOM kills, filesystem corruption, failed services, SELinux /
AppArmor denials, network errors, cluster fencing, auth failures, etc.),
runs structured fact-checks (disk usage, memory pressure, load average,
failed systemd units, log coverage window / staleness), builds a
cross-file chronological timeline of the highest-severity events, and
writes a condensed, evidence-linked digest.

Nothing is skipped: inventory.json lists every file encountered, and
findings.json keeps every deduplicated pattern match with exact
file:line provenance so a human or an LLM reasoning layer can jump to
the original source and verify/expand any finding. digest.md is the
condensed, ranked summary meant to be read first.

Usage:
    python analyzer.py <input_path> [--output DIR] [--min-severity SEV]
                        [--top-per-category N] [--max-examples N]
                        [--start TIME] [--end TIME] | [--around TIME --window MIN]

    <input_path> may be:
      - an archive: .tar.xz/.txz, .tar.gz/.tgz, .tar.bz2/.tbz/.tbz2, .tar, .zip
      - a directory that already contains an extracted sosreport or
        supportconfig tree

    Time-window scoping (optional): by default the whole archive is
    analyzed. To narrow the pattern-scan to a known incident window
    instead of scanning every line of every log, pass either:
      --start "2026-07-10 11:00" --end "2026-07-10 12:00"   (either may be omitted for an open-ended bound)
      --around "2026-07-10 11:30" --window 60                (center +/- window/2 minutes; window default 60)
    Only chronological log files (var/log/messages, audit.log, journal
    exports, etc.) are gated by the window - configuration dumps, package
    lists, and other point-in-time snapshot files are always fully scanned
    regardless, since a time window doesn't meaningfully apply to them.

Outputs (written to --output, default "<input>_analysis" next to input):
    digest.md         - condensed, ranked, human/AI-readable report (start here)
    findings.json      - every deduplicated finding, with file:line examples
    facts.json         - structured fact-check results
    inventory.json     - every file found, with size + assigned category
"""
import argparse
import json
import os
import re
import sys
import tarfile
import time
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

__version__ = "3.1.0"

# --------------------------------------------------------------------------
# Severity model
# --------------------------------------------------------------------------
SEVERITY_ORDER = ["INFO", "WARNING", "ERROR", "CRITICAL"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# --------------------------------------------------------------------------
# Failure-signature patterns: (id, severity, category_hint, regex)
# category_hint overrides the file's own category when set (e.g. a
# fencing event found inside a generic messages.txt dump is more useful
# bucketed under "cluster_ha" than under "logs_messages"). Left as None
# for broad/generic patterns, which stay bucketed under the source file's
# own category. Ordered most-specific/critical first; classify_line()
# picks the highest severity match for a given line, tie-broken by order.
# --------------------------------------------------------------------------
PATTERNS = [
    ("kernel_panic", "CRITICAL", "kernel_boot", r"Kernel panic"),
    ("kernel_oops", "CRITICAL", "kernel_boot", r"\bOops\b"),
    ("call_trace", "CRITICAL", "kernel_boot", r"Call Trace:"),
    ("segfault", "CRITICAL", "process_performance", r"segfault|Segmentation fault"),
    ("gpf", "CRITICAL", "kernel_boot", r"general protection fault"),
    ("oom_kill", "CRITICAL", "memory", r"Out of memory:|oom[-_]kill|Killed process \d+"),
    ("fs_corruption", "CRITICAL", "storage_filesystem", r"EXT4-fs error|EXT4-fs.*error|XFS.*(corrupt|Corruption)|Buffer I/O error|I/O error, dev|structure needs cleaning"),
    ("fs_readonly", "CRITICAL", "storage_filesystem", r"Remounting filesystem read-only|read-only file system"),
    ("watchdog", "CRITICAL", "kernel_boot", r"NMI watchdog|watchdog.*(reset|timeout|expired)|hung_task_timeout|blocked for more than \d+ seconds"),
    ("fencing", "CRITICAL", "cluster_ha", r"\bfenced\b|STONITH|fencing.*(action|failed)|[Ss]tonith.*fail"),
    ("hw_error", "CRITICAL", "hardware", r"Machine Check Exception|\bMCE:|[Hh]ardware [Ee]rror"),
    ("disk_predictive_fail", "CRITICAL", "storage_filesystem", r"predictive failure|Currently unreadable \(pending\) sectors|[Rr]eallocated_?[Ss]ector"),
    ("cluster_fail", "CRITICAL", "cluster_ha", r"[Cc]orosync.*(fail|error|unable)|[Pp]acemaker.*(fail|not running|unable)"),
    ("quorum_lost", "CRITICAL", "cluster_ha", r"[Qq]uorum.*(lost|not present)|unable to form a quorum"),
    ("node_unclean", "CRITICAL", "cluster_ha", r"\bUNCLEAN\b"),
    ("resource_not_running", "ERROR", "cluster_ha", r"Resource .* is not running|not running \(not managed\)"),
    ("core_dump", "CRITICAL", "process_performance", r"core dumped"),
    ("multipath_fail", "CRITICAL", "storage_filesystem", r"multipath.*(fail|no usable paths)"),
    ("ata_reset", "ERROR", "storage_filesystem", r"ata\d+.*(exception|failed command|hard resetting link)"),
    ("selinux_denial", "ERROR", "security", r"avc:\s*denied"),
    ("apparmor_denial", "ERROR", "security", r'apparmor="DENIED"'),
    ("auth_failure", "ERROR", "users_auth", r"authentication failure|Failed password|FAILED su for|pam_unix.*failure"),
    ("service_failed", "ERROR", "services_systemd", r"Failed to start|Dependency failed for|entered failed state|failed to start"),
    ("no_space", "ERROR", "storage_filesystem", r"[Nn]o space left on device"),
    ("exception_tb", "ERROR", None, r"\bTraceback\b|\bException\b"),
    ("link_flap", "WARNING", "network", r"NIC Link is Down|link becomes ready|link is not ready"),
    ("timeout", "WARNING", None, r"\btimed?[ -]?out\b"),
    ("unreachable", "WARNING", None, r"\bunreachable\b"),
    ("degraded", "WARNING", None, r"\bdegraded\b"),
    ("dropped", "WARNING", None, r"\bdropped\b"),
    ("throttle", "WARNING", None, r"throttl"),
    ("clock_skew", "WARNING", "time_sync", r"clock skew|time.*drift|System clock wrong"),
    ("deprecated", "INFO", None, r"\bdeprecated\b"),
    ("retry", "INFO", None, r"\bretry(?:ing)?\b"),
    ("generic_critical", "ERROR", None, r"\bcritical\b"),
    ("generic_denied", "ERROR", None, r"\bdenied\b|\brefused\b"),
    ("generic_failed", "ERROR", None, r"\bfail(?:ed|ure)\b"),
    ("generic_error", "ERROR", None, r"\berror\b"),
]
# Pattern ids considered "broad / low specificity" - still recorded as
# findings, but excluded from the chronological timeline to keep it
# high-signal.
GENERIC_PATTERN_IDS = {
    "generic_error", "generic_failed", "generic_denied", "generic_critical",
    "timeout", "unreachable", "degraded", "deprecated", "retry", "dropped",
    "throttle",
}

COMPILED_PATTERNS = [(pid, sev, cat, re.compile(pat, re.IGNORECASE)) for pid, sev, cat, pat in PATTERNS]

# Fast pre-filter: a plain lowercase substring scan (C-level str.__contains__)
# is far cheaper per line than evaluating a ~30-way regex alternation on
# every single line of a multi-hundred-MB log. This list is a deliberately
# over-inclusive superset of everything the real PATTERNS regexes above can
# match; false positives here just fall through the full regex check below
# and cost nothing extra, but it must never produce a false NEGATIVE.
COARSE_KEYWORDS = [
    "panic", "oops", "call trace", "segfault", "segmentation fault", "protection fault",
    "out of memory", "oom", "killed process", "ext4-fs", "xfs", "corrupt", "buffer i/o error",
    "i/o error", "structure needs cleaning", "read-only", "watchdog", "hung_task",
    "blocked for more than", "fenced", "stonith", "fencing", " mce", "mce:", "hardware error",
    "machine check", "predictive failure", "unreadable", "reallocated", "corosync", "pacemaker",
    "quorum", "unclean", "not running", "core dumped", "multipath", "no usable paths", "ata",
    "exception", "failed command",
    "hard resetting link", "avc:", "denied", "apparmor", "authentication failure",
    "failed password", "failed su", "pam_unix", "failed to start", "dependency failed",
    "entered failed state", "no space left", "traceback", "nic link is down",
    "link becomes ready", "link is not ready", "timed out", "timeout", "unreachable",
    "degraded", "dropped", "throttl", "clock skew", "drift", "system clock wrong",
    "deprecated", "retry", "critical", "refused", "fail", "error",
]

LOG_LIKE_CATEGORIES = {"logs_messages", "logs_audit", "logs_journal", "kernel_boot", "cluster_ha_logs"}

# --------------------------------------------------------------------------
# Category rules
# --------------------------------------------------------------------------
SOS_CATEGORY_RULES = [
    ("sos_commands/logs", "logs_journal"),
    ("var/log/messages", "logs_messages"),
    ("var/log/syslog", "logs_messages"),
    ("var/log/boot.log", "logs_messages"),
    ("var/log/dmesg", "kernel_boot"),
    ("sos_commands/kernel/dmesg", "kernel_boot"),
    ("var/log/audit", "logs_audit"),
    ("var/log/secure", "logs_audit"),
    ("sos_commands/selinux", "security"),
    ("sos_commands/apparmor", "security"),
    ("etc/selinux", "security"),
    ("etc/apparmor.d", "security"),
    ("etc/pam.d", "security"),
    ("etc/sudoers", "security"),
    ("etc/ssh", "security"),
    ("sos_commands/kernel", "kernel_boot"),
    ("sos_commands/boot", "kernel_boot"),
    ("grub", "kernel_boot"),
    ("/boot/", "kernel_boot"),
    ("sos_commands/block", "storage_filesystem"),
    ("sos_commands/filesys", "storage_filesystem"),
    ("sos_commands/lvm2", "storage_filesystem"),
    ("sos_commands/multipath", "storage_filesystem"),
    ("sos_commands/md", "storage_filesystem"),
    ("sos_commands/devicemapper", "storage_filesystem"),
    ("etc/fstab", "storage_filesystem"),
    ("sos_commands/networkmanager", "network"),
    ("sos_commands/networking", "network"),
    ("etc/sysconfig/network", "network"),
    ("etc/networkmanager", "network"),
    ("etc/resolv.conf", "dns"),
    ("etc/hosts", "dns"),
    ("sos_commands/firewalld", "network"),
    ("iptables", "network"),
    ("nftables", "network"),
    ("installed-rpms", "packages_updates"),
    ("installed-debs", "packages_updates"),
    ("sos_commands/yum", "packages_updates"),
    ("sos_commands/dnf", "packages_updates"),
    ("sos_commands/dpkg", "packages_updates"),
    ("sos_commands/apt", "packages_updates"),
    ("sos_commands/rpm", "packages_updates"),
    ("sos_commands/subscription_manager", "packages_updates"),
    ("sos_commands/systemd", "services_systemd"),
    ("sos_commands/service", "services_systemd"),
    ("etc/systemd", "services_systemd"),
    ("sos_commands/chkconfig", "services_systemd"),
    ("sos_commands/process", "process_performance"),
    ("sos_commands/perf", "process_performance"),
    ("sos_commands/memory", "memory"),
    ("meminfo", "memory"),
    ("slabinfo", "memory"),
    ("sos_commands/hardware", "hardware"),
    ("sos_commands/pci", "hardware"),
    ("sos_commands/usb", "hardware"),
    ("dmidecode", "hardware"),
    ("sos_commands/cpu", "hardware"),
    ("sos_commands/virsh", "virtualization"),
    ("sos_commands/libvirt", "virtualization"),
    ("sos_commands/vdsm", "virtualization"),
    ("sos_commands/docker", "virtualization"),
    ("sos_commands/podman", "virtualization"),
    ("sos_commands/kubernetes", "virtualization"),
    ("sos_commands/pacemaker", "cluster_ha"),
    ("sos_commands/corosync", "cluster_ha"),
    ("sos_commands/cluster", "cluster_ha"),
    ("var/log/pacemaker", "cluster_ha"),
    ("var/log/cluster", "cluster_ha"),
    ("sos_commands/crontab", "cron"),
    ("etc/cron", "cron"),
    ("var/spool/cron", "cron"),
    ("etc/passwd", "users_auth"),
    ("etc/group", "users_auth"),
    ("etc/shadow", "users_auth"),
    ("sos_commands/login", "users_auth"),
    ("sos_commands/ntp", "time_sync"),
    ("sos_commands/chrony", "time_sync"),
    ("etc/chrony", "time_sync"),
    ("etc/ntp.conf", "time_sync"),
    ("sos_commands/postfix", "mail"),
    ("sos_commands/sendmail", "mail"),
    ("var/log/maillog", "mail"),
    ("var/crash", "core_dumps"),
    ("vmcore", "core_dumps"),
    ("sos_commands/kdump", "core_dumps"),
    ("etc/", "config_etc"),
]

SUPPORTCONFIG_CATEGORY_RULES = [
    ("messages", "logs_messages"),
    ("boot", "logs_messages"),
    ("warn", "logs_messages"),
    ("audit", "logs_audit"),
    ("security-apparmor", "security"),
    ("security", "security"),
    ("ssh", "security"),
    ("ldap", "security"),
    ("fs-diskio", "storage_filesystem"),
    ("fs-iostat", "storage_filesystem"),
    ("fs-diskusage", "storage_filesystem"),
    ("filesystems", "storage_filesystem"),
    ("lvm", "storage_filesystem"),
    ("soft-raid", "storage_filesystem"),
    ("scsi", "storage_filesystem"),
    ("fc-", "storage_filesystem"),
    ("network", "network"),
    ("routes", "network"),
    ("dns", "dns"),
    ("nfs", "network"),
    ("samba", "network"),
    ("iscsi", "storage_filesystem"),
    ("rpm", "packages_updates"),
    ("updates", "packages_updates"),
    ("patches", "packages_updates"),
    ("zypper", "packages_updates"),
    ("chkconfig", "services_systemd"),
    ("systemd", "services_systemd"),
    ("services", "services_systemd"),
    ("insserv", "services_systemd"),
    ("sar", "process_performance"),
    ("memory", "memory"),
    ("slabinfo", "memory"),
    ("hardware", "hardware"),
    ("pci", "hardware"),
    ("usb", "hardware"),
    ("dmi", "hardware"),
    ("xen", "virtualization"),
    ("kvm", "virtualization"),
    ("libvirt", "virtualization"),
    ("docker", "virtualization"),
    ("ha.txt", "cluster_ha"),
    ("pacemaker", "cluster_ha"),
    ("corosync", "cluster_ha"),
    ("cluster", "cluster_ha"),
    ("csync2", "cluster_ha"),
    ("sbd", "cluster_ha"),
    ("drbd", "cluster_ha"),
    ("cron", "cron"),
    ("ntp", "time_sync"),
    ("chrony", "time_sync"),
    ("mail", "mail"),
    ("postfix", "mail"),
    ("y2log", "kernel_boot"),
    ("yast", "kernel_boot"),
    ("modules", "kernel_boot"),
    ("basic-environment", "system_info"),
    ("env", "system_info"),
    ("crash", "core_dumps"),
]

# crm_report / hb_report (crmsh) filenames, per crmsh/report/constants.py.
# Ordered most-specific first. Time-series per-node logs get their own
# "cluster_ha_logs" category (gated by --start/--end time windows);
# config/state snapshots stay under "cluster_ha" (always fully scanned,
# since a time window doesn't meaningfully apply to a point-in-time
# snapshot like cib.xml). categorize() matches by substring anywhere in
# the relative path, so per-node subdirectories (e.g. "node1/pacemaker.log")
# are categorized correctly without any special-casing.
CRM_REPORT_CATEGORY_RULES = [
    ("journal_pacemaker.log", "cluster_ha_logs"),
    ("journal_corosync.log", "cluster_ha_logs"),
    ("journal_sbd.log", "cluster_ha_logs"),
    ("journal.log", "cluster_ha_logs"),
    ("pacemaker.log", "cluster_ha_logs"),
    ("corosync.log", "cluster_ha_logs"),
    ("ha-log", "cluster_ha_logs"),
    ("analysis.txt", "cluster_ha_analysis"),  # crm_report's own pre-analysis - surfaced verbatim in the digest
    ("description.txt", "system_info"),
    ("hb_report.log", "system_info"),
    ("time.txt", "time_sync"),
    ("cib.xml", "cluster_ha"),
    ("crm_mon.txt", "cluster_ha"),
    ("crm_verify.txt", "cluster_ha"),
    ("configure_show.txt", "cluster_ha"),
    ("corosync.conf", "cluster_ha"),
    ("corosync_status.txt", "cluster_ha"),
    ("members.txt", "cluster_ha"),
    ("quorum_qdevice_qnetd.txt", "cluster_ha"),
    ("fdata", "cluster_ha"),
    ("sbd", "cluster_ha"),
    ("events.txt", "cluster_ha"),
    ("backtraces.txt", "core_dumps"),
    ("coredump_info.txt", "core_dumps"),
    ("dlm_dump.txt", "storage_filesystem"),
    ("ocfs2.txt", "storage_filesystem"),
    ("gfs2.txt", "storage_filesystem"),
    ("permissions.txt", "security"),
    ("sysstats.txt", "process_performance"),
    ("sysinfo.txt", "system_info"),
    ("rpm", "packages_updates"),
    ("packages", "packages_updates"),
]

CATEGORY_RULES_BY_KIND = {
    "sosreport": SOS_CATEGORY_RULES,
    "supportconfig": SUPPORTCONFIG_CATEGORY_RULES,
    "crm_report": CRM_REPORT_CATEGORY_RULES,
}

# Top-level crm_report filenames - anything else at the top level of a
# crm_report tree is a per-node subdirectory named after that node's
# hostname (see detect_crm_report_nodes()).
CRM_REPORT_TOP_FILES = {
    "analysis.txt", "description.txt", "cib.xml", "configure_show.txt",
    "corosync.conf", "corosync_status.txt", "crm_mon.txt", "crm_verify.txt",
    "members.txt", "sysinfo.txt", "sysstats.txt", "sbd.txt", "dlm_dump.txt",
    "ocfs2.txt", "gfs2.txt", "quorum_qdevice_qnetd.txt", "permissions.txt",
    "coredump_info.txt", "hb_report.log", "time.txt", "events.txt",
    "backtraces.txt", "fdata.txt",
}
CRM_REPORT_DETECT_MARKERS = {
    "analysis.txt", "cib.xml", "description.txt", "members.txt",
    "crm_mon.txt", "corosync.conf",
}

BINARY_SKIP_EXTS = {
    ".rpm", ".deb", ".gz", ".bz2", ".xz", ".zip", ".png", ".jpg", ".jpeg",
    ".gif", ".ico", ".pdf", ".db", ".sqlite", ".sqlite3", ".journal",
    ".pcap", ".pcapng", ".so", ".ko", ".bin", ".img", ".qcow2", ".vmdk",
    ".tar", ".core",
}

SECTION_HEADER_RE = re.compile(r"^#==\[\s*(.+?)\s*\]=+#\s*$")
SYSLOG_TS_RE = re.compile(r"^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})")
ISO_TS_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})")
AUDIT_EPOCH_RE = re.compile(r"audit\((\d{9,11})\.\d+:\d+\)")
# dmesg -T / dmesg --time-format=ctime bracket format: "[Fri Jul 10 11:28:01 2026] ..."
DMESG_CTIME_RE = re.compile(r"^\[[A-Za-z]{3}\s+([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})\]")
MONTH_NUM = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], start=1)}
NUM_RE = re.compile(r"\d+")
HEX_RE = re.compile(r"0x[0-9a-fA-F]+")
PID_RE = re.compile(r"\[\d+\]")
DF_LINE_RE = re.compile(r"^(?P<fs>\S+)\s+(?P<blocks>\d+)\s+(?P<used>\d+)\s+(?P<avail>\d+)\s+(?P<pct>\d+)%\s+(?P<mount>.+)$")
FAILED_UNIT_RE = re.compile(r"^(?P<unit>\S+\.(?:service|socket|timer|mount|path))\s+\S+\s+failed\s+failed", re.IGNORECASE)

# --------------------------------------------------------------------------
# Focused-analysis support: a support engineer can describe what they're
# actually investigating (e.g. "find root cause of NC and IP cluster
# resource restart issue") and have the mechanical scan surface a
# dedicated section of matching evidence, ahead of the full exhaustive
# scan - instead of every finding being weighted purely by severity
# regardless of relevance to the question actually being asked.
# --------------------------------------------------------------------------
FOCUS_STOPWORDS = {
    "a", "an", "the", "is", "are", "was", "were", "be", "been", "being", "to", "of", "in",
    "on", "at", "by", "for", "and", "or", "but", "not", "this", "that", "these", "those",
    "it", "its", "with", "from", "as", "if", "so", "no", "do", "does", "did", "doing",
    "we", "us", "i", "you", "your", "our", "me", "my", "find", "finding", "root", "cause",
    "causes", "issue", "issues", "problem", "problems", "problematic", "analysis",
    "analyze", "analyse", "please", "help", "investigate", "investigating",
    "investigation", "focus", "focused", "related", "about", "why", "what", "when",
    "where", "how", "happening", "happened", "happens", "occur", "occurs", "occurred",
    "occurring", "restart", "restarts", "restarting", "restarted", "cluster", "resource",
    "resources", "log", "logs", "report", "reports", "see", "check", "checking",
    "looking", "look", "need", "want", "would", "like", "also", "just", "only", "seems",
}
FOCUS_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_\-]*")
FOCUS_QUOTED_RE = re.compile(r'"([^"]+)"|\'([^\']+)\'')


def extract_focus_keywords(focus_text):
    """Turn a free-text investigation focus (e.g. "find root cause of NC
    and IP cluster resource restart issue") into a list of keywords used
    to identify relevant findings. Deliberately inclusive: a keyword
    that's too broad just highlights a finding that didn't strictly need
    it; a keyword that's missing silently drops exactly the thing the
    engineer asked about, which is the worse failure mode. Short
    all-caps-style tokens (NC, IP, DC, HA...) are exactly the kind of
    resource/subsystem identifiers a support engineer would use, so
    length alone is not a filter - only a stopword list is."""
    if not focus_text or not focus_text.strip():
        return []
    text = focus_text.strip()
    keywords = set()
    for m in FOCUS_QUOTED_RE.finditer(text):
        kw = (m.group(1) or m.group(2)).strip().lower()
        if kw:
            keywords.add(kw)
    for tok in FOCUS_TOKEN_RE.findall(text):
        low = tok.lower()
        if low in FOCUS_STOPWORDS or len(low) < 2:
            continue
        keywords.add(low)
    return sorted(keywords)


def compile_focus_patterns(keywords):
    # A plain \b...\b boundary treats underscore as a "word" character,
    # so it fails to match e.g. "ip" inside the extremely common
    # Pacemaker/crm resource-naming convention "rsc_ip_cluster". Real
    # support bundles name resources with underscores/hyphens joining
    # short identifiers (rsc_ip_cluster, rsc-nc-share, rsc_st_azure...),
    # so treat underscore and hyphen as separators too: only require
    # that the character immediately before/after the keyword isn't
    # itself alphanumeric.
    return [
        re.compile(r"(?<![A-Za-z0-9])" + re.escape(kw) + r"(?![A-Za-z0-9])", re.IGNORECASE)
        for kw in keywords
    ]


def _finding_focus_haystack(finding):
    parts = [finding.get("message", ""), finding.get("category", ""), finding.get("pattern", "")]
    for ex in finding.get("examples", []):
        parts.append(ex.get("file", ""))
        parts.append(ex.get("text", ""))
    return " ".join(parts)


def finding_matches_focus(finding, focus_patterns):
    if not focus_patterns:
        return False
    haystack = _finding_focus_haystack(finding)
    return any(p.search(haystack) for p in focus_patterns)


def event_matches_focus(event, focus_patterns):
    if not focus_patterns:
        return False
    haystack = f"{event.get('text', '')} {event.get('file', '')} {event.get('category', '')}"
    return any(p.search(haystack) for p in focus_patterns)


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def die(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(2)


def human_size(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"


def strip_archive_suffix(name: str) -> str:
    for suf in (".tar.xz", ".tar.gz", ".tar.bz2", ".tar", ".txz", ".tgz", ".tbz2", ".tbz", ".zip"):
        if name.lower().endswith(suf):
            return name[: -len(suf)]
    return name


def detect_archive_kind(path: Path):
    name = path.name.lower()
    if name.endswith(".zip"):
        return "zip"
    if name.endswith((".tar.xz", ".txz", ".tar.gz", ".tgz", ".tar.bz2", ".tbz", ".tbz2", ".tar")):
        return "tar"
    try:
        with open(path, "rb") as fh:
            head = fh.read(6)
        if head[:2] == b"PK":
            return "zip"
        if head[:2] == b"\x1f\x8b" or head[:3] == b"BZh" or head[:6] == b"\xfd7zXZ\x00":
            return "tar"
    except OSError:
        pass
    return None


def safe_extract_tar(tar_path, dest_dir):
    skipped = []
    dest_abs = os.path.abspath(str(dest_dir))
    with tarfile.open(tar_path, "r:*") as tf:
        for m in tf:
            try:
                target = os.path.abspath(os.path.join(dest_abs, m.name))
                if not (target == dest_abs or target.startswith(dest_abs + os.sep)):
                    skipped.append((m.name, "path traversal"))
                    continue
                if m.isdev() or m.ischr() or m.isblk() or m.isfifo():
                    skipped.append((m.name, "device/special file"))
                    continue
                tf.extract(m, dest_dir)
            except Exception as e:
                skipped.append((m.name, str(e)))
    return skipped


def safe_extract_zip(zip_path, dest_dir):
    skipped = []
    dest_abs = os.path.abspath(str(dest_dir))
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            try:
                target = os.path.abspath(os.path.join(dest_abs, info.filename))
                if not (target == dest_abs or target.startswith(dest_abs + os.sep)):
                    skipped.append((info.filename, "path traversal"))
                    continue
                zf.extract(info, dest_dir)
            except Exception as e:
                skipped.append((info.filename, str(e)))
    return skipped


def resolve_root(dest_dir: Path) -> Path:
    try:
        entries = list(dest_dir.iterdir())
    except OSError:
        return dest_dir
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return dest_dir


def detect_type(root: Path) -> str:
    try:
        top = [p.name.lower() for p in root.iterdir()]
    except OSError:
        top = []
    if "sos_commands" in top or "installed-rpms" in top or "sos_reports" in top:
        return "sosreport"
    if len(set(top) & CRM_REPORT_DETECT_MARKERS) >= 2:
        return "crm_report"
    txt_files = {n for n in top if n.endswith(".txt")}
    markers = {"basic-environment.txt", "supportconfig.txt", "rpm.txt", "messages.txt", "hardware.txt"}
    if len(txt_files & markers) >= 2:
        return "supportconfig"
    # Fallback: bounded one-level-deeper scan for unusual archive layouts
    checked = 0
    for dirpath, dirnames, filenames in os.walk(root):
        for n in dirnames:
            if n.lower() == "sos_commands":
                return "sosreport"
        lower_filenames = {n.lower() for n in filenames}
        if len(lower_filenames & CRM_REPORT_DETECT_MARKERS) >= 2:
            return "crm_report"
        for n in filenames:
            if n.lower() == "basic-environment.txt":
                return "supportconfig"
            if n.lower() == "installed-rpms":
                return "sosreport"
        checked += len(filenames)
        if checked > 5000:
            break
    return "unknown"


def detect_crm_report_nodes(inventory):
    """Per-node subdirectories in a crm_report tree are named after each
    node's hostname and aren't among the known top-level crm_report
    filenames - anything else at the top of the tree is a node dir."""
    nodes = set()
    for it in inventory:
        parts = it["path"].split("/")
        if len(parts) > 1 and parts[0].lower() not in CRM_REPORT_TOP_FILES:
            nodes.add(parts[0])
    return sorted(nodes)


def categorize(relpath_lower: str, kind: str) -> str:
    rules = CATEGORY_RULES_BY_KIND.get(kind, [])
    for needle, cat in rules:
        if needle in relpath_lower:
            return cat
    return "other"


def is_probably_text(path: Path) -> bool:
    if path.suffix.lower() in BINARY_SKIP_EXTS:
        return False
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(4096)
    except OSError:
        return False
    if not chunk:
        return True
    if b"\x00" in chunk:
        return False
    text_chars = sum(1 for b in chunk if 9 <= b <= 13 or 32 <= b <= 126 or b >= 128)
    return (text_chars / len(chunk)) > 0.85


def build_inventory(root: Path, kind: str):
    inventory = []
    for dirpath, dirnames, filenames in os.walk(root):
        for fn in filenames:
            fpath = Path(dirpath) / fn
            try:
                rel = fpath.relative_to(root).as_posix()
            except ValueError:
                continue
            try:
                size = fpath.stat().st_size
            except OSError:
                size = -1
            cat = categorize(rel.lower(), kind)
            inventory.append({"path": rel, "size": size, "category": cat})
    return inventory


def find_inventory(inventory, *substrings):
    subs = [s.lower() for s in substrings]
    return [it["path"] for it in inventory if any(s in it["path"].lower() for s in subs)]


def find_by_basename_prefix(inventory, *prefixes):
    out = []
    for it in inventory:
        base = it["path"].rsplit("/", 1)[-1].lower()
        for pref in prefixes:
            if base == pref or base.startswith(pref + "_") or base.startswith(pref + "-"):
                out.append(it["path"])
                break
    return out


def get_text(root: Path, relpath: str, max_bytes=2_000_000) -> str:
    p = root / relpath
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(max_bytes)
    except OSError:
        return ""


def extract_supportconfig_section(text: str, *command_substrings) -> list:
    subs = [s.lower() for s in command_substrings]
    lines = text.splitlines()
    out = []
    capture = False
    for i, line in enumerate(lines):
        if SECTION_HEADER_RE.match(line):
            capture = False
            if i + 1 < len(lines) and lines[i + 1].startswith("#"):
                src = lines[i + 1].lower()
                if any(s in src for s in subs):
                    capture = True
            continue
        if capture:
            if line.startswith("#==["):
                capture = False
                continue
            out.append(line)
    return out


def iter_supportconfig_lines(fh):
    current_source = None
    expect_source_line = False
    for lineno, raw in enumerate(fh, start=1):
        line = raw.rstrip("\n")
        if SECTION_HEADER_RE.match(line):
            expect_source_line = True
            current_source = None
            continue
        if expect_source_line:
            expect_source_line = False
            if line.startswith("#"):
                current_source = line.lstrip("#").strip()
                continue
        yield lineno, line, current_source


def normalize_message(line: str) -> str:
    s = line.strip()
    s = HEX_RE.sub("0x#", s)
    s = PID_RE.sub("[#]", s)
    s = NUM_RE.sub("#", s)
    s = re.sub(r"\s+", " ", s)
    return s[:220]


def parse_timestamp(line: str, year_hint: int):
    # Hot path (called per-line for every log-like file) - hand-rolled
    # parsing instead of strptime() is materially faster at multi-million
    # line scale.
    m = SYSLOG_TS_RE.match(line)
    if m:
        mon = MONTH_NUM.get(m.group(1).lower())
        if mon is None:
            return None
        try:
            return datetime(year_hint, mon, int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)))
        except ValueError:
            return None
    m = ISO_TS_RE.match(line)
    if m:
        try:
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)), int(m.group(6)))
        except ValueError:
            return None
    # dmesg -T / --time-format=ctime bracketed absolute timestamp. Plain
    # boot-relative dmesg ("[   123.456789] ...") intentionally does NOT
    # match here and falls through to None - it can't be mapped to a wall
    # clock without knowing the boot epoch, so it's correctly left
    # unfiltered by any time-window request rather than guessed at.
    m = DMESG_CTIME_RE.match(line)
    if m:
        mon = MONTH_NUM.get(m.group(1).lower())
        if mon is None:
            return None
        try:
            return datetime(int(m.group(6)), mon, int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)))
        except ValueError:
            return None
    # Fallback: raw /var/log/audit/audit.log records carry no leading
    # syslog-style timestamp, only an embedded epoch, e.g.
    # "type=AVC msg=audit(1752150602.123:456): ...". Only reached when
    # the anchored checks above already failed, so this doesn't add cost
    # to the common syslog/ISO/dmesg case.
    m = AUDIT_EPOCH_RE.search(line)
    if m:
        try:
            return datetime.utcfromtimestamp(int(m.group(1)))
        except (ValueError, OSError, OverflowError):
            return None
    return None


def parse_user_datetime(s: str, end_of_day: bool = False):
    """Parse a user-supplied --start/--end/--around value. Accepts
    'YYYY-MM-DD', 'YYYY-MM-DD HH:MM[:SS]', and the same with a 'T'
    separator. Returns None if unparseable. When only a bare date is
    given and end_of_day is True, the time is set to 23:59:59 instead of
    midnight (so --end 2026-07-10 covers the whole day)."""
    s = s.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    try:
        d = datetime.strptime(s, "%Y-%m-%d")
        return d.replace(hour=23, minute=59, second=59) if end_of_day else d
    except ValueError:
        return None


def try_parse_full_date(text: str):
    text = re.sub(r"\s+", " ", text.strip())
    candidates = [text, re.sub(r"\s+[A-Z]{2,5}\s+(\d{4})$", r" \1", text)]
    fmts = [
        "%a %b %d %H:%M:%S %Z %Y", "%a %b %d %H:%M:%S %Y",
        "%a %d %b %Y %H:%M:%S %Z", "%a %d %b %Y %H:%M:%S",
    ]
    for cand in candidates:
        for fmt in fmts:
            try:
                return datetime.strptime(cand, fmt)
            except ValueError:
                continue
    return None


def classify_line(line: str, low: str):
    if not any(k in low for k in COARSE_KEYWORDS):
        return None
    best = None
    for pid, sev, cat, rx in COMPILED_PATTERNS:
        if rx.search(line):
            rank = SEVERITY_RANK[sev]
            if best is None or rank > best[1]:
                best = (pid, rank, sev, cat)
    if best is None:
        return None
    return best[0], best[2], best[3]


# --------------------------------------------------------------------------
# Core scan
# --------------------------------------------------------------------------
def scan_file(root, relpath, kind, file_category, ctx):
    fpath = root / relpath
    is_sc_txt = kind == "supportconfig"
    findings = ctx["findings"]
    timeline = ctx["timeline"]
    log_spans = ctx["log_spans"]
    stats = ctx["stats"]
    max_examples = ctx["max_examples"]
    window_start = ctx["window_start"]
    window_end = ctx["window_end"]
    try:
        size = fpath.stat().st_size
    except OSError:
        return
    stats["bytes_scanned"] += max(size, 0)
    track_span = file_category in LOG_LIKE_CATEGORIES
    # Only chronological log-like files are gated by a time window; config
    # dumps/package lists/other point-in-time snapshots are always fully
    # scanned regardless (a time window doesn't meaningfully apply to them).
    gate_by_window = track_span and (window_start is not None or window_end is not None)
    cursor_ts = None  # last timestamp seen in this file so far; carried
    # forward across timestamp-less continuation lines (e.g. multi-line
    # stack traces) so they inherit the enclosing event's time for both
    # window-gating and timeline placement.
    try:
        with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
            gen = iter_supportconfig_lines(fh) if is_sc_txt else ((i, l.rstrip("\n"), None) for i, l in enumerate(fh, start=1))
            for lineno, line, source in gen:
                stats["lines_scanned"] += 1
                ts = None
                if track_span:
                    ts = parse_timestamp(line, stats["year_hint"])
                    if ts:
                        cursor_ts = ts
                        span = log_spans.setdefault(relpath, [ts, ts])
                        if ts < span[0]:
                            span[0] = ts
                        if ts > span[1]:
                            span[1] = ts
                if gate_by_window:
                    # No timestamp ever seen yet on this line/file (e.g. a
                    # preamble/header line, or a file whose timestamp
                    # format we don't recognize) -> don't silently drop it;
                    # only exclude lines we can positively place outside
                    # the requested window.
                    in_window = cursor_ts is None or (
                        (window_start is None or cursor_ts >= window_start) and
                        (window_end is None or cursor_ts <= window_end)
                    )
                    if in_window:
                        stats["lines_in_window"] += 1
                    else:
                        stats["lines_out_of_window"] += 1
                        continue
                result = classify_line(line, line.lower())
                if result is None:
                    continue
                pid, sev, cat_hint = result
                category = cat_hint or file_category
                provenance = relpath + (f" [{source}]" if source else "")
                key = (category, sev, pid, normalize_message(line))
                entry = findings.get(key)
                if entry is None:
                    entry = {
                        "category": category, "severity": sev, "pattern": pid,
                        "message": line.strip()[:300], "count": 0, "examples": [],
                    }
                    findings[key] = entry
                entry["count"] += 1
                if len(entry["examples"]) < max_examples:
                    entry["examples"].append({"file": provenance, "line": lineno, "text": line.strip()[:300]})
                if (sev == "CRITICAL" or (sev == "ERROR" and pid not in GENERIC_PATTERN_IDS)) and len(timeline) < 20000:
                    ts_for_timeline = ts if ts is not None else (cursor_ts if track_span else parse_timestamp(line, stats["year_hint"]))
                    if ts_for_timeline:
                        timeline.append({
                            "ts": ts_for_timeline.isoformat(), "severity": sev, "category": category,
                            "file": provenance, "line": lineno, "text": line.strip()[:220],
                        })
    except (OSError, UnicodeDecodeError):
        stats["read_errors"] += 1


# --------------------------------------------------------------------------
# Structured fact checks
# --------------------------------------------------------------------------
def check_capture_date(root, kind, inventory):
    text = ""
    if kind == "sosreport":
        cands = [it["path"] for it in inventory if it["path"].lower() in ("date", "date.txt")]
        cands += find_by_basename_prefix(inventory, "date")
        for relp in cands:
            text = get_text(root, relp, 2000).strip()
            if text:
                break
    elif kind == "crm_report":
        # crm_report has no single "date" command dump. description.txt's
        # generated template includes a clean "Date:" field (preferred);
        # time.txt records each node's clock as "<node>: <date output>"
        # but may have a title/divider line first, so search for the
        # first line that actually looks like a date rather than
        # assuming it's line 0.
        for relp in find_inventory(inventory, "description.txt"):
            t = get_text(root, relp, 4000)
            m = re.search(r"^Date:\s*(.+)$", t, re.MULTILINE)
            if m:
                text = m.group(1).strip()[:200]
                break
        if not text:
            date_line_re = re.compile(r"[A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}.*\b\d{4}\b")
            for relp in find_inventory(inventory, "time.txt"):
                t = get_text(root, relp, 4000)
                for line in t.splitlines():
                    m = date_line_re.search(line)
                    if m:
                        text = m.group(0)[:200]
                        break
                if text:
                    break
    else:
        for relp in find_inventory(inventory, "basic-environment.txt"):
            t = get_text(root, relp, 200000)
            sec = extract_supportconfig_section(t, "/bin/date", "# date")
            if sec:
                text = "\n".join(s for s in sec if s.strip() and not s.startswith("#"))[:200].strip()
                break
    year = None
    m = re.search(r"\b(19|20)\d{2}\b", text)
    if m:
        year = int(m.group(0))
    full_dt = try_parse_full_date(text) if text else None
    return text[:200], year, full_dt


def check_system_info(root, kind, inventory):
    info = {}
    if kind == "sosreport":
        lookups = [
            ("hostname", find_by_basename_prefix(inventory, "hostname")),
            ("uname", find_by_basename_prefix(inventory, "uname")),
            ("uptime", find_by_basename_prefix(inventory, "uptime")),
            ("os_release", find_inventory(inventory, "etc/os-release", "etc/redhat-release", "etc/system-release")),
        ]
        for name, cands in lookups:
            for relp in cands:
                t = get_text(root, relp, 4000).strip()
                if t:
                    info[name] = t.splitlines()[0][:300]
                    break
    elif kind == "crm_report":
        nodes = detect_crm_report_nodes(inventory)
        if nodes:
            info["cluster_nodes"] = ", ".join(nodes)
        for relp in find_inventory(inventory, "sysinfo.txt"):
            t = get_text(root, relp, 1_000_000)
            m = re.search(r"^Linux\s+\S+\s+\S+.*$", t, re.MULTILINE)
            if m:
                info["uname"] = m.group(0)[:300]
                break
        for relp in find_inventory(inventory, "sysinfo.txt", "rpm.txt", "packages"):
            t = get_text(root, relp, 1_000_000)
            m = re.search(r"^(pacemaker|corosync)[-\s].*?(\d+\.\d+[\.\d]*)", t, re.MULTILINE | re.IGNORECASE)
            if m:
                info.setdefault("cluster_stack_version", m.group(0).strip()[:200])
    else:
        for relp in find_inventory(inventory, "basic-environment.txt"):
            t = get_text(root, relp, 300000)
            for name, subs in [
                ("hostname", ["/bin/hostname", "# hostname"]),
                ("uname", ["/bin/uname"]),
                ("uptime", ["/usr/bin/uptime", "bin/uptime"]),
                ("os_release", ["suse-release", "os-release", "/etc/*release"]),
            ]:
                sec = [s for s in extract_supportconfig_section(t, *subs) if s.strip() and not s.startswith("#")]
                if sec:
                    info[name] = " ".join(sec).strip()[:300]
    return info


def parse_df_text(text):
    rows = []
    for line in text.splitlines():
        m = DF_LINE_RE.match(line.strip())
        if m:
            rows.append({"filesystem": m.group("fs"), "use_pct": int(m.group("pct")), "mount": m.group("mount").strip()})
    return rows


def check_disk_usage(root, kind, inventory):
    text = ""
    if kind == "sosreport":
        for relp in find_by_basename_prefix(inventory, "df"):
            text += get_text(root, relp) + "\n"
    elif kind == "crm_report":
        # sysinfo.txt is a per-node grab-bag of basic command output
        # (crmsh doesn't wrap it in the supportconfig-style section
        # markers), so a direct regex scan across the whole file is the
        # most reliable approach rather than trying to locate a specific
        # command header.
        for relp in find_inventory(inventory, "sysinfo.txt"):
            text += get_text(root, relp, 1_000_000) + "\n"
    else:
        for relp in find_inventory(inventory, "fs-diskusage.txt", "filesystems.txt"):
            t = get_text(root, relp, 500000)
            sec = extract_supportconfig_section(t, "/bin/df")
            text += "\n".join(sec) + "\n"
    rows = parse_df_text(text)
    rows.sort(key=lambda r: -r["use_pct"])
    flagged = [r for r in rows if r["use_pct"] >= 85]
    return {"all": rows[:60], "flagged_over_85pct": flagged}


def check_memory(root, kind, inventory):
    text = ""
    if kind == "sosreport":
        for relp in find_by_basename_prefix(inventory, "free"):
            text = get_text(root, relp)
            if text.strip():
                break
    elif kind == "crm_report":
        for relp in find_inventory(inventory, "sysinfo.txt"):
            t = get_text(root, relp, 1_000_000)
            if re.search(r"Mem:\s+\d+", t):
                text = t
                break
    else:
        for relp in find_inventory(inventory, "memory.txt"):
            t = get_text(root, relp, 500000)
            sec = extract_supportconfig_section(t, "/usr/bin/free", "bin/free")
            if sec:
                text = "\n".join(sec)
                break
    result = {"raw": text.strip()[:500]}
    m = re.search(r"Mem:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)", text)
    if m:
        total, used, free_, shared, buff, avail = map(int, m.groups())
        result.update(total=total, used=used, free=free_, available=avail)
        if total > 0:
            result["available_pct"] = round(avail / total * 100, 1)
    m2 = re.search(r"Swap:\s+(\d+)\s+(\d+)\s+(\d+)", text)
    if m2:
        stotal, sused, sfree = map(int, m2.groups())
        result["swap_total"] = stotal
        result["swap_used"] = sused
        if stotal > 0:
            result["swap_used_pct"] = round(sused / stotal * 100, 1)
    return result


def check_load(root, kind, inventory):
    uptime_text = ""
    cpu_count = None
    if kind == "sosreport":
        for relp in find_by_basename_prefix(inventory, "uptime"):
            uptime_text = get_text(root, relp)
            if uptime_text.strip():
                break
        for relp in find_by_basename_prefix(inventory, "lscpu"):
            t = get_text(root, relp, 2_000_000)
            m = re.search(r"CPU\(s\):\s*(\d+)", t)
            if m:
                cpu_count = int(m.group(1))
                break
        if cpu_count is None:
            for relp in find_inventory(inventory, "proc/cpuinfo"):
                t = get_text(root, relp, 2_000_000)
                cnt = len(re.findall(r"^processor\s*:", t, re.MULTILINE))
                if cnt:
                    cpu_count = cnt
                    break
    elif kind == "crm_report":
        for relp in find_inventory(inventory, "sysinfo.txt"):
            t = get_text(root, relp, 1_000_000)
            if "load average:" in t:
                uptime_text = t
            cnt = len(re.findall(r"^processor\s*:", t, re.MULTILINE))
            if cnt:
                cpu_count = cnt
            if uptime_text and cpu_count:
                break
    else:
        for relp in find_inventory(inventory, "basic-environment.txt"):
            t = get_text(root, relp, 500000)
            sec = extract_supportconfig_section(t, "/usr/bin/uptime", "bin/uptime")
            if sec:
                uptime_text = "\n".join(sec)
                break
        for relp in find_inventory(inventory, "basic-environment.txt", "hardware.txt"):
            t = get_text(root, relp, 1_000_000)
            cnt = len(re.findall(r"^processor\s*:", t, re.MULTILINE))
            if cnt:
                cpu_count = cnt
                break
    result = {"uptime_raw": uptime_text.strip()[:300], "cpu_count": cpu_count}
    m = re.search(r"load average:\s*([\d.]+),?\s*([\d.]+),?\s*([\d.]+)", uptime_text)
    if m:
        l1, l5, l15 = map(float, m.groups())
        result.update(load1=l1, load5=l5, load15=l15)
        if cpu_count:
            result["load1_per_core"] = round(l1 / cpu_count, 2)
    return result


def check_failed_services(root, kind, inventory):
    text = ""
    if kind == "sosreport":
        for relp in find_by_basename_prefix(inventory, "systemctl"):
            base = relp.lower()
            if "failed" in base or "list-units" in base or "list_units" in base:
                text += get_text(root, relp) + "\n"
    elif kind == "crm_report":
        for relp in find_inventory(inventory, "sysinfo.txt"):
            text += get_text(root, relp, 1_000_000) + "\n"
    else:
        for relp in find_inventory(inventory, "systemd.txt", "services.txt"):
            t = get_text(root, relp, 1_000_000)
            sec = extract_supportconfig_section(t, "systemctl --failed", "systemctl list-units")
            text += "\n".join(sec) + "\n"
    units = []
    for line in text.splitlines():
        clean = line.strip().lstrip("●*").strip()
        m = FAILED_UNIT_RE.match(clean)
        if m:
            units.append(m.group("unit"))
    return {"failed_units": sorted(set(units))}


def check_cluster_health(root, kind, inventory):
    """crm_report-specific: cluster membership, crm_mon status (offline/
    unclean nodes, failed resource actions), and crm_report's own
    analysis.txt verbatim (it runs a basic CRIT:/ERROR:/WARNING: log scan
    during collection - a useful independent cross-check)."""
    result = {}
    nodes = detect_crm_report_nodes(inventory)
    if nodes:
        result["nodes_detected"] = nodes
    for relp in find_inventory(inventory, "members.txt"):
        t = get_text(root, relp, 4000).strip()
        if t:
            result["members_raw"] = t[:2000]
            break
    for relp in find_inventory(inventory, "crm_mon.txt"):
        t = get_text(root, relp, 200000)
        if not t.strip():
            continue
        result["crm_mon_raw"] = t[:4000]
        offline = set()
        # Newer crm_mon grouped format: "* OFFLINE: [ node2 node3 ]"
        for m in re.finditer(r"\*?\s*(OFFLINE|UNCLEAN)\s*:\s*\[([^\]]*)\]", t, re.IGNORECASE):
            status = m.group(1).upper()
            for name in m.group(2).split():
                offline.add(f"{name} ({status})")
        # Older per-node format: "Node node2: UNCLEAN (offline)" / "Node node2 (2): OFFLINE"
        for m in re.finditer(r"Node\s+(\S+)\s*(?:\(\d+\))?\s*:\s*\(?\s*(OFFLINE|UNCLEAN)\b", t, re.IGNORECASE):
            offline.add(f"{m.group(1)} ({m.group(2).upper()})")
        if offline:
            result["offline_or_unclean_nodes"] = sorted(offline)
        if re.search(r"Failed Resource Actions", t, re.IGNORECASE):
            fa_section = t.split("Failed Resource Actions", 1)[-1][:2000]
            result["failed_resource_actions_raw"] = fa_section.strip()
        break
    for relp in find_inventory(inventory, "analysis.txt"):
        t = get_text(root, relp, 20000).strip()
        if t:
            result["crm_analysis_txt"] = t
            break
    return result


def run_structured_checks(root, kind, inventory):
    facts = {}
    try:
        raw, year, full_dt = check_capture_date(root, kind, inventory)
        facts["capture_date_raw"] = raw
        facts["capture_year"] = year
        facts["capture_datetime"] = full_dt.isoformat() if full_dt else None
    except Exception as e:
        facts["capture_date_error"] = str(e)
    try:
        facts["system_info"] = check_system_info(root, kind, inventory)
    except Exception as e:
        facts["system_info_error"] = str(e)
    try:
        facts["disk_usage"] = check_disk_usage(root, kind, inventory)
    except Exception as e:
        facts["disk_usage_error"] = str(e)
    try:
        facts["memory"] = check_memory(root, kind, inventory)
    except Exception as e:
        facts["memory_error"] = str(e)
    try:
        facts["load_average"] = check_load(root, kind, inventory)
    except Exception as e:
        facts["load_error"] = str(e)
    try:
        facts["failed_services"] = check_failed_services(root, kind, inventory)
    except Exception as e:
        facts["failed_services_error"] = str(e)
    try:
        facts["core_dumps_present"] = any(it["category"] == "core_dumps" and it["size"] > 1024 for it in inventory)
    except Exception as e:
        facts["core_dumps_error"] = str(e)
    if kind == "crm_report":
        try:
            facts["cluster_health"] = check_cluster_health(root, kind, inventory)
        except Exception as e:
            facts["cluster_health_error"] = str(e)
    return facts


# --------------------------------------------------------------------------
# Digest rendering
# --------------------------------------------------------------------------
def build_digest(kind, root, input_path, inventory, findings_list, facts, timeline, log_spans, stats, args, elapsed):
    lines = []
    lines.append(f"# Root-Cause Analysis Digest — {input_path.name}")
    lines.append("")
    lines.append(f"- **Analyzer version:** {__version__}")
    lines.append(f"- **Detected type:** {kind}")
    lines.append(f"- **Source:** `{input_path}`")
    lines.append(f"- **Extracted root:** `{root}`")
    lines.append(f"- **Files inventoried:** {len(inventory):,}")
    lines.append(f"- **Files content-scanned:** {stats['files_scanned']:,} (binary/empty skipped: {stats['files_skipped_binary']:,}, read errors: {stats['read_errors']:,})")
    if stats.get("window_active"):
        lines.append(f"- **Lines scanned:** {stats['lines_scanned']:,} (~{human_size(stats['bytes_scanned'])}) — **{stats['lines_in_window']:,} in-window / {stats['lines_out_of_window']:,} excluded by time filter**")
    else:
        lines.append(f"- **Lines scanned:** {stats['lines_scanned']:,} (~{human_size(stats['bytes_scanned'])})")
    lines.append(f"- **Distinct findings:** {len(findings_list):,}")
    lines.append(f"- **Analysis duration:** {elapsed:.1f}s")
    lines.append("")

    focus_text = getattr(args, "focus_text", None)
    focus_keywords = getattr(args, "focus_keywords", None) or []
    if focus_text:
        lines.append("## 🎯 Focused Findings — matching your investigation")
        lines.append(f'> You asked this analysis to focus on: "{focus_text}"')
        if focus_keywords:
            lines.append(f"> Keywords derived from this focus: {', '.join(f'`{k}`' for k in focus_keywords)}")
        lines.append("")
        matching = [f for f in findings_list if f.get("focus_match")]
        if matching:
            matching_sorted = sorted(matching, key=lambda f: (-SEVERITY_RANK[f["severity"]], -f["count"]))
            for f in matching_sorted[:40]:
                lines.append(f"- **[{f['severity']}]** ({f['count']}x) [{f['category']}] {f['message']}")
                for ex in f["examples"][:2]:
                    lines.append(f"  - `{ex['file']}:{ex['line']}`")
            if len(matching) > 40:
                lines.append(f"- _(+{len(matching) - 40} more focus-matching findings — see findings.json, filter on \"focus_match\": true)_")
            lines.append("")
            lines.append(f"_{len(matching)} of {len(findings_list)} total findings matched your stated focus. Every finding is still listed in full below under \"Findings by Category\" for completeness — matches are marked with 🎯 there too._")
        else:
            lines.append("_No findings directly matched keywords derived from your focus text. This could mean: (a) the issue you're investigating didn't trip any of the engine's pattern rules, (b) it's described differently in the source logs than your wording, or (c) it needs detail this evidence digest doesn't fully capture. Check `inventory.json` for relevant files and open them directly, or try re-phrasing the focus with more specific resource/host names._")
        lines.append("")

    if stats.get("window_active"):
        lines.append("## Time Window Filter")
        ws = args.start_dt.isoformat() if args.start_dt else "(no lower bound)"
        we = args.end_dt.isoformat() if args.end_dt else "(no upper bound)"
        lines.append(f"- **Scoped to:** `{ws}` → `{we}`")
        lines.append("- Only chronological log-like files (messages, audit, journal exports, etc.) were gated by this window. Configuration dumps, package lists, and other point-in-time snapshot files were still fully scanned, since a time window doesn't meaningfully apply to a single-snapshot file.")
        lines.append("- Lines whose timestamp could not be determined were conservatively kept in-scope rather than silently dropped.")
        lines.append("")

    si = facts.get("system_info", {})
    if si or facts.get("capture_date_raw"):
        lines.append("## System Information")
        for k, v in si.items():
            lines.append(f"- **{k}:** {v}")
        if facts.get("capture_date_raw"):
            lines.append(f"- **capture_date:** {facts['capture_date_raw']}")
        lines.append("")

    if kind == "crm_report":
        ch = facts.get("cluster_health", {})
        if ch:
            lines.append("## Cluster Status (crm_report)")
            if ch.get("nodes_detected"):
                lines.append(f"- **Nodes in report:** {', '.join(ch['nodes_detected'])}")
            if ch.get("offline_or_unclean_nodes"):
                lines.append(f"- ⚠️ **Offline/unclean nodes:** {', '.join(ch['offline_or_unclean_nodes'])}")
            if ch.get("failed_resource_actions_raw"):
                lines.append("- ⚠️ **Failed Resource Actions detected** in crm_mon.txt (see `## Findings by Category` / `facts.json` → `cluster_health.failed_resource_actions_raw` for detail)")
            if not (ch.get("offline_or_unclean_nodes") or ch.get("failed_resource_actions_raw")):
                lines.append("- No offline/unclean nodes or failed resource actions detected in crm_mon.txt at capture time.")
            lines.append("")
            if ch.get("crm_analysis_txt"):
                lines.append("## crm_report Built-in Analysis (analysis.txt, verbatim)")
                lines.append("_crm_report runs its own basic log-pattern scan (CRIT:/ERROR:/WARNING:) during collection. Shown verbatim here as an independent cross-check against this tool's own findings below — agreement between the two raises confidence; a mismatch is worth investigating directly._")
                lines.append("")
                lines.append("```")
                lines.append(ch["crm_analysis_txt"][:4000])
                lines.append("```")
                lines.append("")

    lines.append("## Key Facts")
    any_fact = False
    mem = facts.get("memory", {})
    if mem.get("available_pct") is not None:
        any_fact = True
        swap = mem.get("swap_used_pct")
        lines.append(f"- **Memory available:** {mem['available_pct']}% (total {mem.get('total','?')} kB)" + (f" — swap used: {swap}%" if swap is not None else ""))
    load = facts.get("load_average", {})
    if load.get("load1") is not None:
        any_fact = True
        extra = f", {load['load1_per_core']}/core over {load.get('cpu_count','?')} cores" if load.get("load1_per_core") else ""
        lines.append(f"- **Load average:** {load['load1']}, {load['load5']}, {load['load15']}{extra}")
    disk = facts.get("disk_usage", {})
    if disk.get("flagged_over_85pct"):
        any_fact = True
        lines.append("- **Filesystems ≥85% full:** " + ", ".join(f"{r['mount']} ({r['use_pct']}%)" for r in disk["flagged_over_85pct"][:10]))
    fs_units = facts.get("failed_services", {}).get("failed_units")
    if fs_units:
        any_fact = True
        lines.append("- **Failed systemd units:** " + ", ".join(fs_units[:15]))
    if facts.get("core_dumps_present"):
        any_fact = True
        lines.append("- **Core dumps / crash artifacts present:** yes — inspect `core_dumps` category")
    if not any_fact:
        lines.append("- _(no structured anomalies detected by fact-checks; rely on pattern findings below)_")
    lines.append("")

    if log_spans:
        lines.append("## Log Coverage Window")
        cap_dt = facts.get("capture_datetime")
        cap_dt_parsed = datetime.fromisoformat(cap_dt) if cap_dt else None
        for relp, (start, end) in sorted(log_spans.items()):
            note = ""
            if cap_dt_parsed:
                gap_hours = (cap_dt_parsed - end).total_seconds() / 3600.0
                if gap_hours > 1:
                    note = f"  ⚠️ **stopped updating ~{gap_hours:.1f}h before capture — possible logging outage / hang / reboot**"
            lines.append(f"- `{relp}`: {start.isoformat()} → {end.isoformat()}{note}")
        lines.append("")

    lines.append("## Findings by Category")
    by_cat = defaultdict(list)
    for f in findings_list:
        by_cat[f["category"]].append(f)
    min_rank = SEVERITY_RANK[args.min_severity]
    cat_order = sorted(by_cat, key=lambda c: -max(SEVERITY_RANK[f["severity"]] for f in by_cat[c]))
    for cat in cat_order:
        cat_findings = [f for f in by_cat[cat] if SEVERITY_RANK[f["severity"]] >= min_rank]
        if not cat_findings:
            continue
        cat_findings.sort(key=lambda f: (-SEVERITY_RANK[f["severity"]], -f["count"]))
        sev_counts = Counter(f["severity"] for f in by_cat[cat])
        sev_summary = ", ".join(f"{n} {s}" for s, n in sorted(sev_counts.items(), key=lambda kv: -SEVERITY_RANK[kv[0]]))
        lines.append(f"### {cat}  ({sev_summary})")
        for f in cat_findings[: args.top_per_category]:
            marker = "🎯 " if f.get("focus_match") else ""
            lines.append(f"- {marker}**[{f['severity']}]** ({f['count']}x) {f['message']}")
            for ex in f["examples"][:2]:
                lines.append(f"  - `{ex['file']}:{ex['line']}`")
        if len(cat_findings) > args.top_per_category:
            lines.append(f"  - _(+{len(cat_findings) - args.top_per_category} more {cat} findings at/above {args.min_severity} — see findings.json)_")
        lines.append("")

    if timeline:
        timeline_sorted = sorted(timeline, key=lambda x: x["ts"])
        lines.append("## Chronological Timeline of Significant Events")
        lines.append("_CRITICAL events and high-signal ERROR events, in time order (year inferred where the source log omits it):_")
        lines.append("")
        shown = 0
        prev_key = None
        total = len(timeline_sorted)
        for ev in timeline_sorted:
            key = (ev["ts"][:16], ev["category"], ev["text"][:60])
            if key == prev_key:
                continue
            prev_key = key
            marker = "🎯 " if ev.get("focus_match") else ""
            lines.append(f"- {marker}`{ev['ts']}` **[{ev['severity']}/{ev['category']}]** {ev['text']}  (`{ev['file']}:{ev['line']}`)")
            shown += 1
            if shown >= 120:
                lines.append(f"- _(+{total - shown} more timeline events — see findings.json / raw logs)_")
                break
        lines.append("")

    lines.append("## Coverage Notes")
    if stats.get("window_active"):
        lines.append("- Generated by mechanical pattern scanning across **every** text file in the archive, with chronological logs restricted to the time window above (binary/compressed/known-opaque files are inventoried but not line-scanned).")
    else:
        lines.append("- Generated by mechanical pattern scanning across **every** text file in the archive (binary/compressed/known-opaque files are inventoried but not line-scanned).")
    lines.append("- `inventory.json` = every file found. `findings.json` = every deduplicated match with file:line provenance. `facts.json` = structured checks.")
    lines.append(f"- Findings below `{args.min_severity}` and beyond the per-category cap ({args.top_per_category}) are omitted here for readability but remain in `findings.json`.")
    lines.append("- Treat this digest as evidence for root-cause synthesis — open the referenced `file:line` in the extracted tree for full context on any item.")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
class AnalysisError(Exception):
    """Raised for user-facing analysis errors (bad path, unrecognized
    archive, invalid time range). Safe to catch anywhere (e.g. a web
    backend) - unlike die(), this never calls sys.exit()."""
    pass


class _DigestArgs:
    """Lightweight stand-in for the argparse.Namespace that build_digest()
    expects, so the CLI and the library entrypoint can share one digest
    renderer without build_digest() needing to know which caller it has."""
    def __init__(self, min_severity, top_per_category, start_dt, end_dt, focus_text=None, focus_keywords=None):
        self.min_severity = min_severity
        self.top_per_category = top_per_category
        self.start_dt = start_dt
        self.end_dt = end_dt
        self.focus_text = focus_text
        self.focus_keywords = focus_keywords or []


def run_analysis(input_path, output_dir=None, min_severity="WARNING", top_per_category=25,
                  max_examples=3, start=None, end=None, around=None, window=60.0,
                  focus=None, progress_cb=None):
    """
    Library entrypoint - run a full analysis and return a result dict:
        {kind, root, input_path, output_dir, inventory, findings, facts,
         timeline, stats, digest_markdown, elapsed_seconds}
    Also writes inventory.json/findings.json/facts.json/digest.md into
    output_dir, exactly as the CLI does, so both entrypoints stay
    consistent and either can be used to inspect a prior run's output.

    start/end/around accept either datetime objects or the same string
    formats the CLI --start/--end/--around flags accept ('YYYY-MM-DD' or
    'YYYY-MM-DD HH:MM[:SS]'). window is minutes of total padding around
    'around', split evenly on both sides.

    focus is an optional free-text description of what the engineer is
    actually investigating (e.g. "find root cause of NC and IP cluster
    resource restart issue"). When given, every finding and timeline
    event is tagged with whether it matches keywords derived from this
    text, and the digest gets a dedicated "Focused Findings" section
    ahead of the full exhaustive scan - this is what lets the tool
    answer a specific question instead of just surfacing whatever is
    highest-severity regardless of relevance.

    progress_cb(message: str), if given, is called with human-readable
    progress strings instead of printing to stdout - used by the web
    backend to stream live status to the browser.

    Raises AnalysisError for any user-facing problem. Never calls
    sys.exit(), so it's safe to call from a long-lived server process.
    """
    def report(msg):
        if progress_cb:
            progress_cb(msg)
        else:
            print(msg)

    if around and (start or end):
        raise AnalysisError("'around' cannot be combined with 'start'/'end' - use one or the other")

    def _coerce_dt(value, end_of_day=False):
        if value is None or isinstance(value, datetime):
            return value
        dt = parse_user_datetime(str(value), end_of_day=end_of_day)
        if dt is None:
            raise AnalysisError(f"could not parse time value: {value!r} (expected 'YYYY-MM-DD' or 'YYYY-MM-DD HH:MM[:SS]')")
        return dt

    start_dt = _coerce_dt(start)
    end_dt = _coerce_dt(end, end_of_day=True)
    if around:
        around_dt = _coerce_dt(around)
        pad = timedelta(minutes=max(float(window), 0) / 2.0)
        start_dt = around_dt - pad
        end_dt = around_dt + pad
    if start_dt and end_dt and start_dt > end_dt:
        raise AnalysisError(f"start ({start_dt}) is after end ({end_dt})")

    input_path = Path(input_path).resolve()
    if not input_path.exists():
        raise AnalysisError(f"input path not found: {input_path}")

    default_name = input_path.name if input_path.is_dir() else strip_archive_suffix(input_path.name)
    output_dir = Path(output_dir).resolve() if output_dir else (input_path.parent / f"{default_name}_analysis")
    output_dir.mkdir(parents=True, exist_ok=True)

    report(f"LDI Copilot analysis engine v{__version__}")
    t0 = time.time()
    if input_path.is_dir():
        root = resolve_root(input_path)  # auto-descend if user pointed at a wrapper folder with one subdir
    else:
        kind_archive = detect_archive_kind(input_path)
        if kind_archive is None:
            raise AnalysisError(f"could not determine archive type for {input_path} (expected .tar.xz/.tgz/.tbz2/.zip, or pass a directory)")
        extract_dir = output_dir / "extracted"
        extract_dir.mkdir(parents=True, exist_ok=True)
        report(f"Extracting {input_path.name} -> {extract_dir}")
        try:
            skipped = safe_extract_zip(input_path, extract_dir) if kind_archive == "zip" else safe_extract_tar(input_path, extract_dir)
        except Exception as e:
            raise AnalysisError(f"failed to extract archive: {e}") from e
        if skipped:
            report(f"  ({len(skipped)} archive members skipped - symlinks/specials/errors; see extraction_skipped.json)")
            (output_dir / "extraction_skipped.json").write_text(json.dumps(skipped[:2000], indent=2), encoding="utf-8")
        root = resolve_root(extract_dir)

    kind = detect_type(root)
    report(f"Detected archive type: {kind}")
    report(f"Root directory: {root}")

    report("Building file inventory...")
    inventory = build_inventory(root, kind)
    report(f"  {len(inventory)} files found")

    report("Running structured fact-checks...")
    facts = run_structured_checks(root, kind, inventory)

    year_hint = facts.get("capture_year") or datetime.utcnow().year
    window_active = start_dt is not None or end_dt is not None
    ctx = {
        "findings": {}, "timeline": [], "log_spans": {},
        "max_examples": max_examples,
        "window_start": start_dt, "window_end": end_dt,
        "stats": {"bytes_scanned": 0, "lines_scanned": 0, "read_errors": 0,
                   "files_scanned": 0, "files_skipped_binary": 0, "year_hint": year_hint,
                   "lines_in_window": 0, "lines_out_of_window": 0, "window_active": window_active},
    }
    if window_active:
        report(f"Time window active: {start_dt or '(open start)'} -> {end_dt or '(open end)'} (chronological logs only; config/snapshot files always fully scanned)")

    report("Scanning files for known failure signatures (this can take a while for large archives)...")
    last_report = time.time()
    for item in inventory:
        relpath = item["path"]
        if item["size"] <= 0:
            continue
        fpath = root / relpath
        if not is_probably_text(fpath):
            ctx["stats"]["files_skipped_binary"] += 1
            continue
        scan_file(root, relpath, kind, item["category"], ctx)
        ctx["stats"]["files_scanned"] += 1
        if time.time() - last_report > 5:
            report(f"  ...scanned {ctx['stats']['files_scanned']}/{len(inventory)} files, {len(ctx['findings'])} distinct findings so far")
            last_report = time.time()

    stats = ctx["stats"]
    report(f"Scan complete: {stats['files_scanned']} files scanned, {stats['lines_scanned']:,} lines, {len(ctx['findings'])} distinct findings")
    if window_active:
        report(f"  ({stats['lines_in_window']:,} lines in-window, {stats['lines_out_of_window']:,} excluded by time filter)")

    findings_list = sorted(ctx["findings"].values(), key=lambda f: (-SEVERITY_RANK[f["severity"]], -f["count"]))

    focus_text = (focus or "").strip() or None
    focus_keywords = extract_focus_keywords(focus_text) if focus_text else []
    focus_patterns = compile_focus_patterns(focus_keywords)
    num_focus_matches = 0
    if focus_patterns:
        for f in findings_list:
            f["focus_match"] = finding_matches_focus(f, focus_patterns)
            if f["focus_match"]:
                num_focus_matches += 1
        for ev in ctx["timeline"]:
            ev["focus_match"] = event_matches_focus(ev, focus_patterns)
        report(f"Focus applied: {len(focus_keywords)} keyword(s) derived from focus text, {num_focus_matches} of {len(findings_list)} findings matched")

    facts["analyzer_version"] = __version__
    facts["scan_window"] = {
        "active": window_active,
        "start": start_dt.isoformat() if start_dt else None,
        "end": end_dt.isoformat() if end_dt else None,
        "lines_in_window": stats["lines_in_window"],
        "lines_out_of_window": stats["lines_out_of_window"],
    }
    facts["focus"] = {
        "text": focus_text,
        "keywords": focus_keywords,
        "num_matching_findings": num_focus_matches,
    }

    (output_dir / "inventory.json").write_text(json.dumps(inventory, indent=2), encoding="utf-8")
    (output_dir / "findings.json").write_text(json.dumps(findings_list, indent=2), encoding="utf-8")
    (output_dir / "facts.json").write_text(json.dumps(facts, indent=2, default=str), encoding="utf-8")

    digest_args = _DigestArgs(min_severity, top_per_category, start_dt, end_dt, focus_text=focus_text, focus_keywords=focus_keywords)
    elapsed = time.time() - t0
    digest = build_digest(kind, root, input_path, inventory, findings_list, facts, ctx["timeline"], ctx["log_spans"], stats, digest_args, elapsed)
    (output_dir / "digest.md").write_text(digest, encoding="utf-8")

    report(f"\nDone in {elapsed:.1f}s. Reports written to: {output_dir}")
    report("  - digest.md      (start here)")
    report("  - findings.json")
    report("  - facts.json")
    report("  - inventory.json")

    return {
        "kind": kind,
        "root": str(root),
        "input_path": str(input_path),
        "output_dir": str(output_dir),
        "inventory": inventory,
        "findings": findings_list,
        "facts": facts,
        "timeline": ctx["timeline"],
        "stats": stats,
        "digest_markdown": digest,
        "elapsed_seconds": elapsed,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    ap.add_argument("input", help="Path to sosreport/supportconfig/crm_report archive or an already-extracted directory")
    ap.add_argument("--output", help="Output directory (default: '<input>_analysis' next to input)")
    ap.add_argument("--max-examples", type=int, default=3, help="Example file:line references kept per finding group (default 3)")
    ap.add_argument("--min-severity", choices=SEVERITY_ORDER, default="WARNING", help="Minimum severity included in digest.md (findings.json always keeps everything)")
    ap.add_argument("--top-per-category", type=int, default=25, help="Max distinct findings rendered per category in digest.md (default 25)")
    ap.add_argument("--start", help="Only scan chronological logs from this time onward. Format: 'YYYY-MM-DD' or 'YYYY-MM-DD HH:MM[:SS]'. Config/snapshot files are always fully scanned regardless.")
    ap.add_argument("--end", help="Only scan chronological logs up to this time. Same format as --start.")
    ap.add_argument("--around", help="Convenience: center the window on this time instead of giving --start/--end. Combine with --window.")
    ap.add_argument("--window", type=float, default=60.0, help="Minutes of padding on each side of --around (default 60 = +/-1h total 2h window). Ignored without --around.")
    ap.add_argument("--focus", help="Free text describing what you're actually investigating (e.g. 'find root cause of NC and IP cluster resource restart issue'). Adds a dedicated Focused Findings section to the digest ahead of the full scan.")
    args = ap.parse_args()

    try:
        run_analysis(
            args.input, output_dir=args.output, min_severity=args.min_severity,
            top_per_category=args.top_per_category, max_examples=args.max_examples,
            start=args.start, end=args.end, around=args.around, window=args.window,
            focus=args.focus,
        )
    except AnalysisError as e:
        die(str(e))


if __name__ == "__main__":
    main()
