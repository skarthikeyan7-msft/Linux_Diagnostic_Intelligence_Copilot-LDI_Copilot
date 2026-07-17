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
condensed, ranked summary meant to be read first. Individually
compressed files (gzip/bz2/xz - the common rotated-log pattern, e.g.
"messages-20180803.gz", including stacked compression like
"messages-20260406.xz.gz") are transparently decompressed and scanned
exactly like plain text, detected by content (magic bytes), not
filename - see "Compressed-file support" below.

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
import bz2
import ctypes
import gzip
import io
import json
import lzma
import os
import platform
import re
import sys
import tarfile
import time
import zipfile
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path

__version__ = "4.9.0"

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

# .gz/.bz2/.xz stay listed here too, as a deliberate fallback: real
# detection of compressed content below is by MAGIC BYTES, not this
# extension list, so a corrupted/zero-byte ".gz" (or a file mis-named
# with a compression extension it doesn't actually have) still correctly
# lands here and gets skipped as binary, rather than being fed raw
# compressed bytes through the text-line scanner as garbage. ".zip" is
# deliberately NOT given the same magic-byte-decompression treatment as
# gzip/bz2/xz below - it's a multi-member container format (could hold
# many files, not one compressed stream), which is a materially bigger
# feature (member listing, path-traversal safety, "which member(s) do we
# even scan") than this project's actual real-world need: individual
# rotated-log-style files compressed with gzip/bz2/xz, optionally
# stacked (e.g. "messages-20260406.xz.gz") - see open_decompressed_text()
# below. A full sosreport/supportconfig/crm_report bundle that is ITSELF
# a .zip is already handled separately, at extraction time, before any
# of this per-file categorization ever runs.
BINARY_SKIP_EXTS = {
    ".rpm", ".deb", ".gz", ".bz2", ".xz", ".zip", ".png", ".jpg", ".jpeg",
    ".gif", ".ico", ".pdf", ".db", ".sqlite", ".sqlite3", ".journal",
    ".pcap", ".pcapng", ".so", ".ko", ".bin", ".img", ".qcow2", ".vmdk",
    ".tar", ".core",
}

# --------------------------------------------------------------------------
# Compressed-file support (v4.8.0)
# --------------------------------------------------------------------------
# Real sosreport/supportconfig bundles routinely carry rotated logs that
# are individually compressed - e.g. "messages-20180803.gz", or (seen on
# a real customer bundle) double-compressed "messages-20260406.xz.gz"
# (an xz-compressed log that got gzipped again on top, most likely by a
# separate backup/transfer step). Before v4.8.0 these were silently
# skipped as "binary" (.gz/.bz2/.xz are in BINARY_SKIP_EXTS above) and
# NEVER scanned for failure signatures - a real, silent gap, especially
# since rotated logs from just before an incident are exactly the kind
# of evidence a root-cause investigation needs.
#
# Detection is by MAGIC BYTES, not filename extension - deliberately, so
# a mis-named or extra/missing extension (like the ".xz.gz" case above,
# where it's ambiguous from the name alone whether that's genuinely two
# compression layers or an extra suffix tacked onto an already-single-
# compressed file) is still handled correctly: peel_one_compression_layer()
# below is only ever driven by what the bytes actually are, checked again
# after each peel, so it naturally stops exactly where genuine compression
# stops - whether that's after 0, 1, or 2 layers - regardless of what the
# filename claims.
_GZIP_MAGIC = b"\x1f\x8b"
_BZ2_MAGIC = b"BZh"
_XZ_MAGIC = b"\xfd7zXZ\x00"
_MAX_COMPRESSION_LAYERS = 3  # generous (real cases need at most 2); bounds worst-case work on a pathological filename
_MAX_DECOMPRESSED_BYTES = 2 * 1024 ** 3  # 2 GB - a zip-bomb/corruption guard, not a real-world limit (see scan_file)


def sniff_compression_kind(head: bytes):
    """Given the first few bytes already read from a file, returns
    'gzip'/'bz2'/'xz' if they match a known compression magic number,
    else None. Split out from any actual file I/O so peel_one_
    compression_layer() can call this again on already-decompressed
    in-memory bytes without a redundant read."""
    if head.startswith(_GZIP_MAGIC):
        return "gzip"
    if head.startswith(_BZ2_MAGIC):
        return "bz2"
    if head.startswith(_XZ_MAGIC):
        return "xz"
    return None


def _peel_one_layer(binary_stream, kind):
    """Wraps binary_stream in the decompressor for `kind`, returning a
    new binary file-like object that streams the decompressed content
    (decompression happens lazily as it's read, not all at once)."""
    if kind == "gzip":
        return gzip.GzipFile(fileobj=binary_stream)
    if kind == "bz2":
        return bz2.BZ2File(binary_stream)
    return lzma.LZMAFile(binary_stream)


def open_decompressed_binary(fpath, max_layers=_MAX_COMPRESSION_LAYERS):
    """Opens fpath and peels up to max_layers of gzip/bz2/xz compression,
    one layer at a time, re-checking the magic bytes after each peel -
    correctly handles both a single layer (the common case) and a
    genuinely double-compressed file like "messages-20260406.xz.gz"
    (gzip-of-xz) without needing to know in advance which of those it is.
    Returns a binary streaming file-like object positioned at the start
    of the fully-decompressed content, or None if fpath isn't compressed
    at all (no magic bytes matched on the very first layer - caller
    should fall back to a plain open()) or if opening/peeling fails for
    any reason (corrupt/truncated archive) - never raises."""
    try:
        stream = open(fpath, "rb")
        head = stream.read(6)
        stream.seek(0)
    except OSError:
        return None
    kind = sniff_compression_kind(head)
    if kind is None:
        stream.close()
        return None
    try:
        for _ in range(max_layers):
            stream = _peel_one_layer(stream, kind)
            head = stream.read(6)
            stream.seek(0)
            kind = sniff_compression_kind(head)
            if kind is None:
                break
        return stream
    except (OSError, EOFError, lzma.LZMAError) as e:
        try:
            stream.close()
        except Exception:
            pass
        return None


def open_decompressed_text(fpath, max_layers=_MAX_COMPRESSION_LAYERS):
    """Same as open_decompressed_binary(), wrapped in a text-mode
    TextIOWrapper (UTF-8, invalid bytes replaced rather than raising) so
    callers can iterate it exactly like a plain open(fpath, "r", ...) -
    this is what makes decompressed logs reuse every existing line-by-
    line scanning helper (classify_line, parse_timestamp,
    iter_supportconfig_lines, ...) completely unchanged."""
    stream = open_decompressed_binary(fpath, max_layers=max_layers)
    if stream is None:
        return None
    return io.TextIOWrapper(stream, encoding="utf-8", errors="replace")


def is_probably_text_bytes(chunk: bytes) -> bool:
    """The actual text-vs-binary heuristic, extracted from
    is_probably_text() so it can also be applied to a peek of
    DECOMPRESSED content (a compressed file might still wrap genuine
    binary data - some backup/monitoring tools gzip arbitrary state, not
    just logs - and that should still be skipped, not fed through the
    line scanner as garbage)."""
    if not chunk:
        return True
    if b"\x00" in chunk:
        return False
    text_chars = sum(1 for b in chunk if 9 <= b <= 13 or 32 <= b <= 126 or b >= 128)
    return (text_chars / len(chunk)) > 0.85


def classify_file_readability(fpath):
    """Single-open, single-read decision (deliberately: this runs once
    per file in a bundle that can hold 90,000+ files, so it must not add
    a second I/O pass over every ordinary, non-compressed file just to
    support the compressed-log case) on how - or whether - fpath should
    be line-scanned. Returns (mode, compression_kind):
      ("text", None)         - open normally
      ("compressed", "gzip"/"bz2"/"xz") - open via open_decompressed_text()
                                 (compression_kind is the OUTERMOST layer
                                 found, informational only)
      ("skip", None)         - binary, unreadable, or a compressed
                                 stream whose decompressed content still
                                 isn't text
    """
    try:
        with open(fpath, "rb") as fh:
            head = fh.read(4096)
    except OSError:
        return "skip", None
    kind = sniff_compression_kind(head)
    if kind is not None:
        try:
            dec = open_decompressed_text(fpath)
            if dec is None:
                return "skip", None
            with dec as fh2:
                dec_head = fh2.read(4096)
            if is_probably_text_bytes(dec_head.encode("utf-8", errors="replace")):
                return "compressed", kind
        except Exception:
            pass
        return "skip", None
    if fpath.suffix.lower() in BINARY_SKIP_EXTS:
        return "skip", None
    return ("text", None) if is_probably_text_bytes(head) else ("skip", None)

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
# v4.0.0 analyzers: SAR/timezone, crash, boot, SELinux/AppArmor, package
# drift, systemd cascade, container correlation - shared regexes/tables.
# --------------------------------------------------------------------------
_TZ_ABBR_OFFSETS = {
    # Best-effort common timezone abbreviation -> UTC offset in minutes.
    # Not exhaustive, and a couple of abbreviations are inherently
    # ambiguous (e.g. "IST" is also used for Ireland/Israel) - the raw
    # abbreviation is always shown as-is either way; arithmetic is only
    # attempted where the mapping is unambiguous enough to be useful.
    "UTC": 0, "GMT": 0, "Z": 0,
    "IST": 330,  # India Standard Time - overwhelmingly the common case here
    "EST": -300, "EDT": -240,
    "CST": -360, "CDT": -300,
    "MST": -420, "MDT": -360,
    "PST": -480, "PDT": -420,
    "CET": 60, "CEST": 120,
    "BST": 60, "WET": 0, "WEST": 60,
    "AEST": 600, "AEDT": 660, "ACST": 570, "ACDT": 630, "AWST": 480,
    "JST": 540, "KST": 540, "SGT": 480, "HKT": 480, "MSK": 180,
}

_SAR_TIME_RE = re.compile(r"^(\d{1,2}):(\d{2}):(\d{2})(?:\s*([AaPp][Mm]))?\s+(.*)$")
_SAR_HEADER_DATE_RE = re.compile(r"(\d{2})/(\d{2})/(\d{4})")
_SAR_HEADER_HINTS = [
    # (header columns that must ALL appear on a header line, metric group)
    (("%user", "%idle"), "cpu"),
    (("kbmemfree",), "memory"),
    (("%memused",), "memory"),
    (("tps", "bread/s"), "disk_io"),
    (("tps", "rd_sec/s"), "disk_io"),
    (("tps", "rkB/s"), "disk_io"),
    (("IFACE", "rxkB/s"), "network"),
    (("IFACE", "rxpck/s"), "network"),
    (("ldavg-1",), "load"),
    (("runq-sz",), "load"),
    (("kbswpfree",), "swap"),
    (("pgpgin/s",), "paging"),
]

_AVC_FIELD_RE = re.compile(r'(\w+)=("[^"]*"|\S+)')

_DEP_FAILED_RE = re.compile(r"[Dd]ependency failed for (.+?)\.?\s*$")
_TRIGGERING_ONFAILURE_RE = re.compile(r"Triggering OnFailure=? ?dependencies of (\S+?)\.?\s*$")
_UNIT_FAILED_RESULT_RE = re.compile(
    r"(?P<unit>\S+\.(?:service|socket|mount|timer|path|target))\S*:?\s+"
    r"(?:Main process exited|Failed with result|Job for \S+ failed|start-limit-hit)")

_PKG_LINE_RE = re.compile(r"^(\S+)\s+(.+?)\s*$")

_EXITED_RE = re.compile(r"Exited\s*\((-?\d+)\)")
_RESTARTING_RE = re.compile(r"Restarting\s*\((-?\d+)\)")
_EXIT_CODE_NOTES = {
    "137": "SIGKILL (128+9) - often OOM-killed by the kernel or a healthcheck/orchestrator force-kill",
    "143": "SIGTERM (128+15) - graceful stop signal, likely a normal shutdown/restart",
    "139": "SIGSEGV (128+11) - segmentation fault inside the container process",
    "1": "generic application error exit",
}

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


_WINDOWS_ILLEGAL_CHARS_RE = re.compile(r'[<>:"|?*]')


def _windows_safe_member_name(name):
    """Real-world Linux archive member names can contain characters that
    are illegal in Windows paths - most commonly ':', in ABRT crash
    report directories (e.g. "ccpp-2026-07-10-11:15:22-9999") which this
    tool's own crash analyzer specifically looks for. Without this,
    tarfile/zipfile's extract() would raise OSError for that single
    member (caught below and recorded in `skipped` - the run wouldn't
    crash) but the member's content would then be silently invisible to
    every downstream check, on the one runtime (Windows) this tool
    actually ships on. Sanitizing case-by-case keeps the vast majority
    of paths byte-identical to the original archive while still letting
    the handful of otherwise-uncooperative ones land on disk.
    """
    if os.name != "nt":
        return name
    return "/".join(_WINDOWS_ILLEGAL_CHARS_RE.sub("_", part) for part in name.split("/"))


def safe_extract_tar(tar_path, dest_dir):
    skipped = []
    dest_abs = os.path.abspath(str(dest_dir))
    with tarfile.open(tar_path, "r:*") as tf:
        for m in tf:
            try:
                safe_name = _windows_safe_member_name(m.name)
                target = os.path.abspath(os.path.join(dest_abs, safe_name))
                if not (target == dest_abs or target.startswith(dest_abs + os.sep)):
                    skipped.append((m.name, "path traversal"))
                    continue
                if m.isdev() or m.ischr() or m.isblk() or m.isfifo():
                    skipped.append((m.name, "device/special file"))
                    continue
                if safe_name != m.name:
                    m.name = safe_name
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
                safe_name = _windows_safe_member_name(info.filename)
                target = os.path.abspath(os.path.join(dest_abs, safe_name))
                if not (target == dest_abs or target.startswith(dest_abs + os.sep)):
                    skipped.append((info.filename, "path traversal"))
                    continue
                if safe_name != info.filename:
                    info.filename = safe_name
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
    return is_probably_text_bytes(chunk)


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
    """Reads up to max_bytes of text from relpath. Transparently
    decompresses gzip/bz2/xz (and stacked combinations) content first if
    the file's magic bytes indicate it's compressed - every analyzer
    that reads a specific known file via find_inventory()+get_text()
    (SELinux denial counts, package lists, systemd-analyze output, ...)
    gets compressed-log support for free this way, with zero changes
    needed in any of those individual check functions."""
    p = root / relpath
    dec = open_decompressed_binary(p)
    if dec is not None:
        try:
            with dec as fh:
                return fh.read(max_bytes).decode("utf-8", errors="replace")
        except OSError:
            return ""
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
    # Strip a trailing timezone-abbreviation-like token before parsing,
    # regardless of whether it appears at the very end ("... 15:22:10
    # IST") or before a trailing year ("... 15:22:10 IST 2026") - the
    # two real orderings `rpm -qa --last`/`zypper` output actually uses.
    # Python's %Z directive only reliably recognizes "UTC"/"GMT" (and
    # inconsistently, the machine's OWN configured local abbreviation) -
    # verified directly: strptime("...IST", "%a %d %b %Y %H:%M:%S %Z")
    # raises ValueError even though the string is perfectly well-formed.
    # Any real customer server using a non-UTC/GMT abbreviation (IST,
    # EST, PST, CST, JST, ... - the overwhelmingly common real-world
    # case) would otherwise silently fail here, producing ZERO dated
    # package-drift results even from a file full of them. Nothing
    # downstream needs genuine timezone-aware arithmetic (every
    # comparison is against another naive timestamp from the SAME
    # bundle), so the abbreviation is discarded rather than converted -
    # it's only used to recognize where to cut the string.
    tz_stripped = re.sub(r"\s+[A-Za-z]{2,5}(\s+\d{4})?\s*$", r"\1", text)
    candidates = [text, tz_stripped, re.sub(r"\s+[A-Z]{2,5}\s+(\d{4})$", r" \1", text)]
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
def scan_file(root, relpath, kind, file_category, ctx, compression_kind=None):
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
    decompressed_bytes_seen = 0  # only ever incremented/checked when
    # compression_kind is set (see below) - zero added cost to the
    # ordinary plain-text path, which has no equivalent cap: an on-disk
    # plain-text file's scan cost is bounded by its own real size, but a
    # compressed file's on-disk size can be wildly smaller than what it
    # decompresses to (accidentally, via corruption, or a deliberate
    # zip-bomb-style archive) - _MAX_DECOMPRESSED_BYTES is a safety net
    # for that specific risk, not a real-world limit on legitimate
    # rotated logs (which compress at best a few dozen:1).
    try:
        if compression_kind:
            fh_cm = open_decompressed_text(fpath)
            if fh_cm is None:
                stats["read_errors"] += 1
                return
        else:
            fh_cm = open(fpath, "r", encoding="utf-8", errors="replace")
        with fh_cm as fh:
            gen = iter_supportconfig_lines(fh) if is_sc_txt else ((i, l.rstrip("\n"), None) for i, l in enumerate(fh, start=1))
            for lineno, line, source in gen:
                stats["lines_scanned"] += 1
                if compression_kind:
                    decompressed_bytes_seen += len(line) + 1
                    if decompressed_bytes_seen > _MAX_DECOMPRESSED_BYTES:
                        stats["decompressed_size_capped"] += 1
                        break
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
    except (OSError, UnicodeDecodeError, EOFError, lzma.LZMAError):
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


def _fmt_utc_offset(minutes):
    sign = "+" if minutes >= 0 else "-"
    m = abs(minutes)
    return f"UTC{sign}{m // 60:02d}:{m % 60:02d}"


def detect_vm_timezone(root, kind, inventory):
    """Best-effort detection of the timezone the analyzed VM/host itself
    was configured with at capture time, so SAR (and other) timestamps
    can be explicitly labeled as VM-local rather than left ambiguous -
    directly avoids a support engineer confusing "the time I'm reading
    this in" with "the time it happened on the customer's box". Tries,
    in priority order:
      1. /etc/timezone - a plain-text IANA zone name (Debian/Ubuntu-
         style). A regular file, so the most reliable signal regardless
         of how the archive was extracted.
      2. The captured `date` command output (sos_commands/date/date for
         sosreport; basic-environment.txt's "/bin/date" section for
         supportconfig; sysinfo.txt for crm_report) - looks for the
         trailing zone abbreviation Linux `date` prints by default (e.g.
         "Fri Jul 10 11:28:01 IST 2026").
      3. /etc/localtime, IF it happens to still be a real symlink in the
         extracted tree (tar/zip extraction can occasionally fail to
         recreate symlinks depending on host OS/privileges, so this is a
         bonus check, not the primary signal) - the zoneinfo path suffix
         is the IANA zone name.
    Returns None if nothing could be determined - callers must treat
    that as "unknown", never silently assume UTC.
    """
    for relp in find_inventory(inventory, "etc/timezone"):
        t = get_text(root, relp, 200).strip()
        if t and not t.startswith("#") and "/" in t and " " not in t:
            return {"label": f"{t} (from /etc/timezone)", "iana": t, "abbr": None, "utc_offset_minutes": None}

    date_text = ""
    if kind == "sosreport":
        for relp in find_by_basename_prefix(inventory, "date"):
            date_text = get_text(root, relp, 500).strip()
            if date_text:
                break
    elif kind == "crm_report":
        for relp in find_inventory(inventory, "sysinfo.txt"):
            t = get_text(root, relp, 1_000_000)
            m = re.search(r"^[A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{1,2}\s+[\d:]+\s+[A-Za-z]{2,5}\s+\d{4}\s*$", t, re.MULTILINE)
            if m:
                date_text = m.group(0).strip()
                break
    else:
        for relp in find_inventory(inventory, "basic-environment.txt"):
            t = get_text(root, relp, 300_000)
            sec = extract_supportconfig_section(t, "/bin/date", "# date")
            if sec:
                date_text = "\n".join(s for s in sec if s.strip() and not s.startswith("#")).strip()
                break

    m = re.search(r"\b([A-Za-z]{2,5})\s+(\d{4})\s*$", date_text)
    if m:
        abbr = m.group(1)
        offset = _TZ_ABBR_OFFSETS.get(abbr.upper())
        label = f"{abbr} ({_fmt_utc_offset(offset)})" if offset is not None else f"{abbr} (offset unknown - unrecognized abbreviation)"
        return {"label": label, "iana": None, "abbr": abbr, "utc_offset_minutes": offset}

    for relp in find_inventory(inventory, "etc/localtime"):
        p = root / relp
        try:
            if p.is_symlink():
                target = os.readlink(str(p))
                if "zoneinfo/" in target:
                    iana = target.split("zoneinfo/", 1)[1]
                    return {"label": f"{iana} (from /etc/localtime)", "iana": iana, "abbr": None, "utc_offset_minutes": None}
        except OSError:
            pass
    return None


def _is_all_numeric(tokens):
    if not tokens:
        return True
    for t in tokens:
        try:
            float(t)
        except ValueError:
            return False
    return True


def _detect_sar_block_kind(header_cols):
    header_set = set(header_cols)
    for hints, group in _SAR_HEADER_HINTS:
        if all(h in header_set for h in hints):
            return group
    return None


def _parse_sar_time(hh, mm, ss, ampm):
    h, mi, s = int(hh), int(mm), int(ss)
    if ampm:
        ampm = ampm.upper()
        if ampm == "PM" and h != 12:
            h += 12
        if ampm == "AM" and h == 12:
            h = 0
    if h > 23:
        return None
    return h, mi, s


def _parse_sar_text(text, fallback_date):
    """Parses one sar-plugin text capture (sysstat's own pre-rendered
    tables - CPU/memory/disk/network/load, possibly several back-to-back
    in the same file) into {metric_group: [{"ts": iso, <col>: val, ...}]}.
    Header vs. data rows are told apart generically: a header row's
    columns (after the leading timestamp) are never all-numeric ("CPU",
    "%user", "kbmemfree", "IFACE", ...); a data row's are (aside from a
    possible leading label like "all"/"eth0", which is excluded from the
    all-numeric check by design). This one heuristic handles every sar
    table shape uniformly without hardcoding per-table column layouts.
    Unrecognized table shapes are silently skipped - a sar capture always
    includes several table types most callers don't need, and failing to
    parse one must never invalidate the others. "Average:" summary rows
    are intentionally skipped (the caller computes its own averages from
    the parsed series instead).
    """
    series = defaultdict(list)
    current_date = None
    header_cols = None
    block_kind = None
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            header_cols = None
            block_kind = None
            continue
        low = stripped.lower()
        if low.startswith("linux"):
            dm = _SAR_HEADER_DATE_RE.search(stripped)
            if dm:
                mm, dd, yyyy = dm.groups()
                try:
                    current_date = datetime(int(yyyy), int(mm), int(dd)).date()
                except ValueError:
                    pass
            header_cols = None
            block_kind = None
            continue
        if low.startswith("average:") or low.startswith("summary:"):
            continue
        m = _SAR_TIME_RE.match(stripped)
        if not m:
            continue
        hh, mm_, ss, ampm, rest = m.groups()
        cols = rest.split()
        if not cols:
            continue
        if not _is_all_numeric(cols[1:]):
            header_cols = cols
            block_kind = _detect_sar_block_kind(cols)
            continue
        if header_cols is None or block_kind is None:
            continue
        t = _parse_sar_time(hh, mm_, ss, ampm)
        if t is None:
            continue
        h, mi, se = t
        the_date = current_date or fallback_date
        if the_date is None:
            continue
        ts = datetime(the_date.year, the_date.month, the_date.day, h, mi, se)
        row = {}
        for i, colname in enumerate(header_cols):
            if i >= len(cols):
                break
            val = cols[i]
            try:
                row[colname] = float(val)
            except ValueError:
                row[colname] = val
        series[block_kind].append({"ts": ts.isoformat(), **row})
    return series


def check_sar_performance(root, kind, inventory, capture_dt=None, vm_tz=None):
    """Parses pre-rendered `sar` text captures - sysstat's own plain-text
    table output - into per-metric time series plus a condensed summary.
    Looks in every location a bundle realistically stores this:
      - sosreport: the dedicated sar-plugin capture (sos_commands/sar/*),
        AND the raw sysstat spool directory it also copies in wholesale
        (var/log/sa/* - mostly binary saDD files this tool can't decode
        without the sar/sadf binary, but occasionally also pre-rendered
        sarDD/sadDD text reports if the box was configured to write
        those via cron - worth checking rather than assuming binary).
      - supportconfig: files live under a dedicated sar/ directory, but
        are typically named by day-of-month/date (e.g. "15"), NOT by
        anything containing the literal word "sar" - so matching must be
        by directory membership (an exact path SEGMENT equal to "sar"),
        never by filename substring, or every file in that directory is
        silently missed.
      - crm_report: sysstats.txt.
    Binary candidates are filtered out via is_probably_text() before
    attempting to parse them as text - the parser itself is also safe
    against binary noise (no real sar table header will ever match
    random bytes), but skipping early avoids a wasted read on what can
    be a multi-MB raw sa file.
    Best-effort and intentionally silent when a bundle has no sar data at
    all (common - sysstat isn't always installed on the customer's box).
    """
    if kind == "sosreport":
        candidates = find_inventory(inventory, "sos_commands/sar/", "var/log/sa/")
    elif kind == "supportconfig":
        candidates = [p for p in find_inventory(inventory, "sar")
                      if "sar" in p.lower().split("/")[:-1] or "sar" in p.rsplit("/", 1)[-1].lower()]
    else:
        candidates = find_inventory(inventory, "sysstats.txt")
    candidates = [p for p in candidates if is_probably_text(root / p)]

    fallback_date = capture_dt.date() if capture_dt else None
    all_series = defaultdict(list)
    files_parsed = []
    for relp in candidates:
        text = get_text(root, relp, 3_000_000)
        if not text.strip():
            continue
        parsed = _parse_sar_text(text, fallback_date)
        if any(parsed.values()):
            files_parsed.append(relp)
            for group, rows in parsed.items():
                all_series[group].extend(rows)

    if not files_parsed:
        return {}

    for group in all_series:
        all_series[group].sort(key=lambda r: r["ts"])

    summary = {}
    cpu_rows = all_series.get("cpu", [])
    if cpu_rows:
        # "all" is sar's own aggregate-across-cores row, always present
        # even when a per-core breakdown (-P ALL) was also captured -
        # using it avoids conflating one busy core with overall load.
        idle_vals = [r["%idle"] for r in cpu_rows if isinstance(r.get("%idle"), float) and r.get("CPU", "all") == "all"]
        if not idle_vals:
            idle_vals = [r["%idle"] for r in cpu_rows if isinstance(r.get("%idle"), float)]
        if idle_vals:
            used_vals = [round(100.0 - v, 2) for v in idle_vals]
            summary["cpu_pct_used_avg"] = round(sum(used_vals) / len(used_vals), 2)
            summary["cpu_pct_used_peak"] = round(max(used_vals), 2)
            summary["cpu_pct_used_peak_ts"] = cpu_rows[used_vals.index(max(used_vals))]["ts"]
        iowait_vals = [r["%iowait"] for r in cpu_rows if isinstance(r.get("%iowait"), float)]
        if iowait_vals:
            summary["iowait_pct_avg"] = round(sum(iowait_vals) / len(iowait_vals), 2)
            summary["iowait_pct_peak"] = round(max(iowait_vals), 2)

    mem_rows = all_series.get("memory", [])
    if mem_rows:
        memused_vals = [r["%memused"] for r in mem_rows if isinstance(r.get("%memused"), float)]
        if memused_vals:
            summary["mem_pct_used_avg"] = round(sum(memused_vals) / len(memused_vals), 2)
            summary["mem_pct_used_peak"] = round(max(memused_vals), 2)

    load_rows = all_series.get("load", [])
    if load_rows:
        l1_vals = [r["ldavg-1"] for r in load_rows if isinstance(r.get("ldavg-1"), float)]
        if l1_vals:
            summary["load1_avg"] = round(sum(l1_vals) / len(l1_vals), 2)
            summary["load1_peak"] = round(max(l1_vals), 2)

    disk_rows = all_series.get("disk_io", [])
    if disk_rows:
        tps_vals = [r["tps"] for r in disk_rows if isinstance(r.get("tps"), float)]
        if tps_vals:
            summary["disk_tps_avg"] = round(sum(tps_vals) / len(tps_vals), 2)
            summary["disk_tps_peak"] = round(max(tps_vals), 2)

    net_rows = all_series.get("network", [])
    if net_rows:
        by_iface = defaultdict(list)
        for r in net_rows:
            iface, rx = r.get("IFACE"), r.get("rxkB/s")
            if iface and isinstance(rx, float):
                by_iface[iface].append(rx)
        if by_iface:
            busiest_iface, vals = max(by_iface.items(), key=lambda kv: sum(kv[1]) / len(kv[1]))
            summary["busiest_iface"] = busiest_iface
            summary["busiest_iface_rxkbps_avg"] = round(sum(vals) / len(vals), 2)

    return {
        "files_parsed": files_parsed,
        "metric_groups_found": sorted(all_series.keys()),
        "sample_points": {g: len(rows) for g, rows in all_series.items()},
        "summary": summary,
        "series": {g: rows[:2000] for g, rows in all_series.items()},
        "vm_timezone": vm_tz,
    }


def check_crash_analysis(root, kind, inventory):
    """Correlates whatever crash/coredump *evidence* is realistically
    available inside a sosreport/supportconfig/crm_report bundle. Bundles
    essentially never contain the actual (huge) core file, and even if
    they did, symbolizing a raw core requires gdb plus matching debug
    symbols for the exact kernel/binary build - infeasible in this
    tool's own runtime. What IS realistic and genuinely useful: ABRT's
    own already-human-readable backtrace captured at crash time, kdump/
    kexec configuration, and vmcore presence/size (existence only).
    """
    result = {}

    abrt_dirs = set()
    for relp in find_inventory(inventory, "var/spool/abrt/", "abrt/ccpp-"):
        parts = relp.split("/")
        for i, p in enumerate(parts):
            if p.startswith("ccpp-") or p.startswith("oops-"):
                abrt_dirs.add("/".join(parts[: i + 1]))
                break
    abrt_reports = []
    for d in sorted(abrt_dirs):
        entry = {"dir": d}
        for relp in find_inventory(inventory, d + "/backtrace"):
            t = get_text(root, relp, 20000).strip()
            if t:
                entry["backtrace"] = t[:3000]
        for fname, key in (("reason", "reason"), ("cmdline", "cmdline"),
                           ("executable", "executable"), ("time", "crash_time"), ("uid", "uid")):
            for relp in find_inventory(inventory, d + "/" + fname):
                t = get_text(root, relp, 2000).strip()
                if t:
                    entry[key] = t
        if len(entry) > 1:
            abrt_reports.append(entry)
    if abrt_reports:
        result["abrt_reports"] = abrt_reports

    vmcores = [{"path": it["path"], "size": it["size"], "size_human": human_size(it["size"])}
               for it in inventory if "vmcore" in it["path"].lower() and it["size"] > 0]
    if vmcores:
        result["vmcore_files"] = vmcores

    kdump_text = ""
    if kind == "sosreport":
        for relp in find_inventory(inventory, "sos_commands/kdump", "etc/kdump.conf"):
            kdump_text += get_text(root, relp, 20000) + "\n"
    elif kind == "supportconfig":
        for relp in find_inventory(inventory, "kdump"):
            kdump_text += get_text(root, relp, 20000) + "\n"
    if kdump_text.strip():
        m = re.search(r"^path\s+(\S+)", kdump_text, re.MULTILINE)
        result["kdump_configured"] = bool(m) or bool(re.search(r"^\s*KDUMP_KERNELVER", kdump_text, re.MULTILINE))
        if m:
            result["kdump_path"] = m.group(1)

    oops_count = 0
    for relp in find_inventory(inventory, "sos_commands/kernel/dmesg", "var/log/dmesg"):
        t = get_text(root, relp, 2_000_000)
        oops_count += len(re.findall(r"\b(?:kernel panic|Oops:|general protection fault|BUG: unable to handle)", t, re.IGNORECASE))
    if oops_count:
        result["kernel_oops_signature_count"] = oops_count

    return result


def check_boot_performance(root, kind, inventory):
    """systemd-analyze's own timing breakdown, when the bundle happens to
    include it (sos_commands/systemd/systemd-analyze* for sosreport;
    folded into systemd.txt/boot.txt for supportconfig) - the single
    best "why did this box take N minutes to come up" signal available
    without re-running anything on the customer's box.
    """
    result = {}
    text = ""
    if kind == "sosreport":
        for relp in find_by_basename_prefix(inventory, "systemd-analyze"):
            text += get_text(root, relp, 200000) + "\n"
    else:
        for relp in find_inventory(inventory, "systemd.txt", "boot.txt", "basic-environment.txt", "systemd-analyze"):
            text += get_text(root, relp, 500000) + "\n"

    if not text.strip():
        return result

    m = re.search(r"Startup finished in\s+(.+?)=\s*([\d.]+)(min|s)\b", text)
    if m:
        result["startup_breakdown_raw"] = m.group(0).strip()
        total = float(m.group(2))
        result["total_boot_seconds"] = round(total * 60 if m.group(3) == "min" else total, 2)

    unit_re = re.compile(r"^\s*([\d.]+)(min|s|ms)\s+(\S+\.(?:service|target|mount|socket|timer|path|device))\s*$")
    best = {}
    for line in text.splitlines():
        m2 = unit_re.match(line)
        if not m2:
            continue
        val, unit, unit_name = float(m2.group(1)), m2.group(2), m2.group(3)
        seconds = val * 60 if unit == "min" else (val / 1000.0 if unit == "ms" else val)
        if unit_name not in best or seconds > best[unit_name]:
            best[unit_name] = seconds
    if best:
        ordered = sorted(({"unit": k, "seconds": round(v, 3)} for k, v in best.items()), key=lambda r: -r["seconds"])
        result["slowest_units"] = ordered[:15]

    chain_lines = []
    in_chain = False
    for line in text.splitlines():
        if not in_chain and re.match(r"^\S+\.target\s*$", line.strip()):
            in_chain = True
            chain_lines = [line]
            continue
        if in_chain:
            if line.strip().startswith(("└─", "├─", "│")):
                chain_lines.append(line)
            else:
                break
    if len(chain_lines) > 1:
        result["critical_chain_raw"] = "\n".join(chain_lines)[:3000]

    return result


def check_security_mac(root, kind, inventory):
    """SELinux/AppArmor status plus a structured breakdown of access-
    control denials (by scontext/tcontext/tclass for SELinux, by
    profile/operation for AppArmor) - a recurring denial pattern jumps
    out this way, versus being buried in a long list of near-identical
    raw lines from the generic pattern scanner.
    """
    result = {}

    status_text = ""
    if kind == "sosreport":
        for relp in find_by_basename_prefix(inventory, "sestatus"):
            status_text = get_text(root, relp, 5000)
            if status_text.strip():
                break
    elif kind == "supportconfig":
        for relp in find_inventory(inventory, "security-selinux.txt", "security.txt"):
            t = get_text(root, relp, 200000)
            sec = extract_supportconfig_section(t, "sestatus")
            if sec:
                status_text = "\n".join(sec)
                break
    if status_text.strip():
        m = re.search(r"SELinux status:\s*(\S+)", status_text)
        mode = re.search(r"Current mode:\s*(\S+)", status_text)
        if m:
            result["selinux_status"] = m.group(1)
        if mode:
            result["selinux_mode"] = mode.group(1)

    apparmor_text = ""
    for relp in find_inventory(inventory, "sos_commands/apparmor", "apparmor-status", "apparmor.txt"):
        apparmor_text += get_text(root, relp, 200000) + "\n"
    if apparmor_text.strip():
        m = re.search(r"(\d+)\s+profiles are in enforce mode", apparmor_text)
        if m:
            result["apparmor_profiles_enforce"] = int(m.group(1))
        m = re.search(r"(\d+)\s+profiles are in complain mode", apparmor_text)
        if m:
            result["apparmor_profiles_complain"] = int(m.group(1))

    if kind == "crm_report":
        denial_sources = find_inventory(inventory, "sysinfo.txt")
    else:
        denial_sources = find_inventory(inventory, "var/log/audit", "audit.log", "var/log/messages", "messages.txt", "warn.txt")

    selinux_by_context = Counter()
    apparmor_by_profile = Counter()
    selinux_total = apparmor_total = 0
    for relp in denial_sources[:20]:
        # Bounded - this tally is a best-effort summary, not exhaustive
        # forensics; findings.json already keeps every individual
        # matching line with file:line provenance via the generic scan.
        text = get_text(root, relp, 3_000_000)
        if not text:
            continue
        for line in text.splitlines():
            low = line.lower()
            if "avc:" in low and "denied" in low:
                fields = dict(_AVC_FIELD_RE.findall(line))
                key = (fields.get("scontext", "?").strip('"'), fields.get("tcontext", "?").strip('"'), fields.get("tclass", "?").strip('"'))
                selinux_by_context[key] += 1
                selinux_total += 1
            elif 'apparmor="denied"' in low:
                fields = dict(_AVC_FIELD_RE.findall(line))
                key = (fields.get("profile", "?").strip('"'), fields.get("operation", "?").strip('"'))
                apparmor_by_profile[key] += 1
                apparmor_total += 1

    if selinux_total:
        result["selinux_denial_total"] = selinux_total
        result["selinux_top_denials"] = [{"scontext": s, "tcontext": t, "tclass": c, "count": n}
                                          for (s, t, c), n in selinux_by_context.most_common(10)]
    if apparmor_total:
        result["apparmor_denial_total"] = apparmor_total
        result["apparmor_top_denials"] = [{"profile": p, "operation": o, "count": n}
                                           for (p, o), n in apparmor_by_profile.most_common(10)]
    return result


def check_package_drift(root, kind, inventory, capture_dt=None):
    """Surfaces packages installed/updated close to the capture time (or,
    when a yum/dnf transaction-history log is available, actual install/
    update/erase events with timestamps) - a very common real "what
    changed right before this broke" RCA question. Best-effort: exact
    availability/format varies a lot by distro and tooling version, and
    dates that can't be confidently parsed are simply skipped rather
    than guessed at.
    """
    result = {}
    reference = capture_dt or datetime.utcnow()
    pkg_events = []

    if kind == "sosreport":
        for relp in find_inventory(inventory, "installed-rpms"):
            t = get_text(root, relp, 3_000_000)
            for line in t.splitlines():
                m = _PKG_LINE_RE.match(line)
                if not m:
                    continue
                pkg, rest = m.groups()
                dt = try_parse_full_date(rest)
                if dt:
                    pkg_events.append({"package": pkg, "when": dt.isoformat(), "action": "installed"})
            break
        for relp in find_inventory(inventory, "sos_commands/yum/history", "sos_commands/dnf/history"):
            t = get_text(root, relp, 1_000_000)
            for line in t.splitlines():
                m = re.match(r"^\s*\d+\s*\|\s*(\S.*?)\s*\|\s*([\d-]+\s[\d:]+)\s*\|\s*(\S.*?)\s*\|", line)
                if not m:
                    continue
                who, when_s, action = m.groups()
                try:
                    dt = datetime.strptime(when_s.strip(), "%Y-%m-%d %H:%M")
                except ValueError:
                    continue
                pkg_events.append({"package": who.strip(), "when": dt.isoformat(), "action": action.strip().lower()})
    elif kind == "supportconfig":
        for relp in find_inventory(inventory, "rpm.txt"):
            t = get_text(root, relp, 3_000_000)
            sec = extract_supportconfig_section(t, "rpm -qa --last", "rpm -qa")
            for line in (sec or t.splitlines()):
                m = _PKG_LINE_RE.match(line.strip())
                if not m:
                    continue
                pkg, rest = m.groups()
                dt = try_parse_full_date(rest)
                if dt:
                    pkg_events.append({"package": pkg, "when": dt.isoformat(), "action": "installed"})
            break
        for relp in find_inventory(inventory, "updates.txt", "patches.txt"):
            t = get_text(root, relp, 1_000_000)
            for line in t.splitlines():
                m = _PKG_LINE_RE.match(line.strip())
                if not m:
                    continue
                pkg, rest = m.groups()
                dt = try_parse_full_date(rest)
                if dt:
                    pkg_events.append({"package": pkg, "when": dt.isoformat(), "action": "updated"})

    if not pkg_events:
        return result

    pkg_events.sort(key=lambda e: e["when"])
    result["total_dated_packages"] = len(pkg_events)
    result["most_recent_change"] = pkg_events[-1]

    window_start_iso = (reference - timedelta(days=7)).isoformat()
    reference_iso = reference.isoformat()
    recent = [e for e in pkg_events if window_start_iso <= e["when"] <= reference_iso]
    recent.sort(key=lambda e: e["when"], reverse=True)
    if recent:
        result["recent_changes_7d"] = recent[:50]
        result["recent_changes_7d_count"] = len(recent)
    return result


def check_systemd_cascade(root, kind, inventory):
    """Best-effort service-failure *cascade* reconstruction: instead of
    just listing every currently-failed unit independently (already done
    by check_failed_services), looks for boot/journal-log evidence of one
    unit's failure triggering others - "Dependency failed for X",
    "Triggering OnFailure= dependencies of X" - and groups failures that
    happened within a few seconds of each other, since near-simultaneous
    multi-unit failures are a strong signal of a shared root cause (e.g.
    a mount or network-online target failing takes a whole dependent
    chain down with it) rather than N independent problems.
    """
    result = {}
    if kind == "sosreport":
        sources = find_inventory(inventory, "var/log/messages", "sos_commands/logs/journalctl", "var/log/syslog")
    elif kind == "supportconfig":
        sources = find_inventory(inventory, "messages.txt", "boot.txt", "warn.txt")
    else:
        sources = find_inventory(inventory, "sysinfo.txt", "pacemaker.log", "journal.log")

    events = []
    year_hint = datetime.utcnow().year
    for relp in sources[:15]:
        text = get_text(root, relp, 3_000_000)
        if not text:
            continue
        for line in text.splitlines():
            low = line.lower()
            if "dependency failed for" not in low and "triggering onfailure" not in low and not _UNIT_FAILED_RESULT_RE.search(line):
                continue
            ts = parse_timestamp(line, year_hint)
            m1 = _DEP_FAILED_RE.search(line)
            if m1:
                events.append({"ts": ts, "subject": m1.group(1).strip(), "kind": "dependency_failed"})
                continue
            m2 = _TRIGGERING_ONFAILURE_RE.search(line)
            if m2:
                events.append({"ts": ts, "subject": m2.group(1).strip(), "kind": "onfailure_triggered"})
                continue
            m3 = _UNIT_FAILED_RESULT_RE.search(line)
            if m3:
                events.append({"ts": ts, "subject": m3.group("unit"), "kind": "unit_failed"})

    if not events:
        return result
    result["cascade_events_found"] = len(events)

    timed = sorted([e for e in events if e["ts"]], key=lambda e: e["ts"])
    clusters, current = [], []
    for e in timed:
        if current and (e["ts"] - current[-1]["ts"]).total_seconds() > 5:
            if len(current) > 1:
                clusters.append(current)
            current = []
        current.append(e)
    if len(current) > 1:
        clusters.append(current)

    cascade_summary = []
    for cluster in clusters[:10]:
        subjects, seen = [], set()
        for e in cluster:
            if e["subject"] not in seen:
                seen.add(e["subject"])
                subjects.append(e["subject"])
        if len(subjects) > 1:
            cascade_summary.append({
                "start_ts": cluster[0]["ts"].isoformat(),
                "end_ts": cluster[-1]["ts"].isoformat(),
                "likely_trigger": subjects[0],
                "cascaded_units": subjects[1:],
            })
    if cascade_summary:
        result["cascades"] = cascade_summary
    else:
        undated = sorted({e["subject"] for e in events if not e["ts"]})
        if undated:
            result["dependency_failures_untimed"] = undated[:20]
    return result


def check_container_logs(root, kind, inventory):
    """Correlates container-runtime state (Docker/Podman ps snapshots,
    inventory of container-specific log files) with host-level findings -
    e.g. surfacing containers that exited with a signal consistent with
    an OOM-kill, or an unusually high restart count. Deliberately does
    NOT attempt full container-log content analysis: containers can log
    in arbitrary application-specific formats the engine has no general
    way to interpret; this focuses on the runtime's own lifecycle signal
    plus correlation with host-level OOM/kernel evidence instead.
    """
    result = {}
    ps_text = ""
    if kind == "sosreport":
        for relp in find_inventory(inventory, "sos_commands/docker/docker_ps", "sos_commands/podman/podman_ps"):
            ps_text += get_text(root, relp, 200000) + "\n"
    elif kind == "supportconfig":
        for relp in find_inventory(inventory, "docker.txt", "podman.txt"):
            t = get_text(root, relp, 200000)
            sec = extract_supportconfig_section(t, "docker ps", "podman ps")
            ps_text += "\n".join(sec) + "\n"

    total_containers = 0
    exited_nonzero, restarting = [], []
    for line in ps_text.splitlines():
        s = line.strip()
        if not s or s.upper().startswith("CONTAINER ID"):
            continue
        if any(tok in line for tok in ("Exited", "Restarting", "Up ")) or s.startswith(("Created", "Dead")):
            total_containers += 1
        m = _EXITED_RE.search(line)
        if m and m.group(1) != "0":
            exited_nonzero.append({"name": line.split()[-1], "exit_code": m.group(1),
                                    "note": _EXIT_CODE_NOTES.get(m.group(1), ""), "raw": s[:200]})
        m2 = _RESTARTING_RE.search(line)
        if m2:
            restarting.append({"name": line.split()[-1], "exit_code": m2.group(1), "raw": s[:200]})

    if total_containers:
        result["total_containers_seen"] = total_containers
    if exited_nonzero:
        result["exited_nonzero"] = exited_nonzero[:20]
    if restarting:
        result["currently_restarting"] = restarting[:20]

    log_files = find_inventory(inventory, "var/log/containers/", "var/log/pods/")
    if log_files:
        result["container_log_files_found"] = len(log_files)

    oom_hits = 0
    for relp in find_inventory(inventory, "sos_commands/kernel/dmesg", "var/log/dmesg", "var/log/messages", "messages.txt", "warn.txt"):
        t = get_text(root, relp, 2_000_000)
        oom_hits += len(re.findall(r"oom-kill.*(?:docker|containerd|podman|libpod|runc)", t, re.IGNORECASE))
        oom_hits += len(re.findall(r"(?:docker|containerd|podman|runc)[^\n]{0,80}(?:killed process|out of memory)", t, re.IGNORECASE))
    if oom_hits:
        result["host_oom_events_mentioning_containers"] = oom_hits

    return result


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
    full_dt = None
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

    # --- v4.0.0 analyzers -------------------------------------------------
    vm_tz = None
    try:
        vm_tz = detect_vm_timezone(root, kind, inventory)
        facts["vm_timezone"] = vm_tz
    except Exception as e:
        facts["vm_timezone_error"] = str(e)
    try:
        facts["sar_performance"] = check_sar_performance(root, kind, inventory, capture_dt=full_dt, vm_tz=vm_tz)
    except Exception as e:
        facts["sar_performance_error"] = str(e)
    try:
        facts["crash_analysis"] = check_crash_analysis(root, kind, inventory)
    except Exception as e:
        facts["crash_analysis_error"] = str(e)
    try:
        facts["boot_performance"] = check_boot_performance(root, kind, inventory)
    except Exception as e:
        facts["boot_performance_error"] = str(e)
    try:
        facts["security_mac"] = check_security_mac(root, kind, inventory)
    except Exception as e:
        facts["security_mac_error"] = str(e)
    try:
        facts["package_drift"] = check_package_drift(root, kind, inventory, capture_dt=full_dt)
    except Exception as e:
        facts["package_drift_error"] = str(e)
    try:
        facts["systemd_cascade"] = check_systemd_cascade(root, kind, inventory)
    except Exception as e:
        facts["systemd_cascade_error"] = str(e)
    try:
        facts["container_logs"] = check_container_logs(root, kind, inventory)
    except Exception as e:
        facts["container_logs_error"] = str(e)

    # --- v4.7.0: OS/version knowledge base + config-file anomaly detection.
    # os_knowledge.py is imported the same sys.path-safe way as
    # pcap_analyzer.py below (this file supports being run both as a
    # standalone script and as part of the engine package).
    os_kb = None
    _build_os_knowledge = _check_config_anomalies = None
    try:
        _engine_dir = str(Path(__file__).resolve().parent)
        if _engine_dir not in sys.path:
            sys.path.insert(0, _engine_dir)
        from os_knowledge import build_os_knowledge as _build_os_knowledge, check_config_anomalies as _check_config_anomalies
    except Exception as e:
        facts["os_knowledge_error"] = str(e)
    if _build_os_knowledge:
        try:
            os_kb = _build_os_knowledge(root, kind, inventory, find_inventory, get_text, extract_supportconfig_section)
            if os_kb:
                facts["os_knowledge"] = os_kb
        except Exception as e:
            facts["os_knowledge_error"] = str(e)
    if _check_config_anomalies:
        try:
            facts["config_anomalies"] = _check_config_anomalies(
                root, kind, inventory, find_inventory, get_text, extract_supportconfig_section,
                security_mac=facts.get("security_mac"), os_detected=(os_kb or {}).get("detected"),
            )
        except Exception as e:
            facts["config_anomalies_error"] = str(e)

    return facts


# --------------------------------------------------------------------------
# Digest rendering
# --------------------------------------------------------------------------
def build_digest(kind, root, input_path, inventory, findings_list, facts, timeline, log_spans, stats, args, elapsed):
    enabled_sections = getattr(args, "enabled_sections", None)

    def _section_on(key):
        # None (the default for every pre-v4.0.0 caller) means every
        # section is enabled - an empty/partial set only ever narrows
        # from there, never silently hides something an old caller never
        # knew to ask for.
        return enabled_sections is None or key in enabled_sections

    lines = []
    lines.append(f"# Root-Cause Analysis Digest — {input_path.name}")
    lines.append("")
    lines.append(f"- **Analyzer version:** {__version__}")
    lines.append(f"- **Detected type:** {kind}")
    lines.append(f"- **Source:** `{input_path}`")
    lines.append(f"- **Extracted root:** `{root}`")
    lines.append(f"- **Files inventoried:** {len(inventory):,}")
    compressed_note = f", {stats['compressed_files_scanned']:,} transparently decompressed (gzip/bz2/xz)" if stats.get("compressed_files_scanned") else ""
    lines.append(f"- **Files content-scanned:** {stats['files_scanned']:,}{compressed_note} (binary/empty skipped: {stats['files_skipped_binary']:,}, read errors: {stats['read_errors']:,})")
    if stats.get("decompressed_size_capped"):
        lines.append(f"- ⚠️ **{stats['decompressed_size_capped']} compressed file(s) exceeded the {human_size(_MAX_DECOMPRESSED_BYTES)} decompressed-size safety cap** and were only partially scanned (guards against a corrupted or maliciously-crafted archive expanding without bound - not expected on legitimate rotated logs).")
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

    os_kb = facts.get("os_knowledge") or {}
    if os_kb:
        det = os_kb.get("detected", {})
        lines.append("## 🐧 OS Knowledge")
        lines.append(f"- **Detected:** {det.get('pretty_name') or det.get('name') or '?'} — {os_kb.get('family_label', '?')}" + (f" (source: `{os_kb['source_file']}`)" if os_kb.get("source_file") else ""))
        if os_kb.get("lifecycle_hint"):
            lines.append(f"- **Support lifecycle:** {os_kb['lifecycle_hint']}")
        if os_kb.get("docs_hub_link"):
            lines.append(f"- **Official docs for this version:** {os_kb['docs_hub_link']}")
        if os_kb.get("cve_search_link"):
            lines.append(f"- **Vendor security-advisory/CVE search:** {os_kb['cve_search_link']}")
        if os_kb.get("version_notes"):
            lines.append("- **What's different about this major version (quick orientation, not exhaustive):**")
            for note in os_kb["version_notes"]:
                lines.append(f"  - {note}")
        if os_kb.get("known_issues"):
            lines.append(f"- ⚠️ **{len(os_kb['known_issues'])} known version-specific item(s) worth checking against this bundle:**")
            for ki in os_kb["known_issues"]:
                lines.append(f"  - **{ki['title']}** — {ki['detail']}" + (f" ({ki['doc_link']})" if ki.get("doc_link") else ""))
        lines.append("")

    cfg = facts.get("config_anomalies") or {}
    if cfg.get("anomalies"):
        lines.append("## ⚙️ Configuration File Anomalies")
        lines.append(f"_Checked {len(cfg.get('files_checked', []))} configuration file(s) present in this bundle against a fixed set of known-risky/known-inconsistent settings — not an exhaustive audit, but a fast pass over the files that most often matter for support cases._")
        lines.append("")
        for a in cfg["anomalies"]:
            marker = "⚠️" if a["severity"] == "WARNING" else "ℹ️"
            lines.append(f"- {marker} **[{a['severity']}]** `{a['file']}` — **{a['title']}**")
            lines.append(f"  - {a['detail']}" + (f" ({a['doc_link']})" if a.get("doc_link") else ""))
        lines.append("")
    elif cfg.get("files_checked"):
        lines.append("## ⚙️ Configuration File Anomalies")
        lines.append(f"_Checked {len(cfg['files_checked'])} configuration file(s) present in this bundle ({', '.join('`'+f+'`' for f in cfg['files_checked'][:10])}) — no anomalies found among the fixed set of known-risky/known-inconsistent settings this project currently checks for._")
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
    sar = facts.get("sar_performance", {}) or {}
    if _section_on("sar") and sar.get("summary", {}).get("cpu_pct_used_peak") is not None:
        any_fact = True
        lines.append(f"- **Peak CPU used (SAR):** {sar['summary']['cpu_pct_used_peak']}% at {sar['summary'].get('cpu_pct_used_peak_ts','?')}")
    pkg_drift = facts.get("package_drift", {}) or {}
    if _section_on("packages") and pkg_drift.get("recent_changes_7d_count"):
        any_fact = True
        lines.append(f"- **Packages changed in the 7 days before capture:** {pkg_drift['recent_changes_7d_count']} — see \"Recent Package Changes\" below")
    sec_mac = facts.get("security_mac", {}) or {}
    if _section_on("security") and (sec_mac.get("selinux_denial_total") or sec_mac.get("apparmor_denial_total")):
        any_fact = True
        bits = []
        if sec_mac.get("selinux_denial_total"):
            bits.append(f"{sec_mac['selinux_denial_total']} SELinux denials")
        if sec_mac.get("apparmor_denial_total"):
            bits.append(f"{sec_mac['apparmor_denial_total']} AppArmor denials")
        lines.append(f"- **Access-control denials:** {', '.join(bits)} — see \"Security (SELinux/AppArmor)\" below")
    cascade = facts.get("systemd_cascade", {}) or {}
    if _section_on("cascade") and cascade.get("cascades"):
        any_fact = True
        lines.append(f"- **Service failure cascades detected:** {len(cascade['cascades'])} — see \"Service Failure Cascade\" below")
    if not any_fact:
        lines.append("- _(no structured anomalies detected by fact-checks; rely on pattern findings below)_")
    lines.append("")

    sar = facts.get("sar_performance", {}) or {}
    if _section_on("sar") and (sar.get("summary") or sar.get("metric_groups_found")):
        lines.append("## 📊 Performance (SAR)")
        vm_tz = sar.get("vm_timezone")
        if vm_tz:
            lines.append(f"_Timestamps below are VM-local time, as printed by `sar` on the analyzed host: **{vm_tz['label']}**. Keep this in mind when correlating with your own clock or the customer's stated incident time._")
        else:
            lines.append("_The analyzed host's timezone could not be determined from this bundle - timestamps below are shown exactly as `sar` printed them (VM-local wall clock, zone unknown). Confirm the VM's zone with the customer before correlating against externally-reported incident times._")
        lines.append("")
        s = sar["summary"]
        if s.get("cpu_pct_used_avg") is not None:
            lines.append(f"- **CPU used:** avg {s['cpu_pct_used_avg']}%, peak {s['cpu_pct_used_peak']}% (at `{s.get('cpu_pct_used_peak_ts','?')}`)")
        if s.get("iowait_pct_avg") is not None:
            lines.append(f"- **I/O wait:** avg {s['iowait_pct_avg']}%, peak {s['iowait_pct_peak']}%")
        if s.get("mem_pct_used_avg") is not None:
            lines.append(f"- **Memory used:** avg {s['mem_pct_used_avg']}%, peak {s['mem_pct_used_peak']}%")
        if s.get("load1_avg") is not None:
            lines.append(f"- **Load average (1min):** avg {s['load1_avg']}, peak {s['load1_peak']}")
        if s.get("disk_tps_avg") is not None:
            lines.append(f"- **Disk transactions/sec:** avg {s['disk_tps_avg']}, peak {s['disk_tps_peak']}")
        if s.get("busiest_iface"):
            lines.append(f"- **Busiest network interface:** {s['busiest_iface']} (avg {s['busiest_iface_rxkbps_avg']} kB/s received)")
        lines.append(f"- **Data points parsed:** {sum(sar.get('sample_points', {}).values())} across {len(sar.get('files_parsed', []))} file(s); metric groups found: {', '.join(sar.get('metric_groups_found', [])) or 'none'}")
        lines.append("- _Full time series available in `facts.json` → `sar_performance.series` for graphing (CPU/memory/disk/network/load, each timestamped in VM-local time)._")
        lines.append("")

    crash = facts.get("crash_analysis", {}) or {}
    if _section_on("crash") and crash:
        lines.append("## 💥 Crash Analysis")
        if crash.get("abrt_reports"):
            lines.append(f"- ⚠️ **{len(crash['abrt_reports'])} ABRT crash report(s) found:**")
            for r in crash["abrt_reports"][:10]:
                exe = r.get("executable", "?")
                reason = r.get("reason", "?")
                when = r.get("crash_time", "?")
                lines.append(f"  - `{exe}` crashed ({reason}) at {when} — see `{r['dir']}/backtrace`")
        if crash.get("vmcore_files"):
            lines.append(f"- ⚠️ **Kernel crash dump (vmcore) present:** " + ", ".join(f"{v['path']} ({v['size_human']})" for v in crash["vmcore_files"][:5]))
        if "kdump_configured" in crash:
            lines.append(f"- **kdump configured:** {'yes' if crash['kdump_configured'] else 'no'}" + (f" (path: {crash['kdump_path']})" if crash.get("kdump_path") else ""))
        if crash.get("kernel_oops_signature_count"):
            lines.append(f"- ⚠️ **Kernel panic/oops signatures in dmesg:** {crash['kernel_oops_signature_count']} — see `core_dumps`/`kernel_boot` findings below")
        if not any(k in crash for k in ("abrt_reports", "vmcore_files", "kernel_oops_signature_count")):
            lines.append("- No ABRT reports, vmcore files, or kernel oops signatures found in this bundle.")
        lines.append("")

    boot = facts.get("boot_performance", {}) or {}
    if _section_on("boot") and boot:
        lines.append("## 🥾 Boot Performance")
        if boot.get("startup_breakdown_raw"):
            lines.append(f"- **Startup breakdown:** {boot['startup_breakdown_raw']}")
        if boot.get("slowest_units"):
            lines.append("- **Slowest units to start:**")
            for u in boot["slowest_units"][:10]:
                lines.append(f"  - {u['unit']}: {u['seconds']}s")
        if boot.get("critical_chain_raw"):
            lines.append("- **Critical chain (systemd-analyze critical-chain, verbatim):**")
            lines.append("```")
            lines.append(boot["critical_chain_raw"])
            lines.append("```")
        lines.append("")

    if _section_on("security") and sec_mac:
        lines.append("## 🛡️ Security (SELinux/AppArmor)")
        if sec_mac.get("selinux_status"):
            lines.append(f"- **SELinux status:** {sec_mac['selinux_status']}" + (f" ({sec_mac['selinux_mode']})" if sec_mac.get("selinux_mode") else ""))
        if "apparmor_profiles_enforce" in sec_mac or "apparmor_profiles_complain" in sec_mac:
            lines.append(f"- **AppArmor profiles:** {sec_mac.get('apparmor_profiles_enforce', 0)} enforce, {sec_mac.get('apparmor_profiles_complain', 0)} complain")
        if sec_mac.get("selinux_top_denials"):
            lines.append(f"- ⚠️ **Top SELinux denials** (of {sec_mac['selinux_denial_total']} total):")
            for d in sec_mac["selinux_top_denials"][:10]:
                lines.append(f"  - ({d['count']}x) `{d['scontext']}` → `{d['tcontext']}` [{d['tclass']}]")
        if sec_mac.get("apparmor_top_denials"):
            lines.append(f"- ⚠️ **Top AppArmor denials** (of {sec_mac['apparmor_denial_total']} total):")
            for d in sec_mac["apparmor_top_denials"][:10]:
                lines.append(f"  - ({d['count']}x) profile `{d['profile']}`, operation `{d['operation']}`")
        lines.append("")

    if _section_on("packages") and (pkg_drift.get("recent_changes_7d") or pkg_drift.get("most_recent_change")):
        lines.append("## 📦 Recent Package Changes")
        if pkg_drift.get("most_recent_change"):
            mrc = pkg_drift["most_recent_change"]
            lines.append(f"- **Most recent package change on record:** {mrc['package']} ({mrc['action']}) at {mrc['when']}")
        if pkg_drift.get("recent_changes_7d"):
            lines.append(f"- ⚠️ **{pkg_drift['recent_changes_7d_count']} package change(s) in the 7 days before capture** — a strong \"what changed right before this broke\" candidate list, newest first:")
            for e in pkg_drift["recent_changes_7d"][:20]:
                lines.append(f"  - `{e['when']}` — {e['package']} ({e['action']})")
            if pkg_drift["recent_changes_7d_count"] > 20:
                lines.append(f"  - _(+{pkg_drift['recent_changes_7d_count'] - 20} more — see facts.json → package_drift.recent_changes_7d)_")
        lines.append("")

    if _section_on("cascade") and (cascade.get("cascades") or cascade.get("dependency_failures_untimed")):
        lines.append("## 🔗 Service Failure Cascade")
        if cascade.get("cascades"):
            for c in cascade["cascades"]:
                lines.append(f"- ⚠️ **{c['start_ts']} → {c['end_ts']}:** `{c['likely_trigger']}` failed first, likely triggering: {', '.join(c['cascaded_units'])}")
        if cascade.get("dependency_failures_untimed"):
            lines.append("- Dependency-failure evidence found but timestamps couldn't be parsed: " + ", ".join(cascade["dependency_failures_untimed"][:10]))
        lines.append("")

    containers = facts.get("container_logs", {}) or {}
    if _section_on("containers") and containers:
        lines.append("## 🐳 Container Correlation")
        if containers.get("total_containers_seen"):
            lines.append(f"- **Containers observed:** {containers['total_containers_seen']}")
        if containers.get("exited_nonzero"):
            lines.append(f"- ⚠️ **{len(containers['exited_nonzero'])} container(s) exited with a non-zero code:**")
            for c in containers["exited_nonzero"][:10]:
                lines.append(f"  - {c['name']}: exit code {c['exit_code']}" + (f" — {c['note']}" if c["note"] else ""))
        if containers.get("currently_restarting"):
            lines.append(f"- ⚠️ **{len(containers['currently_restarting'])} container(s) currently restarting** (restart-loop candidate)")
        if containers.get("host_oom_events_mentioning_containers"):
            lines.append(f"- ⚠️ **Host-level OOM events mentioning container runtimes:** {containers['host_oom_events_mentioning_containers']}")
        if containers.get("container_log_files_found"):
            lines.append(f"- **Container-specific log files found:** {containers['container_log_files_found']} (see `inventory.json`, category varies by path)")
        lines.append("")

    pcap = facts.get("network_capture") or {}
    if _section_on("network") and pcap:
        lines.append("## 🌐 Network Capture (pcap)")
        lines.append("_Metadata only - packet/byte counts, top talkers, protocol mix, and TCP/DNS summaries. Raw payload content is never parsed, stored, or included here - see SECURITY.md._")
        lines.append("")
        if pcap.get("error"):
            lines.append(f"- _{pcap['error']}_")
        else:
            lines.append(f"- **Packets:** {pcap['total_packets']:,} ({pcap['total_bytes_human']})" + (f" over {pcap['duration_seconds']}s ({pcap['packets_per_second']} pkt/s)" if pcap.get("duration_seconds") else ""))
            if pcap.get("protocol_counts"):
                lines.append("- **Protocol mix:** " + ", ".join(f"{k}: {v:,}" for k, v in sorted(pcap["protocol_counts"].items(), key=lambda kv: -kv[1])))
            if pcap.get("top_talkers"):
                lines.append("- **Top talkers (by bytes):**")
                for t in pcap["top_talkers"][:10]:
                    lines.append(f"  - {t['src']} → {t['dst']}: {t['bytes_human']}")
            tcp_bits = []
            if pcap.get("tcp_reset"):
                tcp_bits.append(f"{pcap['tcp_reset']} RSTs")
            if pcap.get("tcp_retransmits_suspected"):
                tcp_bits.append(f"{pcap['tcp_retransmits_suspected']} suspected retransmissions")
            if tcp_bits:
                lines.append(f"- ⚠️ **TCP anomalies:** {', '.join(tcp_bits)} (SYN: {pcap.get('tcp_syn',0)}, SYN-ACK: {pcap.get('tcp_synack',0)})")
            if pcap.get("possible_port_scan_pattern"):
                lines.append("- ⚠️ **Possible port-scan pattern:** many SYNs with disproportionately few SYN-ACKs - could also just be a one-sided capture; worth a second look, not a certainty.")
            if pcap.get("dns_top_queries"):
                lines.append("- **Top DNS queries:** " + ", ".join(f"{q['qname']} ({q['count']}x)" for q in pcap["dns_top_queries"][:10]))
            if pcap.get("truncated_at_max_packets"):
                lines.append(f"- _(capture truncated after {pcap['truncated_at_max_packets']:,} packets for analysis speed - counts above reflect only that prefix)_")
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


ALL_FOCUS_AREAS = {"sar", "crash", "boot", "security", "packages", "cascade", "containers", "network"}


class _DigestArgs:
    """Lightweight stand-in for the argparse.Namespace that build_digest()
    expects, so the CLI and the library entrypoint can share one digest
    renderer without build_digest() needing to know which caller it has."""
    def __init__(self, min_severity, top_per_category, start_dt, end_dt, focus_text=None,
                 focus_keywords=None, enabled_sections=None):
        self.min_severity = min_severity
        self.top_per_category = top_per_category
        self.start_dt = start_dt
        self.end_dt = end_dt
        self.focus_text = focus_text
        self.focus_keywords = focus_keywords or []
        # None means "everything enabled" (the default, and what every
        # existing CLI/API caller gets unless it opts into the v4.0.0
        # focus-area toggles) - never an empty-set-means-nothing-shown
        # trap for old callers that don't know this parameter exists.
        self.enabled_sections = enabled_sections


# --------------------------------------------------------------------------
# Parallel scanning (v4.9.0)
# --------------------------------------------------------------------------
# The line-by-line scan (scan_file(), above) is CPU-bound - regex matching
# against every line of every file - not I/O-bound, so Python threads
# don't help here (the GIL means only one thread executes Python bytecode
# at a time regardless of thread count; this was directly confirmed on a
# real customer bundle where a single worker pegged one CPU core at ~100%
# for the whole multi-minute scan). Real parallelism for CPU-bound work in
# Python requires separate PROCESSES (each with its own GIL) -
# concurrent.futures.ProcessPoolExecutor is the stdlib tool for that.
#
# Design constraints this section works within:
#   - No new dependency (no psutil) - memory detection below is
#     OS-native (ctypes on Windows, /proc/meminfo on Linux), matching
#     this project's stdlib-only philosophy everywhere else.
#   - Worker functions must be plain top-level module functions (not
#     closures/lambdas) so they're picklable across the process
#     boundary - _scan_batch() below takes only plain, picklable
#     arguments (strings, a Path, primitives) and returns a
#     self-contained partial result with no shared mutable state.
#   - Small bundles must not pay process-pool startup overhead for no
#     benefit - determine_worker_count() only recommends >1 worker once
#     the bundle is big enough that parallelizing is actually worth it.
#   - The sequential (single-process) code path is left completely
#     untouched as the workers<=1 branch in run_analysis() - the
#     multi-worker path is strictly additive, not a rewrite of the
#     proven-correct single-threaded scan.
_DEFAULT_MAX_WORKERS = 8  # hard ceiling regardless of CPU count - beyond
# this, per-worker overhead (process startup, result-merging) and disk
# I/O contention dominate any further gain for this workload; also keeps
# a huge-core-count shared VM from being monopolized by one analysis job.
_MIN_FILES_FOR_PARALLEL = 300      # below this, sequential is already fast
_MIN_BYTES_FOR_PARALLEL = 20 * 1024 * 1024  # 20MB - ditto
_EST_MB_PER_WORKER = 300  # conservative per-worker memory budget used to
# cap worker count on a memory-constrained VM - covers the Python
# interpreter + compiled regex tables + one file's decompression buffers
# + that worker's share of accumulated findings; deliberately generous
# rather than tightly tuned, since under-provisioning workers just costs
# some speed, while over-provisioning them risks the VM's memory pressure.


def _get_available_memory_mb():
    """Best-effort available-memory detection, OS-native only (no psutil
    dependency). Returns None if it can't be determined on this platform
    - callers must treat that as "unknown, don't let memory constrain the
    worker count" rather than as zero."""
    system = platform.system()
    if system == "Windows":
        try:
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]
            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                return stat.ullAvailPhys / (1024 * 1024)
        except Exception:
            pass
        return None
    if system == "Linux":
        try:
            with open("/proc/meminfo", "r", encoding="ascii", errors="replace") as fh:
                for line in fh:
                    if line.startswith("MemAvailable:"):
                        return int(line.split()[1]) / 1024  # kB -> MB
        except (OSError, ValueError, IndexError):
            pass
        return None
    return None  # macOS/other: no stdlib-only reliable API - treated as unknown, not zero


def determine_worker_count(total_files, total_bytes, requested_workers=None):
    """Decides how many worker PROCESSES to use for the line-scanning
    pass. requested_workers overrides auto-detection entirely when given
    (1 forces the original sequential path; any other positive int is
    used as-is, capped only by CPU count - an explicit request is
    trusted over the heuristic). None (the default) auto-detects from:
      - CPU count (os.cpu_count()) - the hard upper bound, since more
        worker processes than cores cannot run truly concurrently;
      - available memory / _EST_MB_PER_WORKER - a soft cap so a
        memory-constrained VM doesn't get oversubscribed;
      - bundle size - below _MIN_FILES_FOR_PARALLEL/_MIN_BYTES_FOR_PARALLEL,
        returns 1 unconditionally, since process-pool startup overhead
        would outweigh any benefit on a small bundle;
      - _DEFAULT_MAX_WORKERS - a hard ceiling regardless of how many
        cores/memory are available (see constant comment above).
    Always returns at least 1.
    """
    if requested_workers is not None:
        try:
            requested_workers = int(requested_workers)
        except (TypeError, ValueError):
            requested_workers = None
    if requested_workers is not None and requested_workers >= 1:
        cpu_count = os.cpu_count() or 1
        return max(1, min(requested_workers, cpu_count))

    if total_files < _MIN_FILES_FOR_PARALLEL or total_bytes < _MIN_BYTES_FOR_PARALLEL:
        return 1

    cpu_count = os.cpu_count() or 1
    workers = min(cpu_count, _DEFAULT_MAX_WORKERS)

    avail_mb = _get_available_memory_mb()
    if avail_mb is not None:
        mem_cap = max(1, int(avail_mb // _EST_MB_PER_WORKER))
        workers = min(workers, mem_cap)

    return max(1, workers)


def _partition_items_by_size(items, num_partitions):
    """Greedy longest-processing-time-first (LPT) partitioning: sorts
    items by size descending, then repeatedly assigns the next item to
    whichever partition currently has the smallest accumulated total
    size. A well-known good approximation for balancing work across N
    workers when task sizes vary widely - directly relevant here, since
    real bundles routinely mix thousands of small files with a handful
    of individually huge ones (a real customer bundle had several
    100MB+ pacemaker logs among ~96,000 mostly-small files); naive
    equal-COUNT chunking would leave one worker stuck with all the huge
    files while the others finish early and sit idle."""
    partitions = [[] for _ in range(num_partitions)]
    totals = [0] * num_partitions
    for item in sorted(items, key=lambda it: it[3], reverse=True):  # it[3] = size
        idx = totals.index(min(totals))
        partitions[idx].append(item)
        totals[idx] += item[3]
    return [p for p in partitions if p]  # drop any empty partition (more workers than items)


def _scan_batch(root, kind, batch, window_start, window_end, max_examples, year_hint):
    """Worker-process entry point (must stay a plain top-level function -
    picklability across the process boundary depends on it). Scans every
    item in `batch` (a list of (relpath, category, compression_kind,
    size) tuples) into a fresh, self-contained ctx local to this call -
    no state is shared with the main process or other workers, so this
    needs zero locking. Reuses scan_file() completely unchanged; the only
    difference from the sequential path is that each worker gets its OWN
    ctx instead of all files sharing one - _merge_scan_contexts() below
    combines them back into a single result afterward."""
    local_ctx = {
        "findings": {}, "timeline": [], "log_spans": {},
        "max_examples": max_examples,
        "window_start": window_start, "window_end": window_end,
        "stats": {"bytes_scanned": 0, "lines_scanned": 0, "read_errors": 0,
                   "files_scanned": 0, "files_skipped_binary": 0, "year_hint": year_hint,
                   "lines_in_window": 0, "lines_out_of_window": 0,
                   "compressed_files_scanned": 0, "decompressed_size_capped": 0},
    }
    for relpath, category, compression_kind, _size in batch:
        scan_file(root, relpath, kind, category, local_ctx, compression_kind=compression_kind)
        local_ctx["stats"]["files_scanned"] += 1
        if compression_kind:
            local_ctx["stats"]["compressed_files_scanned"] += 1
    return local_ctx


def _merge_scan_contexts(partial_ctxs, max_examples):
    """Combines the partial per-worker ctx dicts _scan_batch() returns
    into a single ctx with the exact same shape run_analysis()'s
    sequential path builds directly, so every downstream consumer
    (build_digest(), the API's findings_list sort, etc.) works completely
    unchanged regardless of whether 1 or many workers did the scanning.

    One deliberate, documented behavioral nuance versus strictly
    sequential scanning: when a given finding occurs in files handled by
    different workers, which specific occurrences end up as that
    finding's first `max_examples` recorded examples can differ from
    "always the first N encountered in inventory order" - the total
    COUNT is always exact and complete either way (nothing is ever
    dropped or double-counted), only the particular handful of sample
    examples shown for a high-frequency finding might vary. Examples
    have always been "some representative samples," not an exhaustive
    or canonically-ordered list, so this is a reasonable, disclosed
    trade for a meaningful speed win - see CHANGELOG.md's [4.9.0] entry.
    """
    merged = {
        "findings": {}, "timeline": [], "log_spans": {},
        "stats": {"bytes_scanned": 0, "lines_scanned": 0, "read_errors": 0,
                   "files_scanned": 0, "files_skipped_binary": 0,
                   "lines_in_window": 0, "lines_out_of_window": 0,
                   "compressed_files_scanned": 0, "decompressed_size_capped": 0},
    }
    for ctx in partial_ctxs:
        for key, entry in ctx["findings"].items():
            existing = merged["findings"].get(key)
            if existing is None:
                merged["findings"][key] = dict(entry)  # copy - don't alias a worker's own dict
            else:
                existing["count"] += entry["count"]
                if len(existing["examples"]) < max_examples:
                    existing["examples"].extend(entry["examples"][: max_examples - len(existing["examples"])])
        merged["timeline"].extend(ctx["timeline"])
        for relpath, span in ctx["log_spans"].items():
            existing_span = merged["log_spans"].get(relpath)
            if existing_span is None:
                merged["log_spans"][relpath] = list(span)
            else:
                existing_span[0] = min(existing_span[0], span[0])
                existing_span[1] = max(existing_span[1], span[1])
        for k, v in ctx["stats"].items():
            if k in merged["stats"]:
                merged["stats"][k] += v
    # Same soft cap as the sequential path's "and len(timeline) < 20000"
    # guard - preserved post-merge so the guarantee ("never unboundedly
    # many timeline entries") holds regardless of worker count. Which
    # specific entries get kept if the true total exceeds 20000 can differ
    # slightly from sequential order for the same reason as findings
    # examples above - an accepted trade, and only relevant for an
    # extreme/degenerate bundle far outside real-world sosreport norms.
    if len(merged["timeline"]) > 20000:
        merged["timeline"] = merged["timeline"][:20000]
    return merged


def run_analysis(input_path, output_dir=None, min_severity="WARNING", top_per_category=25,
                  max_examples=3, start=None, end=None, around=None, window=60.0,
                  focus=None, progress_cb=None, focus_areas=None, pcap_path=None, workers=None):
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

    focus_areas is an optional iterable of the v4.0.0 analyzer toggle
    keys (subset of ALL_FOCUS_AREAS: "sar", "crash", "boot", "security",
    "packages", "cascade", "containers") controlling which of the new
    digest sections are rendered. Every check still RUNS regardless
    (they're cheap, and the full structured facts remain available via
    facts.json/the API either way) - this only narrows what shows up in
    the digest text itself (and therefore what the AI sees/discusses),
    for engineers who already know a given axis isn't relevant to this
    bundle. None (the default) enables every section, matching the
    tool's original behavior for any caller that doesn't pass this.

    pcap_path is an optional path to a standalone packet capture
    (.pcap/.pcapng) to analyze alongside the bundle - see
    backend/engine/pcap_analyzer.py. Reserved for the network analyzer;
    None means no capture was provided.

    workers controls parallelism for the line-by-line scanning pass
    (v4.9.0): None (the default) auto-detects a sensible worker-process
    count from CPU count, available memory, and bundle size (see
    determine_worker_count()) - small bundles stay fully sequential
    automatically, since process-pool startup overhead wouldn't pay off.
    Pass 1 to force the original single-process sequential path
    unconditionally (e.g. for debugging, or on a memory-constrained
    system where you'd rather it just be slower than risk memory
    pressure), or any other positive int to pin an explicit worker count
    (still capped at the machine's actual CPU count).

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
                   "lines_in_window": 0, "lines_out_of_window": 0, "window_active": window_active,
                   "compressed_files_scanned": 0, "decompressed_size_capped": 0},
    }
    if window_active:
        report(f"Time window active: {start_dt or '(open start)'} -> {end_dt or '(open end)'} (chronological logs only; config/snapshot files always fully scanned)")

    report("Scanning files for known failure signatures (this can take a while for large archives)...")
    last_report = time.time()
    scannable = []  # (relpath, category, compression_kind, size)
    for idx, item in enumerate(inventory, start=1):
        relpath = item["path"]
        if item["size"] <= 0:
            continue
        fpath = root / relpath
        # classify_file_readability() detects gzip/bz2/xz-compressed
        # files (e.g. rotated logs like "messages-20260406.xz.gz") by
        # magic bytes and transparently decompresses them for scanning,
        # rather than skipping them as binary the way a plain extension
        # check would - see the "Compressed-file support" section above.
        readability, compression_kind = classify_file_readability(fpath)
        if readability == "skip":
            ctx["stats"]["files_skipped_binary"] += 1
            continue
        if time.time() - last_report > 5:
            report(f"  ...classifying {relpath}  ({idx}/{len(inventory)} files inspected so far)")
            last_report = time.time()
        scannable.append((relpath, item["category"], compression_kind, item["size"]))

    total_scan_bytes = sum(s[3] for s in scannable)
    worker_count = determine_worker_count(len(scannable), total_scan_bytes, requested_workers=workers)

    if worker_count <= 1:
        # Original, proven-correct sequential path - unconditionally used
        # for small bundles (auto-detection already returns 1 for those)
        # or when workers=1 is explicitly forced. Zero behavior change
        # from pre-v4.9.0 for this branch.
        last_report = time.time()
        for idx, (relpath, category, compression_kind, _size) in enumerate(scannable, start=1):
            if time.time() - last_report > 5:
                suffix = f" (decompressing {compression_kind})" if compression_kind else ""
                report(f"  ...scanning {relpath}{suffix}  ({idx}/{len(scannable)} files, {len(ctx['findings'])} distinct findings so far)")
                last_report = time.time()
            scan_file(root, relpath, kind, category, ctx, compression_kind=compression_kind)
            ctx["stats"]["files_scanned"] += 1
            if compression_kind:
                ctx["stats"]["compressed_files_scanned"] += 1
    else:
        why = "auto-detected from CPU/memory" if workers is None else "requested"
        report(f"  Using {worker_count} parallel worker processes for {len(scannable)} files (~{human_size(total_scan_bytes)}) - {why}")
        partitions = _partition_items_by_size(scannable, worker_count)
        try:
            partial_ctxs = []
            with ProcessPoolExecutor(max_workers=len(partitions)) as pool:
                futures = {
                    pool.submit(_scan_batch, root, kind, part, start_dt, end_dt, max_examples, year_hint): (i, len(part), sum(x[3] for x in part))
                    for i, part in enumerate(partitions, start=1)
                }
                for future in as_completed(futures):
                    worker_idx, n_files, n_bytes = futures[future]
                    try:
                        partial_ctxs.append(future.result())
                        report(f"  worker {worker_idx}/{len(partitions)} finished: {n_files} files (~{human_size(n_bytes)})")
                    except Exception as e:
                        # One worker failing (a genuinely unexpected bug,
                        # not the routine per-file OSError/UnicodeDecodeError
                        # scan_file() already handles internally) shouldn't
                        # take down the whole analysis - report it clearly
                        # and continue with whatever the OTHER workers did
                        # produce, rather than losing all of their work too.
                        report(f"  ⚠️ worker {worker_idx}/{len(partitions)} failed ({n_files} files skipped): {e}")
            merged = _merge_scan_contexts(partial_ctxs, max_examples)
            ctx["findings"] = merged["findings"]
            ctx["timeline"] = merged["timeline"]
            ctx["log_spans"] = merged["log_spans"]
            for k, v in merged["stats"].items():
                ctx["stats"][k] += v
        except Exception as e:
            # ProcessPoolExecutor itself failing to even start (a sandboxed
            # environment forbidding subprocess creation, exotic platform
            # restriction, etc.) falls back to the sequential path rather
            # than aborting the whole analysis - slower, but still correct.
            report(f"  ⚠️ Parallel scanning unavailable ({e}) - falling back to sequential scanning.")
            last_report = time.time()
            for idx, (relpath, category, compression_kind, _size) in enumerate(scannable, start=1):
                if time.time() - last_report > 5:
                    report(f"  ...scanning {relpath}  ({idx}/{len(scannable)} files, {len(ctx['findings'])} distinct findings so far)")
                    last_report = time.time()
                scan_file(root, relpath, kind, category, ctx, compression_kind=compression_kind)
                ctx["stats"]["files_scanned"] += 1
                if compression_kind:
                    ctx["stats"]["compressed_files_scanned"] += 1

    stats = ctx["stats"]
    report(f"Scan complete: {stats['files_scanned']} files scanned ({stats['compressed_files_scanned']} decompressed), {stats['lines_scanned']:,} lines, {len(ctx['findings'])} distinct findings")
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

    if pcap_path:
        report(f"Analyzing packet capture: {pcap_path} (metadata only - see SECURITY.md)")
        try:
            # analyzer_core.py is imported both as part of the `engine`
            # package (relative import would work) and run directly as
            # a standalone script (relative import would fail) - ensure
            # this file's own directory is importable either way rather
            # than committing to one import style.
            _engine_dir = str(Path(__file__).resolve().parent)
            if _engine_dir not in sys.path:
                sys.path.insert(0, _engine_dir)
            from pcap_analyzer import analyze_pcap
            facts["network_capture"] = analyze_pcap(str(pcap_path))
        except Exception as e:
            facts["network_capture"] = {"error": str(e)}

    (output_dir / "inventory.json").write_text(json.dumps(inventory, indent=2), encoding="utf-8")
    (output_dir / "findings.json").write_text(json.dumps(findings_list, indent=2), encoding="utf-8")
    (output_dir / "facts.json").write_text(json.dumps(facts, indent=2, default=str), encoding="utf-8")

    enabled_sections = None
    if focus_areas is not None:
        enabled_sections = {a for a in focus_areas if a in ALL_FOCUS_AREAS}
    digest_args = _DigestArgs(min_severity, top_per_category, start_dt, end_dt, focus_text=focus_text,
                               focus_keywords=focus_keywords, enabled_sections=enabled_sections)
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
    ap.add_argument("--workers", type=int, default=None, help="Parallel worker processes for the line-scanning pass. Default: auto-detect from CPU count/available memory/bundle size. Pass 1 to force the original single-process sequential scan.")
    args = ap.parse_args()

    try:
        run_analysis(
            args.input, output_dir=args.output, min_severity=args.min_severity,
            top_per_category=args.top_per_category, max_examples=args.max_examples,
            start=args.start, end=args.end, around=args.around, window=args.window,
            focus=args.focus, workers=args.workers,
        )
    except AnalysisError as e:
        die(str(e))


if __name__ == "__main__":
    main()
