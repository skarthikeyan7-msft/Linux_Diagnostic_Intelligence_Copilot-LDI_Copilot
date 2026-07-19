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
import multiprocessing
import os
import platform
import queue as queue_mod
import re
import stat
import struct
import sys
import tarfile
import time
import xml.etree.ElementTree as ET
import zipfile
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path

__version__ = "4.14.0"

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
    # .obj/.pkl (v4.12.0) - a pure fast-path optimization, NOT a
    # correctness fix: is_probably_text_bytes()'s content-sniffing
    # already correctly classifies these as binary without needing an
    # extension-list entry at all (confirmed directly against real
    # files below) - this just skips the 4KB-read-and-heuristic probe
    # entirely for a file already known, from real evidence, to always
    # be one. Found in two real bundles this project was tested
    # against: supportconfig's public_cloud/regcache/*.obj (SUSE's
    # cloudregister.smt SMT-registration cache) and a sosreport's own
    # *.pkl file - both genuine Python `pickle`-serialized binary
    # objects (opcode-based serialization, never meaningfully readable
    # as text either way).
    ".obj", ".pkl",
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
# sar's "Linux <kernel> (<host>) <date> ..." header line prints its date
# using the CAPTURING system's own locale (glibc strftime "%x") - a real
# customer bundle (SLES15, modern sysstat) was found to use ISO
# "YYYY-MM-DD", which the original MM/DD/YYYY-only regex below never
# matched, silently leaving current_date unset for every block in the
# file. Both patterns are tried (mutually exclusive by separator, so
# trying both in sequence is unambiguous) - deliberately NOT attempting
# to also guess a DD/MM/YYYY slash-ordering, since that's genuinely
# ambiguous with MM/DD/YYYY from the digits alone and guessing wrong
# would silently corrupt dates rather than just leaving them unset; see
# _extract_date_from_sar_filename() below for the locale-independent
# safety net that covers exactly this gap instead.
_SAR_HEADER_DATE_RE_ISO = re.compile(r"(\d{4})-(\d{2})-(\d{2})")
_SAR_HEADER_DATE_RE_SLASH = re.compile(r"(\d{2})/(\d{2})/(\d{4})")
# A SECOND real customer bundle (stock RHEL 8, default POSIX/"C" locale -
# almost certainly the single most common case in practice, since it's
# what a box gets whenever nobody has explicitly configured a locale)
# was found to print "%x" as "MM/DD/YY" - a 2-DIGIT year, e.g. "07/18/26"
# for 2026-07-18. This is tried only after the 4-digit form above fails
# (mutually exclusive: a 4-digit year would also satisfy \d{2} for its
# first two digits, so the 4-digit pattern MUST be tried first or every
# MM/DD/YYYY date would get mis-parsed as MM/DD/<first-2-digits-of-year>
# with the trailing 2 digits ignored). The century pivot (00-68 -> 2000s,
# 69-99 -> 1900s) is delegated to strptime's own "%y" directive rather
# than hand-rolled, for the same POSIX-standard behavior every other tool
# uses.
_SAR_HEADER_DATE_RE_SLASH_2DIGIT = re.compile(r"(?<!\d)(\d{2})/(\d{2})/(\d{2})(?!\d)")
# The standard sysstat sa1/sa2 spool-rotation naming convention
# ("saYYYYMMDD"/"sarYYYYMMDD", e.g. the real "sar20260621"/"sa20260615"
# seen in a real customer bundle) encodes the exact calendar day
# unambiguously and locale-independently right in the filename - a far
# more reliable date source than parsing locale-dependent header text,
# and used as a fallback whenever the header line's own date can't be
# confidently parsed (see _parse_sar_text()).
_SAR_FILENAME_DATE_RE = re.compile(r"^sar?(\d{4})(\d{2})(\d{2})")
# The STANDARD, out-of-the-box sysstat sa1/sa2 cron naming convention is
# actually just "saDD"/"sarDD" - a bare 2-digit day-of-month, recycled
# monthly (e.g. "sa01".."sa31") - confirmed against a real, freshly
# captured RHEL 8 sosreport ("sa18"/"sar18" for the 18th). The
# "saYYYYMMDD" form above is a less common customization; this bare-day
# form is the one every default install actually produces, so treating
# ONLY the long form as "the" filename fallback (as v4.10.1 did) left
# the far more common case with no filename-derived date at all. Since a
# bare day number carries no month/year of its own, resolving it needs
# an external reference point - see _extract_date_from_sar_filename()'s
# use of the bundle's overall capture date for that.
_SAR_FILENAME_BARE_DAY_RE = re.compile(r"^sar?(\d{2})$")
_SAR_HEADER_HINTS = [
    # (header columns that must ALL appear on a header line, metric group)
    # CPU is keyed on "%idle" ALONE (not paired with "%user"/"%usr") -
    # deliberately, after finding a REAL bug against a real customer
    # bundle: sysstat renamed several CPU columns between major versions
    # (%user/%system -> %usr/%sys as of sysstat v10, used by every
    # currently-supported RHEL/SLES release) while "%idle" itself has
    # remained the one stable, version-independent column name across
    # every sysstat release this project has ever seen - and it never
    # appears in any OTHER sar table type (memory/disk/network/load/
    # swap/paging tables have no "%idle" column), so it's still a safe,
    # unambiguous match on its own. Requiring an exact secondary column
    # name (like the old "%user") meant this hint silently stopped
    # matching ANY modern sysstat CPU table - a real, previously
    # undetected gap that made cpu_pct_used_avg/peak and iowait_pct_avg/
    # peak silently absent from every affected bundle's SAR summary,
    # without ever surfacing as an error (the other metric groups still
    # parsed fine, since none of their hints had this fragility).
    (("%idle",), "cpu"),
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

# sadc/sar writes a special marker record whenever the monitored system
# reboots mid-collection-period, rendered by `sar` as e.g.
# "09:29:14 AM       LINUX RESTART      (64 CPU)" - confirmed against a
# real customer sosreport. This line matches _SAR_TIME_RE (it starts
# with a time) but its trailing columns are non-numeric, so without
# special-casing it, _parse_sar_text() below would misidentify it as an
# ordinary (if unrecognized) table header, clobbering block_kind to None
# and silently discarding every subsequent data row in that same table
# until the next real header line happens to reprint - a real risk
# exactly in the aftermath of a reboot, precisely the kind of moment a
# root-cause investigation cares about most. Recognized explicitly
# instead so it's (a) never mistaken for a header/data row and (b)
# surfaced as its own useful fact - an independent, sar-corroborated
# reboot timestamp.
_SAR_RESTART_RE = re.compile(r"^linux\s+restart\b", re.IGNORECASE)

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
    """Extracts every member, same as before, but as of v4.12.0 ALSO
    returns per-link metadata (`links`) for every symlink/hardlink
    member encountered - not just their eventual byte content.

    Why this matters: on Windows (the one runtime this tool actually
    ships on), `tarfile.extract()` cannot create a real symlink/hardlink
    (no `SeCreateSymbolicLinkPrivilege` by default) - but rather than
    failing, `TarFile.makelink()` silently falls back to copying the
    LINK TARGET's own real byte content in as an ordinary file instead
    (confirmed directly against a real sosreport's 1,064 real symlinks -
    e.g. `etc/localtime` lands as a 127-byte regular file with genuine
    zoneinfo content, not a 0-byte stub or a missing file). That fallback
    means file CONTENT was already correctly readable before this
    change - but every symlink/hardlink was completely indistinguishable
    from an ordinary file afterward, with zero record that it was ever a
    link at all. That's a real, if subtle, RCA gap: it silently hides
    *why* two unrelated-looking paths hold identical content, and a
    genuinely broken/dangling link on the source system (extraction
    itself raising, since there's no target content to fall back to)
    was previously indistinguishable from any other unrelated extraction
    failure buried in the generic `skipped` list.

    Each entry in `links` is `{"name", "type": "symlink"|"hardlink",
    "target": <raw linkname exactly as archived>, "extracted": bool,
    "error": str|None}` - `target` is intentionally left UNRESOLVED here
    (a tar symlink's target is relative to the link's own directory,
    while a tar hardlink's target is relative to the ARCHIVE ROOT - two
    different resolution rules) so it can be interpreted correctly once
    build_inventory() has the full path set to resolve against; see
    _resolve_link_target().
    """
    skipped = []
    links = []
    dest_abs = os.path.abspath(str(dest_dir))
    with tarfile.open(tar_path, "r:*") as tf:
        for m in tf:
            link_type = "symlink" if m.issym() else ("hardlink" if m.islnk() else None)
            safe_name = m.name  # fallback if _windows_safe_member_name() itself never runs below
            try:
                safe_name = _windows_safe_member_name(m.name)
                target = os.path.abspath(os.path.join(dest_abs, safe_name))
                if not (target == dest_abs or target.startswith(dest_abs + os.sep)):
                    skipped.append((m.name, "path traversal"))
                    if link_type:
                        links.append({"name": safe_name, "type": link_type, "target": m.linkname, "extracted": False, "error": "path traversal"})
                    continue
                if m.isdev() or m.ischr() or m.isblk() or m.isfifo():
                    skipped.append((m.name, "device/special file"))
                    continue
                if safe_name != m.name:
                    m.name = safe_name
                tf.extract(m, dest_dir)
                if link_type:
                    links.append({"name": safe_name, "type": link_type, "target": m.linkname, "extracted": True, "error": None})
            except Exception as e:
                skipped.append((m.name, str(e)))
                if link_type:
                    links.append({"name": safe_name, "type": link_type, "target": m.linkname, "extracted": False, "error": str(e)})
    return skipped, links


def safe_extract_zip(zip_path, dest_dir):
    """Same extraction behavior as before, plus symlink metadata
    tracking (as of v4.12.0) - see safe_extract_tar()'s docstring for
    the full rationale.

    The ZIP format has no first-class symlink concept the way tar does
    (no dedicated member "type" byte) - a symlink is instead a plain
    file entry whose Unix permission bits (packed into the upper 16
    bits of `external_attr` by tools that wrote it on a Unix system,
    e.g. Info-Zip - the de facto convention every real Unix zip
    implementation follows) have the S_IFLNK bit set, and whose CONTENT
    is the link's target path text rather than real file data. Detected
    here by checking those permission bits; the target is read directly
    from the zip entry's own content (available immediately, no
    dependency on how/whether the extraction itself succeeds).

    ZIP also has no hardlink concept at all - "type" will only ever be
    "symlink" for a zip-sourced bundle, which is fine since sosreport/
    supportconfig/crm_report are practically always tar-based anyway;
    zip support here is a defensive fallback for whatever a user might
    hand this tool, not the primary real-world path.
    """
    skipped = []
    links = []
    dest_abs = os.path.abspath(str(dest_dir))
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            is_symlink = bool(info.external_attr) and stat.S_ISLNK((info.external_attr >> 16) & 0xFFFF)
            link_target = None
            if is_symlink:
                try:
                    link_target = zf.read(info).decode("utf-8", errors="replace").strip()
                except Exception:
                    link_target = None
            safe_name = info.filename  # fallback if _windows_safe_member_name() itself never runs below
            try:
                safe_name = _windows_safe_member_name(info.filename)
                target = os.path.abspath(os.path.join(dest_abs, safe_name))
                if not (target == dest_abs or target.startswith(dest_abs + os.sep)):
                    skipped.append((info.filename, "path traversal"))
                    if is_symlink:
                        links.append({"name": safe_name, "type": "symlink", "target": link_target, "extracted": False, "error": "path traversal"})
                    continue
                if safe_name != info.filename:
                    info.filename = safe_name
                zf.extract(info, dest_dir)
                if is_symlink:
                    links.append({"name": safe_name, "type": "symlink", "target": link_target, "extracted": True, "error": None})
            except Exception as e:
                skipped.append((info.filename, str(e)))
                if is_symlink:
                    links.append({"name": safe_name, "type": "symlink", "target": link_target, "extracted": False, "error": str(e)})
    return skipped, links


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


def build_inventory(root: Path, kind: str, links=None):
    """Walks the extraction root into the flat {path, size, category}
    list every downstream check works from. As of v4.12.0, also accepts
    `links` (the list safe_extract_tar()/safe_extract_zip() return) so
    every symlink/hardlink that resolves to a FILE gets annotated with
    its type/target instead of looking identical to an ordinary file -
    see those functions' docstrings for why this matters. Purely
    additive: a caller that still passes no `links` (or an archive
    extractor that found none) gets exactly the pre-v4.12.0 inventory
    shape back, just without the new keys ever being set.

    Deliberately does NOT try to also resolve/annotate a link's TARGET
    against the inventory here (an earlier version of this function did
    - removed after testing directly against a real sosreport's 1,064
    real symlinks surfaced two real complications a simple string-based
    resolution can't handle well: many real symlinks point at
    DIRECTORIES, not files - e.g. "sys/block/sdb" -> a device subtree
    - which this file-only inventory never lists at all regardless; and
    a symlink's *documented* target can differ from what tarfile's own
    content-copy fallback actually resolved on THIS specific extraction
    run. check_link_summary() answers "did this link end up as usable
    content" far more reliably by directly checking the filesystem
    after extraction, rather than re-deriving it from path strings).
    """
    links_by_name = {}
    for link in links or []:
        # Tar/zip member names always use "/" - matches os.walk()+
        # as_posix() below, so this lookup is a direct, case-sensitive
        # dict hit with no further normalization needed.
        links_by_name[link["name"]] = link

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
            entry = {"path": rel, "size": size, "category": cat}
            link = links_by_name.get(rel)
            if link:
                entry["is_link"] = True
                entry["link_type"] = link["type"]
                entry["link_target"] = link["target"]
                entry["link_extracted"] = link["extracted"]
                if not link["extracted"]:
                    entry["link_error"] = link["error"]
            inventory.append(entry)
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
def scan_file(root, relpath, kind, file_category, ctx, compression_kind=None, progress_cb=None, progress_every_lines=5000):
    """... (line-by-line pattern scan for one file - see module docstring
    for the overall approach).

    progress_cb (v4.9.1), if given, is called periodically as
    progress_cb(lineno) while scanning THIS file - not just once per
    file the way the outer scan loop already reports. This matters for
    a single genuinely huge file (a real customer bundle had individual
    rotated pacemaker logs in the 78-120MB range): without a hook at
    this level, a multi-minute scan of ONE such file would still show
    zero visible progress the whole time, even with per-file reporting
    one level up - this closes that gap. Checked every
    progress_every_lines lines (a cheap integer-counter check, not a
    per-line function call) purely to bound the overhead of the check
    itself on an ordinary-sized file; the caller (_scan_batch()) is
    expected to further time-throttle its own actual reporting, since
    line-count alone doesn't map predictably to wall-clock time."""
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
                if progress_cb is not None and lineno % progress_every_lines == 0:
                    progress_cb(lineno)
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


def _extract_sar_header_date(line):
    """Tries ISO (YYYY-MM-DD) first, then slash MM/DD/YYYY, then slash
    MM/DD/YY (2-digit year) - see the module-level regex comments above
    for why DD/MM/YYYY is deliberately not guessed at here, and why the
    4-digit-year slash form must be tried before the 2-digit one.
    Returns a date or None."""
    m = _SAR_HEADER_DATE_RE_ISO.search(line)
    if m:
        yyyy, mm, dd = m.groups()
        try:
            return datetime(int(yyyy), int(mm), int(dd)).date()
        except ValueError:
            pass
    m = _SAR_HEADER_DATE_RE_SLASH.search(line)
    if m:
        mm, dd, yyyy = m.groups()
        try:
            return datetime(int(yyyy), int(mm), int(dd)).date()
        except ValueError:
            pass
    m = _SAR_HEADER_DATE_RE_SLASH_2DIGIT.search(line)
    if m:
        mm, dd, yy = m.groups()
        try:
            return datetime.strptime(f"{mm}/{dd}/{yy}", "%m/%d/%y").date()
        except ValueError:
            pass
    return None


def _extract_date_from_sar_filename(filename, reference_date=None):
    """Recognizes two real sysstat spool-rotation naming conventions:
    the long "saYYYYMMDD"/"sarYYYYMMDD" form (a less common customization
    - see the module-level regex comment above), and the bare 2-digit
    "saDD"/"sarDD" day-of-month form that is what the STOCK, out-of-the-
    box sa1/sa2 cron actually produces (confirmed against a real,
    freshly captured RHEL 8 sosreport - "sa18"/"sar18" for the 18th, with
    no month or year encoded at all). `filename` should already have any
    compression extension stripped (the caller does this).

    The bare-day form needs an external month/year reference to resolve
    - `reference_date` (the bundle's overall capture date, passed by the
    caller) fills that role: if the filename's day is <= the reference
    date's own day-of-month, it's assumed to be THIS month (e.g.
    captured on the 20th, "sa18" = 2 days ago); if it's greater, it must
    be from the PREVIOUS month instead (e.g. captured on the 5th, "sa18"
    can only be last month's 18th, since this month's 18th hasn't
    happened yet) - sysstat's default monthly recycling means a bare-day
    file is never more than about one rotation old, so a single
    month-back step covers the realistic range without guessing
    arbitrarily far into the past. Returns a date or None (e.g. no
    reference_date available, or neither convention matches)."""
    m = _SAR_FILENAME_DATE_RE.match(filename.lower())
    if m:
        yyyy, mm, dd = m.groups()
        try:
            return datetime(int(yyyy), int(mm), int(dd)).date()
        except ValueError:
            return None
    m = _SAR_FILENAME_BARE_DAY_RE.match(filename.lower())
    if m and reference_date is not None:
        dd = int(m.group(1))
        year, month = reference_date.year, reference_date.month
        if dd > reference_date.day:
            month -= 1
            if month == 0:
                month, year = 12, year - 1
        try:
            return datetime(year, month, dd).date()
        except ValueError:
            return None
    return None


def _looks_like_sar_spool_filename(basename):
    """True for a filename matching sysstat's own sa1/sa2 spool-rotation
    naming convention (see _SAR_FILENAME_DATE_RE/_SAR_FILENAME_BARE_DAY_RE
    above) - used to recognize a RAW BINARY sadc spool file specifically,
    as opposed to any other unrelated unreadable file that happened to be
    swept in by the generic "sar" directory-membership heuristic in
    check_sar_performance(). This lets the resulting guidance confidently
    name the real, well-understood cause (an un-rendered binary spool)
    instead of a generic "this file could not be read" non-answer.
    Confirmed against a real customer file: a genuine sysstat binary
    sadc spool ("var/log/sa/sa18", 63KB, real header strings "Linux"/
    kernel release/"x86_64" readable amid otherwise-binary bytes) that
    is NOT text and cannot be decoded without the matching sar/sadf
    binary version - see check_sar_performance()'s docstring."""
    low = basename.lower()
    for ext in (".xz", ".gz", ".bz2"):
        if low.endswith(ext):
            low = low[: -len(ext)]
            break
    return bool(_SAR_FILENAME_DATE_RE.match(low) or _SAR_FILENAME_BARE_DAY_RE.match(low))


def _parse_sar_text(text, fallback_date, filename_date=None):
    """Parses one sar-plugin text capture (sysstat's own pre-rendered
    tables - CPU/memory/disk/network/load, possibly several back-to-back
    in the same file) into {metric_group: [{"ts": iso, <col>: val, ...}]}.
    Header vs. data rows are told apart generically: a header row's
    columns (after the leading timestamp) are never all-numeric ("CPU",
    "%usr"/"%user", "kbmemfree", "IFACE", ...); a data row's are (aside
    from a possible leading label like "all"/"eth0", which is excluded
    from the all-numeric check by design). This one heuristic handles
    every sar table shape uniformly without hardcoding per-table column
    layouts. Unrecognized table shapes are silently skipped - a sar
    capture always includes several table types most callers don't
    need, and failing to parse one must never invalidate the others.
    "Average:" summary rows are intentionally skipped (the caller
    computes its own averages from the parsed series instead).

    filename_date (this specific file's own date, derived from its
    filename by the caller via _extract_date_from_sar_filename() - see
    that function) is used whenever the "Linux ..." header line's own
    embedded date can't be parsed (a real gap found against a real
    customer bundle: modern sysstat's header date format is
    locale-dependent, and this fallback is what makes that non-fatal)
    and otherwise falls back further to the caller's generic
    fallback_date (e.g. the bundle's overall capture date) as a last
    resort - see check_sar_performance()'s docstring for the full
    precedence chain and rationale.

    Returns (series, restart_events) - restart_events is a list of ISO
    timestamp strings for every "LINUX RESTART" marker found (see
    _SAR_RESTART_RE) - a reboot noted directly by sar/sadc itself,
    independent of (and a useful corroboration for) any other reboot
    evidence elsewhere in the bundle (last -F, journal, dmesg). The
    caller de-duplicates across files/tables, since the SAME restart
    typically gets echoed once per metric-type table within a `sar -A`
    capture (CPU, memory, disk, ... each replaying the same underlying
    binary records).
    """
    series = defaultdict(list)
    restart_events = []
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
            current_date = _extract_sar_header_date(stripped)
            header_cols = None
            block_kind = None
            continue
        if low.startswith("average:") or low.startswith("summary:"):
            continue
        m = _SAR_TIME_RE.match(stripped)
        if not m:
            continue
        hh, mm_, ss, ampm, rest = m.groups()
        if _SAR_RESTART_RE.match(rest.strip()):
            # Deliberately does NOT reset header_cols/block_kind (unlike
            # every other line shape below) - see _SAR_RESTART_RE's own
            # comment: whatever table was already in progress before the
            # reboot stays in progress after it, so data rows resuming
            # right after this marker (before any real header happens to
            # reprint) are still correctly attributed instead of being
            # silently dropped.
            t = _parse_sar_time(hh, mm_, ss, ampm)
            the_date = current_date or filename_date or fallback_date
            if t is not None and the_date is not None:
                h, mi, se = t
                restart_events.append(datetime(the_date.year, the_date.month, the_date.day, h, mi, se).isoformat())
            continue
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
        the_date = current_date or filename_date or fallback_date
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
    return series, restart_events


# --------------------------------------------------------------------------
# sadf -x XML sar support (v4.13.0)
# --------------------------------------------------------------------------
# sosreport's sar plugin captures BOTH the classic pre-rendered text table
# (sos_commands/sar/sarNN, parsed by _parse_sar_text() above) AND a
# `sadf -x` XML rendition of the SAME underlying binary sadc data
# (sos_commands/sar/saNN.xml) - confirmed against a real customer bundle.
# Before this version the XML file was simply never parsed at all
# (harmless when the text file has usable data too, but real data left
# on the table whenever the text render is incomplete/restart-only and
# the XML happens to cover a different or wider span).
#
# Schema confirmed directly against sysstat's own XML-rendering source
# (xml_stats.c, sadf_misc.c on GitHub) rather than guessed - deliberately,
# after this same project already found THREE real, independently-
# undetected bugs in the text-format parser from assuming a fixed schema
# (see check_sar_performance()'s docstring history). Cross-checked
# against the one real XML file available (a restart-only capture, no
# populated <timestamp> blocks) - which itself already showed a real,
# if minor, version-drift wrinkle: the real file's <boot> used a
# "utc=\"1\"" attribute, while current upstream source instead writes
# "tz=\"...\"" - reinforcing the same "don't assume a byte-perfect fixed
# schema across sysstat versions" stance the text parser already takes,
# so this parser only ever depends on "date"/"time" attributes (stable
# across both) plus the metric attribute names below, never on any of
# the version-drifting extras.
#
# Column names are remapped to the IDENTICAL keys _parse_sar_text()
# already produces (e.g. XML's "idle" attribute -> "%idle", XML's "rkB"
# -> "rkB/s") so check_sar_performance()'s summary/chart code needs ZERO
# changes to also accept XML-sourced samples - both feed the exact same
# {metric_group: [{"ts": iso, <col>: val, ...}]} shape.
_SAR_XML_CPU_ATTR_MAP = {"idle": "%idle", "user": "%usr", "system": "%sys", "nice": "%nice", "iowait": "%iowait", "steal": "%steal"}
_SAR_XML_MEMORY_CHILD_MAP = {
    "memused-percent": "%memused", "memused": "kbmemused", "cached": "kbcached", "buffers": "kbbuffers",
    "commit": "kbcommit", "commit-percent": "%commit",
    "swpused-percent": "%swpused", "swpfree": "kbswpfree", "swpused": "kbswpused",
}
_SAR_XML_DISK_ATTR_MAP = {"dev": "DEV", "tps": "tps", "rkB": "rkB/s", "wkB": "wkB/s"}
_SAR_XML_NET_ATTR_MAP = {"iface": "IFACE", "rxkB": "rxkB/s", "txkB": "txkB/s", "rxpck": "rxpck/s", "txpck": "txpck/s"}
_SAR_XML_QUEUE_ATTR_MAP = {"ldavg-1": "ldavg-1", "ldavg-5": "ldavg-5", "ldavg-15": "ldavg-15", "runq-sz": "runq-sz", "plist-sz": "plist-sz"}
_SAR_XML_PAGING_ATTR_MAP = {"pgpgin": "pgpgin/s", "pgpgout": "pgpgout/s", "fault": "fault/s", "majflt": "majflt/s"}

_XML_DECL_RE = re.compile(r"^\s*<\?xml[^>]*\?>")


def _looks_like_xml(text):
    """Cheap content-based sniff (not filename-based, consistent with
    this project's established preference elsewhere) for whether a sar
    candidate file is the XML rendition rather than the classic text
    table - checked before attempting either parser, since a sosreport
    can capture BOTH sarNN (text) and saNN.xml (XML) side by side and
    each needs a different parser."""
    head = text.lstrip()[:200]
    return head.startswith("<?xml") or head.startswith("<sysstat")


def _strip_xml_namespaces(root):
    """sysstat's XML output declares a default namespace
    (xmlns="http://.../sysstat", confirmed directly against a real
    file) - which means EVERY element's parsed .tag becomes
    "{http://.../sysstat}cpu" rather than plain "cpu". Directly
    confirmed this silently breaks a bare root.iter("cpu")-style search
    (finds zero matches, no error) before writing the rest of this
    parser around bare tag names - stripping the namespace once, right
    after parsing, is simpler and faster than making every subsequent
    .iter() call namespace-aware individually."""
    for el in root.iter():
        if "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return root


def _parse_sar_xml(text, fallback_date):
    """Parses sadf -x XML sar output into the same
    {metric_group: [{"ts": iso, <col>: val, ...}]} shape
    _parse_sar_text() produces - see the module-level comment block
    above for the full schema-verification story.

    Each <timestamp date="..." time="..."> block (found anywhere in the
    tree via .iter(), not assuming one fixed nesting depth - the same
    robustness reasoning as _looks_like_xml() above) supplies the date/
    time context for whatever metric sub-elements it directly contains.
    <boot> restart markers are collected separately, the same way
    _parse_sar_text() surfaces its "LINUX RESTART" line - confirmed
    against the real file that <restarts><boot .../></restarts> is a
    SIBLING of <statistics>, not nested inside any one <timestamp>.

    Best-effort and silent on anything unparseable (not valid XML at
    all, or valid XML that isn't sysstat's - e.g. some other file that
    happens to have a .xml extension), consistent with
    _parse_sar_text()'s philosophy: a sar candidate with no usable data
    must never raise, only contribute nothing.
    """
    series = defaultdict(list)
    restart_events = []
    try:
        root = ET.fromstring(_XML_DECL_RE.sub("", text, count=1))
    except ET.ParseError:
        return series, restart_events
    _strip_xml_namespaces(root)

    for boot in root.iter("boot"):
        d, t = boot.get("date"), boot.get("time")
        if d and t:
            try:
                restart_events.append(datetime.strptime(f"{d} {t}", "%Y-%m-%d %H:%M:%S").isoformat())
            except ValueError:
                pass

    for ts_elem in root.iter("timestamp"):
        d, t = ts_elem.get("date"), ts_elem.get("time")
        the_date = None
        if d:
            try:
                the_date = datetime.strptime(d, "%Y-%m-%d").date()
            except ValueError:
                the_date = None
        the_date = the_date or fallback_date
        if not (the_date and t):
            continue
        try:
            hh, mm, ss = (int(x) for x in t.split(":")[:3])
            ts = datetime(the_date.year, the_date.month, the_date.day, hh, mm, ss).isoformat()
        except (ValueError, TypeError):
            continue

        for cpu in ts_elem.iter("cpu"):
            row = {"CPU": cpu.get("number", "all")}
            for xk, tk in _SAR_XML_CPU_ATTR_MAP.items():
                v = cpu.get(xk)
                if v is not None:
                    try:
                        row[tk] = float(v)
                    except ValueError:
                        pass
            if len(row) > 1:
                series["cpu"].append({"ts": ts, **row})

        for mem in ts_elem.iter("memory"):
            row = {}
            for child in mem:
                tk = _SAR_XML_MEMORY_CHILD_MAP.get(child.tag)
                if tk and child.text:
                    try:
                        row[tk] = float(child.text)
                    except ValueError:
                        pass
            if row:
                series["memory"].append({"ts": ts, **row})

        for disk in ts_elem.iter("disk-device"):
            row = {}
            for xk, tk in _SAR_XML_DISK_ATTR_MAP.items():
                v = disk.get(xk)
                if v is None:
                    continue
                if xk == "dev":
                    row[tk] = v
                else:
                    try:
                        row[tk] = float(v)
                    except ValueError:
                        pass
            if len(row) > 1:
                series["disk_io"].append({"ts": ts, **row})

        for net in ts_elem.iter("net-dev"):
            row = {}
            for xk, tk in _SAR_XML_NET_ATTR_MAP.items():
                v = net.get(xk)
                if v is None:
                    continue
                if xk == "iface":
                    row[tk] = v
                else:
                    try:
                        row[tk] = float(v)
                    except ValueError:
                        pass
            if len(row) > 1:
                series["network"].append({"ts": ts, **row})

        for q in ts_elem.iter("queue"):
            row = {}
            for xk, tk in _SAR_XML_QUEUE_ATTR_MAP.items():
                v = q.get(xk)
                if v is not None:
                    try:
                        row[tk] = float(v)
                    except ValueError:
                        pass
            if row:
                series["load"].append({"ts": ts, **row})

        for pg in ts_elem.iter("paging"):
            row = {}
            for xk, tk in _SAR_XML_PAGING_ATTR_MAP.items():
                v = pg.get(xk)
                if v is not None:
                    try:
                        row[tk] = float(v)
                    except ValueError:
                        pass
            if row:
                series["paging"].append({"ts": ts, **row})

    return series, restart_events


def check_sar_performance(root, kind, inventory, capture_dt=None, vm_tz=None):
    """Parses pre-rendered `sar` captures - both sysstat's classic
    plain-text table output AND (v4.13.0) its `sadf -x` XML rendition,
    via _parse_sar_text()/_parse_sar_xml() respectively (content-sniffed
    per candidate file, see _looks_like_xml()) - into per-metric time
    series plus a condensed summary. A real sosreport captures BOTH
    side by side for the same underlying binary sadc data (e.g.
    sos_commands/sar/sar18 AND sos_commands/sar/sa18.xml) - both are
    always tried, and their results merged into the same series, so a
    text render that's incomplete or restart-only doesn't hide real
    data the XML sibling happens to cover (or vice versa). Looks in
    every location a bundle realistically stores this:
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
        silently missed. Checked UNCONDITIONALLY (regardless of detected
        `kind`), not just when kind=="supportconfig" - a real customer
        bundle was reported where this exact directory shape existed but
        the bundle was classified kind="unknown" (missing the usual
        supportconfig marker files, e.g. a partial/redacted send), which
        previously meant zero SAR candidates were ever even considered
        for it, matching neither the sosreport nor supportconfig branch.
      - crm_report: sysstats.txt.
      - **A bundle that IS JUST the sar/ directory itself, with nothing
        else around it** (root's own name is "sar"/"sa") - a real,
        reported case: a support engineer shared only the sar/ subfolder
        on its own, not the whole bundle. None of the path-based checks
        above can ever match this, because the relative paths in
        `inventory` no longer contain a "sar" segment at all once it WAS
        promoted to be the root itself. In exactly this situation, every
        file directly under the bundle is treated as a sar candidate -
        safe even if occasionally wrong, since the parser below already
        silently discards anything that doesn't actually look like a sar
        table (see _parse_sar_text()'s docstring).
    Candidates are filtered through classify_file_readability() (not the
    plain, non-decompression-aware is_probably_text()) before attempting
    to parse them as text, so an individually-compressed rotated sar
    capture is included rather than silently excluded at this filtering
    step even though get_text() below is fully able to decompress it -
    this filter is the earlier gatekeeper and must agree with what
    get_text() can actually read, or compressed candidates never even
    reach it. Skipping non-text/undecompressable candidates early still
    avoids a wasted read on what can be a multi-MB raw binary sa file.
    Best-effort and intentionally silent when a bundle has no sar data at
    all (common - sysstat isn't always installed on the customer's box).

    Per-file date resolution (see _parse_sar_text()): each candidate's
    own filename is checked for either the long "saYYYYMMDD"/
    "sarYYYYMMDD" spool-rotation convention, or the bare 2-digit
    "saDD"/"sarDD" day-of-month convention that stock/default sysstat
    cron jobs actually produce (both real, confirmed against real
    customer bundles - see _extract_date_from_sar_filename()), tried
    FIRST as a locale-independent, largely unambiguous source. This
    matters because modern sysstat's "Linux ... <date> ..." header line
    prints its date in the CAPTURING system's own locale format - real
    customer bundles have been found using ISO YYYY-MM-DD, MM/DD/YYYY,
    and MM/DD/YY (2-digit year - the POSIX/"C"-locale default, arguably
    the single most common real-world case), and relying on the header
    date alone meant every row in an otherwise perfectly valid, fully
    parseable sar file was silently dropped whenever that locale format
    wasn't one of the recognized patterns - with NO error surfaced,
    since "zero SAR data" and "sar wasn't captured at all" look
    identical to a caller. The header line's own embedded date is still
    tried FIRST inside _parse_sar_text() (more precise for the rare
    multi-block-per-file case); the filename-derived date is the
    fallback that makes an unrecognized locale format non-fatal instead
    of silently zeroing out that entire file's data.

    A mid-collection reboot leaves a "LINUX RESTART" marker line in the
    sar data (see _SAR_RESTART_RE) - handled explicitly so it can't
    silently truncate the rest of that table's data, and surfaced back
    as its own "restart_events" fact (a reboot timestamp corroborated
    directly by sar/sadc, independent of last -F/journal/dmesg evidence
    elsewhere in the bundle). A sysstat spool file captured moments
    after a fresh reboot can hold nothing BUT this marker (confirmed
    against a real RHEL 8 sosreport) - "no_samples_reason" distinguishes
    that specific, genuinely-informative case from an ordinary "no sar
    data in this bundle at all".

    A raw BINARY sadc spool file (var/log/sa/saDD - sysstat's own live,
    continuously-updated data store, as opposed to the once-per-day
    TEXT/XML renders sa2's cron job produces from it) is deliberately
    NEVER hand-decoded here, even though it's easy to positively
    recognize by filename convention plus binary content (confirmed
    against a real 63KB customer file - readable "Linux"/kernel-release/
    "x86_64" header strings sit amid otherwise-opaque binary bytes).
    sysstat's on-disk binary record layout is version-specific and only
    reliably read by a MATCHING major version of sar/sadf - guessing at
    it would risk silently producing WRONG performance numbers, which is
    worse for a root-cause investigation than reporting no data at all.
    Real-world implication worth calling out explicitly rather than
    leaving unexplained: sadc keeps collecting real interval samples
    into this binary spool continuously all day, while the human-
    readable text/XML render is typically only (re)generated once,
    overnight - so a bundle captured mid-day, especially soon after a
    reboot, can have a FULLY POPULATED binary spool sitting right next
    to an all-but-empty text/XML rendering of the very same day (exactly
    the real scenario this was found against). Surfaced as
    "binary_only_spool_files" with actionable guidance (ask for
    `sar -A -f <file>` or `sadf -x -- -A -f <file>` run ON the original
    system) specifically when no other usable sar evidence exists, so
    this doesn't look identical to "sysstat wasn't installed at all".
    """
    if kind == "sosreport":
        candidates = find_inventory(inventory, "sos_commands/sar/", "var/log/sa/")
    elif kind == "crm_report":
        candidates = find_inventory(inventory, "sysstats.txt")
    else:
        candidates = []

    # supportconfig-style "sar/" directory membership - checked for every
    # kind (see docstring above), unioned with whatever kind-specific
    # candidates were already found.
    sar_dir_candidates = [p for p in find_inventory(inventory, "sar")
                           if "sar" in p.lower().split("/")[:-1] or "sar" in p.rsplit("/", 1)[-1].lower()]
    candidates = list(dict.fromkeys(candidates + sar_dir_candidates))  # union, de-duplicated, order-preserving

    # Bundle-root-IS-the-sar-directory fallback (see docstring) - only
    # engages when nothing else matched, so it never overrides a correct,
    # more specific detection above.
    if not candidates and root.name.lower() in ("sar", "sa"):
        candidates = [it["path"] for it in inventory if "/" not in it["path"]]

    readable_candidates = [p for p in candidates if classify_file_readability(root / p)[0] != "skip"]
    # Every candidate that got filtered OUT above (binary/unreadable) AND
    # matches sysstat's own spool-file naming convention is confidently a
    # raw sadc binary spool, not just some other unrelated unreadable
    # file that happened to live in a "sar"-named directory - see
    # _looks_like_sar_spool_filename()'s docstring and this function's
    # own docstring above for why that distinction (and NOT attempting
    # to decode it) matters.
    binary_spool_candidates = sorted({
        p for p in candidates
        if p not in readable_candidates and _looks_like_sar_spool_filename(p.rsplit("/", 1)[-1])
    })
    candidates = readable_candidates

    fallback_date = capture_dt.date() if capture_dt else None
    all_series = defaultdict(list)
    all_restart_events = set()
    files_parsed = []
    # 40MB read cap (not the 3MB most other get_text() calls in this file
    # use for a snippet/summary read) - a real gap found against a real
    # customer bundle: `sar -A` on a many-CPU system (64 cores here)
    # prints its per-core CPU breakdown for EVERY interval before any
    # other table type (memory/network/load/swap/paging) even appears,
    # and on this real system that CPU section alone ran past 10MB for a
    # single day - far beyond the old 3MB cap, meaning every OTHER
    # metric group was silently never even read, let alone parsed, for
    # any sufficiently CPU-dense system. 40MB comfortably covers even a
    # heavily-loaded, many-core, many-device system's full day of
    # `sar -A` text output while still being a bounded, sane ceiling
    # (not an unbounded read) for the rare pathological case.
    for relp in candidates:
        text = get_text(root, relp, 40_000_000)
        if not text.strip():
            continue
        if _looks_like_xml(text):
            # sadf -x XML rendition (v4.13.0) - a real sosreport
            # captures this alongside the classic text table (see
            # _parse_sar_xml()'s module-level comment). No filename-
            # date fallback needed here: unlike the text format, the
            # XML schema's own <timestamp date="..."> is present on
            # every single interval, not just a header line once per
            # file, so there's nothing to fall back FROM in practice.
            parsed, restart_events = _parse_sar_xml(text, fallback_date)
        else:
            basename = relp.rsplit("/", 1)[-1]
            for ext in (".xz", ".gz", ".bz2"):  # strip a compression suffix so the date pattern still matches the underlying spool filename
                if basename.lower().endswith(ext):
                    basename = basename[:-len(ext)]
                    break
            filename_date = _extract_date_from_sar_filename(basename, reference_date=fallback_date)
            parsed, restart_events = _parse_sar_text(text, fallback_date, filename_date=filename_date)
        all_restart_events.update(restart_events)
        if any(parsed.values()):
            files_parsed.append(relp)
            for group, rows in parsed.items():
                all_series[group].extend(rows)
        elif restart_events and relp not in files_parsed:
            # This file had NO usable metric-group data (e.g. a fresh
            # sysstat spool file captured moments after a reboot, before
            # any real interval has elapsed - confirmed against a real
            # RHEL 8 sosreport where "sar18" held nothing but the restart
            # marker itself) but DID positively confirm it was found and
            # read - counted as "parsed" so the caller can tell this
            # genuinely-empty-of-samples case apart from "no sar data in
            # this bundle at all" (see the restart_events-based summary
            # note below).
            files_parsed.append(relp)

    if not files_parsed:
        if binary_spool_candidates:
            # Nothing usable was found in TEXT/XML form, but real binary
            # sadc spool data exists (see docstring above) - worth a
            # distinct, actionable result instead of the bare {} used
            # when there's genuinely no sar evidence of any kind.
            return {
                "files_parsed": [],
                "metric_groups_found": [],
                "sample_points": {},
                "summary": {},
                "series": {},
                "vm_timezone": vm_tz,
                "restart_events": [],
                "binary_only_spool_files": binary_spool_candidates,
                "no_samples_reason": (
                    f"{len(binary_spool_candidates)} raw sysstat binary spool file(s) found "
                    f"({', '.join(binary_spool_candidates[:3])}{', ...' if len(binary_spool_candidates) > 3 else ''}) "
                    f"that hold real performance data sadc already collected, but can't be safely decoded without "
                    f"the matching `sar`/`sadf` version from the original system - ask for the output of "
                    f"`sar -A -f <file>` or `sadf -x -- -A -f <file>` run there for the actual numbers."
                ),
            }
        return {}

    for group in all_series:
        all_series[group].sort(key=lambda r: r["ts"])
    restart_events_sorted = sorted(all_restart_events)

    summary = {}
    cpu_rows = all_series.get("cpu", [])
    if cpu_rows:
        # "all" is sar's own aggregate-across-cores row, always present
        # even when a per-core breakdown (-P ALL) was also captured -
        # using it avoids conflating one busy core with overall load.
        all_rows = [r for r in cpu_rows if isinstance(r.get("%idle"), float) and r.get("CPU", "all") == "all"]
        if not all_rows:
            all_rows = [r for r in cpu_rows if isinstance(r.get("%idle"), float)]
        if all_rows:
            # Real bug found and fixed here (v4.13.0): keeping each row
            # paired with its own "% used" value throughout - rather
            # than computing a separately-filtered idle/used-values list
            # and then indexing back into the ORIGINAL, UNFILTERED
            # cpu_rows with that filtered list's own position - is what
            # this fix is about. The previous code's
            # "cpu_rows[used_vals.index(...)]" silently returned the
            # WRONG row's timestamp (off by however many per-core rows
            # sorted earlier in the same interval) whenever a real
            # -P ALL capture mixed "all" rows together with per-core
            # ones in the same series, exactly the scenario this
            # function's own comment above already anticipated as a
            # normal, expected case - caught by testing against a
            # synthetic multi-row capture while adding XML sar support,
            # not previously covered by any existing regression check.
            used_pairs = [(round(100.0 - r["%idle"], 2), r["ts"]) for r in all_rows]
            used_vals = [u for u, _ in used_pairs]
            summary["cpu_pct_used_avg"] = round(sum(used_vals) / len(used_vals), 2)
            peak_used, peak_ts = max(used_pairs, key=lambda p: p[0])
            summary["cpu_pct_used_peak"] = round(peak_used, 2)
            summary["cpu_pct_used_peak_ts"] = peak_ts
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

    no_samples_reason = None
    if restart_events_sorted and not all_series:
        # Set only when sar data was genuinely found and read but held NO
        # usable samples at all (see the elif branch above) - lets the
        # digest tell "sysstat was just barely restarted, nothing to show
        # yet" apart from "no sar data in this bundle" without treating
        # both as the identical empty-looking result they'd otherwise be.
        no_samples_reason = (
            f"sar data was found and read, but held no interval samples - only a system restart marker "
            f"at {restart_events_sorted[0]}. The box likely rebooted shortly before this bundle was captured."
        )
        if binary_spool_candidates:
            # Real scenario this was found against: the once-a-day text/
            # XML render only ever captured the reboot marker, but
            # sadc's own binary spool (see docstring above) kept
            # collecting real interval samples all day regardless - worth
            # saying explicitly rather than leaving the impression that
            # NO performance data exists for this system at all.
            no_samples_reason += (
                f" However, {len(binary_spool_candidates)} raw sysstat binary spool file(s) "
                f"({', '.join(binary_spool_candidates[:3])}{', ...' if len(binary_spool_candidates) > 3 else ''}) "
                f"show real samples WERE being collected - ask for `sar -A -f <file>` or "
                f"`sadf -x -- -A -f <file>` run on the original system to see them."
            )

    return {
        "files_parsed": files_parsed,
        "metric_groups_found": sorted(all_series.keys()),
        "sample_points": {g: len(rows) for g, rows in all_series.items()},
        "summary": summary,
        "series": {g: rows[:2000] for g, rows in all_series.items()},
        "vm_timezone": vm_tz,
        "restart_events": restart_events_sorted,
        # Present whenever a binary spool sibling exists alongside
        # whatever text/XML data WAS usable (see docstring above) - even
        # a fully-populated result can still be missing coverage for a
        # later, not-yet-rendered part of the same day.
        "binary_only_spool_files": binary_spool_candidates,
        "no_samples_reason": no_samples_reason,
    }


# --------------------------------------------------------------------------
# v4.14.0: vmcore (kernel crash dump) deep analysis - reads the binary
# vmcore's OWN header/notes directly, with zero dependency on the `crash`
# or `gdb` tools (which additionally need a matching vmlinux+debuginfo for
# the EXACT kernel that crashed - rarely on hand during an initial triage
# pass). This intentionally only extracts what's genuinely available
# without symbol resolution: kernel/OS identification, crash timestamp,
# per-CPU register state at capture time, and dump completeness/format
# metadata - plus, when kdump's own companion dmesg text file is present
# alongside the vmcore (the common case on RHEL/SUSE - both share the same
# upstream kdump initscripts/dracut module that auto-generates one), the
# actual panic backtrace text, which is far more valuable than anything
# derivable from the binary alone.
#
# Every VM can be running a different kernel/OS - this is handled by NEVER
# hardcoding a specific kernel/header version's exact layout: every field
# read past the fixed v1 core is gated behind the vmcore's own
# self-reported header_version (fields were added incrementally in real
# makedumpfile history: vmcoreinfo in v3+, ELF notes in v4+, 64-bit
# pfn/mapnr in v6+), and register DECODING (turning raw bytes into named
# RIP/RSP/... registers) is architecture-gated - only x86_64 is decoded
# today (the only architecture verified against a real file); other
# architectures still get honest structural facts (note count, byte size)
# without pretending to decode registers whose layout hasn't been
# verified.
# --------------------------------------------------------------------------
_KDUMP_SIGNATURE = b"KDUMP   "
_DISKDUMP_SIGNATURE = b"DISKDUMP"  # pre-kdump "diskdump"/netdump-era core - same header struct, older tooling
_ELF_MAGIC = b"\x7fELF"

# makedumpfile's own documented `-d`/dump_level bit meanings (page
# categories EXCLUDED from the dump to shrink it) - sourced from
# makedumpfile's man page / --help text, cross-checked against the real
# customer vmcore's own dump_level=31 (=1+2+4+8+16, i.e. every bit below
# set) which matches RHEL's long-standing default kdump.conf preset.
_DUMP_LEVEL_BITS = [
    (1, "zero pages"), (2, "non-private cache pages"), (4, "private cache pages"),
    (8, "user-process data pages"), (16, "free pages"), (32, "hwpoison pages"),
]

# Compressed-page flags (page_desc_t.flags) - makedumpfile diskdump_mod.h.
_PAGE_COMPRESSION_FLAGS = [
    (0x1, "zlib"), (0x2, "lzo"), (0x4, "snappy"), (0x20, "zstd"),
]

# x86_64 elf_prstatus (linux/elfcore.h) general-register order/offset -
# verified directly against a real vmcore's real NT_PRSTATUS notes
# (produced plausible kernel-space RIP/RSP/CS values, not garbage).
# pr_reg begins at byte 112: 12 (pr_info) + 4 (pr_cursig+pad) + 8
# (pr_sigpend) + 8 (pr_sighold) + 16 (pid/ppid/pgrp/sid) + 64 (4x timeval)
# = 112, followed by 27 unsigned longs.
_PRSTATUS_PR_PID_OFFSET = 32
_PRSTATUS_PR_REG_OFFSET = 112
_PRSTATUS_X86_64_GREGS = [
    "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8",
    "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags",
    "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs",
]

# Kernel-release string -> OS flavor/debuginfo resolution. Ordered most-
# specific first. Every convention below is each vendor's own documented,
# standardized package-naming/versioning scheme (not guessed) - RHEL's
# ".elN[_M]" EUS/z-stream suffix, Fedora's ".fcN", Amazon Linux's
# ".amznN", SUSE's "-<flavor>" kernel-flavor suffix, and Ubuntu/Debian's
# "-<abi>-<flavor>" convention. Only ONE real example (RHEL 8.10 EUS,
# "4.18.0-553.144.1.el8_10.x86_64") has been verified directly against a
# real vmcore this session; the others follow the same public, documented
# conventions but are marked "medium" confidence rather than "high" until
# verified the same way - deliberately honest rather than overclaiming.
_KREL_RHEL_EUS_RE = re.compile(r"^(?P<kver>.+)\.el(?P<major>\d+)_(?P<minor>\d+)\.(?P<arch>\w+)$")
_KREL_RHEL_RE = re.compile(r"^(?P<kver>.+)\.el(?P<major>\d+)\.(?P<arch>\w+)$")
_KREL_FEDORA_RE = re.compile(r"^(?P<kver>.+)\.fc(?P<rel>\d+)\.(?P<arch>\w+)$")
_KREL_AMAZON_RE = re.compile(r"^(?P<kver>.+)\.amzn(?P<major>\d+)\.(?P<arch>\w+)$")
_KREL_SUSE_RE = re.compile(r"^(?P<kver>\d+\.\d+\.\d+)-(?P<build>[\d.]+)-(?P<flavor>default|preempt|azure|kvmsmall|smp|pae)$")
_KREL_UBUNTU_RE = re.compile(r"^(?P<kver>\d+\.\d+\.\d+)-(?P<abi>\d+)-(?P<flavor>generic|lowlatency|aws|azure|gcp|oracle|kvm)$")
_KREL_DEBIAN_RE = re.compile(r"^(?P<kver>\d+\.\d+\.\d+)-(?P<abi>\d+)-(?P<flavor>amd64|arm64|686-pae|i386)$")
_KREL_MAINLINE_RE = re.compile(r"^(?P<kver>\d+\.\d+(?:\.\d+)?)(?:-(?P<rc>rc\d+))?$")


def identify_os_flavor(kernel_release, os_release_hint=None):
    """Best-effort maps a `uname -r`-style kernel release string (as
    embedded in the vmcore's own VMCOREINFO OSRELEASE field) to the exact
    debuginfo package name, install command, vmlinux path convention, and
    repo/channel guidance needed to do FULL symbolic analysis with `crash`
    or `gdb` - directly resolving the "which dependencies do I need"
    question, without requiring the analyst to already know their distro's
    packaging conventions. `os_release_hint` (this bundle's own already-
    extracted /etc/os-release text, when available) is used only to refine
    the human-readable distro NAME - never the package-name math itself,
    since RHEL/CentOS Stream/Rocky Linux/AlmaLinux all share the identical
    ".elN" kernel-release convention and are only distinguishable via
    os-release, not the kernel string alone."""
    if not kernel_release:
        return {"distro_family": "unknown", "confidence": "none",
                "notes": ["No kernel release string available to identify from."]}

    krel = kernel_release.strip()
    os_hint_low = (os_release_hint or "").lower()

    m = _KREL_RHEL_EUS_RE.match(krel) or _KREL_RHEL_RE.match(krel)
    if m:
        g = m.groupdict()
        major = g["major"]
        arch = g["arch"]
        eus_note = f" (EUS/z-stream update {g['minor']})" if "minor" in g and g.get("minor") else ""
        distro_name = "RHEL-family (RHEL / CentOS Stream / Rocky Linux / AlmaLinux)"
        if "red hat" in os_hint_low:
            distro_name = "Red Hat Enterprise Linux"
        elif "rocky" in os_hint_low:
            distro_name = "Rocky Linux"
        elif "alma" in os_hint_low:
            distro_name = "AlmaLinux"
        elif "centos" in os_hint_low:
            distro_name = "CentOS Stream"
        return {
            "distro_family": "rhel", "distro_guess": distro_name + eus_note,
            "major_version": major, "arch": arch, "confidence": "high",
            "package_manager": "dnf" if int(major) >= 8 else "yum",
            "debuginfo_package": f"kernel-debuginfo-{krel}",
            "debuginfo_common_package": f"kernel-debuginfo-common-{arch}-{krel}",
            "debuginfo_install_cmd": f"{'dnf' if int(major) >= 8 else 'yum'} debuginfo-install kernel-{krel}",
            "vmlinux_path": f"/usr/lib/debug/lib/modules/{krel}/vmlinux",
            "repo_hint": ("Red Hat CDN debug repos (rhel-{0}-{1}-baseos-debug-rpms / "
                          "-appstream-debug-rpms), enabled via `subscription-manager repos "
                          "--enable=...`, or https://access.redhat.com/downloads (needs an "
                          "active RHEL subscription). Rocky Linux/AlmaLinux/CentOS Stream "
                          "publish their own free debuginfo mirrors instead.").format(major, arch),
            "notes": ["Verified directly against a real RHEL 8.10 EUS vmcore this session."],
        }

    m = _KREL_FEDORA_RE.match(krel)
    if m:
        g = m.groupdict()
        return {
            "distro_family": "fedora", "distro_guess": f"Fedora {g['rel']}",
            "arch": g["arch"], "confidence": "medium", "package_manager": "dnf",
            "debuginfo_package": f"kernel-debuginfo-{krel}",
            "debuginfo_install_cmd": f"dnf debuginfo-install kernel-{krel}",
            "vmlinux_path": f"/usr/lib/debug/lib/modules/{krel}/vmlinux",
            "repo_hint": "Fedora's public debuginfo repos (enabled by default, no subscription needed).",
            "notes": ["Pattern-matched (Fedora's documented \".fcN\" convention) - not yet verified against a real Fedora vmcore."],
        }

    m = _KREL_AMAZON_RE.match(krel)
    if m:
        g = m.groupdict()
        return {
            "distro_family": "amazon_linux", "distro_guess": f"Amazon Linux {g['major']}",
            "arch": g["arch"], "confidence": "medium", "package_manager": "yum/dnf",
            "debuginfo_package": f"kernel-debuginfo-{krel}",
            "debuginfo_install_cmd": f"yum debuginfo-install kernel-{krel}",
            "vmlinux_path": f"/usr/lib/debug/lib/modules/{krel}/vmlinux",
            "repo_hint": "Amazon Linux's own debuginfo repo (amzn2-core-debuginfo / al2023 equivalent).",
            "notes": ["Pattern-matched (Amazon Linux's documented \".amznN\" convention) - not yet verified against a real Amazon Linux vmcore."],
        }

    m = _KREL_SUSE_RE.match(krel)
    if m:
        g = m.groupdict()
        distro_name = "SUSE Linux Enterprise Server / openSUSE"
        for label in ("suse linux enterprise server", "sles", "opensuse"):
            if label in os_hint_low:
                distro_name = os_release_hint.strip().splitlines()[0][:120] if os_release_hint else distro_name
                break
        return {
            "distro_family": "suse", "distro_guess": distro_name, "flavor": g["flavor"],
            "confidence": "medium", "package_manager": "zypper",
            "debuginfo_package": f"kernel-{g['flavor']}-debuginfo-{g['kver']}-{g['build']}",
            "debuginfo_install_cmd": f"zypper install kernel-{g['flavor']}-debuginfo-{g['kver']}-{g['build']}",
            "vmlinux_path": f"/usr/lib/debug/boot/vmlinux-{g['kver']}-{g['build']}-{g['flavor']}.debug",
            "repo_hint": ("SUSE Customer Center (SCC) Debuginfo module/channel matching your "
                          "exact SLE product + service pack (enable via SUSEConnect or the SCC "
                          "web UI), or openSUSE's debuginfo OBS repos for openSUSE."),
            "notes": ["Pattern-matched (SUSE's documented kernel-flavor suffix convention) - "
                      "not yet verified against a real SUSE vmcore. Exact SP is NOT reliably "
                      "derivable from the kernel string alone - cross-check os_release."],
        }

    m = _KREL_UBUNTU_RE.match(krel)
    if m:
        g = m.groupdict()
        return {
            "distro_family": "ubuntu", "distro_guess": "Ubuntu", "flavor": g["flavor"],
            "confidence": "medium", "package_manager": "apt",
            "debuginfo_package": f"linux-image-{krel}-dbgsym",
            "debuginfo_install_cmd": f"apt install linux-image-{krel}-dbgsym  # after enabling ddebs.ubuntu.com",
            "vmlinux_path": f"/usr/lib/debug/boot/vmlinux-{krel}",
            "repo_hint": "Ubuntu's ddebs.ubuntu.com archive - needs a one-time repo+keyring setup (see wiki.ubuntu.com/Debug Symbol Packages).",
            "notes": ["Pattern-matched (Ubuntu's documented \"-<abi>-<flavor>\" convention) - not yet verified against a real Ubuntu vmcore."],
        }

    m = _KREL_DEBIAN_RE.match(krel)
    if m:
        g = m.groupdict()
        return {
            "distro_family": "debian", "distro_guess": "Debian", "arch": g["flavor"],
            "confidence": "medium", "package_manager": "apt",
            "debuginfo_package": f"linux-image-{krel}-dbg",
            "debuginfo_install_cmd": f"apt install linux-image-{krel}-dbg  # from Debian's debug archive",
            "vmlinux_path": f"/usr/lib/debug/boot/vmlinux-{krel}",
            "repo_hint": "Debian's debug archive (debug.mirrors.debian.org).",
            "notes": ["Pattern-matched (Debian's documented \"-<abi>-<arch>\" convention) - not yet verified against a real Debian vmcore."],
        }

    m = _KREL_MAINLINE_RE.match(krel)
    if m:
        return {
            "distro_family": "mainline", "distro_guess": "Vanilla/mainline kernel.org build",
            "confidence": "low",
            "notes": ["No vendor suffix recognized - this looks like a self-built or "
                      "kernel.org-mainline kernel. There is usually no prebuilt debuginfo "
                      "package; you likely need to rebuild the IDENTICAL kernel source+config "
                      "(with CONFIG_DEBUG_INFO=y) to get a matching vmlinux."],
        }

    return {
        "distro_family": "unknown", "confidence": "none",
        "notes": [f"Kernel release string '{krel}' didn't match any known vendor convention. "
                  "Cross-check /etc/os-release or /etc/*-release captured elsewhere in this "
                  "bundle, and consult the OS vendor's own kernel-debuginfo documentation."],
    }


def _parse_elf_notes(buf):
    """Generic ELF PT_NOTE segment parser (Elf64 note entry format: namesz/
    descsz/type as 3 uint32 LE, name padded to 4-byte alignment, descriptor
    padded to 4-byte alignment) - shared by both the KDUMP-embedded notes
    region and a raw-ELF-format vmcore's own PT_NOTE program header."""
    out = []
    off = 0
    n = len(buf)
    while off + 12 <= n:
        try:
            namesz, descsz, ntype = struct.unpack_from("<III", buf, off)
        except struct.error:
            break
        off += 12
        if namesz == 0 and descsz == 0:
            break
        name = buf[off:off + namesz]
        off += (namesz + 3) & ~3
        desc = buf[off:off + descsz]
        off += (descsz + 3) & ~3
        out.append((name.rstrip(b"\x00"), ntype, desc))
        if off > n:
            break
    return out


def _decode_x86_64_prstatus(desc):
    """Decodes one NT_PRSTATUS note descriptor's general-purpose register
    set for x86_64 - see _PRSTATUS_PR_REG_OFFSET/_PRSTATUS_X86_64_GREGS
    above for the verified offset/order. Returns None if desc is too short
    to safely contain the full register block (defensive - never reads
    past what's actually present)."""
    need = _PRSTATUS_PR_REG_OFFSET + len(_PRSTATUS_X86_64_GREGS) * 8
    if len(desc) < need:
        return None
    pid = struct.unpack_from("<i", desc, _PRSTATUS_PR_PID_OFFSET)[0] if len(desc) >= _PRSTATUS_PR_PID_OFFSET + 4 else None
    regs = struct.unpack_from(f"<{len(_PRSTATUS_X86_64_GREGS)}Q", desc, _PRSTATUS_PR_REG_OFFSET)
    return {"pid": pid, **dict(zip(_PRSTATUS_X86_64_GREGS, regs))}


def _parse_vmcoreinfo_text(blob):
    """Splits a VMCOREINFO NOTE/blob's text into a flat dict on the first
    '=' per line (its own native format - confirmed directly against a
    real vmcore's real VMCOREINFO: 'OSRELEASE=...', 'SYMBOL(x)=...', one
    per line, no other structure)."""
    info = {}
    for line in blob.decode("utf-8", errors="replace").splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            info[k.strip()] = v.strip()
    return info


def _parse_kdump_flattened_vmcore(fpath, signature):
    """Parses the makedumpfile/kdump flattened vmcore format (`KDUMP   ` or
    the older `DISKDUMP` signature - IDENTICAL header struct either way,
    only the tooling generation differs) directly from raw bytes. Every
    field beyond the fixed v1 core is gated by the file's own
    header_version, so a vmcore from an older or newer kdump/makedumpfile
    release than the one this was built against still parses whatever it
    genuinely contains, honestly, rather than assuming today's full v6
    layout applies everywhere. Never needs `crash`/`gdb`/a matching
    vmlinux - this is pure container-format parsing, not symbol
    resolution."""
    result = {"format": "kdump_flattened" if signature == _KDUMP_SIGNATURE else "legacy_diskdump",
              "warnings": []}
    try:
        with open(fpath, "rb") as f:
            head = f.read(512)
            off = 8
            (header_version,) = struct.unpack_from("<i", head, off); off += 4
            result["header_version"] = header_version
            sysname, nodename, release, version, machine, domainname = struct.unpack_from(
                "<65s65s65s65s65s65s", head, off)
            off += 390

            def cstr(b):
                return b.split(b"\x00", 1)[0].decode("utf-8", errors="replace")

            result["kernel_release"] = cstr(release) or None
            result["hostname"] = cstr(nodename) or None
            result["architecture"] = cstr(machine) or None
            result["os_sysname"] = cstr(sysname) or None
            result["kernel_build_version"] = cstr(version) or None

            off += (-off) % 8  # struct timeval is 8-byte aligned (verified against a real file)
            tv_sec, _tv_usec = struct.unpack_from("<qq", head, off); off += 16
            if tv_sec > 0:
                try:
                    result["crash_timestamp_utc"] = datetime.utcfromtimestamp(tv_sec).isoformat() + "Z"
                except (OverflowError, OSError, ValueError):
                    result["warnings"].append("timestamp field present but out of range - not decoded")

            (status, block_size, sub_hdr_size, bitmap_blocks, max_mapnr32, total_ram_blocks,
             device_blocks, written_blocks, current_cpu, nr_cpus) = struct.unpack_from(
                "<IiiIIIIIii", head, off)
            off += 40
            result["dump_status_flags"] = status
            result["nr_cpus"] = nr_cpus
            result["block_size"] = block_size

            if block_size <= 0 or block_size > 1 << 20:
                result["warnings"].append(f"implausible block_size ({block_size}) - header may be corrupt or in an unrecognized variant")
                return result

            if header_version >= 3 and sub_hdr_size > 0:
                sub_off = block_size
                sub_len = sub_hdr_size * block_size
                f.seek(sub_off)
                sub = f.read(min(sub_len, 4096))
                phys_base, dump_level, split, start_pfn, end_pfn = struct.unpack_from("<Qiiqq", sub, 0)
                result["phys_base"] = phys_base
                result["dump_level"] = dump_level
                result["dump_level_excludes"] = [label for bit, label in _DUMP_LEVEL_BITS if dump_level & bit]
                # Computed via calcsize() rather than a hardcoded literal
                # (a hand-counted "24" here previously drifted 8 bytes out
                # of alignment with the preceding struct.unpack_from call
                # above, which actually consumes 32 bytes - Q+i+i+q+q = 
                # 8+4+4+8+8 - silently corrupting every subsequent
                # vmcoreinfo/note offset read; caught by testing directly
                # against a real vmcore rather than trusting the arithmetic).
                soff = struct.calcsize("<Qiiqq")
                if header_version >= 3:
                    offset_vmcoreinfo, size_vmcoreinfo = struct.unpack_from("<qQ", sub, soff)
                    soff += 16
                    if header_version >= 4:
                        offset_note, size_note = struct.unpack_from("<qQ", sub, soff)
                        soff += 16
                    else:
                        offset_note, size_note = 0, 0
                    if 0 < size_vmcoreinfo < 5_000_000 and offset_vmcoreinfo > 0:
                        f.seek(offset_vmcoreinfo)
                        vmcoreinfo_raw = f.read(size_vmcoreinfo)
                        vmcoreinfo = _parse_vmcoreinfo_text(vmcoreinfo_raw)
                        result["vmcoreinfo_found"] = True
                        result["vmcoreinfo_lines_count"] = len(vmcoreinfo)
                        if not result.get("kernel_release") and vmcoreinfo.get("OSRELEASE"):
                            result["kernel_release"] = vmcoreinfo["OSRELEASE"]
                        if vmcoreinfo.get("PAGESIZE"):
                            result["pagesize"] = vmcoreinfo["PAGESIZE"]
                    else:
                        result["vmcoreinfo_found"] = False
                    if 0 < size_note < 5_000_000 and offset_note > 0:
                        f.seek(offset_note)
                        notes_raw = f.read(size_note)
                        notes = _parse_elf_notes(notes_raw)
                        prstatus_notes = [desc for (name, ntype, desc) in notes if ntype == 1]
                        result["notes_found"] = True
                        result["prstatus_cpu_count"] = len(prstatus_notes)
                        arch = (result.get("architecture") or "").lower()
                        if arch == "x86_64":
                            all_decoded = []
                            for i, desc in enumerate(prstatus_notes):
                                dec = _decode_x86_64_prstatus(desc)
                                if dec is not None:
                                    all_decoded.append((i, dec))
                            rip_counts = Counter(dec["rip"] for _i, dec in all_decoded)
                            result["register_decode_supported"] = True
                            result["register_samples"] = [
                                {"cpu_index": i, "pid": dec["pid"],
                                 "rip": f"0x{dec['rip']:016x}", "rsp": f"0x{dec['rsp']:016x}",
                                 "cs": f"0x{dec['cs']:x}", "eflags": f"0x{dec['eflags']:x}"}
                                for i, dec in all_decoded[:16]  # bounded preview - full set rarely needed beyond a sanity check
                            ]
                            result["all_cpus_share_rip"] = len(rip_counts) == 1 if rip_counts else None
                            if result["all_cpus_share_rip"]:
                                result["warnings"].append(
                                    "All sampled CPUs show the IDENTICAL RIP - consistent with "
                                    "every CPU being parked in the same NMI/IPI 'freeze' handler "
                                    "during dump capture, not each CPU's own independent fault "
                                    "location. Identify the ACTUAL faulting/triggering CPU from "
                                    "the dmesg panic line ('CPU: N') instead of these registers.")
                            elif rip_counts:
                                # The common real-world shape (confirmed
                                # directly against a real vmcore): N-1
                                # CPUs share one "parked in the IPI-freeze
                                # handler" RIP while exactly the CPU that
                                # was actually running at panic time shows
                                # a DIFFERENT RIP (and a non-zero pid) -
                                # that CPU is the single most actionable
                                # register-derived fact in the whole dump,
                                # so it's surfaced explicitly rather than
                                # left for a human to spot inside a 64-
                                # entry sample list. majority_rip is
                                # whichever RIP most CPUs share (the
                                # "frozen" location), not assumed to be
                                # index 0's value.
                                majority_rip, majority_count = rip_counts.most_common(1)[0]
                                outliers = [
                                    {"cpu_index": i, "pid": dec["pid"],
                                     "rip": f"0x{dec['rip']:016x}", "rsp": f"0x{dec['rsp']:016x}",
                                     "cs": f"0x{dec['cs']:x}", "eflags": f"0x{dec['eflags']:x}"}
                                    for i, dec in all_decoded if dec["rip"] != majority_rip
                                ]
                                if outliers and majority_count > len(all_decoded) // 2:
                                    result["outlier_cpus"] = outliers[:10]
                                    result["warnings"].append(
                                        f"{majority_count}/{len(all_decoded)} CPUs share one RIP "
                                        "(parked in the IPI/NMI 'freeze' handler during capture) "
                                        f"while {len(outliers)} CPU(s) do not - see outlier_cpus "
                                        "for the likely actual faulting/triggering CPU(s) and "
                                        "their PID at capture time (cross-check against the "
                                        "dmesg panic line's own 'CPU: N' for confirmation).")
                        else:
                            result["register_decode_supported"] = False
                            result["warnings"].append(
                                f"Register decode not implemented for architecture '{arch or 'unknown'}' "
                                "(only x86_64 verified so far) - CPU count/note presence still reported.")
                    else:
                        result["notes_found"] = False
                else:
                    result["warnings"].append(f"header_version={header_version} predates VMCOREINFO support (added in v3) - kernel/OS identified from utsname only.")
            else:
                result["warnings"].append(f"header_version={header_version} has no (or empty) sub-header - limited metadata available.")

            # Best-effort single-page compression sniff (informational -
            # confirms whether THIS dump's page data is actually
            # compressed, and with what, without decompressing the whole
            # multi-hundred-MB body).
            if header_version >= 3 and "phys_base" in result:
                bitmap_off = block_size * (1 + sub_hdr_size)
                bitmap_len = bitmap_blocks * block_size
                page_data_start = bitmap_off + bitmap_len
                try:
                    f.seek(page_data_start)
                    probe = f.read(24)
                    if len(probe) == 24:
                        _off, _size, flags, _pflags = struct.unpack_from("<QIIQ", probe, 0)
                        comp_labels = [label for bit, label in _PAGE_COMPRESSION_FLAGS if flags & bit]
                        result["first_page_compression"] = ", ".join(comp_labels) if comp_labels else "none (raw)"
                except OSError:
                    pass
    except OSError as e:
        result["warnings"].append(f"could not read vmcore file: {e}")
    return result


def _parse_elf_format_vmcore(fpath):
    """Best-effort fallback for a raw ELF-format core (produced by e.g.
    `makedumpfile -E`, `virsh dump --format=elf`, or a hypervisor-level
    memory dump) rather than the makedumpfile flattened KDUMP format. Far
    less structured than the flattened format - no VMCOREINFO offset
    table to rely on, so vmcoreinfo is located by CONTENT (scanning notes
    for one whose descriptor starts with the literal text "OSRELEASE=",
    which is how the kernel always begins its vmcoreinfo buffer - a
    content-based check rather than assuming an unverified note-type
    number). Clearly labeled as lower-confidence than the flattened-format
    path, which is independently confirmed against a real file."""
    result = {"format": "raw_elf", "warnings": ["Raw ELF-format core - only partial metadata "
                                                 "extraction is implemented for this format; "
                                                 "prefer the makedumpfile/kdump flattened format when a choice is available."]}
    try:
        with open(fpath, "rb") as f:
            ehdr = f.read(64)
            if len(ehdr) < 64:
                result["warnings"].append("file too small to be a valid ELF core")
                return result
            ei_class = ehdr[4]  # 1=32-bit, 2=64-bit
            is64 = ei_class == 2
            e_machine = struct.unpack_from("<H", ehdr, 18)[0]
            arch_map = {0x3E: "x86_64", 0xB7: "aarch64", 0x15: "ppc64", 0x16: "s390x"}
            result["architecture"] = arch_map.get(e_machine, f"e_machine=0x{e_machine:x}")
            if not is64:
                result["warnings"].append("32-bit ELF core - not parsed further (no verified real-world 32-bit sample)")
                return result
            e_phoff, = struct.unpack_from("<Q", ehdr, 32)
            e_phentsize, e_phnum = struct.unpack_from("<HH", ehdr, 54)
            f.seek(e_phoff)
            phdrs = f.read(e_phentsize * e_phnum)
            note_segments = []
            for i in range(e_phnum):
                base = i * e_phentsize
                if base + 56 > len(phdrs):
                    break
                p_type, _flags, p_offset, _vaddr, _paddr, p_filesz = struct.unpack_from("<IIQQQQ", phdrs, base)
                if p_type == 4:  # PT_NOTE
                    note_segments.append((p_offset, p_filesz))
            all_notes = []
            for p_offset, p_filesz in note_segments:
                if p_filesz <= 0 or p_filesz > 50_000_000:
                    continue
                f.seek(p_offset)
                all_notes.extend(_parse_elf_notes(f.read(p_filesz)))
            prstatus_notes = [desc for (name, ntype, desc) in all_notes if ntype == 1]
            result["notes_found"] = bool(all_notes)
            result["prstatus_cpu_count"] = len(prstatus_notes)
            vmcoreinfo_desc = next((desc for (_name, _ntype, desc) in all_notes
                                    if desc.startswith(b"OSRELEASE=")), None)
            if vmcoreinfo_desc:
                vmcoreinfo = _parse_vmcoreinfo_text(vmcoreinfo_desc)
                result["vmcoreinfo_found"] = True
                result["kernel_release"] = vmcoreinfo.get("OSRELEASE")
            else:
                result["vmcoreinfo_found"] = False
            if result["architecture"] == "x86_64" and prstatus_notes:
                samples = []
                rips = set()
                for i, desc in enumerate(prstatus_notes[:16]):
                    dec = _decode_x86_64_prstatus(desc)
                    if dec:
                        rips.add(dec["rip"])
                        samples.append({"cpu_index": i, "rip": f"0x{dec['rip']:016x}", "rsp": f"0x{dec['rsp']:016x}"})
                result["register_decode_supported"] = True
                result["register_samples"] = samples
                result["all_cpus_share_rip"] = len(rips) == 1 if rips else None
    except OSError as e:
        result["warnings"].append(f"could not read ELF core file: {e}")
    return result


def analyze_vmcore_file(fpath):
    """Entry point: sniffs the vmcore's own magic bytes and dispatches to
    the matching parser. Returns a plain dict of extracted facts - never
    raises; a genuinely unrecognized/corrupt file yields format:
    "unrecognized" plus a clear reason instead of an exception bubbling
    into the wider analysis run."""
    try:
        with open(fpath, "rb") as f:
            head = f.read(8)
    except OSError as e:
        return {"format": "unreadable", "warnings": [str(e)]}
    if head in (_KDUMP_SIGNATURE, _DISKDUMP_SIGNATURE):
        return _parse_kdump_flattened_vmcore(fpath, head)
    if head[:4] == _ELF_MAGIC:
        return _parse_elf_format_vmcore(fpath)
    return {"format": "unrecognized",
            "warnings": [f"First 8 bytes ({head!r}) don't match a known vmcore format "
                         "(makedumpfile KDUMP/DISKDUMP flattened header, or raw ELF core)."]}


# Companion-file discovery: kdump's own dracut module (shared upstream
# code across RHEL/CentOS/Rocky/Alma/SUSE - all package the same kdump
# initscripts, only Ubuntu's separate kdump-tools reimplementation may
# differ) auto-runs `makedumpfile --dump-dmesg` as the LAST step of saving
# a crash dump, writing an already-decoded plain-text dmesg log right next
# to the vmcore. Confirmed directly against a real capture: the exact
# filename "vmcore-dmesg.txt" sitting in the identical directory as
# "vmcore" itself. Matched generically (not just that exact literal name)
# to be robust to naming variance across kdump versions/distros.
_VMCORE_DMESG_COMPANION_RE = re.compile(r"dmesg", re.IGNORECASE)
_SYSRQ_TEST_CRASH_RE = re.compile(r"sysrq[- ]?triggered crash|SysRq\s*:\s*Trigger a crash", re.IGNORECASE)
_PANIC_START_RE = re.compile(r"Kernel panic|^\s*\S*\s*Oops:|general protection fault", re.IGNORECASE | re.MULTILINE)


def _find_vmcore_companions(inventory, vmcore_relpath):
    """Finds sibling files in the SAME directory as a vmcore whose name
    suggests they're a kdump-produced text companion (dmesg-style log) -
    the highest-value, zero-risk source of crash evidence, since it's
    kdump's OWN human-readable rendering, not a re-derivation."""
    vmcore_dir = vmcore_relpath.rsplit("/", 1)[0] if "/" in vmcore_relpath else ""
    out = []
    for it in inventory:
        p = it["path"]
        p_dir = p.rsplit("/", 1)[0] if "/" in p else ""
        if p_dir != vmcore_dir or p == vmcore_relpath:
            continue
        base = p.rsplit("/", 1)[-1].lower()
        if _VMCORE_DMESG_COMPANION_RE.search(base) and base.endswith((".txt", ".log")):
            out.append(p)
    return out


def check_crash_analysis(root, kind, inventory):
    """Correlates whatever crash/coredump *evidence* is realistically
    available inside a sosreport/supportconfig/crm_report bundle - or a
    bare standalone vmcore upload. Bundles essentially never contain the
    actual (huge) core file's FULL symbolic analysis, since properly
    symbolizing a raw core with `crash`/gdb needs a matching vmlinux +
    debuginfo for the EXACT kernel build that crashed, which is rarely on
    hand during an initial triage pass. What IS realistic and genuinely
    useful, and everything this function extracts without any external
    tool: ABRT's own already-human-readable backtrace, kdump/kexec
    configuration, kdump's OWN already-decoded companion dmesg text log
    when present (the single highest-value, lowest-risk source - see
    _find_vmcore_companions()), and (v4.14.0) the vmcore binary's OWN
    header/notes - kernel/OS identification (working across ANY Linux
    flavor/kernel version via identify_os_flavor()'s vendor-convention
    pattern matching, never hardcoded to one), crash timestamp, and per-
    CPU register state at capture time - all read directly, with zero
    dependency on crash/gdb/vmlinux.
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

    # Exact-basename match (v4.14.0 fix) - the previous substring check
    # ("vmcore" in path) also matched kdump's OWN "vmcore-dmesg.txt" text
    # companion (see below), wrongly listing a 45KB human-readable log as
    # if it were itself a multi-hundred-MB binary core dump. "vmcore",
    # "vmcore.1", "vmcore2" etc. (seen on systems with multiple/indexed
    # crash captures) still match; "vmcore-dmesg.txt"/"vmcore.log" no
    # longer do.
    _vmcore_basename_re = re.compile(r"^vmcore\.?\d*$", re.IGNORECASE)
    vmcores = [{"path": it["path"], "size": it["size"], "size_human": human_size(it["size"])}
               for it in inventory
               if it["size"] > 0 and _vmcore_basename_re.match(it["path"].rsplit("/", 1)[-1])]
    if vmcores:
        result["vmcore_files"] = vmcores

        # Light-weight, bounded os-release lookup purely to REFINE the
        # human-readable distro name identify_os_flavor() reports (RHEL
        # vs Rocky vs Alma vs CentOS Stream all share the identical
        # kernel-release convention and are only distinguishable this
        # way) - never used for the package-name math itself.
        os_release_text = ""
        if kind == "sosreport":
            for relp in find_inventory(inventory, "etc/os-release", "etc/redhat-release", "etc/system-release"):
                os_release_text = get_text(root, relp, 4000)
                if os_release_text.strip():
                    break
        elif kind == "supportconfig":
            for relp in find_inventory(inventory, "basic-environment.txt"):
                t = get_text(root, relp, 300000)
                sec = extract_supportconfig_section(t, "os-release", "suse-release")
                if sec:
                    os_release_text = "\n".join(sec)
                    break

        vmcore_analyses = []
        for v in vmcores[:5]:  # bounded - multiple vmcores in one bundle is rare, but never unbounded work
            full_path = root / v["path"]
            analysis = analyze_vmcore_file(full_path)
            analysis["path"] = v["path"]
            analysis["size_human"] = v["size_human"]
            if analysis.get("kernel_release"):
                analysis["os_flavor"] = identify_os_flavor(analysis["kernel_release"], os_release_text)
            companions = _find_vmcore_companions(inventory, v["path"])
            if companions:
                # Content-based selection (consistent with this project's
                # established preference elsewhere - e.g. compression
                # sniffing by magic bytes, not extension): try EVERY
                # companion for an actual panic/oops marker and pick the
                # first one that has it, rather than just companions[0].
                # Confirmed necessary by testing against a real capture
                # with TWO companions side by side - kdump's own
                # "kexec-dmesg.log" (the CRASH kernel's OWN boot log,
                # sorts alphabetically first, never contains the original
                # panic) and "vmcore-dmesg.txt" (the ORIGINAL system's
                # actual panic backtrace) - picking purely by inventory
                # order silently surfaced the wrong, less useful file.
                chosen_relp, chosen_text, chosen_panic_m = None, "", None
                for cand_relp in companions:
                    cand_text = get_text(root, cand_relp, 2_000_000)
                    cand_m = _PANIC_START_RE.search(cand_text)
                    if cand_m:
                        chosen_relp, chosen_text, chosen_panic_m = cand_relp, cand_text, cand_m
                        break
                if chosen_relp is None:  # none had an explicit marker - fall back to the first companion's tail
                    chosen_relp = companions[0]
                    chosen_text = get_text(root, chosen_relp, 2_000_000)
                comp_entry = {"path": chosen_relp}
                if len(companions) > 1:
                    comp_entry["other_companions"] = [c for c in companions if c != chosen_relp]
                sysrq_m = _SYSRQ_TEST_CRASH_RE.search(chosen_text)
                comp_entry["is_sysrq_test_crash"] = bool(sysrq_m)
                if chosen_panic_m:
                    comp_entry["panic_excerpt"] = chosen_text[chosen_panic_m.start():chosen_panic_m.start() + 4000].strip()
                else:
                    # Defensive fallback for a companion file that doesn't
                    # contain an obvious panic/oops marker anywhere -
                    # still surface the tail, since that's almost always
                    # where the actionable content is in a boot+runtime
                    # dmesg capture.
                    tail_lines = [ln for ln in chosen_text.splitlines() if ln.strip()][-80:]
                    comp_entry["tail_lines"] = "\n".join(tail_lines)[:4000]
                analysis["dmesg_companion"] = comp_entry
            vmcore_analyses.append(analysis)
        result["vmcore_analysis"] = vmcore_analyses

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
        # basic-environment.txt does NOT always carry a dedicated
        # "/bin/hostname" section - confirmed against a real, freshly
        # captured SLES15 supportconfig bundle where that section is
        # simply absent (only /bin/date, /bin/uname -a, and
        # /etc/os-release appear there). Without a fallback, info["hostname"]
        # silently stays unset, which is a real, live redaction gap: this
        # analysis never learns the box's real hostname, so
        # collect_known_hostnames() (backend/ai/redaction.py) has nothing
        # to redact - even though the SAME hostname routinely appears
        # verbatim in messages.txt/boot.txt/shell_history.txt/etc. and
        # gets quoted straight into the AI prompt. systemd.txt's
        # "hostnamectl status" output ("Static hostname: <name>") is a
        # second, independent place supportconfig always captures the
        # short hostname, and is tried whenever the primary source found
        # nothing.
        if not info.get("hostname"):
            for relp in find_inventory(inventory, "systemd.txt", "systemd-status.txt"):
                t = get_text(root, relp, 300000)
                sec = extract_supportconfig_section(t, "hostnamectl")
                sec_text = "\n".join(sec)
                m = re.search(r"Static hostname:\s*(\S+)", sec_text)
                if m:
                    info["hostname"] = m.group(1).strip()[:300]
                    break
        # supportconfig's own summary.xml carries the FULL FQDN
        # (<hostname>...</hostname>) in a dedicated, structured field -
        # confirmed against the same real bundle to hold the complete
        # "shorthost.<random-cloud-subdomain>.<domain>" form. This is
        # captured as a DISTINCT fact (not merged into "hostname" above)
        # because collect_known_hostnames() needs both the short label
        # and the full FQDN as separate known strings: redacting only the
        # short label would still leave the (potentially just as
        # identifying) random cloud-subdomain suffix exposed verbatim in
        # any report that happens to quote the full FQDN.
        for relp in find_inventory(inventory, "summary.xml"):
            t = get_text(root, relp, 50000)
            m = re.search(r"<hostname>([^<]+)</hostname>", t)
            if m:
                fqdn = m.group(1).strip()
                if fqdn and fqdn.lower() != "localhost":
                    info["hostname_fqdn"] = fqdn[:300]
                break
    return info


_LINK_SUMMARY_MAX_EXAMPLES = 50  # bounded so a pathological bundle (e.g. thousands of broken links) can't blow up facts.json


def check_link_summary(root, links):
    """Summarizes the raw symlink/hardlink metadata safe_extract_tar()/
    safe_extract_zip() tracked during extraction (as of v4.12.0) - see
    those functions' docstrings for why this exists at all: on this
    tool's own Windows runtime, a link's CONTENT was already correctly
    readable via tarfile's built-in target-copy fallback even before
    this version, but there was previously zero record that a given
    path was ever a link rather than an ordinary file.

    Classifies each link's real, ON-DISK extraction outcome directly
    (by checking `root / link["name"]` after extraction has already
    happened) rather than trying to re-derive it from the archive's own
    recorded target-path string - a real, two-part gap found by testing
    directly against a real sosreport's 1,064 real symlinks:
      - Many real symlinks point at DIRECTORIES, not files (e.g.
        "sys/block/sdb" -> a `/sys` device subtree, "etc/yum/vars" ->
        "../dnf/vars") - tarfile's fallback correctly creates a real
        directory for these, which a naive file-content check would
        never account for.
      - A symlink whose target isn't captured by sosreport/supportconfig
        AT ALL (e.g. "etc/mtab" -> "../proc/self/mounts", or a service
        override pointing at "/dev/null") extracts with NO error raised
        at all, yet nothing lands on disk - tarfile silently no-ops
        rather than raising, so this can't be told apart from a genuine
        extraction failure by exception-catching alone; a direct
        filesystem check afterward is what actually reveals it.
    None of this is framed as "broken" - a symlink whose target isn't
    part of THIS bundle (whether because it resolved to a directory
    build_inventory() correctly never lists, or a path this collector
    simply never captures, like most of `/proc`/`/dev`) is the ordinary,
    expected case, not a sign of a problem on the source system, which
    this tool has no visibility into either way.

    Returns {} (not an error) when `links` is empty - the common case
    for supportconfig (SUSE's collector produced zero symlinks in the
    real bundle this was verified against) and not unusual for
    sosreport either when the archive extractor found none.

    Two DIFFERENT "content unavailable" cases are deliberately kept
    separate, not merged into one count, since they have very different
    severity:
      - `extraction_errors` - the copy-fallback itself raised an
        exception (rare - e.g. a still-uncooperative Windows path even
        after `_windows_safe_member_name()` sanitization). Genuinely
        actionable: this path's content is truly unavailable to this
        analysis, unlike every other link.
      - `target_not_captured` - extraction reported success (no
        exception - tarfile silently no-ops rather than raising when a
        link's target isn't found among the archive's own members) but
        nothing landed on disk. This is the ORDINARY, EXPECTED case for
        a large fraction of real symlinks (most collectors don't grab
        `/proc`/`/dev` contents, or arbitrary system libraries a
        symlink might point at) - informational only, not a sign of a
        problem on the source system.
    """
    if not links:
        return {}
    result = {
        "symlink_count": sum(1 for l in links if l["type"] == "symlink"),
        "hardlink_count": sum(1 for l in links if l["type"] == "hardlink"),
    }
    resolved_as_file = resolved_as_dir = 0
    extraction_errors = []
    target_not_captured = []
    for l in links:
        p = root / l["name"]
        if p.is_file():
            resolved_as_file += 1
        elif p.is_dir():
            resolved_as_dir += 1
        elif not l["extracted"]:
            extraction_errors.append({"path": l["name"], "type": l["type"], "target": l.get("target"), "error": l["error"]})
        else:
            target_not_captured.append({"path": l["name"], "type": l["type"], "target": l.get("target")})
    result["resolved_as_file"] = resolved_as_file
    result["resolved_as_directory"] = resolved_as_dir
    if extraction_errors:
        result["extraction_errors"] = extraction_errors[:_LINK_SUMMARY_MAX_EXAMPLES]
        if len(extraction_errors) > _LINK_SUMMARY_MAX_EXAMPLES:
            result["extraction_errors_truncated"] = True
    if target_not_captured:
        result["target_not_captured_count"] = len(target_not_captured)
        result["target_not_captured_examples"] = target_not_captured[:_LINK_SUMMARY_MAX_EXAMPLES]
    return result


_HOSTNAME_SNIFF_MAX_FILES = 30          # bounded sample - cheap even on a 90,000+-file bundle
_HOSTNAME_SNIFF_MAX_BYTES_PER_FILE = 100_000
_HOSTNAME_SNIFF_MAX_LINES_PER_FILE = 300
_HOSTNAME_SNIFF_MIN_OCCURRENCES = 3     # a real host's identifier repeats on nearly every
# line of a real log; requiring several identical repeats before trusting a
# candidate is what makes this high-precision without needing any allow-list
# to start from - a one-off coincidental token match doesn't repeat this way.
_HOSTNAME_SNIFF_MAX_CANDIDATES = 10
_HOSTNAME_SNIFF_EXCLUDE = {"localhost", "localhost.localdomain"}

# Classic rsyslog "traditional" line format (the near-universal default) is
# "<Mon> <DD> <HH:MM:SS> <hostname> <program>[<pid>]: <message>" - or the
# same shape with an RFC3339/ISO8601 timestamp instead, common on
# journald-exported logs. Requires the THIRD field too (a program token,
# optionally "name[pid]:") so a 2-field "<timestamp> <program>: <message>"
# line (hostname omitted from the format - some minimal/local-only syslog
# configs do this) can't be mistaken for a 3-field line with the program
# name misread as the hostname.
_SYSLOG_HOSTNAME_LINE_RE = re.compile(
    r"^(?:[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    r"|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"\s+([A-Za-z0-9][A-Za-z0-9._-]{0,63})\s+\S+?(?:\[\d+\])?:"
)

# A hostname ending in a run of digits (e.g. "ue2op1dbsp01") has a SIBLING
# with the identical prefix and a different digit run (e.g. "ue2op1dbsp02")
# with extremely high likelihood in HA-cluster contexts specifically - this
# prefix+incrementing-node-number convention is close to universal for
# cluster peers (web01/web02, nodeA1/nodeA2, ...). Unlike the syslog
# hostname FIELD (which only ever shows the LOCAL machine writing its own
# log - never a remote peer), a peer's name legitimately appears only in
# free-text MESSAGE content (corosync membership notices, pacemaker
# fencing/STONITH messages, e.g. "Node ue2op1dbsp02 is now member" or
# "Peer ue2op1dbsp02 is confirmed fenced") - trying to hand-write regexes
# for every real Pacemaker/corosync message wording risks being both
# brittle (misses unanticipated exact phrasings) and still imprecise.
# Instead, once a hostname is ALREADY confirmed via the high-confidence
# syslog-field frequency gate above, searching the SAME already-sampled
# text for other tokens sharing its exact prefix is a much more targeted,
# domain-appropriate heuristic that needs just ONE occurrence to trust,
# since an accidental unrelated token happening to share a real hostname's
# exact multi-character prefix immediately followed by digits is very
# unlikely by chance.
_HOSTNAME_TRAILING_DIGITS_RE = re.compile(r"^(.*?)(\d+)$")


def _find_hostname_siblings(confirmed_hostnames, sampled_text):
    siblings = set()
    for host in confirmed_hostnames:
        m = _HOSTNAME_TRAILING_DIGITS_RE.match(host)
        if not m:
            continue
        prefix, _digits = m.group(1), m.group(2)
        if not prefix:
            continue
        sibling_re = re.compile(r"(?<![A-Za-z0-9_-])" + re.escape(prefix) + r"(\d+)(?![A-Za-z0-9_-])")
        for sm in sibling_re.finditer(sampled_text):
            candidate = prefix + sm.group(1)
            if candidate != host:
                siblings.add(candidate)
    return siblings


def sniff_syslog_hostnames(root, inventory):
    """Generic, content-based hostname-detection fallback that works
    regardless of bundle 'kind' - closes a real gap found from a live
    customer bundle: a raw copy of /var/log has none of the dedicated
    system-info files (sos_commands/, installed-rpms, basic-
    environment.txt) that check_system_info()/check_cluster_health()
    read, so detect_type() correctly classifies it as kind="unknown" -
    but that ALSO meant collect_known_hostnames()
    (backend/ai/redaction.py) had ZERO input to work with, so hostname
    redaction was a complete no-op even though the real hostnames
    appeared in nearly every line of the bundle's own pacemaker/
    corosync logs - exactly the identifiers that then leaked,
    unredacted, into a real AI-generated report.

    Two complementary tiers:
    1. The classic rsyslog line format embeds the LOCAL machine's own
       hostname as the field immediately after the timestamp (see
       _SYSLOG_HOSTNAME_LINE_RE) - this samples a bounded set of
       candidate log-like files (capped in count/bytes/lines; a fixed,
       small cost even on a 90,000+-file bundle, since this is a
       SAMPLE, not a full scan) and tallies how often each candidate
       token repeats identically in that position. Only a candidate
       that repeats at least _HOSTNAME_SNIFF_MIN_OCCURRENCES times is
       trusted - a real host's identifier repeats on nearly every line
       of a real log, while a coincidental one-off match doesn't, so
       this stays high-precision without needing to already know what
       a valid hostname looks like. This tier only ever finds the LOCAL
       host (the one that wrote this log) - never a remote peer.
    2. A cluster PEER's hostname (e.g. the other node in a 2-node HA
       pair) legitimately appears only in free-text message content
       (corosync membership notices, pacemaker fencing/STONITH
       messages), never in the syslog hostname field of THIS node's own
       log. _find_hostname_siblings() catches this common case via the
       near-universal HA-cluster "shared prefix + incrementing node
       number" naming convention (e.g. ue2op1dbsp01/ue2op1dbsp02) - once
       tier 1 confirms one such hostname, any other token sharing its
       exact prefix elsewhere in the same sampled text is trusted with
       just one occurrence, since the shared multi-character prefix
       match already makes an accidental false positive very unlikely.

    Also valuable as a supplementary source even for sosreport/
    supportconfig/crm_report bundles (where system_info.hostname/
    cluster_health.nodes_detected usually already cover the LOCAL
    host) - both tiers here can additionally surface a cluster peer's
    hostname that neither of those existing sources tracks.
    Deliberately unconditional (not gated by kind) for exactly this
    reason - see run_structured_checks()."""
    candidates = Counter()
    sampled_text_parts = []
    files_sampled = 0

    def _priority(item):
        # Prefer paths that look log-ish, then larger files first (more
        # lines sampled per file = higher chance of hitting the pattern
        # at all, and a substantial ongoing log is more likely to be
        # genuinely representative than a tiny one-off snapshot file).
        return (0 if "log" in item["path"].lower() else 1, -item["size"])

    for item in sorted(inventory, key=_priority):
        if files_sampled >= _HOSTNAME_SNIFF_MAX_FILES:
            break
        if item["size"] <= 0:
            continue
        fpath = root / item["path"]
        readability, _compression_kind = classify_file_readability(fpath)
        if readability == "skip":
            continue
        text = get_text(root, item["path"], _HOSTNAME_SNIFF_MAX_BYTES_PER_FILE)
        if not text:
            continue
        files_sampled += 1
        sampled_text_parts.append(text)
        for line in text.splitlines()[:_HOSTNAME_SNIFF_MAX_LINES_PER_FILE]:
            m = _SYSLOG_HOSTNAME_LINE_RE.match(line)
            if m:
                candidates[m.group(1)] += 1

    trusted = {
        name for name, count in candidates.most_common(_HOSTNAME_SNIFF_MAX_CANDIDATES)
        if count >= _HOSTNAME_SNIFF_MIN_OCCURRENCES and name.lower() not in _HOSTNAME_SNIFF_EXCLUDE
    }
    if trusted:
        trusted |= _find_hostname_siblings(trusted, "\n".join(sampled_text_parts))
    return sorted(trusted)


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


def run_structured_checks(root, kind, inventory, links=None):
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
        # Only ever non-empty when the archive extractor tracked link
        # metadata (see safe_extract_tar()/safe_extract_zip()'s `links`
        # return value) - a directory input (user already had it
        # extracted) has no equivalent tracking, so this is correctly
        # {} in that case too.
        facts["link_summary"] = check_link_summary(root, links or [])
    except Exception as e:
        facts["link_summary_error"] = str(e)
    try:
        # Unconditional (not gated by kind, unlike cluster_health below) -
        # this is a fallback/supplementary hostname source that matters
        # MOST precisely for bundles check_system_info() has no dedicated
        # file-based lookup for (kind="unknown", e.g. a raw /var/log copy
        # with no sos_commands/basic-environment.txt), but it can also
        # pick up a cluster PEER's hostname mentioned only in this node's
        # own logs for any kind - see sniff_syslog_hostnames()'s docstring.
        # Feeds collect_known_hostnames() (backend/ai/redaction.py), which
        # is what closes a real gap: hostname redaction was previously a
        # complete no-op for kind="unknown" bundles, since it had no
        # allow-list to work from at all.
        facts["detected_hostnames_from_logs"] = sniff_syslog_hostnames(root, inventory)
    except Exception as e:
        facts["detected_hostnames_from_logs_error"] = str(e)
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
    link_summary_hdr = facts.get("link_summary") or {}
    if link_summary_hdr.get("symlink_count") or link_summary_hdr.get("hardlink_count"):
        link_bits = []
        if link_summary_hdr.get("symlink_count"):
            link_bits.append(f"{link_summary_hdr['symlink_count']:,} symlink(s)")
        if link_summary_hdr.get("hardlink_count"):
            link_bits.append(f"{link_summary_hdr['hardlink_count']:,} hardlink(s)")
        fail_note = ""
        if link_summary_hdr.get("extraction_errors"):
            fail_note = f" — ⚠️ {len(link_summary_hdr['extraction_errors'])} failed to extract, see facts.json → link_summary.extraction_errors"
        lines.append(f"- **Symlinks/hardlinks in bundle:** {', '.join(link_bits)}{fail_note}")
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
    link_summary = facts.get("link_summary") or {}
    if link_summary.get("extraction_errors"):
        any_fact = True
        n = len(link_summary["extraction_errors"])
        lines.append(f"- ⚠️ **{n} symlink(s)/hardlink(s) failed to extract** — their content is genuinely unavailable to this analysis (unlike every other link in this bundle, whose content was still captured correctly); see `facts.json` → `link_summary.extraction_errors` for the exact paths/reasons.")
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
    if _section_on("sar") and (sar.get("summary") or sar.get("metric_groups_found") or sar.get("restart_events") or sar.get("no_samples_reason") or sar.get("binary_only_spool_files")):
        lines.append("## 📊 Performance (SAR)")
        vm_tz = sar.get("vm_timezone")
        if vm_tz:
            lines.append(f"_Timestamps below are VM-local time, as printed by `sar` on the analyzed host: **{vm_tz['label']}**. Keep this in mind when correlating with your own clock or the customer's stated incident time._")
        else:
            lines.append("_The analyzed host's timezone could not be determined from this bundle - timestamps below are shown exactly as `sar` printed them (VM-local wall clock, zone unknown). Confirm the VM's zone with the customer before correlating against externally-reported incident times._")
        lines.append("")
        if sar.get("no_samples_reason"):
            lines.append(f"- ℹ️ **{sar['no_samples_reason']}**")
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
        if sar.get("restart_events"):
            lines.append(f"- 🔄 **System restart(s) noted directly by sar/sadc:** {', '.join(sar['restart_events'])} — an independent corroboration of reboot timing alongside any `last -F`/journal/dmesg evidence elsewhere in this report.")
        if sar.get("metric_groups_found"):
            lines.append(f"- **Data points parsed:** {sum(sar.get('sample_points', {}).values())} across {len(sar.get('files_parsed', []))} file(s); metric groups found: {', '.join(sar.get('metric_groups_found', [])) or 'none'}")
            lines.append("- _Full time series available in `facts.json` → `sar_performance.series` for graphing (CPU/memory/disk/network/load, each timestamped in VM-local time)._")
        if sar.get("binary_only_spool_files") and not sar.get("no_samples_reason"):
            # Only shown standalone when NOT already folded into
            # no_samples_reason above (that already covers this same
            # information with more context in the fully-empty case) -
            # this is the "some text data parsed fine, but a binary
            # sibling covering a different time range is still
            # un-rendered" case.
            lines.append(f"- ℹ️ **{len(sar['binary_only_spool_files'])} additional raw sysstat binary spool file(s) found** that couldn't be decoded directly (`{', '.join(sar['binary_only_spool_files'][:3])}`{', ...' if len(sar['binary_only_spool_files']) > 3 else ''}) - ask for `sar -A -f <file>` output from the original system if this analysis needs a time range not already covered above.")
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
        for va in crash.get("vmcore_analysis", []) or []:
            fmt = va.get("format", "unrecognized")
            if fmt == "unrecognized" or fmt == "unreadable":
                lines.append(f"  - `{va.get('path')}`: format not recognized ({'; '.join(va.get('warnings', []))})")
                continue
            lines.append(f"  - **`{va.get('path')}` ({fmt}{', header v' + str(va['header_version']) if va.get('header_version') is not None else ''}):**")
            if va.get("kernel_release"):
                lines.append(f"    - Kernel: `{va['kernel_release']}` on `{va.get('architecture', '?')}`" + (f", host `{va['hostname']}`" if va.get("hostname") else ""))
            if va.get("crash_timestamp_utc"):
                lines.append(f"    - Crash captured at: **{va['crash_timestamp_utc']}**")
            if va.get("nr_cpus"):
                lines.append(f"    - CPUs: {va['nr_cpus']}" + (f" ({va['prstatus_cpu_count']} register snapshots captured)" if va.get("prstatus_cpu_count") else ""))
            if va.get("dump_level_excludes"):
                lines.append(f"    - Dump excludes: {', '.join(va['dump_level_excludes'])} (level {va.get('dump_level')}) — smaller file, but some page categories aren't present")
            comp = va.get("dmesg_companion")
            if comp:
                if comp.get("is_sysrq_test_crash"):
                    lines.append(f"    - 🧪 **This was a manually-triggered TEST crash** (`sysrq-trigger`), not an organic kernel failure — confirmed from `{comp['path']}`. Common practice to validate kdump capture itself; treat accordingly, not as a production bug.")
                if comp.get("panic_excerpt"):
                    lines.append(f"    - 📋 **Panic excerpt from `{comp['path']}`:**")
                    lines.append("      ```")
                    for ln in comp["panic_excerpt"].splitlines()[:40]:
                        lines.append(f"      {ln}")
                    lines.append("      ```")
                elif comp.get("tail_lines"):
                    lines.append(f"    - 📋 **Last lines of `{comp['path']}`** (no explicit panic/oops marker found):")
                    lines.append("      ```")
                    for ln in comp["tail_lines"].splitlines()[:40]:
                        lines.append(f"      {ln}")
                    lines.append("      ```")
            else:
                lines.append("    - ℹ️ No companion dmesg text log (e.g. `vmcore-dmesg.txt`) found alongside this vmcore — only binary-header metadata is available. If re-collecting, kdump normally writes one automatically in the same directory.")
            if va.get("all_cpus_share_rip"):
                lines.append("    - ⚠️ All sampled CPUs' registers show the identical RIP — that's expected NMI/IPI-freeze behavior during capture, not each CPU's own fault site. Use the dmesg panic line's own `CPU: N` to identify the actual faulting/triggering CPU.")
            if va.get("outlier_cpus"):
                lines.append(f"    - 🎯 **Likely faulting/triggering CPU(s) identified from register state:** {len(va['outlier_cpus'])} CPU(s) show a DIFFERENT RIP than the rest (who are all parked in the same IPI/NMI freeze handler) — the single most actionable register fact in this dump:")
                for oc in va["outlier_cpus"][:5]:
                    lines.append(f"      - CPU index {oc['cpu_index']}, PID {oc['pid']}, RIP `{oc['rip']}`, RSP `{oc['rsp']}` — cross-check against dmesg's own `CPU: {oc['cpu_index']}` line and `ps`/process listing for PID {oc['pid']}")
            flavor = va.get("os_flavor")
            if flavor and flavor.get("distro_family") not in (None, "unknown"):
                lines.append(f"    - **Dependency resolution ({flavor.get('confidence')} confidence):** {flavor.get('distro_guess', '?')}")
                if flavor.get("debuginfo_install_cmd"):
                    lines.append(f"      - Install matching debug symbols: `{flavor['debuginfo_install_cmd']}`")
                if flavor.get("vmlinux_path"):
                    lines.append(f"      - Expected vmlinux path: `{flavor['vmlinux_path']}`")
                if flavor.get("repo_hint"):
                    lines.append(f"      - Repo/channel: {flavor['repo_hint']}")
                lines.append(f"      - Then analyze with: `crash {flavor.get('vmlinux_path', '<vmlinux>')} {va.get('path')}`")
            elif flavor:
                for note in flavor.get("notes", []):
                    lines.append(f"    - ℹ️ {note}")
            for w in va.get("warnings", []):
                lines.append(f"    - ℹ️ {w}")
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
_DEFAULT_MAX_WORKERS = 16  # ceiling for AUTO-DETECTION only (an explicit
# user-requested worker count is handled separately below, capped by
# _ABSOLUTE_MAX_WORKERS instead) - beyond this, per-worker overhead
# (process startup, result-merging) and disk I/O contention dominate any
# further gain for a typical CPU-bound scan; also keeps a huge-core-count
# shared VM from being monopolized by one analysis job by default. Raised
# from 8 (v4.9.0) to 16 (v4.9.1) to better fit real multi-core support
# VMs without requiring a manual override for the common case.
_ABSOLUTE_MAX_WORKERS = 128  # sanity ceiling applied ONLY to an EXPLICIT
# user-requested worker count (never to auto-detection) - prevents an
# obvious typo/misunderstanding from spawning an unreasonable number of
# processes, while still letting an informed user genuinely test
# oversubscription (more workers than CPU cores) up to a generous,
# explicitly-chosen ceiling matching the highest option in the UI
# dropdown. Deliberately NOT capped at this machine's CPU count the way
# auto-detection is - oversubscription can genuinely help an I/O-wait-
# dominated workload (e.g. many small files under real-time antivirus/
# EDR scanning overhead, directly observed to add meaningful per-file
# latency on at least one real deployment) even though it doesn't help
# (and can mildly hurt, via context-switch overhead) a CPU-bound one
# (regex-heavy scanning of a few huge files) - since which shape a given
# bundle is can't be known in advance, this is offered as an informed,
# explicit choice rather than something auto-detection would ever pick.
_MIN_FILES_FOR_PARALLEL = 300      # below this, sequential is already fast
_MIN_BYTES_FOR_PARALLEL = 20 * 1024 * 1024  # 20MB - ditto
_EST_MB_PER_WORKER = 300  # conservative per-worker memory budget used to
# cap worker count on a memory-constrained VM - covers the Python
# interpreter + compiled regex tables + one file's decompression buffers
# + that worker's share of accumulated findings; deliberately generous
# rather than tightly tuned, since under-provisioning workers just costs
# some speed, while over-provisioning them risks the VM's memory pressure.
_CHUNKS_PER_WORKER = 6  # v4.9.1: submit this many times MORE work chunks
# than worker processes, instead of exactly one large chunk per worker -
# this is the actual fix for a real, directly-observed gap: with exactly
# one static chunk per worker, a worker whose chunk happens to contain a
# disproportionately large file (LPT partitioning balances by total
# BYTES, but real scan cost isn't perfectly proportional to bytes alone -
# regex-match density varies by content) becomes a "straggler" that runs
# long after every other worker has already finished and exited, leaving
# those other CPU cores sitting completely idle for the remainder of the
# run even though the whole machine has spare capacity. Submitting many
# more, smaller chunks than there are workers means concurrent.futures'
# OWN internal task queue - not any custom scheduler - hands a newly-free
# worker the next pending chunk immediately, so all cores stay busy until
# the very last chunk is done, not just until each worker's own single
# fixed assignment happens to run out.
_MIN_ITEMS_PER_CHUNK = 3  # keeps a very high explicit worker request
# (e.g. 128) on a modest-sized bundle from fragmenting into an excessive
# number of near-empty chunks, each paying its own process-call/IPC
# round-trip overhead for almost no actual scanning work.


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
    pass. requested_workers overrides auto-detection entirely when given:
      - 1 forces the original single-process sequential path;
      - any other positive int is used AS-IS (an explicit request is
        trusted over any heuristic), capped only by the generous
        _ABSOLUTE_MAX_WORKERS sanity ceiling - deliberately NOT capped
        at this machine's CPU count, unlike auto-detection below, since
        oversubscription (more workers than cores) can genuinely help
        an I/O-wait-dominated workload (e.g. many small files under
        real-time antivirus/EDR scanning overhead) even though it won't
        help - and can mildly hurt - a CPU-bound one. Which shape a
        given bundle is can't be known in advance, so a higher explicit
        request is honored rather than silently clamped back down to
        "whatever this machine happens to have," which would make
        offering those higher choices in the UI pointless.
    None (the default) auto-detects from:
      - CPU count (os.cpu_count()) - the hard upper bound here (but NOT
        for an explicit request above), since more worker processes
        than cores cannot run truly concurrently for CPU-bound work,
        which is the safe assumption for an unspecified bundle;
      - available memory / _EST_MB_PER_WORKER - a soft cap so a
        memory-constrained VM doesn't get oversubscribed;
      - bundle size - below _MIN_FILES_FOR_PARALLEL/_MIN_BYTES_FOR_PARALLEL,
        returns 1 unconditionally, since process-pool startup overhead
        would outweigh any benefit on a small bundle;
      - _DEFAULT_MAX_WORKERS - a ceiling regardless of how many
        cores/memory are available (see constant comment above).
    Always returns at least 1.
    """
    if requested_workers is not None:
        try:
            requested_workers = int(requested_workers)
        except (TypeError, ValueError):
            requested_workers = None
    if requested_workers is not None and requested_workers >= 1:
        return max(1, min(requested_workers, _ABSOLUTE_MAX_WORKERS))

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


def _scan_batch(root, kind, batch, window_start, window_end, max_examples, year_hint, worker_idx=None, progress_queue=None):
    """Worker-process entry point (must stay a plain top-level function -
    picklability across the process boundary depends on it). Scans every
    item in `batch` (a list of (relpath, category, compression_kind,
    size) tuples) into a fresh, self-contained ctx local to this call -
    no state is shared with the main process or other workers, so this
    needs zero locking. Reuses scan_file() completely unchanged; the only
    difference from the sequential path is that each worker gets its OWN
    ctx instead of all files sharing one - _merge_scan_contexts() below
    combines them back into a single result afterward.

    worker_idx/progress_queue (v4.9.1) let this batch report its own
    live progress back to the main process while it's STILL RUNNING -
    not just once the whole batch completes. This matters because a
    single batch can legitimately take many minutes on a real bundle (a
    batch with a share of several 100MB+ rotated logs, for example) -
    without this, the only feedback during that whole stretch was
    silence, which is easy to mistake for a hang. progress_queue is a
    multiprocessing.Manager().Queue(), safely shareable across the
    process boundary on both the "spawn" (Windows) and "fork"
    (Linux/macOS) start methods. Both parameters are optional and default
    to a no-op so this function still works exactly as before when
    called directly (e.g. by tests) without them - and any failure to
    report progress (a queue hiccup, the Manager process being briefly
    unavailable) is swallowed silently rather than ever risking the
    actual scan itself.

    NOTE (v4.9.1): despite the parameter name, worker_idx is really a
    CHUNK index, not a 1:1 worker-process index - since one worker
    process now runs many chunks in sequence over the life of the pool
    (see the dynamic-chunking rationale on _CHUNKS_PER_WORKER above),
    not just the one fixed batch it got in earlier versions. The
    parameter name was left as-is since callers only ever treat it as
    an opaque label to report back in the progress tuple; it never
    needed "worker identity" semantics even before this change."""
    local_ctx = {
        "findings": {}, "timeline": [], "log_spans": {},
        "max_examples": max_examples,
        "window_start": window_start, "window_end": window_end,
        "stats": {"bytes_scanned": 0, "lines_scanned": 0, "read_errors": 0,
                   "files_scanned": 0, "files_skipped_binary": 0, "year_hint": year_hint,
                   "lines_in_window": 0, "lines_out_of_window": 0,
                   "compressed_files_scanned": 0, "decompressed_size_capped": 0},
    }
    last_progress_report = time.time()
    for idx, (relpath, category, compression_kind, _size) in enumerate(batch, start=1):
        # Reported BEFORE scan_file() runs, same rationale as the
        # sequential path's own progress line: a single large/slow file
        # shows up immediately as "currently scanning" instead of the
        # whole ~3s reporting window going silent for however long that
        # one file takes.
        if progress_queue is not None and time.time() - last_progress_report > 3:
            try:
                progress_queue.put_nowait((worker_idx, relpath, idx, len(batch)))
            except Exception:
                pass
            last_progress_report = time.time()
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
    pressure), or any other positive int to pin an explicit worker count -
    capped only at the generous _ABSOLUTE_MAX_WORKERS sanity ceiling
    (128), deliberately NOT at this machine's CPU count, since
    oversubscription can genuinely help an I/O-wait-dominated workload
    (v4.9.1; see determine_worker_count()'s docstring for the full
    rationale). Actual scanning work is split into more, smaller chunks
    than the worker count (v4.9.1) so a worker that finishes its share
    early can immediately pick up more pending work instead of idling
    while a "straggler" worker grinds on alone.

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
    links = []
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
            skipped, links = safe_extract_zip(input_path, extract_dir) if kind_archive == "zip" else safe_extract_tar(input_path, extract_dir)
        except Exception as e:
            raise AnalysisError(f"failed to extract archive: {e}") from e
        if skipped:
            report(f"  ({len(skipped)} archive members skipped - specials/errors; see extraction_skipped.json)")
            (output_dir / "extraction_skipped.json").write_text(json.dumps(skipped[:2000], indent=2), encoding="utf-8")
        root = resolve_root(extract_dir)
        # Archive member names (in `links`, exactly as tarfile/zipfile
        # gave them) are relative to the ARCHIVE'S OWN top-level entry
        # (e.g. "sosreport-RHEL-8-.../sos_commands/..."), but `root` may
        # have just auto-descended past that same wrapper directory
        # (resolve_root() above) - every OTHER path in this tool
        # (inventory.json, findings.json, ...) is relative to `root`,
        # not to `extract_dir`. Without stripping this common prefix
        # here, every link's `name` would silently never match any real
        # inventory path, and build_inventory() below would never
        # annotate a single entry despite `links` being correctly
        # populated - exactly this mismatch was caught by testing
        # directly against a real sosreport before release, not assumed.
        try:
            wrapper_prefix = root.relative_to(extract_dir).as_posix()
        except ValueError:
            wrapper_prefix = ""
        if wrapper_prefix and wrapper_prefix != ".":
            prefix = wrapper_prefix + "/"
            for link in links:
                if link["name"].startswith(prefix):
                    link["name"] = link["name"][len(prefix):]
        if links:
            # As of v4.12.0: symlinks/hardlinks are no longer lumped into
            # `skipped` just because Windows can't create a REAL link -
            # tarfile's own fallback already copies the target's real
            # content in for the overwhelming majority of them (see
            # safe_extract_tar()'s docstring), so reporting them as
            # "skipped" would be actively misleading. This sidecar (and
            # the `link_summary` fact derived from it) is where their
            # type/target metadata lives instead.
            n_failed = sum(1 for l in links if not l["extracted"])
            failed_note = f", {n_failed} failed to extract" if n_failed else ""
            report(f"  ({len(links)} symlink(s)/hardlink(s) found{failed_note}; see extraction_links.json)")
            (output_dir / "extraction_links.json").write_text(json.dumps(links[:5000], indent=2), encoding="utf-8")

    kind = detect_type(root)
    report(f"Detected archive type: {kind}")
    report(f"Root directory: {root}")

    report("Building file inventory...")
    inventory = build_inventory(root, kind, links=links)
    report(f"  {len(inventory)} files found")

    report("Running structured fact-checks...")
    facts = run_structured_checks(root, kind, inventory, links=links)

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
        # from pre-v4.9.0 for this branch, plus the v4.9.1 mid-file
        # progress_cb hook below (a single huge file - a real customer
        # bundle had individual rotated logs in the 78-120MB range - can
        # otherwise run for many minutes with zero visible progress even
        # though the surrounding per-file loop reports every 5s).
        last_report = time.time()
        for idx, (relpath, category, compression_kind, _size) in enumerate(scannable, start=1):
            if time.time() - last_report > 5:
                suffix = f" (decompressing {compression_kind})" if compression_kind else ""
                report(f"  ...scanning {relpath}{suffix}  ({idx}/{len(scannable)} files, {len(ctx['findings'])} distinct findings so far)")
                last_report = time.time()

            def _mid_file_progress(lineno, _relpath=relpath, _idx=idx):
                nonlocal last_report
                if time.time() - last_report > 5:
                    report(f"  ...scanning {_relpath}  (line {lineno:,} - {_idx}/{len(scannable)} files, {len(ctx['findings'])} distinct findings so far)")
                    last_report = time.time()

            scan_file(root, relpath, kind, category, ctx, compression_kind=compression_kind, progress_cb=_mid_file_progress)
            ctx["stats"]["files_scanned"] += 1
            if compression_kind:
                ctx["stats"]["compressed_files_scanned"] += 1
    else:
        cpu_count = os.cpu_count() or 1
        why = "auto-detected from CPU/memory" if workers is None else "requested"
        # Chunked into MANY MORE, smaller pieces than worker_count
        # (_CHUNKS_PER_WORKER) rather than exactly one large chunk per
        # worker - see that constant's comment for the full rationale.
        # In short: this lets concurrent.futures' own internal task
        # queue dynamically hand a newly-free worker the next pending
        # chunk immediately, instead of every worker being stuck with a
        # single large, fixed assignment for the whole run - which is
        # what let some workers finish early and sit idle on spare CPU
        # capacity while a few "unlucky" ones (whichever got assigned a
        # disproportionately huge file) kept grinding away alone.
        chunk_count = min(len(scannable), worker_count * _CHUNKS_PER_WORKER, max(1, len(scannable) // _MIN_ITEMS_PER_CHUNK))
        chunk_count = max(chunk_count, 1)
        chunks = _partition_items_by_size(scannable, chunk_count)
        report(f"  Using {worker_count} parallel worker processes ({len(chunks)} work chunks, dynamically distributed) for {len(scannable)} files (~{human_size(total_scan_bytes)}) - {why} (this machine reports {cpu_count} logical CPU core(s))")
        try:
            partial_ctxs = []
            # multiprocessing.Manager().Queue() (not a plain
            # multiprocessing.Queue()) is used here specifically because
            # it's a proxy object, safely picklable/shareable across the
            # process boundary on both the "spawn" (Windows) and "fork"
            # (Linux/macOS) start methods without any extra setup - a
            # plain multiprocessing.Queue() also works via inheritance on
            # fork, but Manager's version is the more portable choice
            # given this project runs on both platforms.
            with multiprocessing.Manager() as manager:
                progress_queue = manager.Queue()
                with ProcessPoolExecutor(max_workers=worker_count) as pool:
                    # Submitting all chunks up front (far more than
                    # max_workers) is exactly what enables the dynamic
                    # redistribution described above - the executor only
                    # ever runs `worker_count` of these concurrently, and
                    # automatically starts the next pending one on
                    # whichever worker process finishes first, with zero
                    # custom scheduling code needed on this end.
                    futures = {
                        pool.submit(_scan_batch, root, kind, chunk, start_dt, end_dt, max_examples, year_hint, i, progress_queue): (i, len(chunk), sum(x[3] for x in chunk))
                        for i, chunk in enumerate(chunks, start=1)
                    }
                    total_chunks = len(futures)
                    pending = set(futures.keys())
                    completed = 0
                    last_progress_report = time.time()
                    # Polling loop (rather than a blocking as_completed()
                    # iterator) so this can ALSO drain live per-file
                    # progress messages from still-running chunks while
                    # waiting - fixes a real gap where, before v4.9.1,
                    # nothing was reported until an entire chunk finished,
                    # which on a real multi-GB bundle can legitimately
                    # take minutes of apparent silence that's easy to
                    # mistake for a hang.
                    while pending:
                        newly_done = {f for f in pending if f.done()}
                        for future in newly_done:
                            chunk_idx, n_files, n_bytes = futures[future]
                            completed += 1
                            try:
                                partial_ctxs.append(future.result())
                            except Exception as e:
                                # One chunk failing (a genuinely unexpected
                                # bug, not the routine per-file
                                # OSError/UnicodeDecodeError scan_file()
                                # already handles internally) shouldn't
                                # take down the whole analysis - report it
                                # clearly and continue with whatever every
                                # OTHER chunk did produce, rather than
                                # losing all of that work too.
                                report(f"  ⚠️ chunk {chunk_idx}/{total_chunks} failed ({n_files} files skipped): {e}")
                        pending -= newly_done
                        latest_progress = None
                        while True:
                            try:
                                latest_progress = progress_queue.get_nowait()
                            except queue_mod.Empty:
                                break
                            except Exception:
                                break  # a Manager/proxy hiccup here must never abort the actual scan
                        if time.time() - last_progress_report > 5:
                            running_now = min(worker_count, sum(1 for f in pending if f.running()))
                            if latest_progress:
                                w_idx, relpath, i_in_chunk, chunk_len = latest_progress
                                report(f"  ...scanning {relpath}  (chunk {w_idx}/{total_chunks}, {i_in_chunk}/{chunk_len} in that chunk) - {completed}/{total_chunks} chunks done, {running_now} active now")
                            else:
                                report(f"  ...{completed}/{total_chunks} chunks done, {running_now} active now, {len(pending)} remaining")
                            last_progress_report = time.time()
                        if pending:
                            time.sleep(0.5)
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
