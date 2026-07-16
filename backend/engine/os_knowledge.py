"""
os_knowledge.py - Linux OS/version knowledge base + config-file anomaly
detection for LDI Copilot.

Two independent checks live here, both returning plain dicts in the same
"facts" shape as every other analyzer in analyzer_core.py:

  * build_os_knowledge()   - detects the OS family/version from whatever
    release-identification files the bundle contains (etc/os-release,
    legacy etc/redhat-release, legacy etc/SuSE-release, or the
    supportconfig basic-environment.txt equivalents), then attaches:
      - a short "what's different about this major version" orientation
        (VERSION_NOTES) - not a replacement for the vendor docs, just a
        fast first read;
      - a small set of well-known, high-value "watch out for" items for
        that version (KNOWN_ISSUES) - cgroup v1/v2 migration gotchas,
        nftables/iptables coexistence, HA-cluster firewall port gotchas,
        etc.;
      - a lifecycle/support-status hint plus a link to the vendor's own
        LIVE lifecycle page (deliberately never a hardcoded end-of-life
        *date* - those drift and this project has no way to keep a
        hardcoded date correct forever; the qualitative phase is stable
        enough to state, the exact date is always deferred to the vendor).
    Every reference link below was verified to be a real, currently-
    resolving page before being hardcoded here (see the CHANGELOG entry
    for this feature) - deep, specific KB article numbers were
    deliberately avoided since those can't be verified to still exist;
    stable documentation-hub URLs were used instead.

  * check_config_anomalies() - a small, deliberately-scoped set of rule-
    based checks against common configuration files (sysctl, limits.conf,
    fstab, corosync.conf, multipath.conf, chrony/ntp.conf, resolv.conf,
    selinux config) looking for known-risky or known-inconsistent
    settings. This is intentionally NOT an attempt to model every config
    file on a Linux system - it covers the handful that come up
    repeatedly in real support cases (especially HA-cluster ones), each
    with a plain-English explanation of *why* it matters.

Both functions take the same handful of already-available analyzer_core
helpers as explicit parameters (find_inventory/get_text/
extract_supportconfig_section) rather than importing analyzer_core
directly - this keeps the dependency direction one-way (analyzer_core
imports this module, not the reverse) and matches this project's existing
style of passing precomputed context into a check rather than reaching
back into another module's internals (see check_sar_performance's
capture_dt/vm_tz parameters for the established precedent).
"""
import re

# --------------------------------------------------------------------------
# OS release parsing
# --------------------------------------------------------------------------
FAMILY_ALIASES = {
    "rhel": "rhel", "centos": "rhel", "rocky": "rhel", "almalinux": "rhel",
    "ol": "rhel", "fedora": "rhel",
    "sles": "sles", "sles_sap": "sles", "opensuse": "sles", "opensuse-leap": "sles",
    "sled": "sles",
    "ubuntu": "debian", "debian": "debian",
}

FAMILY_LABELS = {"rhel": "RHEL-family (RHEL/CentOS/Rocky/AlmaLinux)", "sles": "SUSE-family (SLES/openSUSE)", "debian": "Debian-family (Debian/Ubuntu)"}


def parse_os_release_text(text):
    """Parses KEY=VALUE (optionally quoted) lines from an /etc/os-release-
    style file into a plain dict. Ignores comments/blank lines."""
    fields = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        fields[key] = val
    return fields


def classify_os(fields):
    """Given a parsed os-release dict, returns a structured
    {distro_id, family, name, pretty_name, version, version_major,
    version_minor} classification, or None if it doesn't look usable."""
    distro_id = (fields.get("ID") or "").strip().lower()
    id_like = (fields.get("ID_LIKE") or "").lower()
    family = FAMILY_ALIASES.get(distro_id)
    if not family:
        for tok in id_like.split():
            if tok in FAMILY_ALIASES:
                family = FAMILY_ALIASES[tok]
                break
    version_id = fields.get("VERSION_ID", "")
    m = re.match(r"(\d+)(?:\.(\d+))?", version_id)
    version_major = int(m.group(1)) if m else None
    version_minor = int(m.group(2)) if m and m.group(2) else None
    if not (distro_id or version_major):
        return None
    return {
        "distro_id": distro_id or None,
        "family": family,
        "name": fields.get("NAME"),
        "pretty_name": fields.get("PRETTY_NAME") or fields.get("NAME"),
        "version": version_id or None,
        "version_major": version_major,
        "version_minor": version_minor,
    }


def parse_legacy_release_text(text):
    """Fallback for the pre-os-release single-line formats still seen on
    older bundles: /etc/redhat-release ('Red Hat Enterprise Linux Server
    release 7.9 (Maipo)', 'CentOS Linux release 7.9.2009 (Core)') and the
    legacy /etc/SuSE-release ('SUSE Linux Enterprise Server 12 (x86_64)'
    plus separate VERSION = / PATCHLEVEL = lines)."""
    m_ver = re.search(r"VERSION\s*=\s*(\d+)", text)
    if m_ver:
        m_pl = re.search(r"PATCHLEVEL\s*=\s*(\d+)", text)
        version_major = int(m_ver.group(1))
        version_minor = int(m_pl.group(1)) if m_pl else None
        first_line = next((l.strip() for l in text.splitlines() if l.strip()), "SUSE Linux Enterprise")
        return {
            "distro_id": "sles", "family": "sles", "name": first_line,
            "pretty_name": f"{first_line} SP{version_minor}" if version_minor else first_line,
            "version": f"{version_major}" + (f" SP{version_minor}" if version_minor else ""),
            "version_major": version_major, "version_minor": version_minor,
        }
    m = re.search(r"release\s+(\d+)(?:\.(\d+))?", text)
    if not m:
        return None
    version_major = int(m.group(1))
    version_minor = int(m.group(2)) if m.group(2) else None
    low = text.lower()
    if "centos" in low:
        distro_id, name = "centos", "CentOS Linux"
    elif "rocky" in low:
        distro_id, name = "rocky", "Rocky Linux"
    elif "alma" in low:
        distro_id, name = "almalinux", "AlmaLinux"
    elif "red hat" in low or "rhel" in low:
        distro_id, name = "rhel", "Red Hat Enterprise Linux"
    else:
        distro_id, name = None, text.split(" release")[0].strip()
    return {
        "distro_id": distro_id, "family": "rhel" if distro_id else None, "name": name,
        "pretty_name": text.strip(),
        "version": f"{version_major}" + (f".{version_minor}" if version_minor is not None else ""),
        "version_major": version_major, "version_minor": version_minor,
    }


# --------------------------------------------------------------------------
# Version-difference orientation notes. Deliberately concise "fast first
# read" bullets, not a replacement for the linked vendor doc - phrased with
# appropriate hedging ("generally", "by default") since exact defaults can
# vary by minor release/service-pack and installed profile.
# --------------------------------------------------------------------------
RHEL_DOCS_HUB = {
    7: "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7",
    8: "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8",
    9: "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9",
}
RHEL_DIFF_DOC = {
    8: "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/considerations_in_adopting_rhel_8/index",
    9: "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/considerations_in_adopting_rhel_9/index",
}
RHEL_HA_DOC = "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/{v}/html/configuring_and_managing_high_availability_clusters/index"
RHEL_SELINUX_DOC = "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/{v}/html/using_selinux/index"
RHEL_LIFECYCLE_DOC = "https://access.redhat.com/support/policy/updates/errata"
RHEL_CVE_DOC = "https://access.redhat.com/security/security-updates/cve"

SLES_DOCS_HUB = {12: "https://documentation.suse.com/sles/12-SP5/", 15: "https://documentation.suse.com/sles/15-SP6/"}
SLES_LIFECYCLE_DOC = "https://www.suse.com/lifecycle/"
SLES_KB_DOC = "https://www.suse.com/support/kb/"
PACEMAKER_DOC = "https://clusterlabs.org/projects/pacemaker/doc/"

VERSION_NOTES = {
    ("rhel", 7): [
        "systemd replaced SysV init/Upstart (first RHEL major to do so) - `service`/`chkconfig` still work as compat wrappers over systemctl.",
        "firewalld (iptables backend) is the default firewall manager, but many 7.x estates still run classic `iptables`/`ip6tables` services directly.",
        "Python 2.7 is the default system Python; Python 3 is available only as an optional package (python3 / python36 etc.), which matters for any custom tooling assuming `python` means Python 3.",
        "cgroups v1 only - not relevant for container-runtime cgroup-driver mismatches the way RHEL 8→9 is (see below), since v2 wasn't an option yet on 7.",
        "By mid-2026 RHEL 7 is well past its standard Full/Maintenance Support window - treat any RHEL 7 host found in production as a modernization/support-risk item, not just a version note.",
    ],
    ("rhel", 8): [
        "NetworkManager is the default and Red-Hat-recommended way to configure networking; legacy `network`/ifcfg-scripts service management is deprecated (still present, but new deployments should use nmcli/nmtui or Cockpit).",
        "dnf replaces yum as the package manager (yum is kept as a compatibility alias calling dnf underneath).",
        "nftables is the default packet-filtering backend; the `iptables` command still works via an `iptables-nft` translation layer, but mixing genuinely-legacy `iptables-legacy` rules with native `nft` rules on the same host is a common source of \"my firewall rule isn't taking effect\" tickets.",
        "Python 3 is the default system Python; Python 2 is available only as an optional legacy package.",
        "cgroups v1 by default (v2 is available opt-in via a kernel boot parameter) - this is the version where the v1→v2 transition Red Hat completed in RHEL 9 begins to matter for container tooling.",
        "SELinux ships enforcing/targeted by default.",
    ],
    ("rhel", 9): [
        "cgroups v2 (the \"unified cgroup hierarchy\") is the only supported mode - this is the single biggest \"upgraded from 8 and containers misbehave\" gotcha: any container runtime, orchestrator, or custom systemd-slice tooling that hardcoded cgroup v1 paths/assumptions needs to be v2-aware before this upgrade, not after.",
        "nftables is fully default; the `iptables-legacy` backend is no longer shipped at all (only the `iptables-nft` translation layer is available).",
        "OpenSSL 3 and a stricter default system-wide crypto policy - older TLS versions/ciphers that RHEL 8 still tolerated by default can start failing handshakes after an 8→9 upgrade.",
        "Python 3.9+ as the default system Python; Python 2 is not available at all, even as an optional package.",
    ],
    ("sles", 12): [
        "systemd replaced the traditional init system (first SLES major to do so).",
        "`wicked` is the default network management service for server roles (NetworkManager is available but not the default outside desktop use).",
        "cgroups v1 only.",
        "SuSEfirewall2 is the traditional firewall tool through most of the SLES 12 lifecycle; firewalld only becomes an option later in the SP train.",
    ],
    ("sles", 15): [
        "Content is delivered as separately-registered modules/extensions (Basesystem, Server Applications, HA, etc.) rather than one monolithic installation media - a module not being registered is a common \"package not found\" cause on SLES 15 that doesn't apply the same way on SLES 12.",
        "`wicked` remains the default network manager for server deployments through most of the SP train; NetworkManager is the alternative, more common on desktop-oriented installs.",
        "firewalld becomes the more common default over the SP lifecycle, superseding SuSEfirewall2.",
        "Transactional-update-capable variants (SLE Micro family) begin to appear alongside the traditional package-managed SLES.",
        "Exact default versions of the above (firewalld vs. SuSEfirewall2, cgroups v1 vs. v2, etc.) vary by service pack - the linked release notes for the specific SP are the authoritative source.",
    ],
}

# Known, high-value "watch out for" items. Matched by family + a version
# range (inclusive). Kept intentionally small and specific rather than an
# exhaustive trivia list - each one is something that repeatedly shows up
# in real support cases, not a generic "read the manual" filler item.
KNOWN_ISSUES = [
    {
        "id": "cgroup-v1-v2-migration",
        "family": "rhel", "min_major": 8, "max_major": 9,
        "title": "cgroup v1 → v2 migration can break container/cluster tooling across an 8→9 upgrade",
        "detail": "RHEL 9 only supports the unified cgroup v2 hierarchy. Container runtimes, Kubernetes/OpenShift node config, and any custom systemd-slice resource limits that assumed cgroup v1 paths should be verified for cgroup v2 compatibility BEFORE upgrading, not diagnosed after containers start silently failing to launch or apply resource limits.",
        "doc_link": RHEL_DIFF_DOC[9],
    },
    {
        "id": "nftables-iptables-coexistence",
        "family": "rhel", "min_major": 8, "max_major": 9,
        "title": "Mixing legacy iptables rules with native nftables rules can silently not enforce as expected",
        "detail": "Since RHEL 8, `iptables` is a translation layer over nftables (`iptables-nft`). Rules added via a genuinely separate `iptables-legacy` toolset (or copied verbatim from an old RHEL 7 host) can coexist with native `nft` rules in ways that don't behave like a single ordered rule set - if firewall rules seem to be present but not taking effect, check which backend actually owns them (`iptables -V`, `nft list ruleset`).",
        "doc_link": RHEL_DIFF_DOC[8],
    },
    {
        "id": "ha-firewall-ports",
        "family": "rhel", "min_major": 7, "max_major": 9,
        "title": "Pacemaker/Corosync cluster communication ports are not open by default under firewalld",
        "detail": "A fresh RHEL install (or an in-place OS upgrade that resets firewall config) leaves firewalld's default zone without the `high-availability` service/ports opened. This shows up as corosync token timeouts or nodes unable to see each other, that look like a network problem but are actually a firewall one - confirm `firewall-cmd --list-services` includes `high-availability` on every cluster node.",
        "doc_link": None,  # filled in per detected major version below
    },
    {
        "id": "selinux-drift-after-upgrade",
        "family": "rhel", "min_major": 7, "max_major": 9,
        "title": "SELinux config-file mode can silently differ from the currently-running mode",
        "detail": "It's common for a prior troubleshooting session to set SELinux to permissive live (`setenforce 0`) without updating `/etc/selinux/config` to match, or vice versa. The live mode reverts to whatever the config file says on the next reboot - this project's Security tab shows the current *runtime* mode; see Configuration Anomalies for a check of the on-disk *configured* mode against it.",
        "doc_link": None,  # filled in per detected major version below
    },
    {
        "id": "network-naming-scheme",
        "family": "rhel", "min_major": 7, "max_major": 9,
        "title": "Predictable network interface names can change across an in-place upgrade or VM migration",
        "detail": "Interface names like `eth0` vs. `ens192`/`enp0s3` are assigned by udev's consistent-naming scheme based on firmware/bus/slot information - moving a VM between hypervisors, changing a vNIC's PCI slot, or an in-place major-version upgrade can change the assigned name, breaking any hardcoded `ifcfg-eth0`-style config or scripts. Confirm interface names in the current bundle match what any referenced config/scripts expect.",
        "doc_link": None,
    },
    {
        "id": "sles-cgroup-migration",
        "family": "sles", "min_major": 12, "max_major": 15,
        "title": "cgroup v1 → v2 default can change between SLES service packs",
        "detail": "As with RHEL, container tooling that assumes a specific cgroup hierarchy version should be verified against the cgroup mode actually in effect on this specific SLES service pack - check the SP's own release notes rather than assuming it matches an earlier SP you're used to.",
        "doc_link": None,  # filled in per detected family docs hub below
    },
    {
        "id": "sles-module-not-registered",
        "family": "sles", "min_major": 15, "max_major": 15,
        "title": "\"Package not found\" on SLES 15 is often a module-registration problem, not a repo problem",
        "detail": "SLES 15's content is split into separately-registered modules (Basesystem, Server Applications, HA, Containers, etc.). A package that exists but isn't installable is frequently explained by the module that owns it not being registered/activated on this system (`SUSEConnect --list-extensions` / `zypper lr`), rather than a corrupted or missing repository.",
        "doc_link": None,
    },
    {
        "id": "eol-modernization",
        "family": None, "min_major": 0, "max_major": 999,
        "title": "Older major versions nearing/past standard vendor support should be flagged as a modernization risk",
        "detail": "Independent of any specific bug, running a major version that's past (or close to) the end of its standard support window means security patches and official fixes may no longer be available for newly-discovered issues - worth flagging as a standing recommendation even when it isn't the direct root cause of the current investigation.",
        "doc_link": None,  # filled in per detected family lifecycle page below
    },
]


def _known_issues_for(family, major):
    if major is None:
        return []
    out = []
    for item in KNOWN_ISSUES:
        if item["family"] is not None and item["family"] != family:
            continue
        if not (item["min_major"] <= major <= item["max_major"]):
            continue
        entry = dict(item)
        if entry["doc_link"] is None:
            if entry["id"] == "ha-firewall-ports":
                entry["doc_link"] = RHEL_HA_DOC.format(v=major) if family == "rhel" else PACEMAKER_DOC
            elif entry["id"] == "selinux-drift-after-upgrade":
                entry["doc_link"] = RHEL_SELINUX_DOC.format(v=major) if family == "rhel" else None
            elif entry["id"] == "sles-cgroup-migration":
                entry["doc_link"] = SLES_DOCS_HUB.get(major)
            elif entry["id"] == "eol-modernization":
                entry["doc_link"] = RHEL_LIFECYCLE_DOC if family == "rhel" else SLES_LIFECYCLE_DOC
        out.append(entry)
    return out


def _lifecycle_hint(family, major):
    """Qualitative-only support-phase hint - deliberately never a hardcoded
    calendar date (see module docstring)."""
    if family == "rhel":
        if major is not None and major <= 7:
            return "RHEL 7 and earlier are, as of this analysis, past or very near the end of standard Full/Maintenance Support - confirm current status on the lifecycle page before assuming standard patching still applies."
        return "Check the live Red Hat lifecycle page for this exact minor release's current support phase (Full Support / Maintenance Support / Extended Life Phase) - phase boundaries are date-based and this project intentionally doesn't hardcode them."
    if family == "sles":
        if major is not None and major <= 12:
            return "SLES 12 is an older major version - confirm current General Support / LTSS status on the SUSE lifecycle page rather than assuming standard support."
        return "Check the live SUSE lifecycle page for this exact service pack's current support phase - phase boundaries are date-based and this project intentionally doesn't hardcode them."
    return None


def build_os_knowledge(root, kind, inventory, find_inventory, get_text, extract_supportconfig_section):
    """Main entry point - detects OS family/version from whatever release-
    identification file the bundle contains, then attaches version notes,
    known issues, and a lifecycle hint. Returns None if no OS could be
    confidently identified at all (kept out of facts.json entirely in that
    case, same convention as the other analyzers' *_error keys)."""
    parsed = None
    source_file = None

    if kind in ("sosreport", "crm_report"):
        for relp in find_inventory(inventory, "etc/os-release"):
            t = get_text(root, relp, 20_000)
            if t.strip():
                fields = parse_os_release_text(t)
                candidate = classify_os(fields)
                if candidate:
                    parsed, source_file = candidate, relp
                    break
        if not parsed:
            for relp in find_inventory(inventory, "etc/redhat-release", "etc/system-release", "etc/suse-release"):
                t = get_text(root, relp, 2000)
                if t.strip():
                    candidate = parse_legacy_release_text(t)
                    if candidate:
                        parsed, source_file = candidate, relp
                        break
    else:  # supportconfig
        for relp in find_inventory(inventory, "basic-environment.txt"):
            t = get_text(root, relp, 300_000)
            sec = extract_supportconfig_section(t, "os-release", "/etc/os-release")
            if sec:
                fields = parse_os_release_text("\n".join(sec))
                candidate = classify_os(fields)
                if candidate:
                    parsed, source_file = candidate, relp
            if not parsed:
                sec2 = extract_supportconfig_section(t, "suse-release", "/etc/suse-release")
                joined = "\n".join(sec2)
                if joined.strip():
                    candidate = parse_legacy_release_text(joined)
                    if candidate:
                        parsed, source_file = candidate, relp
            if parsed:
                break

    if not parsed:
        return None

    family = parsed.get("family")
    major = parsed.get("version_major")
    result = {
        "detected": parsed,
        "source_file": source_file,
        "family_label": FAMILY_LABELS.get(family, family or "Unknown"),
        "version_notes": VERSION_NOTES.get((family, major), []),
        "known_issues": _known_issues_for(family, major),
        "lifecycle_hint": _lifecycle_hint(family, major),
        "docs_hub_link": (RHEL_DOCS_HUB.get(major) if family == "rhel" else SLES_DOCS_HUB.get(major)) if family else None,
        "cve_search_link": RHEL_CVE_DOC if family == "rhel" else (SLES_KB_DOC if family == "sles" else None),
    }
    return result


# --------------------------------------------------------------------------
# Config-file anomaly detection
# --------------------------------------------------------------------------
def _kv_pairs(text):
    """Yields (key, value) for lines shaped like `key = value` or `key value`
    (sysctl/corosync-ish), skipping comments/blanks."""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if "=" in line:
            k, _, v = line.partition("=")
            yield k.strip(), v.strip().split()[0] if v.strip() else ""
        else:
            parts = line.split(None, 1)
            if len(parts) == 2:
                yield parts[0].strip(), parts[1].strip()


def _anomaly(severity, file, title, detail, doc_link=None):
    return {"severity": severity, "file": file, "title": title, "detail": detail, "doc_link": doc_link}


def _check_sysctl(text, relp, out):
    seen = dict(_kv_pairs(text))
    if seen.get("kernel.panic") == "0":
        out.append(_anomaly("WARNING", relp, "kernel.panic = 0",
                             "The system will NOT automatically reboot after a kernel panic. On a production or HA-cluster node this usually should be a small positive value (e.g. 10) unless a crash dump is being deliberately preserved for debugging.",
                             None))
    if seen.get("net.ipv4.tcp_syncookies") == "0":
        out.append(_anomaly("WARNING", relp, "net.ipv4.tcp_syncookies = 0",
                             "SYN-flood protection (SYN cookies) is disabled. Unless this host is intentionally isolated from any untrusted network, this is usually not intended.", None))
    if seen.get("vm.swappiness") == "100":
        out.append(_anomaly("INFO", relp, "vm.swappiness = 100",
                             "Maximally aggressive swapping. Worth confirming this is intentional - most server workloads (especially databases) are tuned toward a much lower value to avoid swapping active memory unnecessarily.", None))
    fmax = seen.get("fs.file-max")
    if fmax and fmax.isdigit() and int(fmax) < 65536:
        out.append(_anomaly("INFO", relp, f"fs.file-max = {fmax}",
                             "This system-wide open-file limit is lower than the typical modern RHEL/SLES default (usually in the hundreds of thousands to millions). Worth checking if this was intentionally tuned down or is a leftover from an old baseline.", None))


def _check_limits(text, relp, out):
    has_override = any(
        line.strip() and not line.strip().startswith("#") and re.search(r"\b(nofile|nproc)\b", line)
        for line in text.splitlines()
    )
    if not has_override:
        out.append(_anomaly("INFO", relp, "No nofile/nproc overrides found in limits.conf",
                             "Relying on OS defaults (often 1024 open files / a few thousand processes per user), which is frequently too low for database, application-server, or cluster-resource workloads that open many files or connections. Consider explicit limits for the relevant service accounts if this host runs such a workload.", None))


def _check_fstab(text, relp, out):
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        device, mount, fstype, opts = parts[0], parts[1], parts[2], parts[3]
        if fstype in ("nfs", "nfs4") and "_netdev" not in opts.split(","):
            out.append(_anomaly("WARNING", relp, f"NFS mount '{mount}' has no _netdev option",
                                 "Without `_netdev`, the boot sequence can attempt this mount before networking is up, causing a hang or a failed mount on some boots - especially common on VMs and cloud instances where network init timing varies.", None))


def _check_corosync(text, relp, out):
    node_blocks = len(re.findall(r"\bnode\s*\{", text))
    has_two_node = re.search(r"\btwo_node\s*:\s*1\b", text) is not None
    if node_blocks == 2 and not has_two_node:
        out.append(_anomaly("WARNING", relp, "Two-node cluster without two_node: 1 in the quorum block",
                             "With exactly two nodes configured and no `two_node: 1` (and no qdevice), quorum is typically lost whenever either node is down - the surviving node can't safely operate on its own. Confirm this is intentional (e.g. a qdevice provides the tie-break instead).",
                             RHEL_HA_DOC.format(v=8)))
    m = re.search(r"\btoken\s*:\s*(\d+)", text)
    if m and int(m.group(1)) < 3000:
        out.append(_anomaly("INFO", relp, f"Corosync token timeout is {m.group(1)}ms (<3000ms)",
                             "A very low token timeout can cause spurious fencing from transient scheduling delays on loaded or virtualized nodes. Worth confirming this matches the actual latency/jitter characteristics of the cluster network.",
                             RHEL_HA_DOC.format(v=8)))


def _check_multipath(text, relp, out):
    if re.search(r"\buser_friendly_names\s+yes\b", text):
        out.append(_anomaly("WARNING", relp, "multipath.conf: user_friendly_names yes",
                             "User-friendly names (mpathN) are not guaranteed to be assigned consistently across reboots or across cluster nodes for the same underlying device - shared-storage cluster resources that reference a device by its mpath name can end up pointing at different devices on different nodes. Prefer referencing devices by WWID (/dev/mapper/<wwid>) for anything shared between cluster nodes.",
                             RHEL_HA_DOC.format(v=8)))


def _check_time_sync(text, relp, out):
    has_source = re.search(r"^\s*(server|pool)\s+\S+", text, re.MULTILINE) is not None
    if not has_source:
        out.append(_anomaly("WARNING", relp, "No NTP/chrony time source configured",
                             "No `server`/`pool` directive found. Clock drift across cluster nodes or between a client and a KDC/certificate-relying service can cause Kerberos authentication failures, TLS handshake failures, cluster-token miscalculation, and misleading cross-host log timelines.", None))


def _check_resolv_conf(text, relp, out):
    if not re.search(r"^\s*nameserver\s+\S+", text, re.MULTILINE):
        out.append(_anomaly("WARNING", relp, "No nameserver entries in resolv.conf",
                             "DNS resolution will fail for anything not in /etc/hosts unless a local resolver (systemd-resolved, NetworkManager-managed DNS, etc.) is handling this outside of resolv.conf - worth confirming which is actually in effect.", None))


def _check_selinux_config(text, relp, security_mac, family, major, out):
    m = re.search(r"^\s*SELINUX\s*=\s*(\w+)", text, re.MULTILINE)
    if not m:
        return
    configured = m.group(1).lower()
    running = (security_mac or {}).get("selinux_mode", "").lower() or None
    running_status = (security_mac or {}).get("selinux_status", "").lower()
    if running_status == "disabled":
        running = "disabled"
    if running and running != configured:
        out.append(_anomaly("WARNING", relp, f"Configured SELinux mode ('{configured}') differs from the currently running mode ('{running}')",
                             "The on-disk config is what will apply after the next reboot - if these two differ, expect SELinux enforcement behavior to change unexpectedly on the next restart. Reconcile intentionally rather than leaving this as an accidental drift.",
                             RHEL_SELINUX_DOC.format(v=major) if family == "rhel" and major else None))


_CHECK_TARGETS = [
    # (sosreport path substring, supportconfig section-file substring,
    #  supportconfig section COMMAND substring(s), checker). The command
    # substring is deliberately independent of the config file's own name -
    # e.g. supportconfig's sysctl.txt is a `sysctl -a` runtime dump, not a
    # `cat /etc/sysctl.conf`, so matching on "sysctl.conf" would never hit.
    ("etc/sysctl.conf", "sysctl.txt", ("sysctl",), _check_sysctl),
    ("etc/security/limits.conf", "limits.conf", ("limits.conf",), _check_limits),
    ("etc/fstab", "fstab.txt", ("fstab",), _check_fstab),
    ("etc/corosync/corosync.conf", "corosync.conf", ("corosync.conf",), _check_corosync),
    ("etc/multipath.conf", "multipath.conf", ("multipath.conf",), _check_multipath),
    ("etc/chrony.conf", "chrony.conf", ("chrony.conf",), _check_time_sync),
    ("etc/ntp.conf", "ntp.conf", ("ntp.conf",), _check_time_sync),
    ("etc/resolv.conf", "resolv.conf", ("resolv.conf",), _check_resolv_conf),
]


def check_config_anomalies(root, kind, inventory, find_inventory, get_text, extract_supportconfig_section, security_mac=None, os_detected=None):
    """Runs a fixed, deliberately-scoped set of rule-based checks against
    common config files present in the bundle. Returns {"anomalies": [...],
    "files_checked": [...]} - both always present (possibly empty), so the
    caller can distinguish "checked and clean" from "nothing to check"."""
    out = []
    files_checked = []

    def _read_sosreport(relp_substr):
        for relp in find_inventory(inventory, relp_substr):
            t = get_text(root, relp, 500_000)
            if t.strip():
                return relp, t
        return None, None

    def _read_supportconfig(section_file, *cmd_subs):
        for relp in find_inventory(inventory, section_file):
            t = get_text(root, relp, 500_000)
            sec = extract_supportconfig_section(t, *cmd_subs)
            joined = "\n".join(sec)
            if joined.strip():
                return relp, joined
        return None, None

    for sos_path, supportconfig_file, cmd_subs, checker in _CHECK_TARGETS:
        if kind in ("sosreport", "crm_report"):
            relp, text = _read_sosreport(sos_path)
        else:
            relp, text = _read_supportconfig(supportconfig_file, *cmd_subs)
        if text:
            files_checked.append(relp)
            checker(text, relp, out)

    # SELinux config-vs-runtime cross-check needs the security_mac fact and
    # the detected OS major version for its doc link, so it's handled
    # separately rather than through the generic (file, checker) table above.
    family = (os_detected or {}).get("family")
    major = (os_detected or {}).get("version_major")
    if kind in ("sosreport", "crm_report"):
        relp, text = _read_sosreport("etc/selinux/config")
    else:
        # Same supportconfig file-name convention as check_security_mac()
        # in analyzer_core.py (security-selinux.txt, falling back to the
        # older security.txt name) - SUSE bundles frequently won't have a
        # SELinux config section at all (AppArmor is the SUSE default MAC),
        # which is expected/normal, not a bug.
        relp, text = _read_supportconfig("security-selinux.txt", "selinux")
        if not text:
            relp, text = _read_supportconfig("security.txt", "selinux")
    if text:
        files_checked.append(relp)
        _check_selinux_config(text, relp, security_mac, family, major, out)

    return {"anomalies": out, "files_checked": files_checked}
