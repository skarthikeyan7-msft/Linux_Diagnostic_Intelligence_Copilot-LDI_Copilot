"""
Packet-capture (tcpdump/.pcap/.pcapng) metadata analyzer.
==========================================================
Extracts summary METADATA ONLY from a standalone packet capture -
packet/byte counts, top talkers, protocol breakdown, TCP anomaly
counts (retransmissions/resets/SYN-without-ACK, a rough port-scan
heuristic), a DNS query summary, and packets/sec timing - never raw
payload bytes or strings.

Why metadata only (privacy): a pcap's payload can contain credentials,
session tokens, or other sensitive customer data that this project's
existing redaction feature (hostname/IP tokenization) was never
designed to handle safely. Nothing from payload CONTENT is ever placed
into facts.json, the digest, or anything sent to an AI provider - see
SECURITY.md for the full policy this module implements. IP addresses
and DNS names ARE included (they're the whole point of a "top talkers"/
"DNS summary" view) and flow through the same redaction path as
everything else in the digest when a non-local AI provider is used.

Uses `dpkt` (pure-Python, lightweight - the one new dependency this
adds to the project) since pcap is a binary format with no stdlib
parser. Best-effort: malformed/truncated captures, or shapes this
parser doesn't fully understand, degrade to a partial result or a
clear {"error": ...} dict rather than raising - a bad capture must
never abort the rest of the analysis.
"""
import socket
from collections import Counter

try:
    import dpkt
except ImportError:  # optional dependency - see backend/requirements.txt
    dpkt = None

PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"  # Section Header Block type - same bytes regardless of endianness


def _ip_to_str(addr):
    try:
        if len(addr) == 4:
            return socket.inet_ntop(socket.AF_INET, addr)
        if len(addr) == 16:
            return socket.inet_ntop(socket.AF_INET6, addr)
    except (ValueError, OSError):
        pass
    return None


def human_bytes(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"


def analyze_pcap(pcap_path, max_packets=2_000_000):
    """Parses a .pcap or .pcapng file and returns a metadata-only summary
    dict, or {"error": "..."} if dpkt isn't installed or the file can't
    be read at all. Never raises - callers should still wrap this in
    their own try/except per this project's established pattern (see
    check_* functions in analyzer_core.py), but every internal failure
    mode here is already handled and reported as data, not an exception.
    """
    if dpkt is None:
        return {"error": "dpkt is not installed - packet capture analysis is unavailable (pip install dpkt)"}

    protocol_counts = Counter()
    top_talkers = Counter()          # (src, dst) -> byte count
    dns_queries = Counter()          # qname -> count
    seen_tcp_seq = {}                # (src, sport, dst, dport) -> set of seen seq numbers (retransmit heuristic)
    total_packets = 0
    total_bytes = 0
    tcp_syn = tcp_synack = tcp_reset = tcp_retransmits = 0
    first_ts = last_ts = None
    truncated = None

    try:
        with open(pcap_path, "rb") as fh:
            head = fh.read(4)
            fh.seek(0)
            reader = dpkt.pcapng.Reader(fh) if head == PCAPNG_MAGIC else dpkt.pcap.Reader(fh)
            for i, (ts, buf) in enumerate(reader):
                if i >= max_packets:
                    truncated = max_packets
                    break
                total_packets += 1
                total_bytes += len(buf)
                first_ts = ts if first_ts is None else first_ts
                last_ts = ts

                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    ip = eth.data
                except Exception:
                    protocol_counts["other/undecoded"] += 1
                    continue

                if isinstance(ip, dpkt.ip6.IP6):
                    pass
                elif isinstance(ip, dpkt.ip.IP):
                    pass
                else:
                    protocol_counts["non-IP (ARP/other L2)"] += 1
                    continue

                src, dst = _ip_to_str(ip.src), _ip_to_str(ip.dst)
                if src and dst:
                    top_talkers[(src, dst)] += len(buf)

                data = ip.data
                if isinstance(data, dpkt.tcp.TCP):
                    protocol_counts["TCP"] += 1
                    is_syn, is_ack, is_rst = bool(data.flags & dpkt.tcp.TH_SYN), bool(data.flags & dpkt.tcp.TH_ACK), bool(data.flags & dpkt.tcp.TH_RST)
                    if is_syn and not is_ack:
                        tcp_syn += 1
                    if is_syn and is_ack:
                        tcp_synack += 1
                    if is_rst:
                        tcp_reset += 1
                    if src and dst and len(data.data) > 0:
                        key = (src, data.sport, dst, data.dport)
                        seen = seen_tcp_seq.setdefault(key, set())
                        if data.seq in seen:
                            tcp_retransmits += 1
                        else:
                            seen.add(data.seq)
                elif isinstance(data, dpkt.udp.UDP):
                    protocol_counts["UDP"] += 1
                    if data.sport == 53 or data.dport == 53:
                        try:
                            dns = dpkt.dns.DNS(data.data)
                            for q in dns.qd:
                                dns_queries[q.name] += 1
                        except Exception:
                            pass
                elif isinstance(data, dpkt.icmp.ICMP):
                    protocol_counts["ICMP"] += 1
                else:
                    protocol_counts["other IP protocol"] += 1
    except Exception as e:
        return {"error": f"failed to parse packet capture: {e}"}

    if total_packets == 0:
        return {"error": "no packets could be read from this capture (empty file or unrecognized format)"}

    duration = (last_ts - first_ts) if (first_ts is not None and last_ts is not None) else None
    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "total_bytes_human": human_bytes(total_bytes),
        "duration_seconds": round(duration, 3) if duration is not None else None,
        "packets_per_second": round(total_packets / duration, 2) if duration and duration > 0 else None,
        "protocol_counts": dict(protocol_counts),
        "top_talkers": [
            {"src": s, "dst": d, "bytes": n, "bytes_human": human_bytes(n)}
            for (s, d), n in top_talkers.most_common(15)
        ],
        "tcp_syn": tcp_syn,
        "tcp_synack": tcp_synack,
        "tcp_reset": tcp_reset,
        "tcp_retransmits_suspected": tcp_retransmits,
        # Rough heuristic only (many unanswered SYNs vs. SYN-ACKs) - a
        # one-sided capture (only one host's traffic) or a busy but
        # healthy server can also trigger this; never asserted as fact
        # in the digest, always phrased as "worth a look".
        "possible_port_scan_pattern": tcp_syn > 50 and tcp_synack < tcp_syn * 0.1,
        "dns_top_queries": [{"qname": q, "count": n} for q, n in dns_queries.most_common(15)],
        "truncated_at_max_packets": truncated,
    }
