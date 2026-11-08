"""Summarize network flow counts and bytes from a local CSV."""

from collections import Counter


def summarize_traffic(flows):
    talkers = Counter()
    ports = Counter()
    total = 0
    for flow in flows:
        talkers[flow.src_ip] += flow.bytes
        ports[(flow.protocol, flow.dst_port)] += 1
        total += flow.bytes
    return {
        "flow_count": len(flows),
        "total_bytes": total,
        "top_sources": [
            {"ip": ip, "bytes": size}
            for ip, size in sorted(talkers.items(), key=lambda item: (-item[1], item[0]))[:5]
        ],
        "top_destination_ports": [
            {"protocol": proto, "port": port, "flows": count}
            for (proto, port), count in sorted(ports.items(), key=lambda item: (-item[1], item[0]))[:5]
        ],
    }
