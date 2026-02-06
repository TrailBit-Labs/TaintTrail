"""Text export formatter for taint analysis reports.

Extracts the text formatting logic that was previously inline in main().
"""


def export_text(report: dict) -> str:
    """Export taint analysis report as human-readable text.

    Args:
        report: Report dict from TaintAnalyzer._generate_report().

    Returns:
        Formatted text string matching the original CLI output.
    """
    lines: list[str] = []

    lines.append("")
    lines.append("Taint Analysis Report")
    lines.append(f"   Methodology: {report['methodology'].upper()}")
    lines.append(f"   Source: {report['source_txid'][:20]}...")

    lines.append("")
    lines.append("Summary:")
    s = report["summary"]
    lines.append(f"   Transactions analyzed: {s['transactions_analyzed']}")
    lines.append(f"   Tainted outputs found: {s['tainted_outputs']}")
    lines.append(f"   Total tainted value:   {s['total_tainted_btc']:.8f} BTC")
    lines.append(f"   Max hop reached:       {s['max_hop_reached']}")

    by_hop = report.get("by_hop", {})
    if by_hop:
        lines.append("")
        lines.append("By Hop:")
        for hop, data in sorted(by_hop.items(), key=lambda x: int(x[0])):
            avg_conf = data.get("avg_confidence", 0)
            lines.append(
                f"   Hop {hop}: {data['count']} outputs, "
                f"{data['total_btc']:.8f} BTC, "
                f"avg taint: {data['avg_taint_pct']}%, "
                f"avg confidence: {avg_conf}"
            )

    top_addrs = report.get("top_tainted_addresses", [])
    if top_addrs:
        lines.append("")
        lines.append("Top Tainted Addresses:")
        for i, addr in enumerate(top_addrs[:5], 1):
            lines.append(
                f"   {i}. {addr['address']} — {addr['tainted_btc']:.8f} BTC"
            )

    tainted_outputs = report.get("tainted_outputs", [])
    if tainted_outputs:
        risk_counts: dict[str, int] = {}
        for o in tainted_outputs:
            r = o.get("risk", "minimal")
            risk_counts[r] = risk_counts.get(r, 0) + 1
        lines.append("")
        lines.append("Risk Summary:")
        for level in ["critical", "high", "medium", "low", "minimal"]:
            if level in risk_counts:
                lines.append(f"   {level.upper()}: {risk_counts[level]} outputs")

    return "\n".join(lines)
