"""Markdown export formatter for taint analysis reports."""

from datetime import datetime


def export_markdown(report: dict) -> str:
    """Export taint analysis report as Markdown.

    Args:
        report: Report dict from TaintAnalyzer._generate_report().

    Returns:
        Markdown-formatted string with summary, findings, and top addresses.
    """
    lines: list[str] = []

    # Title
    lines.append("# Taint Analysis Report")
    lines.append("")
    lines.append(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append("")

    # Summary table
    summary = report.get("summary", {})
    lines.append("## Summary")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|-------|-------|")
    lines.append(f"| Methodology | {report.get('methodology', 'unknown')} |")
    lines.append(f"| Source TXID | `{report.get('source_txid', '')}` |")
    lines.append(f"| Source Label | {report.get('source_label', '')} |")
    lines.append(f"| Transactions Analyzed | {summary.get('transactions_analyzed', 0)} |")
    lines.append(f"| Tainted Outputs | {summary.get('tainted_outputs', 0)} |")
    lines.append(f"| Total Tainted BTC | {summary.get('total_tainted_btc', 0):.8f} |")
    lines.append(f"| Max Hop Reached | {summary.get('max_hop_reached', 0)} |")
    lines.append("")

    # By-hop breakdown
    by_hop = report.get("by_hop", {})
    if by_hop:
        lines.append("## Taint by Hop")
        lines.append("")
        lines.append("| Hop | Count | Total BTC | Avg Taint % |")
        lines.append("|-----|-------|-----------|-------------|")
        for hop, data in sorted(by_hop.items(), key=lambda x: int(x[0])):
            lines.append(
                f"| {hop} | {data.get('count', 0)} "
                f"| {data.get('total_btc', 0):.8f} "
                f"| {data.get('avg_taint_pct', 0):.2f} |"
            )
        lines.append("")

    # Findings table - sorted by hop then by taint % descending
    outputs = report.get("tainted_outputs", [])
    if outputs:
        sorted_outputs = sorted(
            outputs,
            key=lambda o: (o.get("hop", 0), -o.get("taint_percent", 0)),
        )

        lines.append("## Tainted Outputs")
        lines.append("")
        lines.append("| Hop | Address | Value (BTC) | Taint % | Confidence | Risk |")
        lines.append("|-----|---------|-------------|---------|------------|------|")
        for o in sorted_outputs:
            value_btc = o.get("value_sat", 0) / 1e8
            lines.append(
                f"| {o.get('hop', 0)} "
                f"| `{o.get('address', 'unknown')}` "
                f"| {value_btc:.8f} "
                f"| {o.get('taint_percent', 0):.1f} "
                f"| {o.get('confidence', 0):.4f} "
                f"| {o.get('risk', 'minimal')} |"
            )
        lines.append("")

    # Top tainted addresses
    top_addrs = report.get("top_tainted_addresses", [])
    if top_addrs:
        lines.append("## Top Tainted Addresses")
        lines.append("")
        lines.append("| # | Address | Tainted BTC |")
        lines.append("|---|---------|-------------|")
        for i, addr in enumerate(top_addrs[:10], 1):
            lines.append(
                f"| {i} | `{addr.get('address', '')}` "
                f"| {addr.get('tainted_btc', 0):.8f} |"
            )
        lines.append("")

    return "\n".join(lines)
