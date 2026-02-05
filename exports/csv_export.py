"""CSV export formatter for taint analysis reports."""

import csv
import io


HEADER = [
    "txid", "vout_index", "address", "value_sat", "value_btc",
    "taint_pct", "confidence", "risk", "hop",
]


def export_csv(report: dict) -> str:
    """Export taint analysis report as CSV.

    Args:
        report: Report dict from TaintAnalyzer._generate_report().

    Returns:
        CSV-formatted string with header row and one row per tainted output.
    """
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(HEADER)

    for output in report.get("tainted_outputs", []):
        value_sat = output.get("value_sat", 0)
        writer.writerow([
            output.get("txid", ""),
            output.get("vout_index", 0),
            output.get("address", ""),
            value_sat,
            f"{value_sat / 1e8:.8f}",
            output.get("taint_percent", 0.0),
            output.get("confidence", 0.0),
            output.get("risk", "minimal"),
            output.get("hop", 0),
        ])

    return buf.getvalue()
