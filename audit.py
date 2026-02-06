"""
Audit logging for Bitcoin taint analysis.

Provides JSONL-based audit trails for forensic accountability.
Each analysis run is logged with timestamp, parameters, and results
to support compliance and reproducibility requirements.
"""

import json
import os
from datetime import datetime, timezone


TOOL_VERSION = "TrailBit/1.0"


class AuditLogger:
    """
    Logs taint analysis runs to daily JSONL files.

    Each entry contains the analysis parameters, results summary,
    and an ISO 8601 timestamp for forensic chain-of-custody records.
    """

    def __init__(self, log_dir: str = "./audit_logs"):
        self.log_dir = log_dir
        os.makedirs(self.log_dir, exist_ok=True)

    def _log_file_path(self) -> str:
        """Return path to today's log file (audit_YYYY-MM-DD.jsonl)."""
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return os.path.join(self.log_dir, f"audit_{date_str}.jsonl")

    def log_analysis(
        self,
        txid: str,
        methodology: str,
        hops: int,
        result_summary: dict,
    ) -> None:
        """
        Append one JSONL entry for a completed analysis run.

        Args:
            txid: The source transaction ID that was analyzed.
            methodology: Taint methodology used (poison, haircut, etc.).
            hops: Number of BFS hops configured.
            result_summary: Summary dict from the analysis report.
        """
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool_version": TOOL_VERSION,
            "txid": txid,
            "methodology": methodology,
            "hops": hops,
            "result_summary": result_summary,
        }

        log_path = self._log_file_path()
        with open(log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
