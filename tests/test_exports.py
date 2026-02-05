import unittest
import csv
import io
from exports.csv_export import export_csv
from exports.markdown_export import export_markdown
from exports.text_export import export_text


class TestCSVExport(unittest.TestCase):
    def test_csv_has_header(self):
        report = self._sample_report()
        output = export_csv(report)
        reader = csv.reader(io.StringIO(output))
        header = next(reader)
        self.assertIn("txid", header)
        self.assertIn("address", header)
        self.assertIn("taint_pct", header)

    def test_csv_has_data_rows(self):
        report = self._sample_report()
        output = export_csv(report)
        lines = output.strip().split("\n")
        self.assertGreaterEqual(len(lines), 2)  # header + at least 1 row

    def test_csv_values_match_report(self):
        report = self._sample_report()
        output = export_csv(report)
        reader = csv.DictReader(io.StringIO(output))
        rows = list(reader)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["txid"], "aaaa1111")
        self.assertEqual(rows[0]["address"], "1Addr")
        self.assertEqual(rows[0]["taint_pct"], "100.0")
        self.assertEqual(rows[0]["value_sat"], "50000")

    def test_csv_multiple_outputs(self):
        report = self._sample_report()
        report["tainted_outputs"].append(
            {"txid": "bbbb2222", "vout_index": 1, "address": "1Other",
             "value_sat": 30000, "taint_percent": 50.0, "hop": 1,
             "confidence": 0.8, "risk": "high"}
        )
        output = export_csv(report)
        lines = output.strip().split("\n")
        self.assertEqual(len(lines), 3)  # header + 2 rows

    def test_csv_empty_outputs(self):
        report = self._sample_report()
        report["tainted_outputs"] = []
        output = export_csv(report)
        lines = output.strip().split("\n")
        self.assertEqual(len(lines), 1)  # header only

    def _sample_report(self):
        return {
            "methodology": "haircut",
            "source_txid": "aaaa1111",
            "tainted_outputs": [
                {"txid": "aaaa1111", "vout_index": 0, "address": "1Addr",
                 "value_sat": 50000, "taint_percent": 100.0, "hop": 0,
                 "confidence": 0.95, "risk": "critical"},
            ],
            "summary": {"transactions_analyzed": 1, "tainted_outputs": 1,
                         "total_tainted_btc": 0.0005, "max_hop_reached": 0},
        }


class TestMarkdownExport(unittest.TestCase):
    def test_markdown_has_header(self):
        report = self._sample_report()
        output = export_markdown(report)
        self.assertIn("# Taint Analysis Report", output)

    def test_markdown_has_summary_table(self):
        report = self._sample_report()
        output = export_markdown(report)
        self.assertIn("|", output)  # Table formatting
        self.assertIn("Methodology", output)

    def test_markdown_has_findings(self):
        report = self._sample_report()
        output = export_markdown(report)
        self.assertIn("aaaa1111", output)

    def test_markdown_has_methodology(self):
        report = self._sample_report()
        output = export_markdown(report)
        self.assertIn("haircut", output.lower())

    def test_markdown_has_top_addresses(self):
        report = self._sample_report()
        output = export_markdown(report)
        self.assertIn("1Addr", output)

    def test_markdown_sorted_by_hop_then_taint(self):
        report = self._sample_report()
        report["tainted_outputs"].append(
            {"txid": "bbbb2222", "vout_index": 1, "address": "1Other",
             "value_sat": 30000, "taint_percent": 50.0, "hop": 0,
             "confidence": 0.8, "risk": "high"}
        )
        output = export_markdown(report)
        # 100% taint should appear before 50% taint (both at hop 0)
        pos_100 = output.index("100.0")
        pos_50 = output.index("50.0")
        self.assertLess(pos_100, pos_50)

    def _sample_report(self):
        return {
            "methodology": "haircut",
            "source_txid": "aaaa1111",
            "source_label": "Tainted Source",
            "tainted_outputs": [
                {"txid": "aaaa1111", "vout_index": 0, "address": "1Addr",
                 "value_sat": 50000, "taint_percent": 100.0, "hop": 0,
                 "confidence": 0.95, "risk": "critical"},
            ],
            "summary": {"transactions_analyzed": 1, "tainted_outputs": 1,
                         "total_tainted_btc": 0.0005, "max_hop_reached": 0},
            "by_hop": {0: {"count": 1, "total_btc": 0.0005, "avg_taint_pct": 100.0}},
            "top_tainted_addresses": [{"address": "1Addr", "tainted_btc": 0.0005}],
        }


class TestTextExport(unittest.TestCase):
    def test_text_has_report_header(self):
        report = self._sample_report()
        output = export_text(report)
        self.assertIn("Taint Analysis Report", output)

    def test_text_has_methodology(self):
        report = self._sample_report()
        output = export_text(report)
        self.assertIn("HAIRCUT", output)

    def test_text_has_summary(self):
        report = self._sample_report()
        output = export_text(report)
        self.assertIn("Summary", output)
        self.assertIn("Transactions analyzed", output)

    def test_text_has_by_hop(self):
        report = self._sample_report()
        output = export_text(report)
        self.assertIn("Hop 0", output)

    def test_text_has_top_addresses(self):
        report = self._sample_report()
        output = export_text(report)
        self.assertIn("1Addr", output)

    def test_text_has_risk_summary(self):
        report = self._sample_report()
        output = export_text(report)
        self.assertIn("Risk Summary", output)
        self.assertIn("CRITICAL", output)

    def _sample_report(self):
        return {
            "methodology": "haircut",
            "source_txid": "aaaa1111",
            "source_label": "Tainted Source",
            "tainted_outputs": [
                {"txid": "aaaa1111", "vout_index": 0, "address": "1Addr",
                 "value_sat": 50000, "taint_percent": 100.0, "hop": 0,
                 "confidence": 0.95, "risk": "critical"},
            ],
            "summary": {"transactions_analyzed": 1, "tainted_outputs": 1,
                         "total_tainted_btc": 0.0005, "max_hop_reached": 0},
            "by_hop": {0: {"count": 1, "total_btc": 0.0005, "avg_taint_pct": 100.0,
                           "avg_confidence": 0.95}},
            "top_tainted_addresses": [{"address": "1Addr", "tainted_btc": 0.0005}],
        }


if __name__ == "__main__":
    unittest.main()
