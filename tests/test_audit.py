import unittest
import json
import os
import tempfile
from audit import AuditLogger


class TestAuditLogger(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.logger = AuditLogger(log_dir=self.tmpdir)

    def test_log_creates_file(self):
        self.logger.log_analysis(
            txid="aaaa1111",
            methodology="haircut",
            hops=2,
            result_summary={"tainted_outputs": 5},
        )
        files = os.listdir(self.tmpdir)
        self.assertEqual(len(files), 1)
        self.assertTrue(files[0].endswith(".jsonl"))

    def test_log_entry_has_required_fields(self):
        self.logger.log_analysis(
            txid="aaaa1111",
            methodology="haircut",
            hops=2,
            result_summary={"tainted_outputs": 5},
        )
        log_file = os.path.join(self.tmpdir, os.listdir(self.tmpdir)[0])
        with open(log_file) as f:
            entry = json.loads(f.readline())
        self.assertIn("timestamp", entry)
        self.assertIn("txid", entry)
        self.assertIn("methodology", entry)
        self.assertIn("result_summary", entry)

    def test_multiple_logs_append(self):
        self.logger.log_analysis(txid="a", methodology="haircut", hops=1, result_summary={})
        self.logger.log_analysis(txid="b", methodology="poison", hops=2, result_summary={})
        log_file = os.path.join(self.tmpdir, os.listdir(self.tmpdir)[0])
        with open(log_file) as f:
            lines = f.readlines()
        self.assertEqual(len(lines), 2)

    def test_log_entry_has_tool_version(self):
        self.logger.log_analysis(
            txid="aaaa1111",
            methodology="haircut",
            hops=2,
            result_summary={},
        )
        log_file = os.path.join(self.tmpdir, os.listdir(self.tmpdir)[0])
        with open(log_file) as f:
            entry = json.loads(f.readline())
        self.assertEqual(entry["tool_version"], "TrailBit/1.0")

    def test_log_entry_has_hops(self):
        self.logger.log_analysis(
            txid="aaaa1111",
            methodology="haircut",
            hops=3,
            result_summary={},
        )
        log_file = os.path.join(self.tmpdir, os.listdir(self.tmpdir)[0])
        with open(log_file) as f:
            entry = json.loads(f.readline())
        self.assertEqual(entry["hops"], 3)

    def test_log_file_named_with_date(self):
        self.logger.log_analysis(
            txid="aaaa1111",
            methodology="haircut",
            hops=2,
            result_summary={},
        )
        files = os.listdir(self.tmpdir)
        self.assertTrue(files[0].startswith("audit_"))
        # Should match pattern audit_YYYY-MM-DD.jsonl
        name = files[0]
        self.assertRegex(name, r"^audit_\d{4}-\d{2}-\d{2}\.jsonl$")

    def test_timestamp_is_iso8601(self):
        self.logger.log_analysis(
            txid="aaaa1111",
            methodology="haircut",
            hops=2,
            result_summary={},
        )
        log_file = os.path.join(self.tmpdir, os.listdir(self.tmpdir)[0])
        with open(log_file) as f:
            entry = json.loads(f.readline())
        # Should be parseable as ISO 8601
        from datetime import datetime
        ts = entry["timestamp"]
        # datetime.fromisoformat handles ISO 8601 strings
        parsed = datetime.fromisoformat(ts)
        self.assertIsNotNone(parsed)

    def test_creates_log_dir_if_missing(self):
        nested = os.path.join(self.tmpdir, "nested", "audit")
        logger = AuditLogger(log_dir=nested)
        logger.log_analysis(
            txid="aaaa1111",
            methodology="haircut",
            hops=1,
            result_summary={},
        )
        self.assertTrue(os.path.isdir(nested))
        self.assertEqual(len(os.listdir(nested)), 1)

    def test_result_summary_preserved(self):
        summary = {"tainted_outputs": 5, "total_tainted_btc": 0.123}
        self.logger.log_analysis(
            txid="aaaa1111",
            methodology="haircut",
            hops=2,
            result_summary=summary,
        )
        log_file = os.path.join(self.tmpdir, os.listdir(self.tmpdir)[0])
        with open(log_file) as f:
            entry = json.loads(f.readline())
        self.assertEqual(entry["result_summary"], summary)


if __name__ == "__main__":
    unittest.main()
