"""Tests for compare_methodologies and API caching."""

import unittest
import unittest.mock as mock

from tests.conftest import load_sample_data, mock_fetch_tx, mock_fetch_outspends
from taint_analysis import TaintAnalyzer, compare_methodologies


class TestCompareMethodologiesDiverge(unittest.TestCase):
    """compare_methodologies must produce different results when mixing occurs."""

    @mock.patch("taint_analysis.fetch_outspends")
    @mock.patch("taint_analysis.fetch_tx")
    def test_methods_diverge_with_mixing(self, mock_tx, mock_outspends):
        """When the tx graph contains mixing, methodologies must give
        different total_tainted_btc values."""
        sample = load_sample_data()
        mock_tx.side_effect = mock_fetch_tx(sample)
        mock_outspends.side_effect = mock_fetch_outspends(sample)

        result = compare_methodologies("aaaa1111", max_hops=1)
        comp = result["comparison"]

        self.assertEqual(set(comp.keys()), {"poison", "haircut", "pro_rata", "fifo"})

        # Poison must produce higher taint than haircut (binary vs proportional)
        self.assertGreater(
            comp["poison"]["total_tainted_btc"],
            comp["haircut"]["total_tainted_btc"],
        )

    @mock.patch("taint_analysis.fetch_outspends")
    @mock.patch("taint_analysis.fetch_tx")
    def test_fifo_differs_from_haircut_per_output(self, mock_tx, mock_outspends):
        """FIFO should produce different per-output distributions than haircut."""
        sample = load_sample_data()
        mock_tx.side_effect = mock_fetch_tx(sample)
        mock_outspends.side_effect = mock_fetch_outspends(sample)

        analyzer = TaintAnalyzer("aaaa1111")
        haircut_report = analyzer.analyze_haircut(max_hops=1)
        fifo_report = analyzer.analyze_fifo(max_hops=1)

        # Extract hop-1 outputs (the mixed tx bbbb2222)
        haircut_hop1 = [o for o in haircut_report["tainted_outputs"] if o["hop"] == 1]
        fifo_hop1 = [o for o in fifo_report["tainted_outputs"] if o["hop"] == 1]

        # Both should have hop-1 outputs
        self.assertTrue(len(haircut_hop1) > 0)
        self.assertTrue(len(fifo_hop1) > 0)

        # Haircut gives uniform percentages; FIFO gives non-uniform
        haircut_pcts = [o["taint_percent"] for o in haircut_hop1]
        fifo_pcts = [o["taint_percent"] for o in fifo_hop1]

        # All haircut percentages should be the same
        self.assertEqual(len(set(haircut_pcts)), 1)

        # FIFO percentages should NOT all be the same (first output gets more)
        self.assertGreater(len(set(fifo_pcts)), 1)


class TestAPICaching(unittest.TestCase):
    """Verify that the API cache prevents redundant calls."""

    @mock.patch("taint_analysis.fetch_outspends")
    @mock.patch("taint_analysis.fetch_tx")
    def test_cache_prevents_duplicate_api_calls(self, mock_tx, mock_outspends):
        """Running two methodologies on the same analyzer should reuse
        cached API responses, not make duplicate calls."""
        sample = load_sample_data()
        mock_tx.side_effect = mock_fetch_tx(sample)
        mock_outspends.side_effect = mock_fetch_outspends(sample)

        analyzer = TaintAnalyzer("aaaa1111")
        analyzer.analyze_poison(max_hops=1)
        calls_after_first = mock_tx.call_count

        analyzer.analyze_haircut(max_hops=1)
        calls_after_second = mock_tx.call_count

        # Second run should NOT make additional fetch_tx calls (all cached)
        self.assertEqual(calls_after_first, calls_after_second)

    @mock.patch("taint_analysis.fetch_outspends")
    @mock.patch("taint_analysis.fetch_tx")
    def test_analysis_state_resets_between_runs(self, mock_tx, mock_outspends):
        """Analysis state (tainted_outputs, analyzed_txs) must reset,
        but cache must persist."""
        sample = load_sample_data()
        mock_tx.side_effect = mock_fetch_tx(sample)
        mock_outspends.side_effect = mock_fetch_outspends(sample)

        analyzer = TaintAnalyzer("aaaa1111")
        report1 = analyzer.analyze_poison(max_hops=1)
        report2 = analyzer.analyze_haircut(max_hops=1)

        # Both should have results (state was reset properly)
        self.assertNotIn("error", report1)
        self.assertNotIn("error", report2)

        # Cache should be populated
        self.assertGreater(len(analyzer._tx_cache), 0)
        self.assertGreater(len(analyzer._outspends_cache), 0)


if __name__ == "__main__":
    unittest.main()
