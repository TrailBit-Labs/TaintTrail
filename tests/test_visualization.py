import unittest
from visualization import render_tx_flow, render_taint_map


class TestTxFlowVisualization(unittest.TestCase):
    def test_simple_flow_contains_addresses(self):
        """Flow chart should show input and output addresses."""
        inputs = [{"address": "1SourceAddr", "value": 100000, "taint_pct": 100.0}]
        outputs = [
            {"address": "1OutputA", "value": 60000, "taint_pct": 100.0},
            {"address": "1OutputB", "value": 39000, "taint_pct": 100.0},
        ]
        result = render_tx_flow("aaaa1111", inputs, outputs)
        self.assertIn("1SourceAddr", result)
        self.assertIn("1OutputA", result)
        self.assertIn("1OutputB", result)

    def test_flow_contains_values(self):
        inputs = [{"address": "1Src", "value": 100000, "taint_pct": 50.0}]
        outputs = [{"address": "1Dst", "value": 99000, "taint_pct": 50.0}]
        result = render_tx_flow("abcd", inputs, outputs)
        self.assertIn("0.001", result)  # 100000 sats = 0.001 BTC

    def test_flow_is_multiline(self):
        inputs = [{"address": "1Src", "value": 100000, "taint_pct": 100.0}]
        outputs = [{"address": "1Dst", "value": 99000, "taint_pct": 100.0}]
        result = render_tx_flow("abcd", inputs, outputs)
        self.assertGreater(result.count("\n"), 3)


class TestTaintMap(unittest.TestCase):
    def test_taint_map_shows_hops(self):
        """Taint map should show hop levels and taint percentages."""
        tainted_outputs = [
            {"hop": 0, "address": "1Source", "taint_pct": 100.0, "value": 50000},
            {"hop": 1, "address": "1Next", "taint_pct": 60.0, "value": 30000},
        ]
        result = render_taint_map(tainted_outputs)
        self.assertIn("Hop 0", result)
        self.assertIn("Hop 1", result)
        self.assertIn("100.0%", result)

    def test_taint_map_has_bar_chart(self):
        """Should include ASCII bar representation of taint levels."""
        tainted_outputs = [
            {"hop": 0, "address": "1Full", "taint_pct": 100.0, "value": 50000},
            {"hop": 0, "address": "1Half", "taint_pct": 50.0, "value": 50000},
        ]
        result = render_taint_map(tainted_outputs)
        self.assertIn("\u2588", result)  # Unicode full block character


if __name__ == "__main__":
    unittest.main()
