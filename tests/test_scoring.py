import unittest
from scoring import calculate_confidence, calculate_risk_score


class TestConfidenceScoring(unittest.TestCase):
    def test_hop_0_is_high_confidence(self):
        """Source transaction should have near-perfect confidence."""
        score = calculate_confidence(hop=0, taint_pct=100.0, num_inputs=1, num_outputs=2)
        self.assertGreaterEqual(score, 0.95)

    def test_confidence_decreases_with_hops(self):
        s0 = calculate_confidence(hop=0, taint_pct=100.0, num_inputs=1, num_outputs=2)
        s1 = calculate_confidence(hop=1, taint_pct=100.0, num_inputs=1, num_outputs=2)
        s3 = calculate_confidence(hop=3, taint_pct=100.0, num_inputs=1, num_outputs=2)
        self.assertGreater(s0, s1)
        self.assertGreater(s1, s3)

    def test_mixing_reduces_confidence(self):
        """More inputs (mixing) means less certainty about taint attribution."""
        few_inputs = calculate_confidence(hop=1, taint_pct=50.0, num_inputs=2, num_outputs=2)
        many_inputs = calculate_confidence(hop=1, taint_pct=50.0, num_inputs=10, num_outputs=2)
        self.assertGreater(few_inputs, many_inputs)

    def test_confidence_between_0_and_1(self):
        score = calculate_confidence(hop=5, taint_pct=1.0, num_inputs=20, num_outputs=50)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)


class TestRiskScoring(unittest.TestCase):
    def test_high_taint_high_risk(self):
        risk = calculate_risk_score(taint_pct=95.0, confidence=0.9, hop=0)
        self.assertEqual(risk, "critical")

    def test_medium_taint_medium_risk(self):
        risk = calculate_risk_score(taint_pct=40.0, confidence=0.7, hop=1)
        self.assertIn(risk, ["high", "medium"])

    def test_low_taint_low_risk(self):
        risk = calculate_risk_score(taint_pct=2.0, confidence=0.3, hop=4)
        self.assertIn(risk, ["low", "minimal"])

    def test_risk_levels_are_valid(self):
        for taint in [1, 25, 50, 75, 100]:
            for conf in [0.1, 0.5, 0.9]:
                risk = calculate_risk_score(taint_pct=taint, confidence=conf, hop=1)
                self.assertIn(risk, ["critical", "high", "medium", "low", "minimal"])


if __name__ == "__main__":
    unittest.main()
