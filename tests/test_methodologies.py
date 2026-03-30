import unittest
from methodologies.poison import calculate_taint as poison_taint
from methodologies.haircut import calculate_taint as haircut_taint
from methodologies.pro_rata import calculate_taint as pro_rata_taint


class TestPoisonMethodology(unittest.TestCase):
    def test_any_taint_means_100_percent(self):
        """Any tainted input should make all outputs 100% tainted."""
        outputs = [{"value": 50000}, {"value": 40000}]
        result = poison_taint(
            tainted_input_value=1000,
            total_input_value=100000,
            outputs=outputs,
        )
        self.assertEqual(result, [100.0, 100.0])

    def test_no_taint_means_zero(self):
        outputs = [{"value": 50000}]
        result = poison_taint(
            tainted_input_value=0,
            total_input_value=100000,
            outputs=outputs,
        )
        self.assertEqual(result, [0.0])


class TestHaircutMethodology(unittest.TestCase):
    def test_proportional_distribution(self):
        """Taint % = tainted_input / total_input, same for all outputs."""
        outputs = [{"value": 60000}, {"value": 40000}]
        result = haircut_taint(
            tainted_input_value=50000,
            total_input_value=100000,
            outputs=outputs,
        )
        self.assertEqual(result, [50.0, 50.0])

    def test_full_taint(self):
        outputs = [{"value": 100000}]
        result = haircut_taint(
            tainted_input_value=100000,
            total_input_value=100000,
            outputs=outputs,
        )
        self.assertEqual(result, [100.0])


class TestProRataMethodology(unittest.TestCase):
    def test_weighted_distribution(self):
        """Pro-rata distributes tainted sats proportionally to output values."""
        outputs = [{"value": 75000}, {"value": 25000}]
        result = pro_rata_taint(
            tainted_input_value=50000,
            total_input_value=100000,
            outputs=outputs,
        )
        self.assertEqual(result, [50.0, 50.0])

    def test_fully_tainted_input_taints_all_outputs(self):
        """When all input value is tainted, all outputs are 100% regardless of size."""
        outputs = [{"value": 80000}, {"value": 20000}]
        result = pro_rata_taint(
            tainted_input_value=100000,
            total_input_value=100000,
            outputs=outputs,
        )
        self.assertEqual(result, [100.0, 100.0])


class TestProRataVsHaircut(unittest.TestCase):
    """Pro-rata divides by total_output_value (excludes fee);
    haircut divides by total_input_value (includes fee).
    When fees are non-trivial, the percentages diverge."""

    def test_pro_rata_higher_than_haircut_due_to_fee(self):
        outputs = [{"value": 45000}, {"value": 45000}]
        tainted = 50000
        total_input = 100000  # 10000 sat fee (total_output=90000)

        h = haircut_taint(tainted, total_input, outputs)
        p = pro_rata_taint(tainted, total_input, outputs)

        # Haircut: 50000/100000 = 50%
        self.assertEqual(h, [50.0, 50.0])
        # Pro-rata: 50000/90000 ≈ 55.56%
        self.assertAlmostEqual(p[0], 55.56, places=1)
        self.assertAlmostEqual(p[1], 55.56, places=1)
        # Pro-rata is higher because fee doesn't absorb taint
        self.assertGreater(p[0], h[0])


if __name__ == "__main__":
    unittest.main()
