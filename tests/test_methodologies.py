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

    def test_uneven_outputs_different_from_haircut_in_tracking(self):
        outputs = [{"value": 80000}, {"value": 20000}]
        result = pro_rata_taint(
            tainted_input_value=100000,
            total_input_value=100000,
            outputs=outputs,
        )
        self.assertEqual(result, [100.0, 100.0])


if __name__ == "__main__":
    unittest.main()
