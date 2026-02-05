import unittest
from methodologies.fifo import calculate_taint


class TestFIFOMethodology(unittest.TestCase):
    def test_tainted_first_consumes_first_output(self):
        """If tainted input comes first and is larger than first output,
        first output is 100% tainted, remainder spills to second."""
        outputs = [{"value": 30000}, {"value": 70000}]
        result = calculate_taint(
            tainted_input_value=50000,
            total_input_value=100000,
            outputs=outputs,
        )
        self.assertAlmostEqual(result[0], 100.0, places=1)
        self.assertAlmostEqual(result[1], 28.57, places=1)

    def test_small_taint_only_affects_first_output(self):
        """If tainted amount is smaller than first output, only first output is tainted."""
        outputs = [{"value": 60000}, {"value": 40000}]
        result = calculate_taint(
            tainted_input_value=20000,
            total_input_value=100000,
            outputs=outputs,
        )
        self.assertAlmostEqual(result[0], 33.33, places=1)
        self.assertAlmostEqual(result[1], 0.0, places=1)

    def test_fully_tainted(self):
        """When all inputs are tainted, all outputs are 100%."""
        outputs = [{"value": 50000}, {"value": 50000}]
        result = calculate_taint(
            tainted_input_value=100000,
            total_input_value=100000,
            outputs=outputs,
        )
        self.assertEqual(result, [100.0, 100.0])

    def test_no_taint(self):
        outputs = [{"value": 50000}]
        result = calculate_taint(
            tainted_input_value=0,
            total_input_value=100000,
            outputs=outputs,
        )
        self.assertEqual(result, [0.0])

    def test_three_outputs_spillover(self):
        """Taint spills across multiple outputs."""
        outputs = [{"value": 10000}, {"value": 10000}, {"value": 80000}]
        result = calculate_taint(
            tainted_input_value=25000,
            total_input_value=100000,
            outputs=outputs,
        )
        self.assertAlmostEqual(result[0], 100.0, places=1)
        self.assertAlmostEqual(result[1], 100.0, places=1)
        self.assertAlmostEqual(result[2], 6.25, places=1)


if __name__ == "__main__":
    unittest.main()
