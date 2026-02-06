"""Haircut methodology: uniform proportional taint distribution."""


def calculate_taint(
    tainted_input_value: float,
    total_input_value: int,
    outputs: list,
) -> list:
    """Each output gets the same taint %: tainted_input / total_input."""
    if total_input_value == 0:
        return [0.0] * len(outputs)
    taint_pct = round((tainted_input_value / total_input_value) * 100, 2)
    return [taint_pct] * len(outputs)
