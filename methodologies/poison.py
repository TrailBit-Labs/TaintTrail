"""Poison methodology: any tainted input = 100% tainted outputs."""


def calculate_taint(
    tainted_input_value: float,
    total_input_value: int,
    outputs: list,
) -> list:
    """Binary taint: if any input is tainted, all outputs are 100% tainted."""
    taint_pct = 100.0 if tainted_input_value > 0 else 0.0
    return [taint_pct] * len(outputs)
