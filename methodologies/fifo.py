"""FIFO methodology: first-in-first-out taint tracking.

Tainted satoshis are consumed sequentially across outputs in order.
The first output absorbs taint until saturated, then the next, etc.

This produces distinctly different results from haircut/pro-rata
when tainted and clean inputs are mixed.
"""


def calculate_taint(
    tainted_input_value: float,
    total_input_value: int,
    outputs: list,
) -> list:
    """Distribute tainted sats FIFO across outputs."""
    if total_input_value == 0 or tainted_input_value <= 0:
        return [0.0] * len(outputs)

    remaining_taint = tainted_input_value
    result = []

    for o in outputs:
        out_val = o.get("value", 0)
        if out_val <= 0 or remaining_taint <= 0:
            result.append(0.0)
            continue

        consumed = min(remaining_taint, out_val)
        taint_pct = round((consumed / out_val) * 100, 2)
        result.append(taint_pct)
        remaining_taint -= consumed

    return result
