"""Pro-rata methodology: taint distributed proportionally to output values.

Unlike haircut (which gives every output the same taint %),
pro-rata distributes the absolute tainted satoshis across outputs
weighted by each output's share of total output value, then
converts back to a per-output taint percentage.
"""


def calculate_taint(
    tainted_input_value: float,
    total_input_value: int,
    outputs: list,
) -> list:
    """Distribute tainted value proportionally to output sizes."""
    if total_input_value == 0:
        return [0.0] * len(outputs)

    total_output_value = sum(o.get("value", 0) for o in outputs)
    if total_output_value == 0:
        return [0.0] * len(outputs)

    result = []
    for o in outputs:
        out_val = o.get("value", 0)
        share = out_val / total_output_value
        tainted_sats = tainted_input_value * share
        taint_pct = (tainted_sats / out_val * 100) if out_val > 0 else 0.0
        result.append(round(taint_pct, 2))
    return result
