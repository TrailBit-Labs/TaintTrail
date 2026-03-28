"""Confidence and risk scoring for taint analysis results.

Confidence score (0.0-1.0): how reliable is this taint attribution?
Risk score (critical/high/medium/low/minimal): compliance risk level.
"""


def calculate_confidence(
    hop: int,
    taint_pct: float,
    num_inputs: int,
    num_outputs: int,
) -> float:
    """Calculate confidence score for a taint attribution.

    Factors that reduce confidence:
    - More hops from source (exponential decay)
    - More inputs in transaction (mixing uncertainty)
    - More outputs (fan-out uncertainty)
    - Lower taint percentage (dilution)

    Returns float between 0.0 and 1.0.
    """
    hop_factor = 0.85 ** hop
    mixing_factor = 1.0 / (1.0 + 0.15 * (num_inputs - 1))
    fanout_factor = 1.0 / (1.0 + 0.05 * (num_outputs - 1))
    dilution_factor = min(1.0, taint_pct / 10.0) if taint_pct > 0 else 0.0

    raw = hop_factor * mixing_factor * fanout_factor * dilution_factor
    return round(max(0.0, min(1.0, raw)), 4)


def calculate_risk_score(
    taint_pct: float,
    confidence: float,
    hop: int,
) -> str:
    """Calculate compliance risk level.

    Combines taint percentage and confidence into a risk category.
    """
    proximity_boost = max(0.5, 1.0 - (hop * 0.1))
    risk_value = (taint_pct / 100.0) * confidence * proximity_boost

    if risk_value >= 0.7:
        return "critical"
    elif risk_value >= 0.4:
        return "high"
    elif risk_value >= 0.2:
        return "medium"
    elif risk_value >= 0.05:
        return "low"
    else:
        return "minimal"
