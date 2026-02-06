"""
ASCII Visualization for Bitcoin Taint Analysis

Provides text-based visualizations of transaction flow and taint propagation
that work in any terminal without external dependencies.

Functions:
    render_tx_flow  - Box diagram showing inputs -> TX -> outputs with taint bars
    render_taint_map - Hop-grouped taint propagation map with ASCII bar charts
"""

from collections import defaultdict

# Bar chart characters
BLOCK_FULL = "\u2588"   # Full block
BLOCK_LIGHT = "\u2591"  # Light shade
BAR_WIDTH = 20


def _format_btc(value_sat: int) -> str:
    """Format satoshi value as BTC string."""
    return f"{value_sat / 1e8:.8f}"


def _taint_bar(pct: float, width: int = BAR_WIDTH) -> str:
    """Render an ASCII bar for the given taint percentage.

    Returns a string like [##########..........] where # is the filled portion
    using Unicode block characters.
    """
    filled = int(round(pct / 100.0 * width))
    filled = max(0, min(filled, width))
    empty = width - filled
    return f"[{BLOCK_FULL * filled}{BLOCK_LIGHT * empty}]"


def _truncate(text: str, length: int) -> str:
    """Truncate text with ellipsis if it exceeds length."""
    if len(text) <= length:
        return text
    if length <= 3:
        return text[:length]
    return text[: length - 3] + "..."


def render_tx_flow(txid: str, inputs: list, outputs: list) -> str:
    """Render an ASCII box diagram of a single transaction's flow.

    Args:
        txid: Transaction ID string.
        inputs: List of dicts with keys: address, value (satoshis), taint_pct.
        outputs: List of dicts with keys: address, value (satoshis), taint_pct.

    Returns:
        Multi-line string with the box diagram.

    Example output::

        +-----------------------------------------------------------+
        |                    TX: aaaa1111...                         |
        +--------------------------+--------------------------------+
        | INPUTS                   | OUTPUTS                        |
        |                          |                                |
        | 1SourceAddr              | 1OutputA                       |
        | 0.00100000 BTC           | 0.00060000 BTC                 |
        | [####################] 100.0% | [####################] 100.0%  |
        |                          |                                |
        |                          | 1OutputB                       |
        |                          | 0.00039000 BTC                 |
        |                          | [####################] 100.0%  |
        +--------------------------+--------------------------------+
    """
    # Column widths
    left_width = 26
    right_width = 32
    total_width = left_width + right_width + 3  # +3 for | separators

    lines = []

    # Top border
    lines.append("+" + "-" * (total_width - 2) + "+")

    # Title
    title = f"TX: {_truncate(txid, total_width - 10)}"
    lines.append("|" + title.center(total_width - 2) + "|")

    # Separator
    lines.append("+" + "-" * left_width + "+" + "-" * right_width + "+")

    # Column headers
    lines.append(
        "| " + "INPUTS".ljust(left_width - 1)
        + "| " + "OUTPUTS".ljust(right_width - 1) + "|"
    )

    # Build rows for each side
    left_rows = []
    for inp in inputs:
        addr = inp.get("address", "unknown")
        val = inp.get("value", 0)
        taint = inp.get("taint_pct", 0.0)
        left_rows.append("")  # blank separator
        left_rows.append(_truncate(addr, left_width - 2))
        left_rows.append(f"{_format_btc(val)} BTC")
        left_rows.append(f"{_taint_bar(taint)} {taint:.1f}%")

    right_rows = []
    for out in outputs:
        addr = out.get("address", "unknown")
        val = out.get("value", 0)
        taint = out.get("taint_pct", 0.0)
        right_rows.append("")  # blank separator
        right_rows.append(_truncate(addr, right_width - 2))
        right_rows.append(f"{_format_btc(val)} BTC")
        right_rows.append(f"{_taint_bar(taint)} {taint:.1f}%")

    # Pad to equal length
    max_rows = max(len(left_rows), len(right_rows))
    while len(left_rows) < max_rows:
        left_rows.append("")
    while len(right_rows) < max_rows:
        right_rows.append("")

    # Render rows
    for left, right in zip(left_rows, right_rows):
        left_cell = " " + left.ljust(left_width - 1)
        right_cell = " " + right.ljust(right_width - 1)
        lines.append("|" + left_cell + "|" + right_cell + "|")

    # Bottom border
    lines.append("+" + "-" * left_width + "+" + "-" * right_width + "+")

    return "\n".join(lines)


def render_taint_map(tainted_outputs: list) -> str:
    """Render a hop-grouped taint propagation map with ASCII bar charts.

    Args:
        tainted_outputs: List of dicts with keys: hop, address, taint_pct,
            value (satoshis). May also contain value_sat instead of value.

    Returns:
        Multi-line string showing taint propagation grouped by hop.

    Example output::

        === Taint Propagation Map ===

        Hop 0 (Source)
          1SourceAddr...   0.00100000 BTC  [####################] 100.0%

        Hop 1
          1OutputA...      0.00060000 BTC  [##########..........] 50.0%
          1OutputB...      0.00039000 BTC  [####................] 20.0%
    """
    if not tainted_outputs:
        return "=== Taint Propagation Map ===\n\n  (no tainted outputs)"

    # Group by hop
    by_hop = defaultdict(list)
    for entry in tainted_outputs:
        hop = entry.get("hop", 0)
        by_hop[hop].append(entry)

    lines = []
    lines.append("=== Taint Propagation Map ===")

    addr_width = 20
    val_width = 18

    for hop in sorted(by_hop.keys()):
        lines.append("")
        if hop == 0:
            lines.append(f"Hop {hop} (Source)")
        else:
            lines.append(f"Hop {hop}")

        entries = by_hop[hop]
        # Sort by taint descending within each hop
        entries.sort(key=lambda e: e.get("taint_pct", 0), reverse=True)

        for entry in entries:
            addr = _truncate(entry.get("address", "unknown"), addr_width)
            # Support both 'value' and 'value_sat' keys
            val = entry.get("value", entry.get("value_sat", 0))
            taint = entry.get("taint_pct", entry.get("taint_percent", 0.0))
            bar = _taint_bar(taint)
            btc_str = _format_btc(val)
            lines.append(
                f"  {addr:<{addr_width}}  {btc_str} BTC  {bar} {taint:.1f}%"
            )

    return "\n".join(lines)
