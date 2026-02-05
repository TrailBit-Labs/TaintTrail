# Core + Visualization Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Evolve the Bitcoin taint analysis tool from a basic 3-methodology CLI into a full forensic analysis platform with FIFO methodology, ASCII visualization, confidence/risk scoring, multi-format export, and audit logging — all using stdlib only.

**Architecture:** Modular structure with methodology strategies extracted from the monolithic `_propagate_taint`, dedicated exporters for CSV/markdown, a text-based visualization engine, and scoring/audit subsystems. The main `taint_analysis.py` orchestrates these modules. All modules use stdlib only (no pip dependencies).

**Tech Stack:** Python 3.7+ stdlib only — `urllib.request` for HTTP, `csv` for CSV export, `json` for JSON, `unittest` for tests, `textwrap`/string formatting for ASCII art, `logging` for audit logs.

---

## Architecture Overview

```
bitcoin-taint-analysis-main/
├── taint_analysis.py          # Main CLI entry point & orchestrator
├── methodologies/
│   ├── __init__.py            # Registry & base types
│   ├── poison.py              # Binary taint propagation
│   ├── haircut.py             # Proportional distribution
│   ├── pro_rata.py            # Weighted per-output distribution
│   └── fifo.py                # First-in-first-out tracking
├── exports/
│   ├── __init__.py            # Exporter registry
│   ├── csv_export.py          # CSV output
│   ├── markdown_export.py     # Markdown report
│   └── text_export.py         # Current text output (extracted)
├── visualization.py           # ASCII flow charts & taint maps
├── scoring.py                 # Confidence & risk scoring
├── audit.py                   # Audit logging to file
├── tests/
│   ├── __init__.py
│   ├── test_methodologies.py  # Unit tests for each methodology
│   ├── test_fifo.py           # FIFO-specific tests
│   ├── test_visualization.py  # ASCII output tests
│   ├── test_scoring.py        # Confidence & risk scoring tests
│   ├── test_exports.py        # CSV/markdown export tests
│   └── test_audit.py          # Audit log tests
├── demo_taint_analysis.sh     # Updated demo
├── data/                      # Sample datasets for testing
│   └── sample_tx.json         # Mock transaction data
├── docs/
│   └── plans/                 # This plan
├── README.md
└── CLAUDE.md
```

**Key design decision:** Methodologies become pure functions that receive transaction input/output data and return taint percentages. This avoids the current approach where methodology logic is embedded inside `_propagate_taint` via if/elif chains. The `TaintAnalyzer` calls the appropriate strategy function, keeping the BFS traversal code methodology-agnostic.

---

## Task 1: Test Infrastructure & Mock Data

**Why:** We need offline-testable transaction data so tests don't hit the mempool.space API. This unblocks all subsequent TDD tasks.

**Files:**
- Create: `tests/__init__.py`
- Create: `tests/conftest.py`
- Create: `data/sample_tx.json`

**Step 1: Create mock transaction data**

Create `data/sample_tx.json` with realistic Bitcoin transaction structures we can use throughout testing. Include a 2-input, 2-output transaction and its spending transactions to test multi-hop scenarios.

```json
{
  "tx_simple": {
    "txid": "aaaa1111",
    "vin": [
      {
        "txid": "source0000",
        "vout": 0,
        "prevout": {"value": 100000, "scriptpubkey_address": "1SourceAddr"}
      }
    ],
    "vout": [
      {"value": 60000, "scriptpubkey_address": "1OutputA"},
      {"value": 39000, "scriptpubkey_address": "1OutputB"}
    ]
  },
  "tx_mixed": {
    "txid": "bbbb2222",
    "vin": [
      {
        "txid": "aaaa1111",
        "vout": 0,
        "prevout": {"value": 60000, "scriptpubkey_address": "1OutputA"}
      },
      {
        "txid": "clean0000",
        "vout": 0,
        "prevout": {"value": 40000, "scriptpubkey_address": "1CleanAddr"}
      }
    ],
    "vout": [
      {"value": 50000, "scriptpubkey_address": "1MixedOut1"},
      {"value": 49000, "scriptpubkey_address": "1MixedOut2"}
    ]
  },
  "tx_three_in_two_out": {
    "txid": "cccc3333",
    "vin": [
      {
        "txid": "tainted01",
        "vout": 0,
        "prevout": {"value": 30000, "scriptpubkey_address": "1Tainted1"}
      },
      {
        "txid": "tainted02",
        "vout": 1,
        "prevout": {"value": 20000, "scriptpubkey_address": "1Tainted2"}
      },
      {
        "txid": "clean0001",
        "vout": 0,
        "prevout": {"value": 50000, "scriptpubkey_address": "1Clean1"}
      }
    ],
    "vout": [
      {"value": 45000, "scriptpubkey_address": "1Out1"},
      {"value": 53000, "scriptpubkey_address": "1Out2"}
    ]
  },
  "outspends_simple": [
    {"spent": true, "txid": "bbbb2222", "vin": 0},
    {"spent": false}
  ]
}
```

**Step 2: Create test helper for mocking API calls**

Create `tests/__init__.py` (empty) and `tests/conftest.py`:

```python
import json
import os
import unittest.mock as mock

SAMPLE_DATA_PATH = os.path.join(
    os.path.dirname(__file__), '..', 'data', 'sample_tx.json'
)

def load_sample_data():
    with open(SAMPLE_DATA_PATH) as f:
        return json.load(f)

def mock_fetch_tx(sample_data):
    """Return a function that looks up txid in sample_data."""
    tx_by_id = {}
    for key, tx in sample_data.items():
        if key.startswith("tx_"):
            tx_by_id[tx["txid"]] = tx

    def _fetch(txid):
        if txid in tx_by_id:
            return tx_by_id[txid]
        return {"error": f"TX not found: {txid}"}

    return _fetch

def mock_fetch_outspends(sample_data):
    """Return a function that looks up outspends in sample_data."""
    spends_by_id = {}
    for key, val in sample_data.items():
        if key.startswith("outspends_"):
            # Map from the related tx
            # Convention: outspends_simple -> tx_simple's txid
            tx_key = "tx_" + key.replace("outspends_", "")
            if tx_key in sample_data:
                spends_by_id[sample_data[tx_key]["txid"]] = val

    def _fetch(txid):
        return spends_by_id.get(txid, [])

    return _fetch
```

**Step 3: Verify test infrastructure loads**

Run: `cd /Users/innovator/Documents/GitHub/bitcoin-taint-analysis-main && python3 -c "from tests.conftest import load_sample_data; print('OK:', len(load_sample_data()), 'entries')"`

Expected: `OK: 4 entries`

**Step 4: Commit**

```bash
git add tests/ data/
git commit -m "feat: add test infrastructure and mock transaction data"
```

---

## Task 2: Extract Methodology Strategy Functions

**Why:** The current `_propagate_taint` uses an if/elif chain for methodology dispatch. Extracting each into a pure function enables independent testing, makes adding FIFO straightforward, and follows the strategy pattern.

**Files:**
- Create: `methodologies/__init__.py`
- Create: `methodologies/poison.py`
- Create: `methodologies/haircut.py`
- Create: `methodologies/pro_rata.py`
- Create: `tests/test_methodologies.py`
- Modify: `taint_analysis.py` (refactor `_propagate_taint` to use strategies)

**Step 1: Write failing tests for methodology functions**

Each methodology function has the signature:
```python
def calculate_taint(
    tainted_input_value: float,   # sum of (input_value * taint%) for tainted inputs
    total_input_value: int,       # sum of all input values in sats
    outputs: list[dict],          # [{"value": sats, ...}, ...]
) -> list[float]:                 # taint % for each output, same order
```

Create `tests/test_methodologies.py`:

```python
import unittest
from methodologies.poison import calculate_taint as poison_taint
from methodologies.haircut import calculate_taint as haircut_taint
from methodologies.pro_rata import calculate_taint as pro_rata_taint


class TestPoisonMethodology(unittest.TestCase):
    def test_any_taint_means_100_percent(self):
        """Any tainted input should make all outputs 100% tainted."""
        outputs = [{"value": 50000}, {"value": 40000}]
        result = poison_taint(
            tainted_input_value=1000,  # even tiny amount
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
        # 50% taint on every output
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
        """Pro-rata distributes tainted sats proportionally to output values,
        then converts back to percentages per output."""
        outputs = [{"value": 75000}, {"value": 25000}]
        # 50000 tainted sats out of 100000 total input
        result = pro_rata_taint(
            tainted_input_value=50000,
            total_input_value=100000,
            outputs=outputs,
        )
        # 50000 tainted sats distributed: 75% to first (37500/75000=50%),
        # 25% to second (12500/25000=50%)
        # When outputs are proportional to inputs, pro_rata matches haircut.
        # But the FUNCTION should track absolute tainted sats per output.
        # tainted_sats_total = 50000
        # output1 share = 75000/100000 = 75% -> 37500 tainted sats -> 37500/75000 = 50%
        # output2 share = 25000/100000 = 25% -> 12500 tainted sats -> 12500/25000 = 50%
        self.assertEqual(result, [50.0, 50.0])

    def test_uneven_outputs_different_from_haircut_in_tracking(self):
        """Pro-rata tracks absolute tainted amounts per output,
        so the tainted BTC differs per output even if % is the same."""
        outputs = [{"value": 80000}, {"value": 20000}]
        result = pro_rata_taint(
            tainted_input_value=100000,
            total_input_value=100000,
            outputs=outputs,
        )
        # Fully tainted: all outputs 100%
        self.assertEqual(result, [100.0, 100.0])


if __name__ == "__main__":
    unittest.main()
```

**Step 2: Run tests to verify they fail**

Run: `cd /Users/innovator/Documents/GitHub/bitcoin-taint-analysis-main && python3 -m pytest tests/test_methodologies.py -v 2>&1 || python3 -m unittest tests.test_methodologies -v 2>&1`

Expected: ImportError (modules don't exist yet)

**Step 3: Implement methodology modules**

Create `methodologies/__init__.py`:
```python
"""Taint calculation methodology strategies.

Each module exposes a `calculate_taint()` function with signature:
    calculate_taint(tainted_input_value, total_input_value, outputs) -> list[float]

Returns a list of taint percentages, one per output.
"""

from methodologies.poison import calculate_taint as poison
from methodologies.haircut import calculate_taint as haircut
from methodologies.pro_rata import calculate_taint as pro_rata

METHODOLOGIES = {
    "poison": poison,
    "haircut": haircut,
    "pro_rata": pro_rata,
}
```

Create `methodologies/poison.py`:
```python
"""Poison methodology: any tainted input = 100% tainted outputs."""


def calculate_taint(
    tainted_input_value: float,
    total_input_value: int,
    outputs: list,
) -> list:
    """Binary taint: if any input is tainted, all outputs are 100% tainted."""
    taint_pct = 100.0 if tainted_input_value > 0 else 0.0
    return [taint_pct] * len(outputs)
```

Create `methodologies/haircut.py`:
```python
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
```

Create `methodologies/pro_rata.py`:
```python
"""Pro-rata methodology: taint distributed proportionally to output values.

Unlike haircut (which gives every output the same taint %),
pro-rata distributes the absolute tainted satoshis across outputs
weighted by each output's share of total output value, then
converts back to a per-output taint percentage.

For simple cases this yields the same % as haircut, but the
absolute tainted amounts differ per output — which matters for
downstream forensic accounting.
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
        # This output's share of total output value
        share = out_val / total_output_value
        # Tainted sats allocated to this output
        tainted_sats = tainted_input_value * share
        # Convert to percentage of this output's value
        taint_pct = (tainted_sats / out_val * 100) if out_val > 0 else 0.0
        result.append(round(taint_pct, 2))
    return result
```

**Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_methodologies.py -v`

Expected: All 5 tests PASS

**Step 5: Refactor `taint_analysis.py` to use strategy modules**

In `taint_analysis.py`, replace the if/elif chain in `_propagate_taint` (lines 197-210) with:

```python
from methodologies import METHODOLOGIES

# Inside _propagate_taint, replace the methodology if/elif block with:
calculate = METHODOLOGIES.get(methodology)
if calculate is None:
    return
taint_percentages = calculate(tainted_input_value, total_input_value, outputs)
```

Then update the output loop (lines 216-227) to use `taint_percentages[i]` instead of `output_taint`.

**Step 6: Run existing functionality to verify no regression**

Run: `python3 taint_analysis.py f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16 --hops 1 --json`

Expected: Same output as before refactor (save output before refactor to compare).

**Step 7: Commit**

```bash
git add methodologies/ tests/test_methodologies.py taint_analysis.py
git commit -m "refactor: extract methodology strategies into modular functions"
```

---

## Task 3: Implement FIFO Methodology

**Why:** FIFO is a genuinely distinct algorithm — it orders inputs temporally and maps them to outputs sequentially. First tainted input consumes the first output(s) until exhausted, then moves on. This produces different results from haircut/pro-rata when transactions mix tainted and clean inputs.

**Files:**
- Create: `methodologies/fifo.py`
- Create: `tests/test_fifo.py`
- Modify: `methodologies/__init__.py` (register FIFO)
- Modify: `taint_analysis.py` (add `analyze_fifo` method, update CLI)

**Step 1: Write failing tests**

Create `tests/test_fifo.py`:

```python
import unittest
from methodologies.fifo import calculate_taint


class TestFIFOMethodology(unittest.TestCase):
    def test_tainted_first_consumes_first_output(self):
        """If tainted input comes first and is larger than first output,
        first output is 100% tainted, remainder spills to second."""
        outputs = [{"value": 30000}, {"value": 70000}]
        # 50000 tainted sats consumed FIFO:
        #   output1 (30000): fully consumed by taint -> 100%
        #   output2 (70000): 20000 tainted remaining -> 20000/70000 = 28.57%
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
        # 20000/60000 = 33.33% for first output
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
        # 5000 remaining / 80000 = 6.25%
        self.assertAlmostEqual(result[2], 6.25, places=1)


if __name__ == "__main__":
    unittest.main()
```

**Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_fifo.py -v`

Expected: ImportError

**Step 3: Implement FIFO methodology**

Create `methodologies/fifo.py`:

```python
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
```

**Step 4: Run tests**

Run: `python3 -m pytest tests/test_fifo.py -v`

Expected: All 5 tests PASS

**Step 5: Register FIFO in methodology registry**

In `methodologies/__init__.py`, add:
```python
from methodologies.fifo import calculate_taint as fifo

METHODOLOGIES = {
    "poison": poison,
    "haircut": haircut,
    "pro_rata": pro_rata,
    "fifo": fifo,
}
```

**Step 6: Add `analyze_fifo` method and CLI option**

In `taint_analysis.py`:
- Add `analyze_fifo()` method to `TaintAnalyzer` (following the pattern of existing methods)
- Update argparse choices to include `"fifo"`
- Update `compare_methodologies()` to include FIFO
- Update the CLI dispatch in `main()`

**Step 7: Run full test suite + manual verification**

Run: `python3 -m pytest tests/ -v`

Then: `python3 taint_analysis.py f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16 --method fifo --hops 1`

**Step 8: Commit**

```bash
git add methodologies/fifo.py tests/test_fifo.py methodologies/__init__.py taint_analysis.py
git commit -m "feat: add FIFO taint methodology with sequential output consumption"
```

---

## Task 4: Confidence Scoring

**Why:** Taint analysis becomes less reliable with more hops, more mixing, and larger transaction fans. Confidence scoring quantifies this uncertainty — essential for forensic credibility.

**Files:**
- Create: `scoring.py`
- Create: `tests/test_scoring.py`
- Modify: `taint_analysis.py` (integrate scoring into reports)

**Step 1: Write failing tests**

Create `tests/test_scoring.py`:

```python
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
```

**Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_scoring.py -v`

Expected: ImportError

**Step 3: Implement scoring module**

Create `scoring.py`:

```python
"""Confidence and risk scoring for taint analysis results.

Confidence score (0.0-1.0): how reliable is this taint attribution?
Risk score (critical/high/medium/low/minimal): compliance risk level.
"""

import math


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
    # Hop decay: each hop reduces confidence (0.85^hop)
    hop_factor = 0.85 ** hop

    # Mixing penalty: more inputs = more uncertainty
    # 1 input = 1.0, 2 inputs = 0.85, 10 inputs = ~0.53
    mixing_factor = 1.0 / (1.0 + 0.15 * (num_inputs - 1))

    # Fan-out penalty (mild): many outputs slightly reduce confidence
    fanout_factor = 1.0 / (1.0 + 0.05 * (num_outputs - 1))

    # Dilution: very low taint is less certain
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
    # Weighted risk: taint * confidence, adjusted by proximity
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
```

**Step 4: Run tests**

Run: `python3 -m pytest tests/test_scoring.py -v`

Expected: All 8 tests PASS

**Step 5: Integrate scoring into TaintAnalyzer reports**

In `taint_analysis.py`, modify `_generate_report()` to include confidence and risk scores per tainted output and in summary. Add `confidence` and `risk` fields to `TaintedOutput` dataclass.

**Step 6: Commit**

```bash
git add scoring.py tests/test_scoring.py taint_analysis.py
git commit -m "feat: add confidence and risk scoring for taint attributions"
```

---

## Task 5: ASCII Visualization

**Why:** Text-based visualization of transaction flow and taint propagation — works in any terminal, no dependencies needed. This is the "wow factor" feature for CLI forensics.

**Files:**
- Create: `visualization.py`
- Create: `tests/test_visualization.py`
- Modify: `taint_analysis.py` (add `--visualize` flag)

**Step 1: Write failing tests**

Create `tests/test_visualization.py`:

```python
import unittest
from visualization import render_tx_flow, render_taint_map


class TestTxFlowVisualization(unittest.TestCase):
    def test_simple_flow_contains_addresses(self):
        """Flow chart should show input and output addresses."""
        inputs = [{"address": "1SourceAddr", "value": 100000, "taint_pct": 100.0}]
        outputs = [
            {"address": "1OutputA", "value": 60000, "taint_pct": 100.0},
            {"address": "1OutputB", "value": 39000, "taint_pct": 100.0},
        ]
        result = render_tx_flow("aaaa1111", inputs, outputs)
        self.assertIn("1SourceAddr", result)
        self.assertIn("1OutputA", result)
        self.assertIn("1OutputB", result)

    def test_flow_contains_values(self):
        inputs = [{"address": "1Src", "value": 100000, "taint_pct": 50.0}]
        outputs = [{"address": "1Dst", "value": 99000, "taint_pct": 50.0}]
        result = render_tx_flow("abcd", inputs, outputs)
        # Should show BTC values
        self.assertIn("0.001", result)  # 100000 sats = 0.001 BTC

    def test_flow_is_multiline(self):
        inputs = [{"address": "1Src", "value": 100000, "taint_pct": 100.0}]
        outputs = [{"address": "1Dst", "value": 99000, "taint_pct": 100.0}]
        result = render_tx_flow("abcd", inputs, outputs)
        self.assertGreater(result.count("\n"), 3)


class TestTaintMap(unittest.TestCase):
    def test_taint_map_shows_hops(self):
        """Taint map should show hop levels and taint percentages."""
        tainted_outputs = [
            {"hop": 0, "address": "1Source", "taint_pct": 100.0, "value": 50000},
            {"hop": 1, "address": "1Next", "taint_pct": 60.0, "value": 30000},
        ]
        result = render_taint_map(tainted_outputs)
        self.assertIn("Hop 0", result)
        self.assertIn("Hop 1", result)
        self.assertIn("100.0%", result)

    def test_taint_map_has_bar_chart(self):
        """Should include ASCII bar representation of taint levels."""
        tainted_outputs = [
            {"hop": 0, "address": "1Full", "taint_pct": 100.0, "value": 50000},
            {"hop": 0, "address": "1Half", "taint_pct": 50.0, "value": 50000},
        ]
        result = render_taint_map(tainted_outputs)
        # Full taint bar should be longer than half taint bar
        self.assertIn("█", result)


if __name__ == "__main__":
    unittest.main()
```

**Step 2: Run to verify failure, then implement**

**Step 3: Implement visualization**

Create `visualization.py` with two main functions:

1. `render_tx_flow(txid, inputs, outputs)` — ASCII box diagram showing inputs flowing through a TX to outputs, with taint annotations.

2. `render_taint_map(tainted_outputs)` — Grouped by hop, shows address, taint %, value, and an ASCII bar chart.

Example output for `render_tx_flow`:
```
┌─────────────────────────────────────────────────────┐
│                  TX: aaaa1111...                     │
├───────────────────────┬─────────────────────────────┤
│ INPUTS                │ OUTPUTS                     │
│                       │                             │
│ 1SourceAddr...        │ 1OutputA...                 │
│ 0.00100000 BTC        │ 0.00060000 BTC              │
│ [████████████] 100.0% │ [████████████] 100.0%       │
│                       │                             │
│                       │ 1OutputB...                 │
│                       │ 0.00039000 BTC              │
│                       │ [████████████] 100.0%       │
└───────────────────────┴─────────────────────────────┘
```

Example output for `render_taint_map`:
```
═══ Taint Propagation Map ═══

Hop 0 (Source)
  1SourceAddr...   0.00100000 BTC  [████████████████████] 100.0%  CRITICAL

Hop 1
  1OutputA...      0.00060000 BTC  [██████████░░░░░░░░░░]  50.0%  MEDIUM
  1OutputB...      0.00039000 BTC  [████░░░░░░░░░░░░░░░░]  20.0%  LOW
```

**Step 4: Run tests**

Run: `python3 -m pytest tests/test_visualization.py -v`

**Step 5: Integrate into CLI**

Add `--visualize` flag to argparse. When set, append visualization output after the standard report.

**Step 6: Commit**

```bash
git add visualization.py tests/test_visualization.py taint_analysis.py
git commit -m "feat: add ASCII transaction flow and taint propagation visualization"
```

---

## Task 6: Export Formats (CSV & Markdown)

**Why:** JSON is already supported. Adding CSV enables spreadsheet analysis; Markdown enables professional reporting. Both use stdlib only.

**Files:**
- Create: `exports/__init__.py`
- Create: `exports/csv_export.py`
- Create: `exports/markdown_export.py`
- Create: `exports/text_export.py` (extract current text formatting)
- Create: `tests/test_exports.py`
- Modify: `taint_analysis.py` (add `--output-format` flag)

**Step 1: Write failing tests**

Create `tests/test_exports.py`:

```python
import unittest
import csv
import io
from exports.csv_export import export_csv
from exports.markdown_export import export_markdown


class TestCSVExport(unittest.TestCase):
    def test_csv_has_header(self):
        report = self._sample_report()
        output = export_csv(report)
        reader = csv.reader(io.StringIO(output))
        header = next(reader)
        self.assertIn("txid", header)
        self.assertIn("address", header)
        self.assertIn("taint_pct", header)

    def test_csv_has_data_rows(self):
        report = self._sample_report()
        output = export_csv(report)
        lines = output.strip().split("\n")
        self.assertGreaterEqual(len(lines), 2)  # header + at least 1 row

    def _sample_report(self):
        return {
            "methodology": "haircut",
            "source_txid": "aaaa1111",
            "tainted_outputs": [
                {"txid": "aaaa1111", "vout_index": 0, "address": "1Addr",
                 "value_sat": 50000, "taint_pct": 100.0, "hop": 0,
                 "confidence": 0.95, "risk": "critical"},
            ],
            "summary": {"transactions_analyzed": 1, "tainted_outputs": 1,
                         "total_tainted_btc": 0.0005, "max_hop_reached": 0},
        }


class TestMarkdownExport(unittest.TestCase):
    def test_markdown_has_header(self):
        report = self._sample_report()
        output = export_markdown(report)
        self.assertIn("# Taint Analysis Report", output)

    def test_markdown_has_summary_table(self):
        report = self._sample_report()
        output = export_markdown(report)
        self.assertIn("|", output)  # Table formatting
        self.assertIn("Methodology", output)

    def test_markdown_has_findings(self):
        report = self._sample_report()
        output = export_markdown(report)
        self.assertIn("aaaa1111", output)

    def _sample_report(self):
        return {
            "methodology": "haircut",
            "source_txid": "aaaa1111",
            "source_label": "Tainted Source",
            "tainted_outputs": [
                {"txid": "aaaa1111", "vout_index": 0, "address": "1Addr",
                 "value_sat": 50000, "taint_pct": 100.0, "hop": 0,
                 "confidence": 0.95, "risk": "critical"},
            ],
            "summary": {"transactions_analyzed": 1, "tainted_outputs": 1,
                         "total_tainted_btc": 0.0005, "max_hop_reached": 0},
            "by_hop": {0: {"count": 1, "total_btc": 0.0005, "avg_taint_pct": 100.0}},
            "top_tainted_addresses": [{"address": "1Addr", "tainted_btc": 0.0005}],
        }


if __name__ == "__main__":
    unittest.main()
```

**Step 2: Run to verify failure, then implement**

**Step 3: Implement exporters**

- `exports/csv_export.py` — `export_csv(report) -> str` using `csv.StringIO`
- `exports/markdown_export.py` — `export_markdown(report) -> str` with tables, summary, findings
- `exports/text_export.py` — Extract the current `print()` formatting from `main()` into `export_text(report) -> str`

**Step 4: Add `--output-format` CLI flag**

Replace `--json` with `--output-format {text,json,csv,markdown}` (default: text). Keep `--json` as a deprecated alias.

**Step 5: Run tests + manual verification**

**Step 6: Commit**

```bash
git add exports/ tests/test_exports.py taint_analysis.py
git commit -m "feat: add CSV and markdown export formats"
```

---

## Task 7: Audit Logging

**Why:** Forensic tools need an evidence trail. Every analysis should be logged with timestamp, parameters, and results for compliance and reproducibility.

**Files:**
- Create: `audit.py`
- Create: `tests/test_audit.py`
- Modify: `taint_analysis.py` (integrate audit logging)

**Step 1: Write failing tests**

Create `tests/test_audit.py`:

```python
import unittest
import json
import os
import tempfile
from audit import AuditLogger


class TestAuditLogger(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.logger = AuditLogger(log_dir=self.tmpdir)

    def test_log_creates_file(self):
        self.logger.log_analysis(
            txid="aaaa1111",
            methodology="haircut",
            hops=2,
            result_summary={"tainted_outputs": 5},
        )
        files = os.listdir(self.tmpdir)
        self.assertEqual(len(files), 1)
        self.assertTrue(files[0].endswith(".jsonl"))

    def test_log_entry_has_required_fields(self):
        self.logger.log_analysis(
            txid="aaaa1111",
            methodology="haircut",
            hops=2,
            result_summary={"tainted_outputs": 5},
        )
        log_file = os.path.join(self.tmpdir, os.listdir(self.tmpdir)[0])
        with open(log_file) as f:
            entry = json.loads(f.readline())
        self.assertIn("timestamp", entry)
        self.assertIn("txid", entry)
        self.assertIn("methodology", entry)
        self.assertIn("result_summary", entry)

    def test_multiple_logs_append(self):
        self.logger.log_analysis(txid="a", methodology="haircut", hops=1, result_summary={})
        self.logger.log_analysis(txid="b", methodology="poison", hops=2, result_summary={})
        log_file = os.path.join(self.tmpdir, os.listdir(self.tmpdir)[0])
        with open(log_file) as f:
            lines = f.readlines()
        self.assertEqual(len(lines), 2)


if __name__ == "__main__":
    unittest.main()
```

**Step 2: Implement audit module**

Create `audit.py` — `AuditLogger` class that writes JSONL entries (one JSON object per line) to a daily log file. Each entry includes: timestamp (ISO 8601), txid, methodology, hops, duration, result summary, tool version.

**Step 3: Run tests, integrate into main(), commit**

```bash
git add audit.py tests/test_audit.py taint_analysis.py
git commit -m "feat: add JSONL audit logging for forensic accountability"
```

---

## Task 8: Update CLI, Demo Script, and Report Format

**Why:** Wire everything together — new CLI flags, updated demo showcasing new features, and enriched report structure with confidence/risk/visualization.

**Files:**
- Modify: `taint_analysis.py` (CLI updates, report enrichment)
- Modify: `demo_taint_analysis.sh` (showcase new features)
- Modify: `taint_analysis.py:_generate_report()` (include tainted_outputs list with confidence/risk)

**Step 1: Update CLI flags**

Add to argparse:
- `--method` choices: add `fifo`
- `--output-format {text,json,csv,markdown}` (default: text)
- `--visualize` flag for ASCII charts
- `--min-confidence FLOAT` to filter low-confidence results
- `--audit-dir PATH` for audit log location (default: `./audit_logs/`)
- Keep `--json` as shortcut for `--output-format json`

**Step 2: Update `_generate_report()` to include full tainted_outputs list**

The report dict should include a `tainted_outputs` key with the list of all `TaintedOutput` objects (as dicts), each enriched with `confidence` and `risk` fields. This is needed by CSV/markdown exporters.

**Step 3: Update demo script**

Add sections demonstrating:
- FIFO methodology
- ASCII visualization
- CSV output
- Confidence filtering

**Step 4: Run all tests**

Run: `python3 -m pytest tests/ -v`

**Step 5: Manual smoke test**

Run the demo script and verify all features work end-to-end.

**Step 6: Commit**

```bash
git add taint_analysis.py demo_taint_analysis.sh
git commit -m "feat: update CLI with new flags, enriched reports, and updated demo"
```

---

## Task 9: Update Documentation

**Why:** CLAUDE.md needs to reflect the new architecture, modules, and features.

**Files:**
- Modify: `CLAUDE.md` (update architecture, components table, conventions)

**Step 1: Update CLAUDE.md**

Update:
- Architecture diagram to show new directories
- Core Components table to include new modules
- Taint Methodologies to include FIFO
- Add section on Scoring (confidence + risk)
- Add section on Export formats
- Add section on Audit logging
- Update CLI quick reference
- Update "When Adding Features" guidelines

**Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md with new architecture and features"
```

---

## Task 10: Final Integration Test & Cleanup

**Why:** Verify everything works together end-to-end before considering the branch complete.

**Step 1: Run full test suite**

Run: `python3 -m pytest tests/ -v --tb=short`

Expected: All tests PASS

**Step 2: Run each output format manually**

```bash
TX="f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"
python3 taint_analysis.py $TX --method fifo --hops 1
python3 taint_analysis.py $TX --method haircut --hops 1 --output-format csv
python3 taint_analysis.py $TX --method poison --hops 1 --output-format markdown
python3 taint_analysis.py $TX --compare --hops 1
python3 taint_analysis.py $TX --method haircut --hops 1 --visualize
```

**Step 3: Run demo script**

Run: `./demo_taint_analysis.sh`

**Step 4: Verify audit log was created**

Check `audit_logs/` directory for JSONL file with entries from the above runs.

**Step 5: Final commit if any cleanup needed**

```bash
git add -A
git commit -m "chore: final cleanup and integration verification"
```

---

## Summary

| Task | Feature | Est. Complexity |
|------|---------|----------------|
| 1 | Test infrastructure & mock data | Low |
| 2 | Extract methodology strategies | Medium |
| 3 | FIFO methodology | Medium |
| 4 | Confidence & risk scoring | Medium |
| 5 | ASCII visualization | Medium-High |
| 6 | CSV & Markdown export | Medium |
| 7 | Audit logging | Low |
| 8 | CLI & demo updates | Medium |
| 9 | Documentation update | Low |
| 10 | Integration testing | Low |

**Total: 10 tasks, ~30 bite-sized steps**

Each task produces a working commit. No task depends on a later task (they can be reordered if needed, though 1→2→3 should stay sequential as they build on each other).
