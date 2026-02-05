# CLAUDE.md - Bitcoin Taint Analysis Tool

## Project Overview

Bitcoin forensics utility for tracing tainted funds through the blockchain. Implements multiple taint calculation methodologies (poison, haircut, pro-rata, FIFO) using BFS traversal of the transaction graph, with confidence scoring, risk assessment, and multi-format export.

**Purpose:** Educational blockchain forensics for the Bitcoin Heuristics Newsletter and TrailBit research.

## Quick Reference

```bash
# Run analysis (default: haircut, 2 hops)
python3 taint_analysis.py <txid>

# Choose methodology
python3 taint_analysis.py <txid> --method fifo --hops 3

# Compare all methodologies
python3 taint_analysis.py <txid> --compare --hops 3

# Output formats
python3 taint_analysis.py <txid> --output-format csv
python3 taint_analysis.py <txid> --output-format markdown
python3 taint_analysis.py <txid> --json  # shortcut for --output-format json

# ASCII visualization
python3 taint_analysis.py <txid> --visualize

# Filter by confidence
python3 taint_analysis.py <txid> --min-confidence 0.5

# Audit logging
python3 taint_analysis.py <txid> --audit-dir ./audit_logs/

# Demo
./demo_taint_analysis.sh
```

## Architecture

```
bitcoin-taint-analysis-main/
├── taint_analysis.py          # Main CLI entry point & orchestrator
├── methodologies/
│   ├── __init__.py            # Registry (METHODOLOGIES dict)
│   ├── poison.py              # Binary taint propagation
│   ├── haircut.py             # Proportional distribution
│   ├── pro_rata.py            # Weighted per-output distribution
│   └── fifo.py                # First-in-first-out tracking
├── exports/
│   ├── __init__.py            # Exporter package
│   ├── csv_export.py          # CSV output
│   ├── markdown_export.py     # Markdown report
│   └── text_export.py         # Text output (default)
├── visualization.py           # ASCII flow charts & taint maps
├── scoring.py                 # Confidence & risk scoring
├── audit.py                   # JSONL audit logging
├── tests/
│   ├── __init__.py
│   ├── conftest.py            # Mock data helpers
│   ├── test_methodologies.py  # Poison/haircut/pro-rata tests
│   ├── test_fifo.py           # FIFO-specific tests
│   ├── test_scoring.py        # Confidence & risk tests
│   ├── test_visualization.py  # ASCII output tests
│   ├── test_exports.py        # CSV/markdown/text export tests
│   └── test_audit.py          # Audit log tests
├── data/
│   └── sample_tx.json         # Mock transaction data for tests
├── demo_taint_analysis.sh     # Demo script
├── README.md                  # User documentation
└── CLAUDE.md                  # This file
```

### Core Components

| Component | Location | Purpose |
|-----------|----------|---------|
| `TaintedOutput` | `taint_analysis.py` | Dataclass for tainted UTXOs (with confidence/risk) |
| `TaintAnalyzer` | `taint_analysis.py` | Main BFS analysis engine |
| `fetch_tx()` | `taint_analysis.py` | API calls to mempool.space |
| `METHODOLOGIES` | `methodologies/__init__.py` | Strategy registry for taint algorithms |
| `calculate_confidence()` | `scoring.py` | Confidence scoring (0.0-1.0) |
| `calculate_risk_score()` | `scoring.py` | Risk level (critical/high/medium/low/minimal) |
| `render_taint_map()` | `visualization.py` | ASCII taint propagation visualization |
| `render_tx_flow()` | `visualization.py` | ASCII transaction flow diagram |
| `export_csv()` | `exports/csv_export.py` | CSV format export |
| `export_markdown()` | `exports/markdown_export.py` | Markdown report export |
| `export_text()` | `exports/text_export.py` | Text format export |
| `AuditLogger` | `audit.py` | JSONL audit trail |

### Taint Methodologies

- **Poison** (`methodologies/poison.py`): Binary - any tainted input = 100% tainted outputs
- **Haircut** (`methodologies/haircut.py`): Proportional - taint% = tainted_value / total_value, uniform across all outputs
- **Pro-rata** (`methodologies/pro_rata.py`): Weighted distribution by output value, tracks absolute tainted sats per output
- **FIFO** (`methodologies/fifo.py`): First-in-first-out - tainted sats consumed sequentially across outputs

Each methodology is a pure function: `calculate_taint(tainted_input_value, total_input_value, outputs) -> list[float]`

### Scoring

- **Confidence** (0.0-1.0): Decays with hops (0.85^n), penalizes mixing (many inputs) and fan-out (many outputs)
- **Risk** (critical/high/medium/low/minimal): Combines taint%, confidence, and hop proximity

### Export Formats

All exporters follow `export_*(report: dict) -> str`:
- **Text**: Human-readable terminal output (default)
- **JSON**: Machine-readable (`json.dumps`)
- **CSV**: Spreadsheet-compatible with header row
- **Markdown**: Professional report with tables

## Code Conventions

### Style
- Python 3.7+ with type hints
- Dataclasses for data structures
- Standard library only (no pip dependencies)
- User-Agent: `TrailBit/1.0`

### Patterns
- Strategy pattern for methodologies (pure functions in `methodologies/`)
- BFS for graph traversal (`_analyze` method)
- Output key format: `{txid}:{vout_index}`
- Taint threshold: 0.01% minimum (per-output)
- Values in satoshis internally, BTC for display

### API
- Base URL: `https://mempool.space/api/`
- Endpoints: `/tx/{txid}`, `/tx/{txid}/outspends`
- Timeout: 15 seconds

## Development Guidelines

### When Adding Features
1. Keep zero external dependencies (stdlib only)
2. Follow TDD: write tests in `tests/` first
3. Use mock data from `data/sample_tx.json` for offline tests

### When Adding a New Methodology
1. Create `methodologies/<name>.py` with `calculate_taint()` function
2. Register in `methodologies/__init__.py` METHODOLOGIES dict
3. Add `analyze_<name>()` method to `TaintAnalyzer`
4. Update `compare_methodologies()` loop
5. Add CLI option in `main()` argparse
6. Add tests in `tests/test_<name>.py`

### When Adding a New Export Format
1. Create `exports/<name>_export.py` with `export_<name>(report) -> str`
2. Add to `--output-format` choices in argparse
3. Add dispatch in `main()` output section
4. Add tests in `tests/test_exports.py`

### When Modifying Analysis
- Taint propagation uses `METHODOLOGIES.get(methodology)` for dispatch
- Report generation in `_generate_report()` includes `tainted_outputs` list
- Keep trace_log entries for debugging

### Testing
```bash
# Run all tests
python3 -m pytest tests/ -v

# Run specific test file
python3 -m pytest tests/test_fifo.py -v

# Test with known transaction (requires network)
python3 taint_analysis.py f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16 --hops 1
```

## Important Context

### What This Tool Does
- Traces taint through Bitcoin transaction graph
- Calculates taint percentages using academic methodologies
- Scores confidence and risk for each attribution
- Generates forensic reports in multiple formats
- Maintains audit trail for compliance

### What This Tool Does NOT Do
- Store personal data or credentials
- Perform unauthorized surveillance
- Connect to any private APIs

### Legal Framework
- Educational and research use only
- Based on published academic methodologies (Reid & Harrigan 2011, Meiklejohn et al. 2013)
- Designed for Daubert-compliant forensic analysis
