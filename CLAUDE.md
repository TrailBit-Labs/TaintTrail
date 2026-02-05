# CLAUDE.md - Bitcoin Taint Analysis Tool

## Project Overview

Bitcoin forensics utility for tracing tainted funds through the blockchain. Implements multiple taint calculation methodologies (poison, haircut, pro-rata) using BFS traversal of the transaction graph.

**Purpose:** Educational blockchain forensics for the Bitcoin Heuristics Newsletter and TrailBit research.

## Quick Reference

```bash
# Run analysis (default: haircut, 2 hops)
python3 taint_analysis.py <txid>

# Compare all methodologies
python3 taint_analysis.py <txid> --compare --hops 3

# JSON output
python3 taint_analysis.py <txid> --json

# Demo
./demo_taint_analysis.sh
```

## Architecture

```
bitcoin-taint-analysis-main/
├── taint_analysis.py      # Main engine (~395 lines, pure Python)
├── demo_taint_analysis.sh # Demo script
├── README.md              # User documentation
└── CLAUDE.md              # This file
```

### Core Components

| Component | Location | Purpose |
|-----------|----------|---------|
| `TaintedOutput` | `taint_analysis.py:23` | Dataclass for tainted UTXOs |
| `TaintAnalyzer` | `taint_analysis.py:58` | Main analysis engine |
| `fetch_tx()` | `taint_analysis.py:36` | API calls to mempool.space |
| `compare_methodologies()` | `taint_analysis.py:288` | Run all methods |

### Taint Methodologies

- **Poison** (`analyze_poison`): Binary - any tainted input = 100% tainted outputs
- **Haircut** (`analyze_haircut`): Proportional - taint% = tainted_value / total_value
- **Pro-rata** (`analyze_pro_rata`): Weighted distribution (currently same as haircut)

## Code Conventions

### Style
- Python 3.7+ with type hints
- Dataclasses for data structures
- Standard library only (no pip dependencies)
- User-Agent: `TrailBit/1.0`

### Patterns
- BFS for graph traversal (`_analyze` method)
- Output key format: `{txid}:{vout_index}`
- Taint threshold: 0.01% minimum
- Values in satoshis internally, BTC for display

### API
- Base URL: `https://mempool.space/api/`
- Endpoints: `/tx/{txid}`, `/tx/{txid}/outspends`
- Timeout: 15 seconds

## Development Guidelines

### When Adding Features
1. Keep zero external dependencies (stdlib only)
2. Add new methodologies as `analyze_*` methods
3. Update `compare_methodologies()` if adding methods
4. Maintain JSON and text output formats

### When Modifying Analysis
- Taint propagation logic is in `_propagate_taint()`
- Report generation in `_generate_report()`
- Keep trace_log entries for debugging

### Testing
```bash
# Test with known transaction
python3 taint_analysis.py f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16 --hops 1

# Compare methodologies
python3 taint_analysis.py <txid> --compare
```

## Important Context

### What This Tool Does
- Traces taint through Bitcoin transaction graph
- Calculates taint percentages using academic methodologies
- Generates forensic reports for research/compliance

### What This Tool Does NOT Do
- Store personal data or credentials
- Perform unauthorized surveillance
- Connect to any private APIs

### Legal Framework
- Educational and research use only
- Based on published academic methodologies (Reid & Harrigan 2011, Meiklejohn et al. 2013)
- Designed for Daubert-compliant forensic analysis

## Common Tasks

### Add a new taint methodology
1. Add `analyze_<name>()` method to `TaintAnalyzer`
2. Add case in `_propagate_taint()` for the methodology
3. Add to `compare_methodologies()` loop
4. Add CLI option in `main()` argparse

### Change API source
1. Modify `fetch_tx()` and `fetch_outspends()` URLs
2. Adjust JSON parsing for new API format
3. Update User-Agent header

### Add new output format
1. Create formatter in `_generate_report()` or new method
2. Add CLI flag in argparse
3. Handle in main() output section
