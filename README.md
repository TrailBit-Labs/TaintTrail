# Bitcoin Taint Analysis Tool

An educational Bitcoin taint analysis tool that traces funds through the transaction graph using multiple methodologies.

Built for the **Bitcoin Heuristics Newsletter** and **TrailBit** research.

## What It Does

Takes a Bitcoin transaction ID, fetches transaction data from [mempool.space](https://mempool.space), and traces how tainted funds propagate through subsequent transactions using BFS graph traversal.

## Quick Start

```bash
# Run analysis (will prompt for number of hops)
python3 taint_analysis.py <txid>

# Specify method and hops
python3 taint_analysis.py <txid> --method haircut --hops 3

# Compare all methodologies side by side
python3 taint_analysis.py <txid> --compare --hops 3

# Run the demo
./demo_taint_analysis.sh
```

No dependencies beyond Python 3.7+ standard library.

## Methodologies

| Method | How It Works |
|--------|-------------|
| **Poison** | Binary — any tainted input means 100% tainted outputs |
| **Haircut** | Proportional — taint% = tainted value / total input value, applied uniformly |
| **Pro-rata** | Weighted — taint distributed proportional to each output's share of total value |
| **FIFO** | Sequential — tainted sats consumed by outputs in order until exhausted |

```bash
python3 taint_analysis.py <txid> --method poison --hops 2
python3 taint_analysis.py <txid> --method fifo --hops 4
python3 taint_analysis.py <txid> --compare
```

## Output Options

```bash
# Text report (default)
python3 taint_analysis.py <txid> --method haircut --hops 2

# JSON
python3 taint_analysis.py <txid> --json

# CSV
python3 taint_analysis.py <txid> --output-format csv

# Markdown
python3 taint_analysis.py <txid> --output-format markdown

# ASCII visualization
python3 taint_analysis.py <txid> --visualize

# Save to file
python3 taint_analysis.py <txid> -o report.txt
```

## Other Features

- **Confidence scoring** — decay by hop distance, mixing penalty, fan-out penalty
- **Risk scoring** — critical/high/medium/low/minimal based on taint%, confidence, and proximity
- **Min-confidence filter** — `--min-confidence 0.3` to focus on high-confidence results
- **Audit logging** — `--audit-dir ./logs/` writes JSONL logs for each analysis run
- **Interactive hops** — omit `--hops` and you'll be prompted

## Project Structure

```
├── taint_analysis.py       # Main CLI and analysis engine
├── methodologies/          # Taint calculation strategies
│   ├── poison.py
│   ├── haircut.py
│   ├── pro_rata.py
│   └── fifo.py
├── scoring.py              # Confidence and risk scoring
├── visualization.py        # ASCII flow charts and taint maps
├── exports/                # CSV, markdown, text formatters
├── audit.py                # JSONL audit logger
├── tests/                  # Unit tests (50 tests)
├── data/                   # Sample transaction data for tests
└── demo_taint_analysis.sh  # Demo script
```

## Methodology References

Based on ideas from:
- Reid & Harrigan (2011) — "An Analysis of Anonymity in Bitcoin"
- Ron & Shamir (2012) — "Quantitative Analysis of Bitcoin"
- Meiklejohn et al. (2013) — "A Fistful of Bitcoins"

## Disclaimer

This is an educational tool for learning about blockchain analysis. It is not professional forensic software. Results should not be treated as accurate or authoritative. Use it to learn, experiment, and explore — do whatever you want with it.

Not for unauthorized surveillance or illegal activities.

## License

Educational use. Do what you want with it.

---

*Built for the Bitcoin Heuristics Newsletter*
