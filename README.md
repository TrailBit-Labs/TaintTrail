# TaintTrail

Trace tainted Bitcoin through the transaction graph using four competing methodologies — side by side.

Built by **[TrailBit Labs](https://github.com/TrailBit-Labs)** for the **[Bitcoin Heuristics Newsletter](https://trailbit.substack.com)**.

> Companion tool to **[DustLine](https://github.com/TrailBit-Labs/DustLine)** — which estimates the cost of tracing an address. TaintTrail answers the next question: *how tainted is it, and according to whom?*

## What It Does

Give TaintTrail any Bitcoin transaction ID. It fetches transaction data from [mempool.space](https://mempool.space), then traces how tainted funds propagate through subsequent transactions using BFS graph traversal — across four different taint models simultaneously.

The same transaction scored by four models can return 100%, 40%, 28%, or 12% taint. There is no industry standard. TaintTrail makes that visible.

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

| Method | How It Works | Typical Use |
|--------|-------------|-------------|
| **Poison** | Binary — any tainted input means 100% tainted outputs | Most conservative; law enforcement |
| **Haircut** | Proportional — taint% = tainted value / total input value, applied uniformly | Most common in commercial tools |
| **Pro-rata** | Weighted — taint distributed proportional to each output's share of total value | Academic research |
| **FIFO** | Sequential — tainted sats consumed by outputs in order until exhausted | Tax accounting contexts |

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

## Features

- **Side-by-side comparison** — `--compare` runs all four models on the same transaction
- **Confidence scoring** — decay by hop distance, mixing penalty, fan-out penalty
- **Risk scoring** — critical/high/medium/low/minimal based on taint%, confidence, and proximity
- **Min-confidence filter** — `--min-confidence 0.3` to focus on high-confidence results
- **Audit logging** — `--audit-dir ./logs/` writes JSONL logs for each analysis run
- **Multiple export formats** — text, JSON, CSV, markdown
- **ASCII visualization** — flow charts and taint maps in the terminal

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

## Why This Exists

Commercial blockchain forensics tools (Chainalysis, Elliptic, Crystal) don't publish which taint model they use. A compliance officer making a freeze/release decision based on a "3% taint score" has no way to know whether that 3% was calculated using haircut (where 3% means proportional exposure) or poison (where any contact means 100%).

TaintTrail makes the methodology transparent. Run all four models. See how the scores diverge. Decide for yourself.

The full analysis is in [Issue 4 of the Bitcoin Heuristics Newsletter](https://trailbit.substack.com).

## Methodology References

Based on ideas from:
- Reid & Harrigan (2011) — "An Analysis of Anonymity in Bitcoin"
- Ron & Shamir (2012) — "Quantitative Analysis of Bitcoin"
- Meiklejohn et al. (2013) — "A Fistful of Bitcoins"

## TrailBit Labs Forensics Toolkit

| Tool | What It Does |
|------|-------------|
| **[DustLine](https://github.com/TrailBit-Labs/DustLine)** | Estimates the cost of tracing a Bitcoin address |
| **[TaintTrail](https://github.com/TrailBit-Labs/TaintTrail)** | Traces taint propagation using four competing models |

## Disclaimer

This is an educational tool for learning about blockchain analysis. It is not professional forensic software. Results should not be treated as accurate or authoritative.

Not for unauthorized surveillance or illegal activities.

## License

MIT License. See [LICENSE](LICENSE) for details.

---

*Built by [TrailBit Labs](https://github.com/TrailBit-Labs) for the [Bitcoin Heuristics Newsletter](https://trailbit.substack.com)*
