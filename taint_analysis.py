#!/usr/bin/env python3
"""
Taint Analysis Tool for Bitcoin Forensics

Implements multiple taint calculation methodologies:
- FIFO (First-In-First-Out)
- Poison (binary taint propagation)
- Haircut (proportional distribution)
- Pro-rata (weighted by amounts)

Used for Newsletter Issue 4 and TrailBit research.
"""

import json
import urllib.request
import sys
from collections import defaultdict
from dataclasses import dataclass, asdict
from typing import Optional
from datetime import datetime
from methodologies import METHODOLOGIES
from scoring import calculate_confidence, calculate_risk_score


@dataclass
class TaintedOutput:
    """Represents a tainted transaction output."""
    txid: str
    vout_index: int
    address: str
    value_sat: int
    taint_percent: float
    taint_source: str
    methodology: str
    hop: int
    confidence: float = 0.0
    risk: str = "minimal"


def fetch_tx(txid: str) -> Optional[dict]:
    """Fetch transaction from mempool.space API."""
    url = f"https://mempool.space/api/tx/{txid}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "TrailBit/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return {"error": str(e)}


def fetch_outspends(txid: str) -> "list[dict]":
    """Fetch spending info for all outputs of a transaction."""
    url = f"https://mempool.space/api/tx/{txid}/outspends"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "TrailBit/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return []


class TaintAnalyzer:
    """
    Analyze taint propagation through Bitcoin transaction graph.
    
    Methodologies:
    - poison: Binary taint (any input tainted = all outputs tainted)
    - haircut: Proportional (taint % = tainted input value / total input value)
    - fifo: First-in-first-out (tainted inputs consume outputs in order)
    - pro_rata: Each output gets proportional share of taint
    """
    
    def __init__(self, source_txid: str, source_label: str = "Tainted Source"):
        self.source_txid = source_txid
        self.source_label = source_label
        self.tainted_outputs: dict[str, TaintedOutput] = {}  # key = txid:vout
        self.analyzed_txs: set[str] = set()
        self.trace_log: list[dict] = []
    
    def _output_key(self, txid: str, vout: int) -> str:
        return f"{txid}:{vout}"
    
    def analyze_poison(self, max_hops: int = 3, max_txs: int = 50) -> dict:
        """
        Poison methodology: If ANY input is tainted, ALL outputs are 100% tainted.
        Most aggressive method - used by some early chain analysis.
        """
        return self._analyze("poison", max_hops, max_txs)
    
    def analyze_haircut(self, max_hops: int = 3, max_txs: int = 50) -> dict:
        """
        Haircut methodology: Taint percentage = (tainted input value / total input value).
        Each output inherits this percentage.
        More nuanced than poison - commonly used by Chainalysis.
        """
        return self._analyze("haircut", max_hops, max_txs)
    
    def analyze_pro_rata(self, max_hops: int = 3, max_txs: int = 50) -> dict:
        """
        Pro-rata methodology: Taint distributed proportionally across outputs.
        Similar to haircut but tracks absolute tainted amounts.
        """
        return self._analyze("pro_rata", max_hops, max_txs)

    def analyze_fifo(self, max_hops: int = 3, max_txs: int = 50) -> dict:
        """
        FIFO methodology: First-in-first-out taint tracking.
        Tainted satoshis are consumed sequentially across outputs in order.
        First output absorbs taint until saturated, then the next, etc.
        Produces distinctly different results from haircut/pro-rata.
        """
        return self._analyze("fifo", max_hops, max_txs)
    
    def _analyze(self, methodology: str, max_hops: int, max_txs: int) -> dict:
        """Core analysis loop."""
        self.tainted_outputs.clear()
        self.analyzed_txs.clear()
        self.trace_log.clear()
        
        # Initialize: all outputs of source tx are 100% tainted
        source_tx = fetch_tx(self.source_txid)
        if not source_tx or "error" in source_tx:
            return {"error": f"Cannot fetch source tx: {source_tx.get('error', 'Unknown')}"}
        
        source_outputs = source_tx.get("vout", [])
        source_inputs = source_tx.get("vin", [])
        for i, vout in enumerate(source_outputs):
            key = self._output_key(self.source_txid, i)
            conf = calculate_confidence(
                hop=0,
                taint_pct=100.0,
                num_inputs=max(len(source_inputs), 1),
                num_outputs=max(len(source_outputs), 1),
            )
            risk = calculate_risk_score(
                taint_pct=100.0,
                confidence=conf,
                hop=0,
            )
            self.tainted_outputs[key] = TaintedOutput(
                txid=self.source_txid,
                vout_index=i,
                address=vout.get("scriptpubkey_address", "unknown"),
                value_sat=vout.get("value", 0),
                taint_percent=100.0,
                taint_source=self.source_label,
                methodology=methodology,
                hop=0,
                confidence=conf,
                risk=risk,
            )
        
        self.analyzed_txs.add(self.source_txid)
        self.trace_log.append({
            "action": "init",
            "txid": self.source_txid[:16] + "...",
            "outputs_tainted": len(source_tx.get("vout", [])),
            "total_value_btc": sum(v.get("value", 0) for v in source_tx.get("vout", [])) / 1e8
        })
        
        # BFS through transaction graph
        current_hop_txs = [self.source_txid]
        
        for hop in range(1, max_hops + 1):
            if len(self.analyzed_txs) >= max_txs:
                break
            
            next_hop_txs = []
            
            for txid in current_hop_txs:
                # Find which outputs were spent
                outspends = fetch_outspends(txid)
                
                for vout_idx, spend in enumerate(outspends):
                    if not spend.get("spent"):
                        continue
                    
                    spending_txid = spend.get("txid")
                    if not spending_txid or spending_txid in self.analyzed_txs:
                        continue
                    
                    if len(self.analyzed_txs) >= max_txs:
                        break
                    
                    # Analyze the spending transaction
                    self._propagate_taint(spending_txid, methodology, hop)
                    self.analyzed_txs.add(spending_txid)
                    next_hop_txs.append(spending_txid)
            
            current_hop_txs = next_hop_txs
        
        return self._generate_report(methodology)
    
    def _propagate_taint(self, txid: str, methodology: str, hop: int):
        """Propagate taint through a transaction based on methodology."""
        tx = fetch_tx(txid)
        if not tx or "error" in tx:
            return
        
        inputs = tx.get("vin", [])
        outputs = tx.get("vout", [])
        
        # Calculate input taint
        tainted_input_value = 0
        total_input_value = 0
        max_input_taint = 0.0
        
        for vin in inputs:
            prev_txid = vin.get("txid")
            prev_vout = vin.get("vout", 0)
            input_value = vin.get("prevout", {}).get("value", 0)
            total_input_value += input_value
            
            # Check if this input is from a tainted output
            key = self._output_key(prev_txid, prev_vout)
            if key in self.tainted_outputs:
                tainted = self.tainted_outputs[key]
                tainted_input_value += input_value * (tainted.taint_percent / 100)
                max_input_taint = max(max_input_taint, tainted.taint_percent)
        
        if total_input_value == 0:
            return
        
        # Calculate output taint based on methodology (strategy pattern)
        calculate = METHODOLOGIES.get(methodology)
        if calculate is None:
            return
        taint_percentages = calculate(tainted_input_value, total_input_value, outputs)

        # Check if all outputs are below threshold
        if all(tp < 0.01 for tp in taint_percentages):
            return

        # Apply per-output taint percentages
        outputs_tainted = 0
        for i, vout in enumerate(outputs):
            output_taint = taint_percentages[i]
            if output_taint < 0.01:  # Below threshold, skip this output
                continue
            key = self._output_key(txid, i)
            confidence = calculate_confidence(
                hop=hop,
                taint_pct=output_taint,
                num_inputs=len(inputs),
                num_outputs=len(outputs),
            )
            risk = calculate_risk_score(
                taint_pct=output_taint,
                confidence=confidence,
                hop=hop,
            )
            self.tainted_outputs[key] = TaintedOutput(
                txid=txid,
                vout_index=i,
                address=vout.get("scriptpubkey_address", "unknown"),
                value_sat=vout.get("value", 0),
                taint_percent=round(output_taint, 2),
                taint_source=self.source_label,
                methodology=methodology,
                hop=hop,
                confidence=confidence,
                risk=risk,
            )
            outputs_tainted += 1

        self.trace_log.append({
            "action": "propagate",
            "hop": hop,
            "txid": txid[:16] + "...",
            "input_taint_pct": round((tainted_input_value / total_input_value) * 100, 2),
            "output_taint_pct": round(max(taint_percentages), 2),
            "outputs_tainted": outputs_tainted,
        })
    
    def _generate_report(self, methodology: str) -> dict:
        """Generate analysis report."""
        # Group by hop
        by_hop = defaultdict(list)
        for output in self.tainted_outputs.values():
            by_hop[output.hop].append(output)
        
        # Calculate totals
        total_tainted_value = sum(
            o.value_sat * (o.taint_percent / 100) 
            for o in self.tainted_outputs.values()
        )
        
        # Top tainted addresses
        addr_taint = defaultdict(float)
        for o in self.tainted_outputs.values():
            addr_taint[o.address] += o.value_sat * (o.taint_percent / 100)
        
        top_addresses = sorted(
            addr_taint.items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:10]
        
        return {
            "methodology": methodology,
            "source_txid": self.source_txid,
            "source_label": self.source_label,
            "summary": {
                "transactions_analyzed": len(self.analyzed_txs),
                "tainted_outputs": len(self.tainted_outputs),
                "total_tainted_btc": round(total_tainted_value / 1e8, 8),
                "max_hop_reached": max(by_hop.keys()) if by_hop else 0,
            },
            "by_hop": {
                hop: {
                    "count": len(outputs),
                    "total_btc": round(sum(o.value_sat for o in outputs) / 1e8, 8),
                    "avg_taint_pct": round(sum(o.taint_percent for o in outputs) / len(outputs), 2),
                    "avg_confidence": round(sum(o.confidence for o in outputs) / len(outputs), 4),
                }
                for hop, outputs in sorted(by_hop.items())
            },
            "top_tainted_addresses": [
                {"address": addr[:20] + "..." if len(addr) > 20 else addr, "tainted_btc": round(val / 1e8, 8)}
                for addr, val in top_addresses
            ],
            "tainted_outputs": [asdict(o) for o in self.tainted_outputs.values()],
            "trace_log": self.trace_log[:20],  # First 20 entries
        }


def compare_methodologies(txid: str, max_hops: int = 2) -> dict:
    """Run all methodologies and compare results."""
    analyzer = TaintAnalyzer(txid)
    
    results = {
        "source_txid": txid,
        "comparison": {},
    }
    
    for method in ["poison", "haircut", "pro_rata", "fifo"]:
        if method == "poison":
            report = analyzer.analyze_poison(max_hops)
        elif method == "haircut":
            report = analyzer.analyze_haircut(max_hops)
        elif method == "pro_rata":
            report = analyzer.analyze_pro_rata(max_hops)
        else:
            report = analyzer.analyze_fifo(max_hops)
        
        if "error" not in report:
            results["comparison"][method] = {
                "total_tainted_btc": report["summary"]["total_tainted_btc"],
                "tainted_outputs": report["summary"]["tainted_outputs"],
                "txs_analyzed": report["summary"]["transactions_analyzed"],
            }
    
    return results


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Bitcoin Taint Analysis Tool",
        epilog="""
Methodologies:
  poison   - Binary: any tainted input = 100% tainted outputs
  haircut  - Proportional: taint% = tainted_value / total_value
  pro_rata - Weighted distribution across outputs
  fifo     - First-in-first-out: taint consumed sequentially by outputs

Examples:
  taint_analysis.py <txid> --method haircut --hops 3
  taint_analysis.py <txid> --method fifo --hops 2
  taint_analysis.py <txid> --compare
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("txid", help="Source transaction ID (the 'dirty' funds)")
    parser.add_argument("--method", choices=["poison", "haircut", "pro_rata", "fifo"],
                        default="haircut", help="Taint methodology")
    parser.add_argument("--hops", type=int, default=2, help="Max hops to trace (default: 2)")
    parser.add_argument("--max-txs", type=int, default=30, help="Max transactions to analyze")
    parser.add_argument("--label", default="Tainted Source", help="Label for source")
    parser.add_argument("--compare", action="store_true", help="Compare all methodologies")
    parser.add_argument("--json", action="store_true", help="(Deprecated) Output raw JSON. Use --output-format json instead.")
    parser.add_argument("--output-format", choices=["text", "json", "csv", "markdown"],
                        default="text", help="Output format (default: text)")
    parser.add_argument("--visualize", action="store_true", help="Show ASCII visualization")

    args = parser.parse_args()

    # --json is a deprecated shortcut for --output-format json
    output_format = args.output_format
    if args.json:
        output_format = "json"

    if args.compare:
        result = compare_methodologies(args.txid, args.hops)
        if output_format == "json":
            print(json.dumps(result, indent=2))
        elif output_format == "csv":
            # For compare mode, build a simple CSV of the comparison table
            from exports.csv_export import export_csv as _csv
            import csv as _csv_mod, io as _io
            buf = _io.StringIO()
            writer = _csv_mod.writer(buf)
            writer.writerow(["method", "total_tainted_btc", "tainted_outputs", "txs_analyzed"])
            for method, data in result.get("comparison", {}).items():
                writer.writerow([method, data["total_tainted_btc"],
                                 data["tainted_outputs"], data["txs_analyzed"]])
            print(buf.getvalue(), end="")
        elif output_format == "markdown":
            lines = [
                "# Taint Methodology Comparison",
                "",
                f"Source: `{args.txid}`",
                f"Max hops: {args.hops}",
                "",
                "| Method | Tainted BTC | Outputs | TXs |",
                "|--------|-------------|---------|-----|",
            ]
            for method, data in result.get("comparison", {}).items():
                lines.append(
                    f"| {method} | {data['total_tainted_btc']:.8f} "
                    f"| {data['tainted_outputs']} | {data['txs_analyzed']} |"
                )
            print("\n".join(lines))
        else:
            print(f"\nTaint Methodology Comparison")
            print(f"   Source: {args.txid[:20]}...")
            print(f"   Max hops: {args.hops}\n")
            print(f"   {'Method':<12} {'Tainted BTC':<15} {'Outputs':<10} {'TXs':<6}")
            print(f"   {'-'*45}")
            for method, data in result.get("comparison", {}).items():
                print(f"   {method:<12} {data['total_tainted_btc']:<15.8f} {data['tainted_outputs']:<10} {data['txs_analyzed']:<6}")
        return

    analyzer = TaintAnalyzer(args.txid, args.label)

    if args.method == "poison":
        result = analyzer.analyze_poison(args.hops, args.max_txs)
    elif args.method == "haircut":
        result = analyzer.analyze_haircut(args.hops, args.max_txs)
    elif args.method == "pro_rata":
        result = analyzer.analyze_pro_rata(args.hops, args.max_txs)
    else:
        result = analyzer.analyze_fifo(args.hops, args.max_txs)

    if "error" in result:
        print(f"Error: {result['error']}", file=sys.stderr)
        sys.exit(1)

    # Dispatch to the appropriate exporter
    if output_format == "json":
        print(json.dumps(result, indent=2))
    elif output_format == "csv":
        from exports.csv_export import export_csv
        print(export_csv(result), end="")
    elif output_format == "markdown":
        from exports.markdown_export import export_markdown
        print(export_markdown(result))
    else:
        from exports.text_export import export_text
        print(export_text(result))

        # ASCII taint map visualization (text mode only)
        if args.visualize and result.get('tainted_outputs'):
            from visualization import render_taint_map
            map_entries = []
            for o in result['tainted_outputs']:
                map_entries.append({
                    "hop": o.get("hop", 0),
                    "address": o.get("address", "unknown"),
                    "taint_pct": o.get("taint_percent", 0.0),
                    "value": o.get("value_sat", 0),
                })
            print(f"\n{render_taint_map(map_entries)}")


if __name__ == "__main__":
    main()
