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
    
    def _analyze(self, methodology: str, max_hops: int, max_txs: int) -> dict:
        """Core analysis loop."""
        self.tainted_outputs.clear()
        self.analyzed_txs.clear()
        self.trace_log.clear()
        
        # Initialize: all outputs of source tx are 100% tainted
        source_tx = fetch_tx(self.source_txid)
        if not source_tx or "error" in source_tx:
            return {"error": f"Cannot fetch source tx: {source_tx.get('error', 'Unknown')}"}
        
        for i, vout in enumerate(source_tx.get("vout", [])):
            key = self._output_key(self.source_txid, i)
            self.tainted_outputs[key] = TaintedOutput(
                txid=self.source_txid,
                vout_index=i,
                address=vout.get("scriptpubkey_address", "unknown"),
                value_sat=vout.get("value", 0),
                taint_percent=100.0,
                taint_source=self.source_label,
                methodology=methodology,
                hop=0
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
            self.tainted_outputs[key] = TaintedOutput(
                txid=txid,
                vout_index=i,
                address=vout.get("scriptpubkey_address", "unknown"),
                value_sat=vout.get("value", 0),
                taint_percent=round(output_taint, 2),
                taint_source=self.source_label,
                methodology=methodology,
                hop=hop
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
                }
                for hop, outputs in sorted(by_hop.items())
            },
            "top_tainted_addresses": [
                {"address": addr[:20] + "..." if len(addr) > 20 else addr, "tainted_btc": round(val / 1e8, 8)}
                for addr, val in top_addresses
            ],
            "trace_log": self.trace_log[:20],  # First 20 entries
        }


def compare_methodologies(txid: str, max_hops: int = 2) -> dict:
    """Run all methodologies and compare results."""
    analyzer = TaintAnalyzer(txid)
    
    results = {
        "source_txid": txid,
        "comparison": {},
    }
    
    for method in ["poison", "haircut", "pro_rata"]:
        if method == "poison":
            report = analyzer.analyze_poison(max_hops)
        elif method == "haircut":
            report = analyzer.analyze_haircut(max_hops)
        else:
            report = analyzer.analyze_pro_rata(max_hops)
        
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

Examples:
  taint_analysis.py <txid> --method haircut --hops 3
  taint_analysis.py <txid> --compare
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("txid", help="Source transaction ID (the 'dirty' funds)")
    parser.add_argument("--method", choices=["poison", "haircut", "pro_rata"], 
                        default="haircut", help="Taint methodology")
    parser.add_argument("--hops", type=int, default=2, help="Max hops to trace (default: 2)")
    parser.add_argument("--max-txs", type=int, default=30, help="Max transactions to analyze")
    parser.add_argument("--label", default="Tainted Source", help="Label for source")
    parser.add_argument("--compare", action="store_true", help="Compare all methodologies")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    
    args = parser.parse_args()
    
    if args.compare:
        result = compare_methodologies(args.txid, args.hops)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"\n📊 Taint Methodology Comparison")
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
    else:
        result = analyzer.analyze_pro_rata(args.hops, args.max_txs)
    
    if "error" in result:
        print(f"Error: {result['error']}", file=sys.stderr)
        sys.exit(1)
    
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\n🔍 Taint Analysis Report")
        print(f"   Methodology: {result['methodology'].upper()}")
        print(f"   Source: {result['source_txid'][:20]}...")
        print(f"\n📈 Summary:")
        s = result['summary']
        print(f"   Transactions analyzed: {s['transactions_analyzed']}")
        print(f"   Tainted outputs found: {s['tainted_outputs']}")
        print(f"   Total tainted value:   {s['total_tainted_btc']:.8f} BTC")
        print(f"   Max hop reached:       {s['max_hop_reached']}")
        
        if result['by_hop']:
            print(f"\n📊 By Hop:")
            for hop, data in result['by_hop'].items():
                print(f"   Hop {hop}: {data['count']} outputs, {data['total_btc']:.8f} BTC, avg taint: {data['avg_taint_pct']}%")
        
        if result['top_tainted_addresses']:
            print(f"\n🎯 Top Tainted Addresses:")
            for i, addr in enumerate(result['top_tainted_addresses'][:5], 1):
                print(f"   {i}. {addr['address']} — {addr['tainted_btc']:.8f} BTC")


if __name__ == "__main__":
    main()
