#!/bin/bash
# 
# Run this to see the tool in action!

echo "🔍 Taint Analysis Tool Demo"
echo "   Built for Newsletter Issue 4 (due Wed Feb 5)"
echo ""

# Use the famous first Bitcoin transaction (Satoshi → Hal Finney)
DEMO_TX="f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"

echo "📌 Demo Transaction: First Bitcoin payment ever"
echo "   Satoshi Nakamoto → Hal Finney (10 BTC)"
echo "   TXID: ${DEMO_TX:0:20}..."
echo ""

echo "═══════════════════════════════════════════════════"
echo "1️⃣  HAIRCUT METHODOLOGY (Industry Standard)"
echo "═══════════════════════════════════════════════════"
python3 "$(dirname "$0")/scripts/taint_analysis.py" "$DEMO_TX" --method haircut --hops 2

echo ""
echo "═══════════════════════════════════════════════════"
echo "2️⃣  METHODOLOGY COMPARISON"
echo "═══════════════════════════════════════════════════"
python3 "$(dirname "$0")/scripts/taint_analysis.py" "$DEMO_TX" --compare --hops 2

echo ""
echo "═══════════════════════════════════════════════════"
echo "📚 Newsletter Reference:"
echo "   skills/bitcoin-heuristics/references/issue4-taint-analysis.md"
echo ""
echo "🛠️  Usage:"
echo "   python3 scripts/taint_analysis.py <txid> --method haircut --hops 3"
echo "   python3 scripts/taint_analysis.py <txid> --compare"
echo "   python3 scripts/taint_analysis.py <txid> --json"
echo "═══════════════════════════════════════════════════"
