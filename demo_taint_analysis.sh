#!/bin/bash
#
# Bitcoin Taint Analysis Tool - Demo
# Run this to see the tool in action!

echo "Taint Analysis Tool Demo"
echo "========================"
echo ""

# Use the famous first Bitcoin transaction (Satoshi -> Hal Finney)
DEMO_TX="f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"

echo "Demo Transaction: First Bitcoin payment ever"
echo "  Satoshi Nakamoto -> Hal Finney (10 BTC)"
echo "  TXID: ${DEMO_TX:0:20}..."
echo ""

echo "1. HAIRCUT METHODOLOGY (Industry Standard)"
echo "==========================================="
python3 "$(dirname "$0")/taint_analysis.py" "$DEMO_TX" --method haircut --hops 2

echo ""
echo "2. FIFO METHODOLOGY (First-In-First-Out)"
echo "=========================================="
python3 "$(dirname "$0")/taint_analysis.py" "$DEMO_TX" --method fifo --hops 2

echo ""
echo "3. METHODOLOGY COMPARISON"
echo "========================="
python3 "$(dirname "$0")/taint_analysis.py" "$DEMO_TX" --compare --hops 2

echo ""
echo "4. ASCII TAINT VISUALIZATION"
echo "============================"
python3 "$(dirname "$0")/taint_analysis.py" "$DEMO_TX" --method haircut --hops 1 --visualize

echo ""
echo "5. CSV OUTPUT SAMPLE"
echo "===================="
python3 "$(dirname "$0")/taint_analysis.py" "$DEMO_TX" --method haircut --hops 1 --output-format csv | head -5

echo ""
echo "Usage Examples:"
echo "  python3 taint_analysis.py <txid> --method fifo --hops 3"
echo "  python3 taint_analysis.py <txid> --compare"
echo "  python3 taint_analysis.py <txid> --output-format markdown"
echo "  python3 taint_analysis.py <txid> --visualize"
echo "  python3 taint_analysis.py <txid> --min-confidence 0.5"
echo "  python3 taint_analysis.py <txid> --audit-dir ./logs/"
