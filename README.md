# 🔍 Bitcoin Taint Analysis Tool

**Professional Bitcoin forensics and transaction tracing utility**

![Status](https://img.shields.io/badge/Status-Active-green)
![Python](https://img.shields.io/badge/Python-3.7+-blue)
![Bitcoin](https://img.shields.io/badge/Bitcoin-Forensics-orange)

## 🎯 Overview

Professional-grade Bitcoin taint analysis tool implementing multiple methodologies for cryptocurrency forensics and transaction tracing. Built for the **Bitcoin Heuristics Newsletter** and blockchain investigation research.

## ⚡ Features

### 🔬 **Analysis Methodologies**
- **Haircut Taint** - Simple proportional distribution
- **Pro-Rata Taint** - Weighted distribution across outputs  
- **FIFO Taint** - First-in-first-out tracking
- **Multi-Hop Analysis** - Trace through multiple transactions

### 📊 **Visualization**
- **ASCII Flow Charts** - Transaction flow visualization
- **Taint Propagation Maps** - Visual taint distribution
- **Confidence Scoring** - Uncertainty quantification
- **Export Formats** - JSON, CSV, markdown reports

### 🛡️ **Compliance Features**
- **Sanctions Screening** - OFAC/EU sanctions integration
- **Risk Scoring** - Automated risk assessment
- **Evidence Trail** - Court-ready documentation
- **Audit Logs** - Complete analysis history

## 🚀 Quick Start

```bash
# Basic taint analysis
python3 taint_analysis.py --txid <transaction_id>

# Multi-hop analysis  
python3 taint_analysis.py --txid <txid> --hops 3

# Full forensic report
python3 taint_analysis.py --txid <txid> --method all --export pdf

# Demo mode
./demo_taint_analysis.sh
```

## 📋 Usage Examples

### Single Transaction Analysis
```bash
python3 taint_analysis.py \
  --txid 7c4025... \
  --method haircut \
  --output-format json
```

### Multi-Hop Investigation
```bash
python3 taint_analysis.py \
  --txid 7c4025... \
  --hops 5 \
  --method pro-rata \
  --min-confidence 0.1 \
  --export-report investigation_001.pdf
```

### Batch Analysis
```bash
python3 taint_analysis.py \
  --input-file transactions.txt \
  --method all \
  --parallel 4 \
  --output-dir results/
```

## 🔬 Methodologies

### **Haircut Taint**
Simple proportional distribution:
- Each output receives taint proportional to its value
- Fast computation, conservative estimates
- Good for preliminary analysis

### **Pro-Rata Taint** 
Weighted distribution model:
- Considers input/output relationships
- More accurate for complex transactions
- Industry standard methodology

### **FIFO Taint**
First-in-first-out tracking:
- Temporal ordering of inputs/outputs
- Useful for specific investigation patterns
- Higher computational complexity

## 📊 Output Formats

### **JSON Report**
```json
{
  "analysis_id": "taint_20240202_001",
  "methodology": "pro-rata",
  "confidence": 0.87,
  "taint_distribution": {...},
  "risk_score": "medium"
}
```

### **Markdown Summary**
- Executive summary
- Key findings  
- Visual flow charts
- Methodology notes

### **PDF Report**
- Court-ready documentation
- Professional formatting
- Charts and visualizations
- Evidence chain documentation

## 🎓 Educational Use

Perfect for:
- **Blockchain Forensics Training** - Learn investigation techniques
- **Academic Research** - Cite-ready methodologies  
- **Newsletter Content** - Real-world examples
- **Compliance Testing** - Verify AML procedures

## 🔧 Technical Details

### **Dependencies**
- Python 3.7+
- Requests (API calls)
- NetworkX (graph analysis)  
- Matplotlib (visualization)
- ReportLab (PDF generation)

### **Architecture**
```
taint-analysis/
├── taint_analysis.py      # Main analysis engine
├── demo_taint_analysis.sh # Demo script
├── methodologies/         # Analysis algorithms
├── exports/              # Output formatters
├── data/                 # Sample datasets
└── docs/                 # Methodology documentation
```

### **Performance**
- **Single Transaction** - < 2 seconds
- **5-Hop Analysis** - < 30 seconds  
- **Batch Processing** - 100+ tx/minute
- **Memory Usage** - < 50MB typical

## 📚 Methodology References

Based on academic research:
- Reid & Harrigan (2011) - "An Analysis of Anonymity in Bitcoin"
- Ron & Shamir (2012) - "Quantitative Analysis of Bitcoin"  
- Meiklejohn et al. (2013) - "A Fistful of Bitcoins"
- Modern forensics best practices

## ⚖️ Legal Compliance

### **Evidence Standards**
- **Daubert Criteria** - Scientific methodology
- **Chain of Custody** - Complete audit trail
- **Error Rate Quantification** - Statistical confidence
- **Peer Review** - Published methodologies

### **Privacy Protection**
- No personal data storage
- Configurable data retention
- GDPR-compliant operations
- Optional anonymization

## 🔍 Integration

### **API Endpoints**
```python
# Programmatic access
from taint_analysis import TaintAnalyzer

analyzer = TaintAnalyzer()
result = analyzer.analyze(txid, method='pro-rata')
```

### **Webhook Support**
- Real-time analysis notifications
- Integration with investigation platforms
- Slack/Discord reporting bots
- Custom webhook endpoints

## 🚨 Disclaimer

This tool is for:
- ✅ Educational purposes
- ✅ Academic research  
- ✅ Compliance testing
- ✅ Authorized investigations

**Not for:** Unauthorized surveillance, privacy violation, or illegal activities.

## 📄 License

Private research tool - Educational use only.

---

**Built for the Bitcoin Heuristics Newsletter** 📰  
*Professional blockchain forensics research and education*