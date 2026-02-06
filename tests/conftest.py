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
            tx_key = "tx_" + key.replace("outspends_", "")
            if tx_key in sample_data:
                spends_by_id[sample_data[tx_key]["txid"]] = val

    def _fetch(txid):
        return spends_by_id.get(txid, [])

    return _fetch
