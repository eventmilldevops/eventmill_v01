"""Quick check: which techniques from the CrowdStrike report are in the local DB?"""
import json
from pathlib import Path

DB = Path(__file__).parent.parent / "framework/reference_data/mitre_techniques.json"
db = json.load(open(DB))

# All technique IDs from the CrowdStrike Gemini output
report_tids = [
    "T1190", "T1068", "T1082", "T1655", "T1486", "T1003.003",
    "T1574.001", "T1572", "T1557", "T1649", "T1566.002", "T1566.004",
    "T1114.003", "T1219", "T1567.002", "T1195.002", "T1484.002",
    "T1021.002",
]

print(f"Local DB: {len(db)} techniques\n")
for tid in report_tids:
    entry = db.get(tid)
    if entry:
        print(f"  HIT  {tid:12s} → {entry['name']:45s} | {entry['tactics']}")
    else:
        print(f"  MISS {tid:12s} → NOT IN LOCAL DB (LLM-only or hallucinated)")

print(f"\n{sum(1 for t in report_tids if t in db)}/{len(report_tids)} resolved from local DB")
