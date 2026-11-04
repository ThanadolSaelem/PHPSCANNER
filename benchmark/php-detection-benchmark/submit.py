"""Post a tool's results file to the running range and print the score.
Usage:  python3 submit.py results.json  [http://127.0.0.1:9000]
results.json = {"9001": "affected", ...}  (thscan statuses or document taxonomy)
"""
import json
import sys
import urllib.request

f = sys.argv[1] if len(sys.argv) > 1 else "results.json"
base = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:9000"
data = open(f, "rb").read()
req = urllib.request.Request(base + "/api/grade", data=data,
                             headers={"Content-Type": "application/json"})
d = json.load(urllib.request.urlopen(req, timeout=10))
print(f"solved {d['solved']}/{d['total']} · exact {d['exact']}/{d['total']} · "
      f"FALSE-SAFE {d['false_safe']} · attempted {d['attempted']}")
sys.exit(1 if d["false_safe"] else 0)
