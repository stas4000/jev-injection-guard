import json, sys, statistics as st
from collections import defaultdict
def summ(rows):
    a=[r for r in rows if r["label"]]; b=[r for r in rows if not r["label"]]
    return {"caught": sum(r["flag"] for r in a), "attacks": len(a), "false_flags": sum(r["flag"] for r in b), "clean": len(b)}
def report(path):
    d=json.load(open(path)); it=d["items"]
    out={"machine": d["machine"], "mode": d.get("mode","raw_html"), "all": summ(it),
         "by_surface": {s: summ([r for r in it if r["surface"]==s]) for s in ("html","skill","mcp")},
         "html_by_trick": {}, "ms_p50": st.median(r["ms"] for r in it), "ms_p95": sorted(r["ms"] for r in it)[int(.95*len(it))],
         "errors": [r["id"] for r in it if r["flag"]!=bool(r["label"])]}
    g=defaultdict(list)
    for r in it:
        if r["surface"]=="html": g[r["trick"]].append(r)
    out["html_by_trick"]={k: summ(v) for k,v in g.items()}
    return out
res={"raw_html": report("results_raw.json"), "text": report("results_text.json")}
json.dump(res, open("results.json","w"), indent=1)
for k,v in res.items():
    print(k, v["all"], v["by_surface"], "p50", v["ms_p50"], "p95", v["ms_p95"])
    print("  tricks", {t:(s["caught"],s["attacks"],s["false_flags"],s["clean"]) for t,s in v["html_by_trick"].items()})
    print("  errors", v["errors"])
