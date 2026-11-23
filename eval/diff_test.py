"""Differential test: WP2 kernel (original + fixed) vs two engines (Cedar, OPA/Rego) whose policies were
written blind from the prose specification (engines/INTERPRETATION.md), over the full 73,440-request space.
Outputs diff_results.json. Deterministic."""
import json, collections, time
from evaluate import space, decide, kernel, CLINICAL_ROLES
from engines.run_engines import cedar_decide, rego_decide_batch

reqs = list(space())
t = time.time()
orig = [frozenset(decide(r, p, f, a, c, e)["fields"]) for r, p, f, a, c, e in reqs]
fixed = [frozenset(kernel(r, p, f, a, c, e, cfg={"fix_breakglass": True})[1]) for r, p, f, a, c, e in reqs]
cedar = [frozenset(cedar_decide(r, p, f, a, c, e)) for r, p, f, a, c, e in reqs]
rego = rego_decide_batch([dict(role=r, purpose=p, fields=sorted(f), auth=a, cur=c, emg=e) for r, p, f, a, c, e in reqs])
rego = [frozenset(x) for x in rego]

def stratum(q):
    r, p, f, a, c, e = q
    return f"{'clinical' if r in CLINICAL_ROLES else 'nonclinical'}|{'emg' if e else 'routine'}|{'auth_ok' if a and c else 'auth_bad'}"

out = {"n": len(reqs), "seconds": round(time.time() - t, 1), "pairs": {}}
for name, x, y in [("orig_vs_cedar", orig, cedar), ("orig_vs_rego", orig, rego), ("fixed_vs_cedar", fixed, cedar),
                   ("fixed_vs_rego", fixed, rego), ("cedar_vs_rego", cedar, rego)]:
    bad = [i for i in range(len(reqs)) if x[i] != y[i]]
    strat = collections.Counter(stratum(reqs[i]) for i in bad)
    ex = [dict(role=reqs[i][0], purpose=reqs[i][1], req=sorted(reqs[i][2]), auth=reqs[i][3], cur=reqs[i][4],
               emg=reqs[i][5], a=sorted(x[i]), b=sorted(y[i])) for i in bad[:3]]
    out["pairs"][name] = {"disagreements": len(bad), "by_stratum": dict(strat), "examples": ex}
json.dump(out, open("diff_results.json", "w"), indent=1)
for k, v in out["pairs"].items():
    print(k, v["disagreements"], v["by_stratum"])
