"""Independent SMT (Z3) cross-validation of the exhaustive evaluation.

The kernel and properties are re-encoded symbolically (not executed). For each kernel variant Z3
(1) decides whether any unsafe input exists, (2) counts unsafe inputs by model enumeration with
blocking clauses, and (3) proves or refutes the utility property. Results must equal evaluate.py.
Usage: python eval/smt_check.py eval   -> eval/hiss_smt_results.json
"""
import json, os, sys, time
from z3 import Solver, Bool, Int, And, Or, Not, If, BoolVal, sat, unsat, Implies, Sum
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from evaluate import ROLES, PURPOSES, FIELDS, PURPOSE_ALLOW, ROLE_PURPOSE, CLINICAL_ROLES, DIRECT_IDENTIFIERS, BREAK_GLASS

ri = Int("role"); pi = Int("purpose")
req = [Bool("req_" + f) for f in FIELDS]
auth, cur, emg = Bool("auth"), Bool("cur"), Bool("emg")
dom = And(ri >= 0, ri < len(ROLES), pi >= 0, pi < len(PURPOSES), Or(req))
inputs = [ri, pi, auth, cur, emg] + req

def is_role(names): return Or([ri == ROLES.index(r) for r in names])
clinical = is_role(CLINICAL_ROLES)
entitled = Or([And(ri == ROLES.index(r), pi == PURPOSES.index(p)) for r in ROLES for p in ROLE_PURPOSE[r]])
def allowed(f): return Or([pi == PURPOSES.index(p) for p in PURPOSES if f in PURPOSE_ALLOW[p]] or [BoolVal(False)])

def granted(fixed):
    out = []
    for f, r in zip(FIELDS, req):
        bg = And(r, BoolVal(f in BREAK_GLASS))
        if fixed: bg = And(bg, clinical)
        out.append(If(Not(And(auth, cur)), BoolVal(False), If(emg, bg, And(entitled, r, allowed(f)))))
    return out

def props(g):
    any_g = Or(g)
    G = dict(zip(FIELDS, g))
    return {
        "P1": And(any_g, Not(And(auth, cur))),
        "P2": And(any_g, emg, Not(clinical)),
        "P3": And(any_g, Not(emg), Not(entitled)),
        "P4": And(Not(emg), Or([And(G[f], Not(allowed(f))) for f in FIELDS])),
        "P5": And(ri == ROLES.index("researcher"), Or([G[f] for f in DIRECT_IDENTIFIERS])),
        "P6": And(ri == ROLES.index("ai_service"), Or([G[f] for f in (DIRECT_IDENTIFIERS - {"identity"}) | {"operative_note"}])),
        "P7": Or([And(G[f], Not(r)) for f, r in zip(FIELDS, req)]),
    }

def count(phi, cap=100000):
    s = Solver(); s.add(dom, phi); n = 0
    while s.check() == sat and n < cap:
        m = s.model(); n += 1
        s.add(Or([v != m.eval(v, model_completion=True) for v in inputs]))
    return n

def utility_holds(g):
    # legitimate -> granted equals minimum-necessary set (spec), checked for all inputs
    G = dict(zip(FIELDS, g))
    want = {f: If(emg, And(r, BoolVal(f in BREAK_GLASS)), And(r, allowed(f))) for f, r in zip(FIELDS, req)}
    legit = And(auth, cur, If(emg, And(clinical, Or([want[f] for f in FIELDS])), And(entitled, Or([want[f] for f in FIELDS]))))
    s = Solver(); s.add(dom, legit, Or([G[f] != want[f] for f in FIELDS]))
    return s.check() == unsat

if __name__ == "__main__":
    out = {}
    for name, fixed in [("WP2 kernel", False), ("WP2 kernel + break-glass fix", True)]:
        t0 = time.perf_counter()
        g = granted(fixed); P = props(g); unsafe = Or(list(P.values()))
        s = Solver(); s.add(dom, unsafe); exists = s.check() == sat
        r = {"unsafe_exists": exists, "unsafe_count": count(unsafe) if exists else 0,
             "per_property": {k: count(v) for k, v in P.items()}, "utility_proved": utility_holds(g)}
        r["seconds"] = round(time.perf_counter() - t0, 2)
        out[name] = r
    ev = json.load(open(os.path.join(sys.argv[1], "hiss_eval_results.json")))["deciders"]
    out["agrees_with_exhaustive"] = all(
        out[k]["unsafe_count"] == ev[k]["unsafe_requests"] and
        all(out[k]["per_property"][p] == sum(v for q, v in ev[k]["violations"].items() if q.startswith(p + "_")) for p in out[k]["per_property"])
        for k in ["WP2 kernel", "WP2 kernel + break-glass fix"])
    json.dump(out, open(os.path.join(sys.argv[1], "hiss_smt_results.json"), "w"), indent=2)
    print(json.dumps(out, indent=1))
