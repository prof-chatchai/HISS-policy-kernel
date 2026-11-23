"""Scaling study: exhaustive enumeration vs SMT as the number of data fields grows.

Synthetic kernel family with the same structure as the WP2 kernel (6 roles, 6 purposes, 3 context flags),
F fields, deterministic purpose sets (field i allowed for purpose j iff (i + j) % 3 != 0), break-glass set
= first 3 fields, clinical roles = first 3 roles, each role entitled to purpose with the same index.
Variant "defect" omits the clinical-role check in break-glass; "fixed" includes it.
Properties: P1-P4 and P7 (generic, no role-specific P5/P6). No randomness.
Usage: python eval/scaling.py eval [maxF]   -> eval/hiss_scaling_results.json
"""
import itertools, json, os, sys, time
from z3 import Solver, Bool, Int, And, Or, Not, If, BoolVal, sat

R = P = 6; CLIN = {0, 1, 2}

def cfg(F):
    allow = [{i for i in range(F) if (i + j) % 3 != 0} for j in range(P)]
    return allow, set(range(3))

def kernel(F, allow, bg, fixed, r, p, req, a, c, e):
    if not (a and c): return 0
    if e:
        if fixed and r not in CLIN: return 0
        return req & bg
    if p != r: return 0
    return req & allow[p]

def unsafe(F, allow, r, p, req, a, c, e, g):
    if not g: return False
    if not (a and c): return True
    if e and r not in CLIN: return True
    if not e and p != r: return True
    if not e and g & ~allow[p]: return True
    return bool(g & ~req)

def exhaustive(F, fixed):
    allow, bg = cfg(F)
    am = [sum(1 << i for i in s) for s in allow]; bm = sum(1 << i for i in bg)
    n = u = 0; t0 = time.perf_counter()
    for r, p, req, a, c, e in itertools.product(range(R), range(P), range(1, 1 << F), (True, False), (True, False), (False, True)):
        g = kernel(F, am, bm, fixed, r, p, req, a, c, e); n += 1
        if unsafe(F, am, r, p, req, a, c, e, g): u += 1
    return n, u, time.perf_counter() - t0

def smt(F, fixed):
    allow, bg = cfg(F); t0 = time.perf_counter()
    ri, pi = Int("r"), Int("p"); req = [Bool(f"q{i}") for i in range(F)]; a, c, e = Bool("a"), Bool("c"), Bool("e")
    clin = Or([ri == k for k in CLIN]); ent = ri == pi
    al = [Or([pi == j for j in range(P) if i in allow[j]]) for i in range(F)]
    g = [If(Not(And(a, c)), BoolVal(False), If(e, And(req[i], BoolVal(i in bg), clin if fixed else BoolVal(True)), And(ent, req[i], al[i]))) for i in range(F)]
    anyg = Or(g)
    bad = Or(And(anyg, Not(And(a, c))), And(anyg, e, Not(clin)), And(anyg, Not(e), Not(ent)),
             And(Not(e), Or([And(g[i], Not(al[i])) for i in range(F)])), Or([And(g[i], Not(req[i])) for i in range(F)]))
    s = Solver(); s.add(ri >= 0, ri < R, pi >= 0, pi < P, Or(req), bad)
    res = s.check() == sat
    return res, time.perf_counter() - t0

if __name__ == "__main__":
    maxF = int(sys.argv[2]) if len(sys.argv) > 2 else 14
    rows = []
    for F in range(8, maxF + 1, 2):
        n, ud, te = exhaustive(F, False); _, uf, tf = exhaustive(F, True)
        sd, sdt = smt(F, False); sf, sft = smt(F, True)
        rows.append(dict(fields=F, requests=n, unsafe_defect=ud, unsafe_fixed=uf, exhaustive_s_defect=round(te, 2), exhaustive_s_fixed=round(tf, 2),
                         smt_finds_defect=sd, smt_s_defect=round(sdt, 3), smt_proves_fixed_safe=not sf, smt_s_fixed=round(sft, 3)))
        print(rows[-1], flush=True)
    # extrapolation from the largest measured point: seconds per request
    spr = rows[-1]["exhaustive_s_fixed"] / rows[-1]["requests"]
    ext = {F: round(R * P * ((1 << F) - 1) * 8 * spr) for F in (20, 24, 32)}
    json.dump({"rows": rows, "seconds_per_request": spr, "extrapolated_seconds_exhaustive": ext}, open(os.path.join(sys.argv[1], "hiss_scaling_results.json"), "w"), indent=2)
    print("extrapolated seconds", ext)
