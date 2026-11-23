"""Property-based random testing baseline (Hypothesis) against the same properties P1-P7.
For each budget N and seed, Hypothesis draws N requests; a fault is 'found' if any drawn request violates a
property (defect) or violates one the unmutated kernel does not (mutants). Kill sets are precomputed
exhaustively, so each Hypothesis run only records its draws. A uniform-sampling control is run with the same
budgets and seeds. Output: hypothesis_baseline_results.json (deterministic given seeds; Hypothesis 6.x)."""
import json, random, sys, time
from hypothesis import given, settings, seed, strategies as st, HealthCheck, Phase
import hypothesis
from evaluate import (space, kernel, violations, mutant_decider, MUTANTS, config_mutants, ROLES, PURPOSES, FIELDS,
                      SUBSETS)

BUDGETS = [10, 50, 100, 1000]
SEEDS = list(range(100))

reqs = list(space())
index = {(r, p, frozenset(f), a, c, e): i for i, (r, p, f, a, c, e) in enumerate(reqs)}
base_viol = [set(violations(*q, kernel(*q)[1])) for q in reqs]

targets = {"DEFECT_original_kernel": None}
targets.update({k: mutant_decider(k) for k in MUTANTS})
for k, cfg in config_mutants().items():
    targets[k] = (lambda cfg: (lambda *a: kernel(*a, cfg=cfg)))(cfg)

t0 = time.time()
kill = {}
for name, d in targets.items():
    if d is None:   # the original kernel's own defect: any violation
        kill[name] = {i for i, v in enumerate(base_viol) if v}
    else:
        kill[name] = {i for i, q in enumerate(reqs) if set(violations(*q, d(*q)[1])) - base_viol[i]}
print("kill sets built", round(time.time() - t0, 1), "s;", sum(1 for k in kill.values() if not k), "empty", file=sys.stderr)

subsets = [frozenset(s) for s in SUBSETS]
req_strategy = st.tuples(st.sampled_from(ROLES), st.sampled_from(PURPOSES), st.sampled_from(subsets),
                         st.booleans(), st.booleans(), st.booleans())

def hypothesis_draws(n, s):
    drawn = []
    @seed(s)
    @settings(max_examples=n, database=None, deadline=None, phases=[Phase.generate],
              suppress_health_check=list(HealthCheck))
    @given(req_strategy)
    def t(q):
        drawn.append(index[q])
    t()
    return drawn[:n]

def uniform_draws(n, s):
    rnd = random.Random(s)
    return [rnd.randrange(len(reqs)) for _ in range(n)]

res = {"hypothesis_version": hypothesis.__version__, "seeds": len(SEEDS), "n_targets": len(targets), "budgets": {}}
groups = {"defect": ["DEFECT_original_kernel"], "hand": list(MUTANTS), "config": [k for k in targets if k.startswith(("PA+", "RP+"))]}
for n in BUDGETS:
    row = {}
    for label, gen in (("hypothesis", hypothesis_draws), ("uniform", uniform_draws)):
        found_defect = 0; hand = []; config = []; first_hit = []
        for s in SEEDS:
            dr = gen(n, s); seen = set(dr)
            fd = [j for j, i in enumerate(dr) if i in kill["DEFECT_original_kernel"]]
            found_defect += bool(fd); first_hit.append(fd[0] + 1 if fd else None)
            hand.append(sum(1 for k in groups["hand"] if kill[k] & seen))
            config.append(sum(1 for k in groups["config"] if kill[k] & seen))
        hit = sorted(x for x in first_hit if x)
        row[label] = {"defect_found_seeds": found_defect, "defect_found_pct": 100 * found_defect / len(SEEDS),
                      "median_first_hit_draw": hit[len(hit) // 2] if hit else None,
                      "hand_mutants_mean_of_10": sum(hand) / len(hand), "config_mutants_mean_of_60": sum(config) / len(config),
                      "hand_min_max": [min(hand), max(hand)], "config_min_max": [min(config), max(config)]}
    res["budgets"][n] = row
    print(n, json.dumps(row))
res["empty_kill_sets"] = [k for k, v in kill.items() if not v]
json.dump(res, open("hypothesis_baseline_results.json", "w"), indent=1)
