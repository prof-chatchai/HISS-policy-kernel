"""Exhaustive specification-based evaluation of the WANMAI-PDPA policy kernel (WP2, 2026-09-17).

Kernel copied verbatim from 04_policy_kernel.py (WP2 package). Safety properties are written
independently from the threat model (WP1 01_THREAT_MODEL.csv), not derived from kernel code.
Outputs JSON + CSV for the HISS manuscript. Deterministic; no randomness.
"""
import itertools, json, csv, copy, sys, os

# ---------------- kernel under test (verbatim) ----------------
DATA = {'identity': {'sensitivity': 2}, 'cleft_dx': {'sensitivity': 3}, 'facial_image': {'sensitivity': 5}, 'operative_note': {'sensitivity': 4}, 'speech_assessment': {'sensitivity': 4}, 'dental_data': {'sensitivity': 4}, 'family_relationship': {'sensitivity': 4}, 'research_pseudonym': {'sensitivity': 2}}
PURPOSE_ALLOW = {'treatment_surgery': {'operative_note', 'identity', 'cleft_dx', 'facial_image'}, 'treatment_speech': {'identity', 'speech_assessment', 'cleft_dx'}, 'treatment_dental': {'identity', 'cleft_dx', 'dental_data'}, 'guardian_coordination': {'identity', 'cleft_dx'}, 'research': {'research_pseudonym', 'speech_assessment', 'cleft_dx', 'dental_data'}, 'ai_admin_summary': {'identity', 'cleft_dx'}}
ROLE_PURPOSE = {'surgeon': {'treatment_surgery'}, 'speech': {'treatment_speech'}, 'dentist': {'treatment_dental'}, 'guardian': {'guardian_coordination'}, 'researcher': {'research'}, 'ai_service': {'ai_admin_summary'}}

# Original WP2 function, verbatim from 04_policy_kernel.py (05_PRIOR_PACKAGES/WANMAI_PDPA_WP2_Residual_Kill_Policy_Kernel.zip).
# Used only to prove that the instrumented kernel() below is decision-equivalent on the full input space.
def decide(role, purpose, fields, authority=True, current=True, emergency=False):
    fields=set(fields)
    if not authority or not current:
        return {"decision":"DENY","fields":[],"reason":"authority_invalid"}
    if emergency:
        allowed={"identity","cleft_dx","operative_note"}
        return {"decision":"ALLOW_MINIMIZED","fields":sorted(fields & allowed),"reason":"break_glass_bounded"}
    if purpose not in ROLE_PURPOSE.get(role,set()):
        return {"decision":"DENY","fields":[],"reason":"role_purpose_mismatch"}
    granted=fields & PURPOSE_ALLOW[purpose]
    if not granted:
        return {"decision":"DENY","fields":[],"reason":"no_minimum_necessary_fields"}
    return {"decision":"ALLOW" if granted==fields else "ALLOW_MINIMIZED",
            "fields":sorted(granted),"reason":"purpose_minimization"}

def kernel(role, purpose, fields, authority=True, current=True, emergency=False, cfg=None):
    # Instrumented copy of decide(); cfg switches implement mutants and the fix. cfg=None == decide().
    c = cfg or {}
    fields = set(fields)
    pa = c.get("purpose_allow", PURPOSE_ALLOW); rp = c.get("role_purpose", ROLE_PURPOSE)
    if not c.get("skip_authority") and (not authority or not current):
        return "DENY", set(), "authority_invalid"
    if emergency and not c.get("skip_breakglass"):
        allowed = {"identity", "cleft_dx", "operative_note"}
        if c.get("fix_breakglass") and role not in CLINICAL_ROLES:
            return "DENY", set(), "break_glass_not_permitted"
        g = fields & allowed
        return "ALLOW_MINIMIZED", g, "break_glass_bounded"
    if not c.get("skip_role_purpose") and purpose not in rp.get(role, set()):
        return "DENY", set(), "role_purpose_mismatch"
    allow = set(DATA) if c.get("skip_minimisation") else pa[purpose]
    granted = fields & allow
    if not granted:
        return "DENY", set(), "no_minimum_necessary_fields"
    return ("ALLOW" if granted == fields else "ALLOW_MINIMIZED"), granted, "purpose_minimization"

# ---------------- independent safety properties (from WP1 threat model) ----------------
CLINICAL_ROLES = {"surgeon", "speech", "dentist"}           # T09: break-glass narrow scope, clinicians only
DIRECT_IDENTIFIERS = {"identity", "facial_image", "family_relationship"}

def violations(role, purpose, req, auth, cur, emg, granted):
    v = []
    if granted and (not auth or not cur):
        v.append("P1_stale_or_revoked_authority")                     # T02, T10
    if granted and emg and role not in CLINICAL_ROLES:
        v.append("P2_breakglass_by_nonclinical_role")                 # T09
    if granted and not emg and purpose not in ROLE_PURPOSE[role]:
        v.append("P3_role_purpose_mismatch_grant")                    # T03, T08
    if not emg and granted - PURPOSE_ALLOW[purpose]:
        v.append("P4_field_beyond_purpose")                           # T03 minimum necessary
    if role == "researcher" and granted & DIRECT_IDENTIFIERS:
        v.append("P5_identifier_to_research")                         # T05
    if role == "ai_service" and granted & (DIRECT_IDENTIFIERS - {"identity"} | {"operative_note"}):
        v.append("P6_excess_context_to_ai")                           # T07
    if granted - req:
        v.append("P7_granted_unrequested")
    return v

ROLES = list(ROLE_PURPOSE); PURPOSES = list(PURPOSE_ALLOW); FIELDS = list(DATA)
SUBSETS = [set(c) for r in range(1, len(FIELDS) + 1) for c in itertools.combinations(FIELDS, r)]

def space():
    for role, purpose, req, auth, cur, emg in itertools.product(ROLES, PURPOSES, SUBSETS, [True, False], [True, False], [False, True]):
        yield role, purpose, req, auth, cur, emg

BREAK_GLASS = {"identity", "cleft_dx", "operative_note"}
# Threat -> property source mapping (manuscript Table 3). Threats absent here are not evaluated by the kernel.
THREAT_PROPS = {"T02": {"P1"}, "T03": {"P3", "P4"}, "T05": {"P5"}, "T07": {"P6"}, "T08": {"P3"}, "T09": {"P2"}, "T10": {"P1"}}

def legitimate(role, purpose, req, auth, cur, emg):
    # Utility oracle (spec, not kernel): returns the field set a correct policy should release, or None if
    # the request is not legitimate. Routine: entitled role, valid+current authority, overlap with purpose set.
    # Emergency: clinical role, valid+current authority, overlap with the bounded break-glass set.
    if not auth or not cur:
        return None
    if emg:
        g = req & BREAK_GLASS if role in CLINICAL_ROLES else set()
    else:
        g = req & PURPOSE_ALLOW[purpose] if purpose in ROLE_PURPOSE[role] else set()
    return g or None

def run(decider, exclude=()):
    n = req_fields = granted_fields = 0
    unsafe_requests = 0; per_prop = {}; examples = {}
    legit = served = legit_emg = served_emg = 0; per_threat = {}
    for role, purpose, req, auth, cur, emg in space():
        d, g, _ = decider(role, purpose, req, auth, cur, emg)
        n += 1; req_fields += len(req); granted_fields += len(g)
        want = legitimate(role, purpose, req, auth, cur, emg)
        if want is not None:
            ok = (g == want)
            if emg: legit_emg += 1; served_emg += ok
            else: legit += 1; served += ok
        v = [p for p in violations(role, purpose, req, auth, cur, emg, g) if p[:2] not in exclude]
        vp = {p.split("_")[0] for p in v}
        for t, ps in THREAT_PROPS.items():
            if vp & ps: per_threat[t] = per_threat.get(t, 0) + 1
        if v:
            unsafe_requests += 1
            for p in v:
                per_prop[p] = per_prop.get(p, 0) + 1
                examples.setdefault(p, dict(role=role, purpose=purpose, requested=sorted(req), authority=auth, current=cur, emergency=emg, granted=sorted(g)))
    return dict(requests=n, requested_fields=req_fields, granted_fields=granted_fields,
                withheld_pct=round(100 * (1 - granted_fields / req_fields), 2),
                unsafe_requests=unsafe_requests, unsafe_pct=round(100 * unsafe_requests / n, 3),
                violations=per_prop, first_example=examples, per_threat=per_threat,
                legit_routine=legit, served_routine=served, legit_emergency=legit_emg, served_emergency=served_emg)

# ---------------- baselines ----------------
def rbac_whole_record(role, purpose, req, auth, cur, emg):
    # role-based access: any authenticated role may read whatever it requests (no purpose, no lifecycle)
    return "ALLOW", set(req), "rbac"

def rbac_role_scope(role, purpose, req, auth, cur, emg):
    # role-scoped RBAC: union of fields of the role's purposes; ignores stated purpose and authority lifecycle
    scope = set().union(*(PURPOSE_ALLOW[p] for p in ROLE_PURPOSE[role]))
    g = set(req) & scope
    return ("ALLOW" if g else "DENY"), g, "rbac_scope"

def consent_only(role, purpose, req, auth, cur, emg):
    # consent/authority check only (lifecycle), no minimisation
    if not auth or not cur:
        return "DENY", set(), "authority_invalid"
    return "ALLOW", set(req), "consent"

def deny_all(role, purpose, req, auth, cur, emg):
    # trivially safe reference: shows why safety must be read together with utility
    return "DENY", set(), "deny_all"

def wp2_kernel(*a): return kernel(*a)
def wp2_kernel_fixed(*a): return kernel(*a, cfg={"fix_breakglass": True})

# ---------------- the original 10-case suite (WP2 01_POLICY_KERNEL_CASES.csv) ----------------
SUITE10 = [
    ("guardian", "guardian_coordination", {"identity", "cleft_dx"}, True, True, False, "ALLOW"),
    ("guardian", "guardian_coordination", {"identity", "cleft_dx", "facial_image", "operative_note"}, True, True, False, "ALLOW_MINIMIZED"),
    ("guardian", "guardian_coordination", {"identity"}, False, True, False, "DENY"),
    ("surgeon", "treatment_surgery", {"identity", "cleft_dx", "facial_image", "operative_note"}, True, True, False, "ALLOW"),
    ("speech", "treatment_speech", {"identity", "cleft_dx", "speech_assessment", "facial_image"}, True, True, False, "ALLOW_MINIMIZED"),
    ("researcher", "research", {"identity", "cleft_dx", "speech_assessment", "research_pseudonym"}, True, True, False, "ALLOW_MINIMIZED"),
    ("ai_service", "ai_admin_summary", {"identity", "cleft_dx", "facial_image", "operative_note", "family_relationship"}, True, True, False, "ALLOW_MINIMIZED"),
    ("dentist", "treatment_surgery", {"identity", "cleft_dx"}, True, True, False, "DENY"),
    ("surgeon", "treatment_surgery", {"identity", "operative_note"}, True, False, False, "DENY"),
    ("surgeon", "treatment_surgery", {"identity", "operative_note"}, True, True, True, "ALLOW_MINIMIZED"),
]

MUTANTS = {
    "M1_no_authority_check": {"skip_authority": True},
    "M2_no_role_purpose_check": {"skip_role_purpose": True},
    "M3_no_minimisation": {"skip_minimisation": True},
    "M4_breakglass_unbounded": "unbounded",
    "M5_research_gets_identity": "research_identity",
    "M6_ai_gets_full_record": "ai_full",
    "M7_breakglass_before_authority": "bg_first",
    "M8_role_check_clinicians_only": "role_clin_only",
    "M9_dental_purpose_allows_photo": "dental_photo",
    "M10_speech_purpose_allows_family": "speech_family",
}

def mutant_decider(name):
    spec = MUTANTS[name]
    if isinstance(spec, dict):
        return lambda *a: kernel(*a, cfg=spec)
    def d(role, purpose, req, auth, cur, emg):
        if spec == "bg_first" and emg:
            return "ALLOW_MINIMIZED", set(req) & {"identity", "cleft_dx", "operative_note"}, "break_glass_bounded"
        if spec == "role_clin_only" and not emg and auth and cur and role not in CLINICAL_ROLES:
            g = set(req) & PURPOSE_ALLOW[purpose]
            return ("ALLOW" if g == set(req) else "ALLOW_MINIMIZED") if g else "DENY", g, "mutant"
        if spec in ("dental_photo", "speech_family"):
            extra = {"dental_photo": ("treatment_dental", "facial_image"), "speech_family": ("treatment_speech", "family_relationship")}[spec]
            dec, g, r = kernel(role, purpose, req, auth, cur, emg)
            if purpose == extra[0] and dec != "DENY" and extra[1] in req and not emg:
                g = g | {extra[1]}
            return dec, g, r
        if spec == "unbounded" and emg and auth and cur:
            return "ALLOW", set(req), "break_glass_unbounded"
        dec, g, r = kernel(role, purpose, req, auth, cur, emg)
        if spec == "research_identity" and purpose == "research" and dec != "DENY":
            g = g | (set(req) & {"identity"})
        if spec == "ai_full" and purpose == "ai_admin_summary" and dec != "DENY":
            g = set(req)
        return dec, g, r
    return d

def config_mutants():
    # Systematic single-entry configuration faults: add one field to one purpose's allowed set, or entitle
    # one role to one extra purpose. Every such entry over-grants relative to the specification.
    out = {}
    for p in PURPOSES:
        for f in FIELDS:
            if f not in PURPOSE_ALLOW[p]:
                pa = {k: set(v) for k, v in PURPOSE_ALLOW.items()}; pa[p].add(f)
                out[f"PA+{p}:{f}"] = {"purpose_allow": pa}
    for r in ROLES:
        for p in PURPOSES:
            if p not in ROLE_PURPOSE[r]:
                rp = {k: set(v) for k, v in ROLE_PURPOSE.items()}; rp[r].add(p)
                out[f"RP+{r}:{p}"] = {"role_purpose": rp}
    return out

def suite10_kills(decider):
    for role, purpose, req, auth, cur, emg, exp in SUITE10:
        d, g, _ = decider(role, purpose, req, auth, cur, emg)
        ref_d, ref_g, _ = kernel(role, purpose, req, auth, cur, emg)
        if d != exp or g != ref_g:
            return True
    return False

def exhaustive_kills(decider):
    # killed if the mutant violates a property on an input where the unmutated kernel does not
    for args in space():
        if set(violations(*args, decider(*args)[1])) - set(violations(*args, kernel(*args)[1])):
            return True
    return False

if __name__ == "__main__":
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    import time, math, platform
    suite_pass = sum(kernel(r, p, q, a, c, e)[0] == exp for r, p, q, a, c, e, exp in SUITE10)
    # 1. equivalence of instrumented kernel() with the verbatim original decide() on every input
    mism = sum(1 for r, p, q, a, c, e in space()
               if (lambda o, k: (o["decision"], set(o["fields"])) != (k[0], k[1]))(decide(r, p, q, a, c, e), kernel(r, p, q, a, c, e)))
    t0 = time.perf_counter(); wp2 = run(wp2_kernel); t_run = time.perf_counter() - t0
    res = {"input_space": len(ROLES) * len(PURPOSES) * len(SUBSETS) * 8,
           "roles": len(ROLES), "purposes": len(PURPOSES), "field_subsets": len(SUBSETS),
           "suite10_pass": suite_pass, "equivalence_mismatches_vs_original": mism,
           "timing_one_exhaustive_pass_s": round(t_run, 2), "python": platform.python_version(), "machine": platform.machine(),
           "deciders": {"WP2 kernel": wp2,
                        **{k: run(f) for k, f in [("WP2 kernel + break-glass fix", wp2_kernel_fixed),
                                                  ("RBAC whole record", rbac_whole_record), ("RBAC role scope", rbac_role_scope),
                                                  ("Consent/authority only", consent_only), ("Deny all", deny_all)]}},
           "mutation": {m: {"killed_by_suite10": suite10_kills(mutant_decider(m)), "killed_by_exhaustive": exhaustive_kills(mutant_decider(m))} for m in MUTANTS}}
    # 2. sensitivity: alternative reading of T09 that permits break-glass by any role (drop P2)
    res["sensitivity_without_P2"] = {k: run(f, exclude=("P2",))["unsafe_requests"] for k, f in [("WP2 kernel", wp2_kernel), ("WP2 kernel + break-glass fix", wp2_kernel_fixed)]}
    # 3. systematic configuration mutants
    cm = config_mutants()
    ks = {m: suite10_kills(lambda *a, s=s: kernel(*a, cfg=s)) for m, s in cm.items()}
    ke = {m: exhaustive_kills(lambda *a, s=s: kernel(*a, cfg=s)) for m, s in cm.items()}
    res["config_mutation"] = {"n": len(cm), "killed_by_suite10": sum(ks.values()), "killed_by_exhaustive": sum(ke.values()),
                              "n_purpose_allow": sum(m.startswith("PA+") for m in cm), "n_role_purpose": sum(m.startswith("RP+") for m in cm),
                              "survivors_exhaustive": sorted(m for m in cm if not ke[m])}
    # 4. random sampling: requests needed to hit >=1 unsafe input with 95% probability (sampling with replacement)
    pu = wp2["unsafe_requests"] / res["input_space"]
    res["random_sampling_n95"] = math.ceil(math.log(0.05) / math.log(1 - pu))
    res["suite10_hit_prob_if_random"] = round(1 - (1 - pu) ** 10, 3)
    # 5. stratified rate: the defect's stratum (non-clinical role, valid+current authority, emergency, >=1 break-glass field requested)
    strat = [(r, p, q, a, c, e) for r, p, q, a, c, e in space() if e and a and c and r not in CLINICAL_ROLES and q & BREAK_GLASS]
    res["stratum_nonclinical_emergency"] = {"n": len(strat), "unsafe": sum(1 for x in strat if violations(*x, kernel(*x)[1]))}
    # 6. 2-way (pairwise) combinatorial coverage over the five non-field parameters
    PARAMS = [ROLES, PURPOSES, [True, False], [True, False], [False, True]]
    def pairs_of(t): return {(i, t[i], j, t[j]) for i in range(5) for j in range(i + 1, 5)}
    all_pairs = {(i, a, j, b) for i in range(5) for j in range(i + 1, 5) for a in PARAMS[i] for b in PARAMS[j]}
    s10 = set().union(*(pairs_of((r, p, a, c, e)) for r, p, q, a, c, e, _ in SUITE10))
    # deterministic greedy covering array (first best tuple in enumeration order), all fields requested
    ca, left = [], set(all_pairs)
    while left:
        best = max(itertools.product(*PARAMS), key=lambda t: len(pairs_of(t) & left))
        ca.append(best); left -= pairs_of(best)
    CA = [(r, p, set(FIELDS), a, c, e) for r, p, a, c, e in ca]
    def ca_kills(dec):  # property oracle on covering-array inputs only
        return any(set(violations(*x, dec(*x)[1])) - set(violations(*x, kernel(*x)[1])) for x in CA)
    res["pairwise"] = {"total_pairs": len(all_pairs), "suite10_pairs_covered": len(s10 & all_pairs),
                       "suite10_covers_nonclinical_emergency": any(e and r not in CLINICAL_ROLES for r, p, q, a, c, e, _ in SUITE10),
                       "covering_array_size": len(CA),
                       "covering_array_finds_defect": any(violations(*x, kernel(*x)[1]) for x in CA),
                       "covering_array_kills_hand": sum(ca_kills(mutant_decider(m)) for m in MUTANTS),
                       "covering_array_kills_config": sum(ca_kills(lambda *a, s=s: kernel(*a, cfg=s)) for s in cm.values())}
    # 7. same ten suite inputs judged by the property oracle (removes the oracle asymmetry between suite and exhaustive)
    S10 = [(r, p, q, a, c, e) for r, p, q, a, c, e, _ in SUITE10]
    def s10p_kills(dec): return any(set(violations(*x, dec(*x)[1])) - set(violations(*x, kernel(*x)[1])) for x in S10)
    res["suite10_property_oracle"] = {"finds_defect": any(violations(*x, kernel(*x)[1]) for x in S10),
                                      "kills_hand": sum(s10p_kills(mutant_decider(m)) for m in MUTANTS),
                                      "kills_config": sum(s10p_kills(lambda *a, s=s: kernel(*a, cfg=s)) for s in cm.values())}
    json.dump(res, open(os.path.join(out, "hiss_eval_results.json"), "w"), indent=2, default=list)
    with open(os.path.join(out, "hiss_eval_summary.csv"), "w", newline="") as f:
        w = csv.writer(f); w.writerow(["decider", "requests", "withheld_pct", "unsafe_requests", "unsafe_pct"] + [f"P{i}" for i in range(1, 8)]
                                      + ["legit_routine", "served_routine", "legit_emergency", "served_emergency"])
        for k, r in res["deciders"].items():
            row = [k, r["requests"], r["withheld_pct"], r["unsafe_requests"], r["unsafe_pct"]]
            row += [sum(v for p, v in r["violations"].items() if p.startswith(f"P{i}_")) for i in range(1, 8)]
            row += [r["legit_routine"], r["served_routine"], r["legit_emergency"], r["served_emergency"]]
            w.writerow(row)
    print(json.dumps({k: {kk: vv for kk, vv in v.items() if kk != "first_example"} for k, v in res["deciders"].items()}, indent=1))
    print("suite10_pass", suite_pass, "/10"); print(json.dumps(res["mutation"], indent=1))
    print(json.dumps(res["deciders"]["WP2 kernel"]["first_example"], indent=1))
    print(json.dumps({k: res[k] for k in ["equivalence_mismatches_vs_original", "timing_one_exhaustive_pass_s", "python", "machine",
                                          "sensitivity_without_P2", "config_mutation", "random_sampling_n95", "suite10_hit_prob_if_random",
                                          "stratum_nonclinical_emergency", "pairwise", "suite10_property_oracle"]}, indent=1))
