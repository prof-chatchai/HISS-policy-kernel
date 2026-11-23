"""Cedar and Rego engines for the blind spec. Self-test: python run_engines.py"""
import json, subprocess, sys, tempfile, os
import cedarpy

HERE = os.path.dirname(os.path.abspath(__file__))
OPA = os.path.join(HERE, "bin", "opa.exe")
FIELDS = ["identity", "cleft_dx", "facial_image", "operative_note", "speech_assessment",
          "dental_data", "family_relationship", "research_pseudonym"]
# Cedar entity data (configuration, not logic)
_PURP = {
    "treatment_surgery": ["operative_note", "identity", "cleft_dx", "facial_image"],
    "treatment_speech": ["identity", "speech_assessment", "cleft_dx"],
    "treatment_dental": ["identity", "cleft_dx", "dental_data"],
    "guardian_coordination": ["identity", "cleft_dx"],
    "research": ["research_pseudonym", "speech_assessment", "cleft_dx", "dental_data"],
    "ai_admin_summary": ["identity", "cleft_dx"],
}
_ROLE = {"surgeon": "treatment_surgery", "speech": "treatment_speech", "dentist": "treatment_dental",
         "guardian": "guardian_coordination", "researcher": "research", "ai_service": "ai_admin_summary"}
_ent = ([{"uid": {"type": "Purpose", "id": p}, "attrs": {"fields": fs}, "parents": []} for p, fs in _PURP.items()]
        + [{"uid": {"type": "Role", "id": r}, "attrs": {"entitled": {"__entity": {"type": "Purpose", "id": p}}}, "parents": []}
           for r, p in _ROLE.items()]
        + [{"uid": {"type": "Field", "id": f}, "attrs": {"name": f}, "parents": []} for f in FIELDS])
_POL = open(os.path.join(HERE, "cedar_policy.cedar"), encoding="utf-8").read()
_PS = cedarpy.PolicySet.from_str(_POL)
_ES = cedarpy.Entities.from_json_str(json.dumps(_ent))


def cedar_decide(role, purpose, fields, auth, cur, emg):
    if role not in _ROLE or purpose not in _PURP:
        return frozenset()
    ctx = {"purpose": {"__entity": {"type": "Purpose", "id": purpose}},
           "auth": bool(auth), "cur": bool(cur), "emg": bool(emg)}
    out = set()
    for f in fields:
        if f not in FIELDS:
            continue
        r = cedarpy.is_authorized({"principal": {"type": "Role", "id": role},
                                   "action": {"type": "Action", "id": "read"},
                                   "resource": {"type": "Field", "id": f}, "context": ctx}, _PS, _ES)
        if r.allowed:
            out.add(f)
    return frozenset(out)


def rego_decide_batch(inputs):
    """inputs: list of dicts role,purpose,fields,auth,cur,emg -> list[frozenset]"""
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as t:
        json.dump({"requests": inputs}, t)
        path = t.name
    try:
        p = subprocess.run([OPA, "eval", "-f", "json", "-d", os.path.join(HERE, "policy.rego"),
                            "-i", path, "data.hiss.result"], capture_output=True, text=True, check=True)
    finally:
        os.unlink(path)
    val = json.loads(p.stdout)["result"][0]["expressions"][0]["value"]
    return [frozenset(x) for x in val]


def _selftest():
    A = ["identity", "cleft_dx", "facial_image", "operative_note", "speech_assessment", "dental_data",
         "family_relationship", "research_pseudonym"]
    T = [("surgeon", "treatment_surgery", A, 1, 1, 0), ("surgeon", "treatment_surgery", A, 1, 1, 1),
         ("surgeon", "research", A, 1, 1, 0), ("surgeon", "treatment_surgery", A, 0, 1, 0),
         ("surgeon", "treatment_surgery", A, 1, 0, 0), ("speech", "treatment_speech", A, 1, 1, 0),
         ("dentist", "treatment_dental", ["dental_data", "facial_image"], 1, 1, 0),
         ("guardian", "guardian_coordination", A, 1, 1, 0), ("guardian", "guardian_coordination", A, 1, 1, 1),
         ("guardian", "guardian_coordination", A, 1, 0, 0), ("guardian", "guardian_coordination", A, 0, 1, 1),
         ("researcher", "research", A, 1, 1, 0), ("researcher", "research", ["identity"], 1, 1, 0),
         ("researcher", "research", A, 1, 1, 1), ("ai_service", "ai_admin_summary", A, 1, 1, 0),
         ("ai_service", "ai_admin_summary", A, 1, 1, 1), ("ai_service", "treatment_surgery", A, 1, 1, 0),
         ("dentist", "treatment_dental", ["operative_note"], 1, 1, 1),
         ("speech", "treatment_surgery", A, 1, 1, 1), ("surgeon", "treatment_surgery", ["family_relationship"], 1, 1, 0)]
    ins = [dict(role=r, purpose=p, fields=f, auth=bool(a), cur=bool(c), emg=bool(e)) for r, p, f, a, c, e in T]
    rg = rego_decide_batch(ins)
    bad = 0
    for t, i, g in zip(T, ins, rg):
        c = cedar_decide(*t[:3], bool(t[3]), bool(t[4]), bool(t[5]))
        flag = "OK" if c == g else "DISAGREE"
        bad += c != g
        print(f"{t[0]:10}{t[1]:22}a{t[3]}c{t[4]}e{t[5]} cedar={sorted(c)} rego={sorted(g)} {flag}")
    print("disagreements:", bad)
    return bad


if __name__ == "__main__":
    sys.exit(1 if _selftest() else 0)
