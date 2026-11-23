"""Regenerate every reported result, then verify output hashes against MANIFEST_SHA256.txt.
Usage: python run_all.py [--fast]   (--fast skips the ~80 s scaling study and the 12 min differential check)
Timing fields in the JSON depend on hardware and are excluded from the hash check."""
import subprocess, sys, os, json, hashlib
here = os.path.dirname(os.path.abspath(__file__)); ev = os.path.join(here, "eval"); fast = "--fast" in sys.argv
def run(*a):
    print(">", *a, flush=True); subprocess.run([sys.executable, *a], cwd=ev, check=True)
run("evaluate.py", ".")
run("smt_check.py", ".")
if not fast:
    run("scaling.py", ".", "18")
    run("make_figures.py", ".")
    run("hypothesis_baseline.py")
    run("diff_test.py")
def digest(name):
    d = json.load(open(os.path.join(ev, name)))
    def scrub(x):
        if isinstance(x, dict): return {k: scrub(v) for k, v in x.items() if not (k.startswith("timing") or k == "seconds" or "_s_" in k or k.endswith("_s"))}
        if isinstance(x, list): return [scrub(v) for v in x]
        return x
    return hashlib.sha256(json.dumps(scrub(d), sort_keys=True, default=str).encode()).hexdigest()
out = {n: digest(n) for n in ["hiss_eval_results.json", "hiss_smt_results.json"] + ([] if fast else ["hypothesis_baseline_results.json", "diff_results.json"])}
ref_path = os.path.join(here, "MANIFEST_SHA256.txt")
if os.path.exists(ref_path):
    ref = dict(l.split()[::-1] for l in open(ref_path).read().splitlines() if l.strip())
    for n, h in out.items(): print(("OK   " if ref.get(n) == h else "DIFF ") + n)
else:
    open(ref_path, "w").write("".join(f"{h} {n}\n" for n, h in out.items())); print("manifest written")
