"""Vector figures for the HISS manuscript, generated only from eval/hiss_eval_results.json.
Usage: python eval/make_figures.py eval   (writes fig_safety_utility.pdf, fig_property_heatmap.pdf)
"""
import json, os, sys
import matplotlib
matplotlib.use("pdf")
import matplotlib.pyplot as plt

d = sys.argv[1]
R = json.load(open(os.path.join(d, "hiss_eval_results.json")))
D = R["deciders"]
plt.rcParams.update({"font.family": "serif", "font.size": 8, "pdf.fonttype": 42, "axes.spines.top": False, "axes.spines.right": False})

ORDER = [("RBAC whole record", "RBAC, whole record"), ("RBAC role scope", "RBAC, role scope"),
         ("Consent/authority only", "Consent only"), ("WP2 kernel", "Kernel (Sept 2026)"),
         ("WP2 kernel + break-glass fix", "Kernel with fix"), ("Deny all", "Deny all (reference)")]
N = R["input_space"]

# Figure: safety (unsafe decisions) vs utility (exact minimum-necessary release for legitimate requests)
fig, (a1, a2) = plt.subplots(1, 2, figsize=(6.6, 2.4), sharey=True)
ys = list(range(len(ORDER)))[::-1]
for y, (k, lab) in zip(ys, ORDER):
    r = D[k]
    u = 100 * r["unsafe_requests"] / N
    a1.barh(y, u, color="#b2182b" if u > 0 else "#999999", height=0.6)
    a1.text(u + 1.5, y, f"{r['unsafe_requests']:,} ({u:.1f}%)", va="center", fontsize=7)
    leg = r["legit_routine"] + r["legit_emergency"]; srv = r["served_routine"] + r["served_emergency"]
    s = 100 * srv / leg
    a2.barh(y, s, color="#2166ac", height=0.6)
    a2.text(min(s, 100) + 1.5 if s < 80 else s - 1.5, y, f"{srv:,}/{leg:,}", va="center", ha="left" if s < 80 else "right",
            fontsize=7, color="black" if s < 80 else "white")
a1.set_yticks(ys); a1.set_yticklabels([lab for _, lab in ORDER])
a1.set_xlim(0, 125); a1.set_xticks([0, 25, 50, 75, 100])
a1.set_xlabel(f"Unsafe decisions (% of {N:,} requests)")
a2.set_xlim(0, 105); a2.set_xticks([0, 25, 50, 75, 100])
a2.set_xlabel("Legitimate requests released exactly (%)")
a1.set_title("(a) Safety", fontsize=8, loc="left"); a2.set_title("(b) Utility", fontsize=8, loc="left")
fig.tight_layout()
fig.savefig(os.path.join(d, "fig_safety_utility.pdf"))

# Figure: threat coverage -- requests violating any property derived from each threat, per policy
from matplotlib.patches import Rectangle
threats = [f"T{i:02d}" for i in range(1, 13)]
cols = ORDER[:5]
evaluated = set(D["WP2 kernel"]["per_threat"]) | set(D["RBAC whole record"]["per_threat"])
fig, ax = plt.subplots(figsize=(4.8, 3.3))
mx = max(max(D[k]["per_threat"].values(), default=0) for k, _ in cols)
for i, t in enumerate(threats):
    for j, (k, _) in enumerate(cols):
        if t not in evaluated:
            ax.add_patch(Rectangle((j - .5, i - .5), 1, 1, facecolor="#eeeeee", edgecolor="white", hatch="///", lw=0))
            ax.text(j, i, "n.e.", ha="center", va="center", fontsize=6, color="#666666")
            continue
        v = D[k]["per_threat"].get(t, 0)
        ax.add_patch(Rectangle((j - .5, i - .5), 1, 1, facecolor=plt.cm.Reds(0.08 + 0.92 * v / mx), edgecolor="white"))
        ax.text(j, i, f"{v:,}", ha="center", va="center", fontsize=6.5, color="white" if v / mx > 0.55 else "black")
ax.set_xlim(-.5, len(cols) - .5); ax.set_ylim(len(threats) - .5, -.5)
ax.set_xticks(range(len(cols))); ax.set_xticklabels([lab.replace(", ", ",\n").replace(" (", "\n(") for _, lab in cols], fontsize=7)
ax.set_yticks(range(len(threats))); ax.set_yticklabels(threats)
ax.xaxis.tick_top(); ax.tick_params(length=0)
for s in ax.spines.values(): s.set_visible(False)
fig.tight_layout()
fig.savefig(os.path.join(d, "fig_threat_coverage.pdf"))

# Figure: scaling of exhaustive enumeration vs SMT (eval/scaling.py output)
S = json.load(open(os.path.join(d, "hiss_scaling_results.json")))
rows = S["rows"]
F = [r["fields"] for r in rows]
fig, ax = plt.subplots(figsize=(4.4, 2.5))
ax.plot(F, [r["exhaustive_s_fixed"] for r in rows], "o-", color="#b2182b", label="Exhaustive enumeration (all inputs)")
ax.plot(F, [r["smt_s_fixed"] for r in rows], "s-", color="#2166ac", label="SMT proof of safety (Z3)")
ax.set_yscale("log"); ax.set_xticks(F)
ax.set_xlabel("Number of data fields"); ax.set_ylabel("Wall-clock time (s)")
for r in rows:
    ax.annotate(f"{r['requests']:,}", (r["fields"], r["exhaustive_s_fixed"]), textcoords="offset points", xytext=(0, 6), ha="center", fontsize=6)
ax.legend(frameon=False, fontsize=7, loc="upper left")
fig.tight_layout()
fig.savefig(os.path.join(d, "fig_scaling.pdf"))
print("ok")
