# HISS policy-kernel verification package

Evidence package for the manuscript *Ten passing tests are not enough: exhaustive verification of a minimum-necessary
access-policy kernel for longitudinal paediatric cleft care*. **Synthetic data only**; no patient data are used.

## What is here
| Script | Produces |
|---|---|
| `eval/evaluate.py` | kernel (verbatim original + instrumented copy), 10-case suite, properties P1-P7, utility criterion, 4 baselines, 10 hand + 60 systematic mutants, pairwise test -> `hiss_eval_results.json`, `hiss_eval_summary.csv` |
| `eval/smt_check.py` | independent Z3 encoding; must report `agrees_with_exhaustive: true` -> `hiss_smt_results.json` |
| `eval/scaling.py` | enumeration vs Z3 cost, 8-18 fields (about 80 s) -> `hiss_scaling_results.json` |
| `eval/make_figures.py` | vector figures |
| `eval/hypothesis_baseline.py` | Hypothesis property-based random testing vs uniform sampling, 100 seeds -> `hypothesis_baseline_results.json` |
| `eval/diff_test.py` + `eval/engines/` | differential check against Cedar and OPA/Rego policies written blind from the prose spec (`INTERPRETATION.md`) -> `diff_results.json` |

## Run
```
pip install -r requirements.txt            # Python 3.11
python eval/engines/get_opa.py             # pinned OPA v1.22.4 (Windows amd64), checksum verified
python run_all.py                          # regenerates everything, compares hashes with MANIFEST_SHA256.txt
python run_all.py --fast                   # skips scaling, Hypothesis, and the Cedar/OPA differential check
```
Timing fields depend on hardware and are excluded from the hash check. Everything else is deterministic
(Hypothesis runs use fixed seeds 0-99).

## Caveats
* The Cedar and Rego policies were written by a language-model instance from the prose specification, without
  sight of the kernel or the properties. They are a differential check, not an independent validation.
* The kernel is a minimal model of a deployed system and runs on synthetic requests. This is not a security or
  legal compliance assessment.

## Licence and citation
MIT (code). See `LICENSE` and `CITATION.cff`. Release tag and DOI (Zenodo) are to be added by the authors.
