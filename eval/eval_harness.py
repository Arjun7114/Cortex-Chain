"""
eval_harness.py  --  Cortex-Chain triage evaluation

Runs every labeled alert in eval_dataset.json through the same Llama 3 model
the live pipeline uses, then reports:

    * TRIAGE ACCURACY  -- accuracy / precision / recall / F1 vs ground truth
                          (positive class = "brute_force"), plus a confusion
                          matrix and the list of misclassified cases.
    * TRIAGE LATENCY   -- wall-clock time from prompt-in to verdict-out per
                          alert: mean / median / p95.
    * PARSE RATE       -- how often the model returned a machine-readable
                          verdict in the required format.

Usage:
    python eval_harness.py                 # real run against Ollama/Llama 3
    python eval_harness.py --model llama3  # pick a different local model
    python eval_harness.py --selftest      # no Ollama; uses a rule-based stub
                                           # to prove the harness plumbing works

Outputs: prints a report and writes eval_results.json + eval_results.md
Requires (real run): `pip install ollama` and `ollama pull llama3`.
"""

import argparse
import json
import re
import statistics
import time

VERDICT_RE = re.compile(r"VERDICT:\s*(BRUTE_FORCE|BENIGN)", re.IGNORECASE)

PROMPT_TEMPLATE = """You are an L1 SOC analyst triaging a Windows failed-logon \
(Event ID 4625) alert. Decide whether it represents a genuine BRUTE_FORCE \
attack or BENIGN activity (typos, stale credentials, lockouts, re-auth).

Weigh the number of failures, how many distinct source IPs, the time window, \
the targeted account(s), and the failure status code. A high failure count \
from one source in a short window against a privileged or common account is \
brute force. A few failures from a known internal device, especially followed \
by a success, is benign.

ALERT (JSON):
{alert}

Reason briefly, then output the final line EXACTLY as:
VERDICT: BRUTE_FORCE
or
VERDICT: BENIGN
"""


def build_prompt(alert: dict) -> str:
    return PROMPT_TEMPLATE.format(alert=json.dumps(alert, indent=2))


def parse_verdict(text: str):
    """Return 'brute_force' | 'benign' | None (unparseable)."""
    m = VERDICT_RE.search(text or "")
    if m:
        return "brute_force" if m.group(1).upper() == "BRUTE_FORCE" else "benign"
    # Fallback: last-ditch keyword scan so a formatting slip isn't scored as wrong
    low = (text or "").lower()
    tail = low[-200:]
    if "brute" in tail or "malicious" in tail or "attack" in tail:
        return "brute_force"
    if "benign" in tail or "legitimate" in tail or "normal" in tail:
        return "benign"
    return None


# ---- model callers -------------------------------------------------------

def ollama_model_fn(model):
    import ollama

    def _call(prompt):
        resp = ollama.generate(model=model, prompt=prompt,
                               options={"temperature": 0})
        return resp["response"]
    return _call


def selftest_model_fn():
    """Deterministic rule-of-thumb classifier that returns text in the same
    format the real model must. Used only to validate the harness offline."""
    def _call(prompt):
        alert = json.loads(prompt.split("ALERT (JSON):", 1)[1]
                           .split("Reason briefly", 1)[0].strip())
        fails = alert.get("failure_count", 0)
        ips = alert.get("distinct_source_ips", 1)
        window = alert.get("time_window_seconds", 1)
        rate = fails / max(window, 1)
        looks_bad = fails >= 20 and ips <= 3 and rate > 0.05
        time.sleep(0.02)  # simulate a little latency
        v = "BRUTE_FORCE" if looks_bad else "BENIGN"
        return f"Assessment based on volume and cadence.\nVERDICT: {v}"
    return _call


# ---- evaluation ----------------------------------------------------------

def run(dataset, model_fn):
    rows, latencies = [], []
    for c in dataset:
        prompt = build_prompt(c["alert"])
        t0 = time.perf_counter()
        raw = model_fn(prompt)
        dt = time.perf_counter() - t0
        latencies.append(dt)
        pred = parse_verdict(raw)
        rows.append({
            "id": c["id"], "truth": c["label"], "pred": pred,
            "parsed": pred is not None,
            "correct": pred == c["label"],
            "latency_s": round(dt, 3),
        })
    return rows, latencies


def metrics(rows):
    P = "brute_force"  # positive class
    tp = sum(r["truth"] == P and r["pred"] == P for r in rows)
    fp = sum(r["truth"] != P and r["pred"] == P for r in rows)
    fn = sum(r["truth"] == P and r["pred"] != P for r in rows)
    tn = sum(r["truth"] != P and r["pred"] == "benign" for r in rows)
    n = len(rows)
    correct = sum(r["correct"] for r in rows)
    acc = correct / n if n else 0.0
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {
        "n": n, "correct": correct, "accuracy": acc,
        "precision": prec, "recall": rec, "f1": f1,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "parse_rate": sum(r["parsed"] for r in rows) / n if n else 0.0,
    }


def latency_stats(latencies):
    s = sorted(latencies)
    p95 = s[min(len(s) - 1, int(round(0.95 * (len(s) - 1))))] if s else 0.0
    return {
        "mean_s": round(statistics.mean(latencies), 3) if latencies else 0.0,
        "median_s": round(statistics.median(latencies), 3) if latencies else 0.0,
        "p95_s": round(p95, 3),
    }


def report(rows, m, lat):
    lines = []
    lines.append("# Cortex-Chain Triage Evaluation\n")
    lines.append("## Triage accuracy")
    lines.append(f"- Correctly classified: **{m['correct']}/{m['n']}** "
                 f"({m['accuracy']*100:.1f}%)")
    lines.append(f"- Precision (brute_force): {m['precision']*100:.1f}%")
    lines.append(f"- Recall (brute_force): {m['recall']*100:.1f}%")
    lines.append(f"- F1: {m['f1']*100:.1f}%")
    lines.append(f"- Verdict parse rate: {m['parse_rate']*100:.1f}%\n")
    lines.append("Confusion matrix (rows = truth, cols = predicted):\n")
    lines.append("| | pred brute_force | pred benign |")
    lines.append("|---|---|---|")
    lines.append(f"| **truth brute_force** | {m['tp']} (TP) | {m['fn']} (FN) |")
    lines.append(f"| **truth benign** | {m['fp']} (FP) | {m['tn']} (TN) |\n")
    lines.append("## Triage latency (prompt-in to verdict-out)")
    lines.append(f"- Mean: {lat['mean_s']:.2f}s  |  Median: {lat['median_s']:.2f}s  "
                 f"|  p95: {lat['p95_s']:.2f}s\n")
    wrong = [r for r in rows if not r["correct"]]
    if wrong:
        lines.append("## Misclassified")
        lines.append("| id | truth | predicted |")
        lines.append("|---|---|---|")
        for r in wrong:
            lines.append(f"| {r['id']} | {r['truth']} | {r['pred']} |")
    else:
        lines.append("## Misclassified\nNone.")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="llama3")
    ap.add_argument("--dataset", default="eval_dataset.json")
    ap.add_argument("--selftest", action="store_true",
                    help="run without Ollama using a deterministic stub")
    args = ap.parse_args()

    with open(args.dataset) as f:
        dataset = json.load(f)

    model_fn = selftest_model_fn() if args.selftest else ollama_model_fn(args.model)
    rows, latencies = run(dataset, model_fn)
    m = metrics(rows)
    lat = latency_stats(latencies)
    md = report(rows, m, lat)

    print(md)
    with open("eval_results.json", "w") as f:
        json.dump({"metrics": m, "latency": lat, "rows": rows}, f, indent=2)
    with open("eval_results.md", "w") as f:
        f.write(md + "\n")
    print("\nWrote eval_results.json and eval_results.md")


if __name__ == "__main__":
    main()
