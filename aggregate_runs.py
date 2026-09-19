#!/usr/bin/env python3
"""
aggregate_runs.py - تجمیع چند اجرای مستقل (Mean ± 95% CI)
فیدبک استاد، بخش ۴ (خروجی مورد انتظار در گزارش بعدی)، بندهای ۱، ۲ و ۴:
  "جدول مقایسه چهار روش با Precision, Recall, F1, FPR, MCC, Detection Delay
   و Mitigation Delay" + "نتایج جداگانه برای هر attack_type" +
  "چند run مستقل با Mean و confidence interval؛ نه یک اجرای واحد یا CSVهای
   append‌شده."

این اسکریپت هرگز داده‌ی چند run را در یک شمارنده‌ی پیوسته append نمی‌کند: هر
eval_<mode>_<run_id>.csv (خروجی evaluate_run.py) یک نمونه‌ی آماری مستقل است و
Mean±CI روی مجموعه‌ی این نمونه‌ها محاسبه می‌شود.
"""
import argparse
import csv
import glob
import math
import os
import re
import statistics
from collections import defaultdict

MODES = ["snort_only", "ml_only", "hybrid_static", "hybrid_online"]
METRIC_COLS = ['Precision', 'Recall', 'F1', 'FPR', 'MCC', 'Avg_Detection_Delay', 'Avg_Mitigation_Delay']

# مقادیر بحرانی t (سطح اطمینان ۹۵٪، دوطرفه) بر اساس درجه‌ی آزادی (n-1)
T_TABLE = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365,
           8: 2.306, 9: 2.262, 10: 2.228, 11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145,
           15: 2.131, 16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086, 21: 2.080,
           22: 2.074, 23: 2.069, 24: 2.064, 25: 2.060, 26: 2.056, 27: 2.052, 28: 2.048,
           29: 2.045, 30: 2.042}


def t_crit(df):
    if df <= 0:
        return None
    if df in T_TABLE:
        return T_TABLE[df]
    if df > 30:
        return 1.960
    return T_TABLE[max(k for k in T_TABLE if k <= df)]


def mean_ci(values):
    n = len(values)
    if n == 0:
        return None, None, 0
    mean = statistics.mean(values)
    if n == 1:
        return mean, None, 1
    sd = statistics.stdev(values)
    tc = t_crit(n - 1)
    ci = tc * (sd / math.sqrt(n))
    return mean, ci, n


def discover_eval_files(log_dir, mode, run_ids=None):
    files = sorted(glob.glob(os.path.join(log_dir, f"eval_{mode}_*.csv")))
    if run_ids:
        pattern = re.compile(r"^eval_" + re.escape(mode) + r"_(.+)\.csv$")
        keep = []
        for f in files:
            m = pattern.match(os.path.basename(f))
            if m and m.group(1) in run_ids:
                keep.append(f)
        files = keep
    return files


def load_eval_csv(path):
    rows = {}
    with open(path, newline='') as f:
        for r in csv.DictReader(f):
            rows[r['scope']] = r
    return rows


def collect(log_dir, mode, run_ids=None):
    """scope ('overall' یا هر attack_type) -> metric -> [مقدار در هر run مستقل]"""
    data = defaultdict(lambda: defaultdict(list))
    files = discover_eval_files(log_dir, mode, run_ids)
    for path in files:
        rows = load_eval_csv(path)
        for scope, row in rows.items():
            for metric in METRIC_COLS:
                try:
                    data[scope][metric].append(float(row[metric]))
                except (KeyError, ValueError):
                    continue
    return data, len(files)


def summarize(data):
    out = {}
    for scope, metrics in data.items():
        out[scope] = {metric: mean_ci(values) for metric, values in metrics.items()}
    return out


def main():
    ap = argparse.ArgumentParser(description="Aggregate independent evaluate_run.py outputs into Mean +/- 95%% CI.")
    ap.add_argument("--log-dir", default=os.environ.get("IDS_LOG_DIR", "logs"))
    ap.add_argument("--modes", nargs="+", default=MODES, choices=MODES)
    ap.add_argument("--run-ids", nargs="+", default=None,
                     help="اگر داده شود فقط همین run_idها تجمیع می‌شوند (وگرنه همه‌ی eval_<mode>_*.csv موجود)")
    ap.add_argument("--out", default=None, help="مسیر CSV خروجی جدول مقایسه‌ی نهایی")
    args = ap.parse_args()

    out_path = args.out or os.path.join(args.log_dir, "final_comparison_table.csv")
    all_rows = []

    for mode in args.modes:
        data, n_runs = collect(args.log_dir, mode, args.run_ids)
        if n_runs == 0:
            print(f"⚠️ {mode}: هیچ eval_{mode}_*.csv پیدا نشد (ابتدا evaluate_run.py را اجرا کنید).")
            continue
        if n_runs == 1:
            print(f"⚠️ {mode}: فقط ۱ run موجود است - CI معنی‌دار نیست. طبق فیدبک استاد حداقل چند run "
                  f"مستقل (پیشنهاد: ≥5) با --repeats در run_4state_benchmark.py لازم است.")
        summary = summarize(data)
        print(f"\n=== {mode} (n_runs={n_runs}) ===")
        for scope in sorted(summary.keys()):
            print(f"  [{scope}]")
            row = {'mode': mode, 'scope': scope, 'n_runs': n_runs}
            for metric in METRIC_COLS:
                mean, ci, n = summary[scope].get(metric, (None, None, 0))
                if mean is None:
                    continue
                ci_str = f"±{ci:.4f}" if ci is not None else "±N/A(n=1)"
                print(f"    {metric}: {mean:.4f} {ci_str}")
                row[f"{metric}_mean"] = round(mean, 4)
                row[f"{metric}_ci95"] = round(ci, 4) if ci is not None else ''
            all_rows.append(row)

    if all_rows:
        fieldnames = ['mode', 'scope', 'n_runs'] + [f"{m}_mean" for m in METRIC_COLS] + [f"{m}_ci95" for m in METRIC_COLS]
        with open(out_path, 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            for row in all_rows:
                w.writerow(row)
        print(f"\n📄 جدول مقایسه‌ی نهایی ذخیره شد: {out_path}")
    else:
        print("\n❌ هیچ داده‌ای برای تجمیع پیدا نشد.")


if __name__ == "__main__":
    main()
