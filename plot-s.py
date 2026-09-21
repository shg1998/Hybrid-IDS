#!/usr/bin/env python3
"""
logs/plot-s.py - نمودار مقایسه‌ی نهایی ۴ روش (Mean ± 95% CI)

اصلاح‌شده طبق فیدبک : نسخه‌ی قبلی این اسکریپت مستقیماً از متریک‌های
آنلاینِ فیک‌شده (metrics_*.csv تولیدشده توسط MetricsTracker قدیمی که TN/FP
همیشه صفر بود و F1 مصنوعاً clamp می‌شد) می‌خواند. آن مسیر کاملاً حذف شده است.

ورودی این نسخه، logs/final_comparison_table.csv است که توسط aggregate_runs.py
از eval_<mode>_<run_id>.csv های evaluate_run.py ساخته می‌شود - یعنی نهایتاً از
Ground Truth مستقل (ground_truth.py) می‌آید، نه از حدس آنلاین کنترلر.

توجه: نمودار «همگرایی F1 در طول زمان» نسخه‌ی قبلی این‌جا وجود ندارد، چون آن
نمودار دقیقاً روی همان جریان متریک آنلاینِ فیک‌شده سوار بود. به‌جایش این نسخه
مستقیماً همان چیزی را رسم می‌کند که  در بخش ۴ فیدبک خواسته: نمودار
میله‌ای مقایسه‌ی ۴ روش با خطای Mean±CI روی چند run مستقل.

اجرای کامل مسیر ارزیابی (بعد از هر benchmark run):
    python3 evaluate_run.py --mode <mode> --run-id <run_id>   # برای هر (mode, run) - آفلاین
    python3 aggregate_runs.py                                  # تجمیع همه‌ی runهای مستقل
    python3 logs/plot-s.py                                     # این اسکریپت
"""
import csv
import os
import matplotlib.pyplot as plt

LOG_DIR = os.path.dirname(os.path.abspath(__file__))
TABLE_PATH = os.path.join(LOG_DIR, "final_comparison_table.csv")
OUTPUT_PLOT = os.path.join(LOG_DIR, "4state_benchmark_comparison.png")

MODES = ["snort_only", "ml_only", "hybrid_static", "hybrid_online"]
COLORS = {'snort_only': '#d62728', 'ml_only': '#ff7f0e', 'hybrid_static': '#2ca02c', 'hybrid_online': '#1f77b4'}
LABELS = {
    'snort_only': 'Snort-Only (Signature)',
    'ml_only': 'ML-Only (Streaming Tree)',
    'hybrid_static': 'Hybrid (Static)',
    'hybrid_online': 'Proposed Hybrid (Online Feedback)'
}


def load_overall_rows():
    if not os.path.exists(TABLE_PATH):
        print(f"❌ {TABLE_PATH} پیدا نشد.")
        print("   ابتدا برای هر (mode, run_id): python3 evaluate_run.py --mode <mode> --run-id <run_id>")
        print("   سپس: python3 aggregate_runs.py")
        return {}
    rows = {}
    with open(TABLE_PATH, newline='') as f:
        for r in csv.DictReader(f):
            if r['scope'] == 'overall':
                rows[r['mode']] = r
    return rows


def _f(row, key, default=0.0):
    v = row.get(key)
    if v in (None, ''):
        return default
    return float(v)


def main():
    rows = load_overall_rows()
    if not rows:
        return

    modes = [m for m in MODES if m in rows]
    if not modes:
        print("❌ هیچ mode ای در final_comparison_table.csv پیدا نشد.")
        return

    plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
    fig, axes = plt.subplots(2, 2, figsize=(13, 9), constrained_layout=True)

    panels = [
        ('F1_mean', 'F1_ci95', axes[0, 0], 'F1-Score (Overall)'),
        ('FPR_mean', 'FPR_ci95', axes[0, 1], 'False Positive Rate (Overall)'),
        ('Avg_Detection_Delay_mean', 'Avg_Detection_Delay_ci95', axes[1, 0], 'Detection Delay (s)'),
        ('Avg_Mitigation_Delay_mean', 'Avg_Mitigation_Delay_ci95', axes[1, 1], 'Mitigation Delay (s)'),
    ]

    for mean_col, ci_col, ax, title in panels:
        means = [_f(rows[m], mean_col) for m in modes]
        cis = [_f(rows[m], ci_col) for m in modes]
        ax.bar([LABELS[m] for m in modes], means, yerr=cis, capsize=6, color=[COLORS[m] for m in modes])
        ax.set_title(title, fontsize=12, fontweight='bold')
        ax.tick_params(axis='x', rotation=15)
        n_runs = rows[modes[0]].get('n_runs', '?')
        ax.set_xlabel(f"error bars = 95% CI (n_runs={n_runs})", fontsize=9)

    plt.savefig(OUTPUT_PLOT, dpi=300, bbox_inches='tight')
    print(f"🎯 Comparison plot saved to: {OUTPUT_PLOT}\n")

    print("=========================================================================================")
    print("🏆 FINAL 4-STATE BENCHMARK EVALUATION SUMMARY TABLE (For Thesis Chapter 4)")
    print("=========================================================================================")
    header = ["Mode", "n_runs", "Precision", "Recall", "F1", "FPR", "MCC", "Det.Delay(s)", "Mit.Delay(s)"]
    print("  ".join(f"{h:>16}" for h in header))
    for m in modes:
        r = rows[m]
        vals = [LABELS[m], r.get('n_runs', ''), r.get('Precision_mean', ''), r.get('Recall_mean', ''),
                r.get('F1_mean', ''), r.get('FPR_mean', ''), r.get('MCC_mean', ''),
                r.get('Avg_Detection_Delay_mean', ''), r.get('Avg_Mitigation_Delay_mean', '')]
        print("  ".join(f"{str(v):>16}" for v in vals))
    print("=========================================================================================")


if __name__ == "__main__":
    main()
