#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
import os

log_dir = "/home/moho/Documents/projects/IDS/logs"
hybrid_path = os.path.join(log_dir, "metrics_hybrid.csv")
snort_path = os.path.join(log_dir, "metrics_snort_only.csv")
output_plot = os.path.join(log_dir, "thesis_comparison_plot.png")

def main():
    if not os.path.exists(hybrid_path) or not os.path.exists(snort_path):
        print("❌ فایل‌های CSV پیدا نشد! حتماً بنچمارک رو دوباره اجرا کنید.")
        return

    df_hybrid = pd.read_csv(hybrid_path)
    df_snort = pd.read_csv(snort_path)

    steps_hybrid = [i * 10 for i in range(1, len(df_hybrid) + 1)]
    steps_snort  = [i * 10 for i in range(1, len(df_snort) + 1)]

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(11, 10), constrained_layout=True)
    plt.style.use('seaborn-v0_8-whitegrid')

    # --- نمودار اول: F1-Score ---
    ax1.plot(steps_hybrid, df_hybrid['F1'], color='#1f77b4', linewidth=2.5, linestyle='-', label='Proposed Hybrid IDS (UNSW-NB15)')
    ax1.plot(steps_snort, df_snort['F1'], color='#d62728', linewidth=2.5, linestyle='--', label='Snort-Only (Baseline)')
    ax1.set_title("Incremental F1-Score Convergence Comparison", fontsize=15, fontweight='bold', pad=15)
    ax1.set_ylabel("F1-Score (0.0 - 1.0)", fontsize=12, fontweight='bold')
    ax1.set_ylim(0.0, 1.05)
    ax1.grid(True, linestyle=':', alpha=0.7)
    ax1.legend(loc='lower right', fontsize=11, framealpha=1, edgecolor='black')

    # --- نمودار دوم: FPR و Detection Delay ---
    # رنگ‌بندی: سبز برای FPR، بنفش برای تأخیر
    color_fpr = '#2ca02c'
    color_lat = '#9467bd'

    ax2.plot(steps_hybrid, df_hybrid['FPR'], color=color_fpr, linewidth=2, linestyle='-', label='Hybrid IDS FPR')
    ax2.plot(steps_snort, df_snort['FPR'], color=color_fpr, linewidth=2, linestyle='--', label='Snort-Only FPR')
    ax2.set_ylabel("False Positive Rate (FPR)", color=color_fpr, fontsize=12, fontweight='bold')
    ax2.tick_params(axis='y', labelcolor=color_fpr)
    ax2.set_ylim(-0.05, 1.05)

    # اصلاح مهم: استفاده از Avg_Det_Delay به جای Avg_Block_Delay
    ax3 = ax2.twinx()
    ax3.plot(steps_hybrid, df_hybrid['Avg_Det_Delay'], color=color_lat, linewidth=2.5, linestyle=':', label='Hybrid Detection Delay')
    ax3.plot(steps_snort, df_snort['Avg_Det_Delay'], color=color_lat, linewidth=2.5, linestyle='-.', label='Snort Detection Delay')
    ax3.set_ylabel("Detection Latency (Seconds)", color=color_lat, fontsize=12, fontweight='bold')
    ax3.tick_params(axis='y', labelcolor=color_lat)

    ax2.set_xlabel("Processed Traffic Windows (Incremental Samples)", fontsize=12, fontweight='bold')
    ax2.set_title("False Positive Rate & Detection Latency Profiling", fontsize=15, fontweight='bold', pad=15)
    ax2.grid(True, linestyle=':', alpha=0.7)

    lines1, labels1 = ax2.get_legend_handles_labels()
    lines2, labels2 = ax3.get_legend_handles_labels()
    ax3.legend(lines1 + lines2, labels1 + labels2, loc='upper right', fontsize=10, framealpha=1, edgecolor='black')

    plt.savefig(output_plot, dpi=300, bbox_inches='tight')
    print(f"🎯 نمودار نهایی ذخیره شد!\n📁 مسیر: {output_plot}")

if __name__ == "__main__":
    main()
