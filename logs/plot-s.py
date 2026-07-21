#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
import os

LOG_DIR = "/home/moho/Documents/projects/IDS/logs"
MODES = ["snort_only", "ml_only", "hybrid_static", "hybrid_online"]
COLORS = {'snort_only': '#d62728', 'ml_only': '#ff7f0e', 'hybrid_static': '#2ca02c', 'hybrid_online': '#1f77b4'}
LABELS = {
    'snort_only': 'Snort-Only (Signature)',
    'ml_only': 'ML-Only (Streaming Tree)',
    'hybrid_static': 'Hybrid (Static)',
    'hybrid_online': 'Proposed Hybrid (Online Feedback)'
}

def main():
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10), constrained_layout=True)
    plt.style.use('seaborn-v0_8-whitegrid')
    
    summary_data = []

    for mode in MODES:
        path = os.path.join(LOG_DIR, f"metrics_{mode}.csv")
        if not os.path.exists(path):
            print(f"⚠️ Warning: Log file {path} not found. Skipping...")
            continue
            
        df = pd.read_csv(path)
        steps = [i * 10 for i in range(1, len(df) + 1)]
        
        # رسم F1-Score
        ax1.plot(steps, df['F1'], color=COLORS[mode], linewidth=2.2, label=LABELS[mode])
        
        # رسم Latency
        ax2.plot(steps, df['Avg_Det_Delay'], color=COLORS[mode], linewidth=2.2, label=LABELS[mode])
        
        # استخراج آمار نهایی جهت ساخت جدول
        last_row = df.iloc[-1]
        summary_data.append({
            'Execution Mode': LABELS[mode],
            'Precision': f"{last_row['Precision']:.3f}",
            'Recall': f"{last_row['Recall']:.3f}",
            'F1-Score': f"{last_row['F1']:.3f}",
            'FPR': f"{last_row['FPR']:.3f}",
            'Avg Detection Delay (s)': f"{last_row['Avg_Det_Delay']:.3f}",
            'Avg Blocking Delay (s)': f"{last_row['Avg_Block_Delay']:.3f}"
        })

    # تنظیمات نمودار F1
    ax1.set_title("1. Incremental F1-Score Performance Comparison across 4 Execution Modes", fontsize=14, fontweight='bold')
    ax1.set_ylabel("F1-Score", fontsize=12, fontweight='bold')
    ax1.set_ylim(-0.05, 1.05)
    ax1.legend(loc='lower right', frameon=True, edgecolor='black')

    # تنظیمات نمودار Delay
    ax2.set_title("2. Real-Time Detection Latency Comparison (Seconds)", fontsize=14, fontweight='bold')
    ax2.set_xlabel("Processed Traffic Windows (Incremental Samples)", fontsize=12, fontweight='bold')
    ax2.set_ylabel("Detection Latency (s)", fontsize=12, fontweight='bold')
    ax2.legend(loc='upper right', frameon=True, edgecolor='black')

    output_plot = os.path.join(LOG_DIR, "4state_benchmark_comparison.png")
    plt.savefig(output_plot, dpi=300, bbox_inches='tight')
    print(f"🎯 Comparison plot saved to: {output_plot}\n")

    # چاپ جدول نتایج برای درج در فصل ۴ پایان‌نامه
    df_summary = pd.DataFrame(summary_data)
    print("=========================================================================================")
    print("🏆 FINAL 4-STATE BENCHMARK EVALUATION SUMMARY TABLE (For Thesis Chapter 4)")
    print("=========================================================================================")
    print(df_summary.to_string(index=False))
    print("=========================================================================================")

if __name__ == "__main__":
    main()