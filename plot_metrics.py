import pandas as pd
import matplotlib.pyplot as plt

metrics_file = "/home/moho/Documents/projects/IDS/logs/metrics_log.csv"

try:
    df = pd.read_csv(metrics_file)
    
    plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
    
    
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8))
    
    ax1.plot(df.index * 10, df['Precision'], label='Precision', color='#1f77b4', linewidth=2)
    ax1.plot(df.index * 10, df['Recall'], label='Recall (Detection Rate)', color='#ff7f0e', linewidth=2)
    ax1.plot(df.index * 10, df['F1'], label='F1-Score', color='#2ca02c', linewidth=2, linestyle='--')
    ax1.set_title("Online System Performance Across Test Samples", fontsize=14, fontweight='bold')
    ax1.set_ylabel("Score (0.0 - 1.0)", fontsize=12)
    ax1.set_ylim(-0.05, 1.05)
    ax1.legend(loc='lower right', frameon=True)
    
    color = '#d62728'
    ax2.plot(df.index * 10, df['FPR'], label='False Positive Rate (FPR)', color=color, linewidth=2)
    ax2.set_ylabel('FPR', color=color, fontsize=12)
    ax2.tick_params(axis='y', labelcolor=color)
    ax2.set_ylim(-0.05, 1.05)
    
    ax3 = ax2.twinx()
    color = '#9467bd'
    ax3.plot(df.index * 10, df['Avg_Det_Delay'], label='Avg Detection Delay (s)', color=color, linewidth=1.5, linestyle=':')
    ax3.set_ylabel('Delay (Seconds)', color=color, fontsize=12)
    ax3.tick_params(axis='y', labelcolor=color)
    
    ax2.set_xlabel("Processed Traffic Samples (Incremental Time)", fontsize=12)
    ax2.set_title("Error Rate & System Latency Analysis", fontsize=14, fontweight='bold')
    
    plt.tight_layout()
    
    plt.savefig("/home/moho/Documents/projects/IDS/logs/system_evaluation.png", dpi=300)
    print("🎯 نمودارهای ارزیابی با موفقیت رسم و در مسیر logs/system_evaluation.png ذخیره شدند!")
    
except Exception as e:
    print(f"❌ خطایی در رسم نمودار رخ داد: {e}")
    print("نکته: مطمئن شو سناریو حداقل ۱۰ فلو تولید کرده باشد تا لاگ ارزیابی مقدار گرفته باشد.")
