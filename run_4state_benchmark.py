#!/usr/bin/env python3
"""
run_4state_benchmark.py - خودکارسازی کامل بنچمارک ۴ حالته بدون تداخل
====================================================================
اصلاح‌شده طبق فیدبک استاد (بخش ۳ اقدام پیشنهادی، بند "Re-run نهایی" و بخش ۴-۴):
  - هر تکرار (--repeats) یک run_id کاملاً مستقل می‌گیرد و از طریق env var
    IDS_RUN_ID به‌طور هم‌زمان به کنترلر POX و به مولد ترافیک (run_benchmarks.py)
    پاس داده می‌شود - این دو دیگر هرگز run_id متفاوت یا لاگ قاطی‌شده ندارند.
  - workload (ترتیب/تایمینگ فازها) بین تکرارها ثابت می‌ماند (همان
    run_benchmarks.py برای هر تکرار اجرا می‌شود) تا مقایسه‌ی Mean±CI معتبر باشد.
  - خروجی هر تکرار مستقیماً با aggregate_runs.py قابل تجمیع است.
"""
import argparse
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ground_truth import new_run_id

MODES = ["snort_only", "ml_only", "hybrid_static", "hybrid_online"]
BASE_DIR = "/home/moho/Documents/projects/IDS"
HYBRID_DIR = os.path.join(BASE_DIR, "hybrid-ids")
POX_PATH = os.path.join(BASE_DIR, "pox/pox.py")
LOG_DIR = os.path.join(BASE_DIR, "logs")


def get_host_pid(host_name):
    """پیدا کردن PID فضای نام هاست مینی‌نت جهت تزریق دستورات"""
    try:
        result = subprocess.check_output(f"ps aux | grep 'mininet:{host_name}' | grep -v grep", shell=True, text=True)
        pid = result.split()[1]
        return pid
    except Exception as e:
        print(f"❌ Error getting PID for {host_name}: {e}")
        return None


def safe_cleanup():
    """پاکسازی هوشمند بدون کشتن پردازش اصلی پایتون"""
    subprocess.run(["sudo", "mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "pkill", "-9", "-f", "snort"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    subprocess.run(["sudo", "pkill", "-9", "-f", "pox.py"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    subprocess.run(["sudo", "pkill", "-9", "-f", "snort_agent.py"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)


def run_mode(mode, run_id):
    print(f"\n==================================================")
    print(f"🚀 Starting Benchmark Phase for Mode: [{mode}]  run_id={run_id}")
    print(f"==================================================")

    safe_cleanup()
    time.sleep(2)

    env = os.environ.copy()
    env["IDS_MODE"] = mode
    env["IDS_RUN_ID"] = run_id
    env["IDS_LOG_DIR"] = LOG_DIR

    # قبلاً stdout/stderr پواکس با DEVNULL دور ریخته می‌شد - یعنی پیام حیاتی
    # "✅ Model loaded" / "❌ Cannot load model" (که مستقیماً مشخص می‌کنه ML
    # واقعاً کار می‌کنه یا نه) هیچ‌جا قابل دیدن نبود. حالا در یک فایل لاگ
    # جداگانه به‌ازای هر run ذخیره می‌شود.
    pox_log_path = os.path.join(LOG_DIR, f"pox_stdout_{mode}_{run_id}.log")
    pox_log_file = open(pox_log_path, 'w')
    # اصلاح مهم: به‌جای رشته‌ی خام "python3" (که با sudo ممکنه به‌خاطر
    # secure_path به پایتون سیستمی بدون river resolve بشه، نه پایتون venv)،
    # همیشه همون مفسری که خودِ این اسکریپت باهاش اجرا شده به‌صورت مسیر کامل
    # استفاده می‌شود - تضمین می‌کنه POX دقیقاً همون محیطی رو داره که
    # pickle.load مدل را در آن تست کردید.
    pox_cmd = f"{sys.executable} {POX_PATH} openflow.of_01 online_ids"
    pox_proc = subprocess.Popen(pox_cmd, shell=True, env=env, stdout=pox_log_file, stderr=subprocess.STDOUT)
    print(f"🔌 POX Controller started in [{mode}] mode. (log: {pox_log_path})")
    time.sleep(5)

    mn_cmd = "sudo mn --topo single,3 --mac --switch ovsk --controller remote"
    mn_proc = subprocess.Popen(mn_cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True)
    print("🌐 Mininet topology online (h1, h2, h3, s1)...")
    time.sleep(6)

    h1_pid = get_host_pid("h1")
    h3_pid = get_host_pid("h3")

    # نکته‌ی مهم: sudo به‌طور پیش‌فرض env_reset دارد و متغیرهای محیطی رو پاک
    # می‌کنه، حتی وقتی این اسکریپت خودش از قبل با sudo اجرا شده باشه (یعنی
    # `env=env` روی subprocess.run/Popen کافی نیست چون sudo داخل bench_cmd/
    # snort_cmd دوباره env رو ریست می‌کنه). بدون -E، IDS_RUN_ID/IDS_LOG_DIR/
    # IDS_MODE هرگز به run_benchmarks.py نمی‌رسید و ground_truth.py مجبور
    # می‌شد خودش یک run_id تصادفی جدا از کنترلر بسازه - دقیقاً همون چیزی که
    # باعث می‌شد ground_truth_<run_id>.csv و flow_log_<mode>_<run_id>.csv
    # هیچ‌وقت run_id یکسان نداشته باشن.
    snort_proc = None
    if mode != "ml_only" and h3_pid:
        snort_agent_script = os.path.join(HYBRID_DIR, "snort_agent.py")
        snort_cmd = f"sudo -E mnexec -a {h3_pid} python3 {snort_agent_script}"
        snort_proc = subprocess.Popen(snort_cmd, shell=True, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"📡 Snort Agent running inside Host h3 (PID: {h3_pid})...")
        time.sleep(3)

    if h1_pid:
        print(f"⚔️ Launching Attack Benchmark Suite inside Host h1 (PID: {h1_pid})...  run_id={run_id}")
        bench_script = os.path.join(HYBRID_DIR, "run_benchmarks.py")
        bench_cmd = f"sudo -E mnexec -a {h1_pid} python3 {bench_script}"
        subprocess.run(bench_cmd, shell=True, env=env)
    else:
        print("❌ Failed to locate h1 PID!")

    print("⏳ Cleaning up processes for next iteration...")
    safe_cleanup()
    time.sleep(3)
    pox_log_file.close()


def main():
    parser = argparse.ArgumentParser(description="4-state IDS benchmark runner")
    parser.add_argument("--repeats", type=int, default=1,
                         help="تعداد اجراهای مستقل هر mode (برای Mean±CI در aggregate_runs.py)")
    parser.add_argument("--modes", nargs="+", default=MODES, choices=MODES,
                         help="فقط این mode‌ها اجرا شوند (پیش‌فرض: هر ۴ تا)")
    args = parser.parse_args()

    os.makedirs(LOG_DIR, exist_ok=True)
    run_ids_by_mode = {mode: [] for mode in args.modes}

    for rep in range(1, args.repeats + 1):
        print(f"\n########## Repetition {rep}/{args.repeats} ##########")
        for mode in args.modes:
            run_id = new_run_id()
            run_ids_by_mode[mode].append(run_id)
            run_mode(mode, run_id)

    print("\n✅ All Benchmark Modes Executed Successfully!")
    print("📋 run_id ها برای هر mode (برای aggregate_runs.py):")
    for mode, ids in run_ids_by_mode.items():
        print(f"  {mode}: {', '.join(ids)}")


if __name__ == "__main__":
    main()
