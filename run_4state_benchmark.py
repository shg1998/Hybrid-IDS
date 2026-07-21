#!/usr/bin/env python3
"""
run_4state_benchmark.py - خودکارسازی کامل بنچمارک ۴ حالته بدون تداخل
====================================================================
"""
import subprocess, time, os, sys

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
    # پاکسازی مینی‌نت
    subprocess.run(["sudo", "mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # کشتن اسنورت و پواکس به صورت مجزا
    subprocess.run(["sudo", "pkill", "-9", "-f", "snort"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    subprocess.run(["sudo", "pkill", "-9", "-f", "pox.py"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    subprocess.run(["sudo", "pkill", "-9", "-f", "snort_agent.py"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

def run_mode(mode):
    print(f"\n==================================================")
    print(f"🚀 Starting Benchmark Phase for Mode: [{mode}]")
    print(f"==================================================")
    
    # ۱. پاکسازی ایمن محیط
    safe_cleanup()
    time.sleep(2)
    
    # ۲. اجرای POX Controller
    env = os.environ.copy()
    env["IDS_MODE"] = mode
    pox_cmd = f"python3 {POX_PATH} openflow.of_01 online_ids"
    pox_proc = subprocess.Popen(pox_cmd, shell=True, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"🔌 POX Controller started in [{mode}] mode.")
    time.sleep(5)
    
    # ۳. راه‌اندازی مینی‌نت
    mn_cmd = "sudo mn --topo single,3 --mac --switch ovsk --controller remote"
    mn_proc = subprocess.Popen(mn_cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True)
    print("🌐 Mininet topology online (h1, h2, h3, s1)...")
    time.sleep(6) # زمان برای تثبیت سوئیچ
    
    h1_pid = get_host_pid("h1")
    h3_pid = get_host_pid("h3")
    
    # ۴. اجرای Snort Agent در h3
    snort_proc = None
    if mode != "ml_only" and h3_pid:
        snort_agent_script = os.path.join(HYBRID_DIR, "snort_agent.py")
        snort_cmd = f"sudo mnexec -a {h3_pid} python3 {snort_agent_script}"
        snort_proc = subprocess.Popen(snort_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"📡 Snort Agent running inside Host h3 (PID: {h3_pid})...")
        time.sleep(3)
        
    # ۵. اجرای بنچمارک در h1
    if h1_pid:
        print(f"⚔️ Launching Attack Benchmark Suite inside Host h1 (PID: {h1_pid})...")
        bench_script = os.path.join(HYBRID_DIR, "run_benchmarks.py")
        bench_cmd = f"sudo mnexec -a {h1_pid} python3 {bench_script}"
        subprocess.run(bench_cmd, shell=True)
    else:
        print("❌ Failed to locate h1 PID!")

    # ۶. خاموش‌سازی و پاکسازی برای گام بعدی
    print("⏳ Cleaning up processes for next iteration...")
    safe_cleanup()
    time.sleep(3)

def main():
    os.makedirs(LOG_DIR, exist_ok=True)
    for mode in MODES:
        run_mode(mode)
    print("\n✅ All 4 Benchmark Modes Executed Successfully!")

if __name__ == "__main__":
    main()