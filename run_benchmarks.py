#!/usr/bin/env python3
"""
run_benchmarks.py - اسکریپت خودکارسازی سناریوهای تست حملات (مخصوص اجرا در xterm h1)
===================================================================
نسخه اصلاح‌شده برای کنترل نرخ حملات جهت جلوگیری از قطع اتصال (Reset) مینی‌نت
"""

import subprocess
import time
import sys

# آی‌پي قربانی (Victim)
VICTIM_IP = "10.0.0.2"

def run_cmd_direct(cmd):
    """اجرای مستقیم دستور در پس‌زمینه ترمینالِ جاری هاست h1"""
    print(f"[h1 Action] Running: {cmd}")
    return subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def kill_process(proc_name):
    """پاکسازی مطمئن ابزارها برای جلوگیری از تداخل فازهای ارزیابی"""
    print(f"🛑 Stopping {proc_name}...")
    subprocess.run(["sudo", "killall", "-9", proc_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def main():
    print("==================================================")
    print("🚀 Starting Automated Intrusion Detection Benchmark (Inside h1)")
    print("==================================================")
    
    # --- فاز ۰: ترافیک نرمال اولیه (تقویت شده برای ایجاد Baseline واقعی) ---
    print("\n🟢 Phase 0: Gathering Baseline Normal Traffic (30 seconds)...")
    for i in range(15):
        run_cmd_direct(f"ping -c 2 -i 0.5 {VICTIM_IP}")  # پینگ‌های مداوم‌تر
        run_cmd_direct(f"curl --max-time 1 http://{VICTIM_IP}/") 
        time.sleep(2)

    # --- فاز ۱: حمله TCP SYN Flood ---
    print("\n⚔️ Phase 1: Launching TCP SYN Flood Attack...")
    # تغییر از --flood به نرخ کنترل شده: ارسال هر 500 میکروثانیه یک پکت (2000 پکت در ثانیه)
    # --- فاز ۱: حمله TCP SYN Flood ---
    print("\n⚔️ Phase 1: Launching TCP SYN Flood Attack...")
    run_cmd_direct(f"hping3 -S -i u500 -p 80 {VICTIM_IP}")
    time.sleep(60) # 👈 افزایش زمان حمله به ۶۰ ثانیه برای تولید فلوهای بیشتر
    kill_process("hping3")
    
    print("⏳ Cooling down (15s)...")
    time.sleep(15)

    # --- فاز ۲: حمله Port Scanning ---
    print("\n⚔️ Phase 2: Launching TCP SYN Port Scan...")
    run_cmd_direct(f"nmap -sS -p 1-1000 --max-rate 100 {VICTIM_IP}")
    time.sleep(60) # 👈 افزایش زمان اسکن
    kill_process("nmap")
    
    print("⏳ Cooling down (15s)...")
    time.sleep(15)

    # --- فاز ۳: حمله ICMP Flood ---
    print("\n⚔️ Phase 3: Launching ICMP Flood Attack...")
    run_cmd_direct(f"sudo hping3 --icmp -i u500 {VICTIM_IP}")
    time.sleep(60) # 👈 افزایش زمان سیل پینگ
    kill_process("hping3")
    
    print("⏳ Cooling down (10s)...")
    time.sleep(10)

    # --- فاز ۴: حمله SSH Brute-Force ---
    print("\n⚔️ Phase 4: Launching SSH Brute-Force Simulation...")
    nc_loop = f'bash -c "for i in {{1..20}}; do nc -w 1 {VICTIM_IP} 22; sleep 0.2; done"'
    run_cmd_direct(nc_loop)
    time.sleep(15)
    kill_process("nc")

    print("\n==================================================")
    print("✅ Benchmark Finished Successfully!")
    print("==================================================")

if __name__ == "__main__":
    main()