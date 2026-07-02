#!/usr/bin/env python3
"""
run_benchmarks.py - Automated Attack Scenario Suite for Intrusion Detection Benchmarking
========================================================================================
This script executes natively within the network namespace of the attacker host (h1) 
to programmatically generate automated background normal baseline traffic followed by 
sequential multi-vector intrusion signatures targeting the victim machine (10.0.0.2).

DESIGN & AUTOMATION LIFECYCLE:
-----------------------------
1. Non-Blocking Pipeline: Utilizes background sub-shell processing loops via 
   subprocess.Popen to handle high-volume streaming and volumetric flood injections 
   without interrupting the script's main timing sequence.
2. Window Cooldowns: Enforces strict 10-second mitigation intervals between active 
   phases. This isolates sliding-window statistics within the online learning 
   controller, preventing data leakage and ensuring clean log segmentation.

AUTOMATED INJECTION PHASES:
--------------------------
* Phase 0: Baseline Normal Traffic (Duration: 30s)
  - Simulates standard network latency profiling via a low-frequency ICMP sequence. 
  - Seeds the Online Hoeffding Tree with benign data samples prior to attack exposure.
* Phase 1: Volumetric TCP SYN Flood Attack (Duration: 15s)
  - Leverages hping3 to saturate port 80 using a raw synchronization (--flood) frame stream.
  - Validates real-time mitigation response times and soft-label adaptation properties.
* Phase 2: TCP SYN Port Scanning (Duration: 15s)
  - Executes a controlled stealth scan (-sS) across ports 1-100 restricted to a maximum 
    rate of 15 packets per second.
  - Tests the system's capacity to recognize low-volume, highly structured scanning behaviors.
* Phase 3: Volumetric ICMP Flood Attack (Duration: 5s)
  - Triggers a rapid, aggressive flood (-f) of echo requests to overflow processing buffers.
  - Evaluates system classification performance under high packet rates when structural 
    network policies explicitly prevent ICMP flow blocking.
* Phase 4: Application-Layer SSH Brute-Force Simulation (Duration: 15s)
  - Chains persistent netcat (nc) loops to emulate sequential authentication guessing 
    attacks targeting port 22.
  - Assesses cross-traffic statistical tracking capacities for sensitive port violations.
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
