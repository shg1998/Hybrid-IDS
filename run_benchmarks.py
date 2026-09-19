#!/usr/bin/env python3
"""
run_benchmarks.py - اسکریپت خودکارسازی سناریوهای تست حملات (مخصوص اجرا در xterm h1)
===================================================================
نسخه اصلاح‌شده: هر فاز سناریو (نرمال یا حمله) اکنون توسط GroundTruthRecorder
به‌صورت کاملاً مستقل از IP-heuristic / ML / Snort ثبت می‌شود. برچسب واقعی هر
فلو دیگر در کنترلر حدس زده نمی‌شود؛ در عوض از همین پنجره‌های زمانی مستقل در
evaluate_run.py استخراج می‌شود.
"""

import subprocess
import time
import sys

from ground_truth import GroundTruthRecorder, resolve_run_id

# آی‌پي مهاجم (Attacker) و قربانی (Victim)
ATTACKER_IP = "10.0.0.1"
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

    run_id = resolve_run_id()
    print(f"🆔 run_id = {run_id}")
    gt = GroundTruthRecorder(run_id=run_id)

    # --- فاز ۰: ترافیک نرمال اولیه (Ground Truth مستقل: label=0, attack_type='normal') ---
    print("\n🟢 Phase 0: Gathering Baseline Normal Traffic (30 seconds)...")
    gt.start_phase("normal", 0, ATTACKER_IP, VICTIM_IP)
    for i in range(15):
        run_cmd_direct(f"ping -c 2 -i 0.5 {VICTIM_IP}")  # پینگ‌های مداوم‌تر
        run_cmd_direct(f"curl --max-time 1 http://{VICTIM_IP}/")
        time.sleep(2)
    gt.end_phase()

    # --- فاز ۱: حمله TCP SYN Flood (label=1, attack_type='syn_flood') ---
    print("\n⚔️ Phase 1: Launching TCP SYN Flood Attack...")
    gt.start_phase("syn_flood", 1, ATTACKER_IP, VICTIM_IP)
    run_cmd_direct(f"hping3 -S -i u500 -p 80 {VICTIM_IP}")
    time.sleep(60)  # 👈 ۶۰ ثانیه برای تولید فلوهای بیشتر
    kill_process("hping3")
    gt.end_phase()

    print("⏳ Cooling down (15s)...")
    gt.start_phase("normal", 0, ATTACKER_IP, VICTIM_IP)
    time.sleep(15)
    gt.end_phase()

    # --- فاز ۲: حمله Port Scanning (label=1, attack_type='port_scan') ---
    print("\n⚔️ Phase 2: Launching TCP SYN Port Scan...")
    gt.start_phase("port_scan", 1, ATTACKER_IP, VICTIM_IP)
    run_cmd_direct(f"nmap -sS -p 1-1000 --max-rate 100 {VICTIM_IP}")
    time.sleep(60)  # 👈 افزایش زمان اسکن
    kill_process("nmap")
    gt.end_phase()

    print("⏳ Cooling down (15s)...")
    gt.start_phase("normal", 0, ATTACKER_IP, VICTIM_IP)
    time.sleep(15)
    gt.end_phase()

    # --- فاز ۳: حمله ICMP Flood (label=1, attack_type='icmp_flood') ---
    print("\n⚔️ Phase 3: Launching ICMP Flood Attack...")
    gt.start_phase("icmp_flood", 1, ATTACKER_IP, VICTIM_IP)
    run_cmd_direct(f"sudo hping3 --icmp -i u500 {VICTIM_IP}")
    time.sleep(60)  # 👈 افزایش زمان سیل پینگ
    kill_process("hping3")
    gt.end_phase()

    print("⏳ Cooling down (10s)...")
    gt.start_phase("normal", 0, ATTACKER_IP, VICTIM_IP)
    time.sleep(10)
    gt.end_phase()

    # --- فاز ۴: حمله SSH Brute-Force (label=1, attack_type='ssh_bruteforce') ---
    print("\n⚔️ Phase 4: Launching SSH Brute-Force Simulation...")
    gt.start_phase("ssh_bruteforce", 1, ATTACKER_IP, VICTIM_IP)
    nc_loop = f'bash -c "for i in {{1..20}}; do nc -w 1 {VICTIM_IP} 22; sleep 0.2; done"'
    run_cmd_direct(nc_loop)
    time.sleep(15)
    kill_process("nc")
    gt.end_phase()

    print("\n==================================================")
    print(f"✅ Benchmark Finished Successfully! run_id={run_id}")
    print(f"📄 Ground truth written to: {gt.path}")
    print("==================================================")


if __name__ == "__main__":
    main()
