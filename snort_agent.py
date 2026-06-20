#!/usr/bin/env python3
import subprocess, time, sys, atexit, threading, json, csv, os
from datetime import datetime

SNORT_CONFIG_FILE = "/tmp/snort_simple.conf"
SNORT_INTERFACE   = "h3-eth0"
SNORT_LOG_DIR     = "/tmp/snort_log"
FEEDBACK_FILE     = "/tmp/pox_snort_feedback.log"
LOG_CSV           = "/home/moho/snort_alerts.csv"

snort_process = None

def create_simple_snort_conf():
    config = """
var HOME_NET 10.0.0.0/24
var EXTERNAL_NET any

preprocessor stream5_global: track_tcp yes, track_udp yes
preprocessor stream5_tcp: policy first

# 1. تشخیص SYN Flood (تعداد زیاد درخواست SYN به یک مقصد در ۲ ثانیه)
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"SYN Flood Detected"; flags:S; detection_filter:track by_dst, count 30, seconds 2; sid:1000001; rev:1;)

# 2. تشخیص Port Scan (تعداد زیاد درخواست SYN از یک مبدأ در ۵ ثانیه)
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Port Scan Detected"; flags:S; detection_filter:track by_src, count 20, seconds 5; sid:1000002; rev:1;)

# 3. تشخیص ICMP Flood (تعداد زیاد پینگ به یک مقصد در ۲ ثانیه)
alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"ICMP Flood Detected"; itype:8; detection_filter:track by_dst, count 20, seconds 2; sid:1000003; rev:1;)

# 4. تشخیص SSH Brute-Force (تعداد زیاد تلاش برای SSH از یک مبدأ)
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"SSH Brute Force"; flags:SA; detection_filter:track by_src, count 5, seconds 10; sid:1000004; rev:1;)

# (اختیاری) ترافیک عادی به صورت پیش‌فرض نادیده گرفته می‌شود، اما اگر بخواهید می‌توانید برای دیباگ لاگ کنید:
# log tcp any any -> any any (msg:"Normal TCP Traffic"; sid:9999999; rev:1;)
"""
    with open(SNORT_CONFIG_FILE, 'w') as f:
        f.write(config.strip())
    print("✅ Snort config created with attack detection rules.")

def log_alert_to_csv(alert_data):
    file_exists = os.path.isfile(LOG_CSV)
    with open(LOG_CSV, mode='a', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'message', 'protocol'])
        writer.writerow([
            datetime.now().isoformat(),
            alert_data.get('src_ip', ''),
            alert_data.get('dst_ip', ''),
            alert_data.get('src_port', ''),
            alert_data.get('dst_port', ''),
            alert_data.get('message', ''),
            alert_data.get('protocol', '')
        ])

def start_snort():
    global snort_process
    try:
        subprocess.run(["sudo", "killall", "snort"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
    except:
        pass
    os.makedirs(SNORT_LOG_DIR, exist_ok=True)
    cmd = ["sudo", "snort", "-A", "fast", "-i", SNORT_INTERFACE, "-c", SNORT_CONFIG_FILE, "-l", SNORT_LOG_DIR]
    print("🚀 Starting Snort:", ' '.join(cmd))
    snort_process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    time.sleep(3)
    print("Snort started.")
    threading.Thread(target=read_stderr, daemon=True).start()

def stop_snort():
    if snort_process and snort_process.poll() is None:
        snort_process.terminate()
        snort_process.wait(timeout=5)

def read_stderr():
    for line in snort_process.stderr:
        if line.strip():
            print("Snort:", line.strip(), flush=True)

def parse_alert_line(line):
    if "[**]" not in line:
        return None
    try:
        msg_start = line.find("[**] ") + len("[**] ")
        msg_end = line.find(" [**]", msg_start)
        message = line[msg_start:msg_end].strip()

        addr_part = line.split("}")[-1].strip()
        if '->' not in addr_part:
            return None
        src, dst = addr_part.split('->')
        src_ip, src_port = src.strip().split(':')
        dst_ip, dst_port = dst.strip().split(':')

        protocol = "TCP"
        if "{UDP}" in line:
            protocol = "UDP"
        elif "{ICMP}" in line:
            protocol = "ICMP"

        return {
            "message": message,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol
        }
    except Exception as e:
        print(f"Parse error: {e}")
        return None

def send_alert(alert_data):
    try:
        with open(FEEDBACK_FILE, 'a') as f:
            f.write(json.dumps(alert_data) + '\n')
        print("Sent to POX:", alert_data['message'], flush=True)
    except Exception as e:
        print("Send error:", e, flush=True)

def monitor_alert_file():
    alert_file = os.path.join(SNORT_LOG_DIR, "alert")
    print(f"👀 Waiting for {alert_file} ...", flush=True)
    while not os.path.exists(alert_file):
        time.sleep(1)
    print("📄 Reading alerts...", flush=True)
    with open(alert_file, 'r') as f:
        f.seek(0, 2)  # برو به انتهای فایل
        while True:
            line = f.readline()
            if line:
                line = line.strip()
                if line:
                    alert = parse_alert_line(line)
                    if alert:
                        send_alert(alert)
            else:
                time.sleep(0.1)

if __name__ == "__main__":
    atexit.register(stop_snort)
    create_simple_snort_conf()
    start_snort()
    threading.Thread(target=monitor_alert_file, daemon=True).start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Agent stopped.")