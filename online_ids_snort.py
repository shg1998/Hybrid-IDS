# pox/ext/online_ids.py (Snort-Only Execution Mode)

from pox.core import core
import pox.openflow.libopenflow_01 as of
import time, pickle, math, threading, os, json, csv
from collections import deque, defaultdict
from feature_extractor import FlowRecord, ConnectionHistory, build_unsw_features
from soft_tree import SoftLabelHoeffdingTree

log = core.getLogger()

# ============================================================
# پارامترهای تنظیم‌شده برای حالت Snort-Only
# ============================================================
WINDOW_DURATION = 2
TAU_THRESHOLD   = 2.0
ALPHA_MAX       = 0.9
ALPHA_MIN       = 0.1
LAMBDA_DECAY    = 0.005
FEEDBACK_FILE   = "/home/moho/pox_snort_feedback.log"
BUFFER_TIMEOUT  = 2.0
MODEL_PATH      = "/home/moho/Documents/projects/IDS/pox/ext/trained_model_unsw.pkl"

# مسیرهای لاگ
LOG_DIR          = "/home/moho/Documents/projects/IDS/logs"
os.makedirs(LOG_DIR, exist_ok=True)
FLOW_LOG_FILE   = os.path.join(LOG_DIR, "flow_log.csv")
METRICS_LOG_FILE= os.path.join(LOG_DIR, "metrics_snort_only.csv")
SNORT_LOG_FILE  = os.path.join(LOG_DIR, "snort_alerts_log.csv")

# ============================================================
# ۱. کلاس نوشتار غیرهمزمان (Async Logger)
# ============================================================
class AsyncLogger:
    def __init__(self, csv_file, headers):
        self.csv_file = csv_file
        self.headers = headers
        self.queue = deque()
        self.running = True
        
        if not os.path.isfile(self.csv_file):
            with open(self.csv_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                
        self.thread = threading.Thread(target=self._writer_loop, daemon=True)
        self.thread.start()

    def _writer_loop(self):
        while self.running:
            if self.queue:
                batch = []
                while self.queue:
                    batch.append(self.queue.popleft())
                with open(self.csv_file, 'a', newline='') as f:
                    writer = csv.writer(f)
                    for row in batch:
                        writer.writerow(row)
            time.sleep(0.1)

    def log(self, row):
        self.queue.append(row)

    def stop(self):
        self.running = False
        self.thread.join(timeout=1)

# ============================================================
# ۲. کلاس مدیریت مدل (ModelManager)
# ============================================================
class ModelManager:
    def __init__(self, path):
        self.model = None
        self._load_model(path)

    def _load_model(self, path):
        try:
            with open(path, 'rb') as f:
                self.model = pickle.load(f)
            log.info(f"✅ Model loaded successfully from {path}")
        except Exception as e:
            log.error(f"❌ Cannot load model: {e}")
            self.model = None

    def predict(self, features):
        if self.model is None:
            return 0.0
        proba = self.model.predict_proba_one(features)
        return proba.get(1, 0.0)

    def learn(self, features, y_soft):
        if self.model is not None:
            self.model.learn_one(features, y_soft) 

    def get_leaf_count(self, features):
        try:
            stats = self.model.debug_one(features).get('leaf_stats', {0:0, 1:0})
            return sum(stats.values())
        except:
            return 1

# ============================================================
# ۳. کلاس ردیابی معیارها (MetricsTracker)
# ============================================================
class MetricsTracker:
    def __init__(self, logger):
        self.tp = self.tn = self.fp = self.fn = 0
        self.detection_delays = []
        self.blocking_delays = []
        self.logger = logger

    def update(self, y_real, y_pred, decision_time=None, block_time=None, flow_start=None):
        if y_real == 1 and y_pred == 1: self.tp += 1
        elif y_real == 0 and y_pred == 0: self.tn += 1
        elif y_real == 0 and y_pred == 1: self.fp += 1
        elif y_real == 1 and y_pred == 0: self.fn += 1

        if flow_start and decision_time:
            self.detection_delays.append(decision_time - flow_start)
        if decision_time and block_time:
            self.blocking_delays.append(block_time - decision_time)

        total = self.tp + self.tn + self.fp + self.fn
        if total > 0 and total % 10 == 0:
            self._log_metrics()

    def _log_metrics(self):
        total = self.tp + self.tn + self.fp + self.fn
        prec = self.tp / max(self.tp + self.fp, 1)
        rec = self.tp / max(self.tp + self.fn, 1)
        f1 = 2 * (prec * rec) / max(prec + rec, 1e-9)
        fpr = self.fp / max(self.fp + self.tn, 1)
        avg_det_delay = sum(self.detection_delays) / max(len(self.detection_delays), 1)
        avg_block_delay = sum(self.blocking_delays) / max(len(self.blocking_delays), 1)

        row = [
            time.time(),
            self.tp, self.fp, self.fn, self.tn,
            round(prec, 3), round(rec, 3), round(f1, 3), round(fpr, 3),
            round(avg_det_delay, 3), round(avg_block_delay, 3)
        ]
        self.logger.log(row)
        log.info(f"📊 Snort-Only Metrics Update: P={prec:.3f} R={rec:.3f} F1={f1:.3f} FPR={fpr:.3f}")

# ============================================================
# ۴. کلاس مدیریت بازخورد (FeedbackHandler) - ارتقا یافته برای مسدودسازی مستقیم اسنورت
# ============================================================
class FeedbackHandler:
    def __init__(self, model_manager, segment_buffer, metrics_tracker, flow_logger, snort_logger):
        self.model = model_manager
        self.buffer = segment_buffer
        self.metrics = metrics_tracker
        self.flow_logger = flow_logger
        self.snort_logger = snort_logger
        self.last_pos = 0
        self.running = True

    def start(self):
        threading.Thread(target=self._reader_loop, daemon=True).start()

    def _reader_loop(self):
        log.info("📡 Snort feedback reader loop active...")
        while not os.path.exists(FEEDBACK_FILE):
            time.sleep(2)
        open(FEEDBACK_FILE, 'a').close()

        while self.running:
            try:
                with open(FEEDBACK_FILE, 'r') as f:
                    f.seek(self.last_pos)
                    for line in f:
                        line = line.strip()
                        if line:
                            self._process_feedback(line)
                    self.last_pos = f.tell()
                self._clean_buffer()
            except FileNotFoundError:
                self.last_pos = 0
                time.sleep(2)
            except Exception as e:
                log.error(f"Feedback reader error: {e}")
            time.sleep(0.1)

    def _process_feedback(self, line):
        try:
            alert = json.loads(line)
        except:
            return

        self.snort_logger.log([time.time(), alert.get('src_ip'), alert.get('dst_ip'),
                               alert.get('src_port'), alert.get('dst_port'),
                               alert.get('protocol'), alert.get('message')])

        src_ip = alert.get('src_ip', '')
        dst_ip = alert.get('dst_ip', '')
        src_port = str(alert.get('src_port', '0'))
        dst_port = str(alert.get('dst_port', '0'))
        proto = alert.get('protocol', 'tcp').lower()

        search_key = f"{src_ip}|{dst_ip}|{src_port}|{dst_port}|{proto}"
        matched_key = search_key if search_key in self.buffer else None

        if not matched_key:
            for key in list(self.buffer):
                if src_ip in key and dst_ip in key:
                    matched_key = key
                    break
        if not matched_key:
            return

        entry = self.buffer.pop(matched_key)
        features = entry['features']
        decision_time = entry['decision_time']
        flow_start = entry.get('flow_start', decision_time)

        # ══════════════════════════════════════════════════════════════════
        # 🛠 تغییر اصلی Snort-Only: اعمال مستقیم و ناهمگام بلاک به سوئیچ سوئیچ
        # ══════════════════════════════════════════════════════════════════
        log.warning(f"🚨 Threat Detected by Snort: {matched_key} -> Initiating Block")
        
        # دسترسی به نمونه کنترلر فعال زنده برای اعمال دستور بلاک جریان
        if core.hasComponent('online_ids_switch'):
            core.online_ids_switch.enforce_snort_block(matched_key)

        # در حالت اسنورت‌خالی، تشخیص مثبت (y_pred=1) تازه این لحظه پس از آلارم محقق می‌شود
        y_real = 1 if "10.0.0.1" in matched_key else 0
        self.metrics.update(y_real=y_real, y_pred=1, decision_time=time.time(), block_time=time.time(), flow_start=flow_start)

        self.flow_logger.log([matched_key, time.time(), features.get('proto'), features.get('service'), 
                              entry['p_hat'], 1, y_real, 'block', decision_time, flow_start])

    def _clean_buffer(self):
        now = time.time()
        expired_keys = [k for k, v in self.buffer.items() if now - v['timestamp'] > BUFFER_TIMEOUT]
        for key in expired_keys:
            entry = self.buffer.pop(key)
            features = entry['features']
            decision_time = entry['decision_time']
            flow_start = entry.get('flow_start', decision_time)

            # فلوهایی که بدون آلارم اسنورت منقضی شدند = ترافیک مجاز (یا خطای FN اسنورت)
            y_real = 1 if "10.0.0.1" in key else 0
            self.metrics.update(y_real=y_real, y_pred=0, decision_time=decision_time, block_time=None, flow_start=flow_start)
            
            self.flow_logger.log([key, time.time(), features.get('proto'), features.get('service'), 
                                  entry['p_hat'], 0, y_real, 'allow', decision_time, flow_start])

# ============================================================
# ۵. کنترلر اصلی (OnlineLearningSwitch)
# ============================================================
class OnlineLearningSwitch(object):
    def __init__(self, connection):
        self.connection = connection
        self.mac_to_port = {}
        self.flow_windows = {}
        self.conn_history = ConnectionHistory()
        self.last_window_time = time.time()
        self.segment_buffer = {}
        self.blocked_flows = set()
        self.snort_port = 3

        # ثبت کامپوننت در سیستم پواکس جهت دسترسی لایه فیدبک
        core.register("online_ids_switch", self)

        # راه‌اندازی لاگرها
        self.flow_logger = AsyncLogger(FLOW_LOG_FILE,
                                       ['flow_id', 'timestamp', 'proto', 'service', 'p_hat',
                                        'pred_label', 'real_label', 'action', 'decision_time', 'flow_start'])
        self.metrics_logger = AsyncLogger(METRICS_LOG_FILE,
                                          ['timestamp', 'TP', 'FP', 'FN', 'TN', 'Precision',
                                           'Recall', 'F1', 'FPR', 'Avg_Det_Delay', 'Avg_Block_Delay'])
        self.snort_logger = AsyncLogger(SNORT_LOG_FILE,
                                        ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                                         'protocol', 'message'])

        self.model_manager = ModelManager(MODEL_PATH)
        self.metrics = MetricsTracker(self.metrics_logger)
        self.feedback = FeedbackHandler(self.model_manager, self.segment_buffer,
                                        self.metrics, self.flow_logger, self.snort_logger)
        self.feedback.start()

        connection.addListeners(self)
        log.info("🔌 Switch connected – online Snort-Only Monitor active.")

    def _handle_PacketIn(self, event):
        packet = event.parsed
        raw_data = event.ofp.data
        in_port = event.port

        flow_id = self._get_flow_id(packet)

        if flow_id != "unknown":
            if flow_id not in self.flow_windows:
                self.flow_windows[flow_id] = FlowRecord(flow_id)
            self.flow_windows[flow_id].update(packet, raw_data)

        if time.time() - self.last_window_time >= WINDOW_DURATION:
            self._process_windows()
            self.last_window_time = time.time()

        self.mac_to_port[packet.src] = in_port
        out_port = self.mac_to_port.get(packet.dst, of.OFPP_FLOOD)

        icmp = packet.find('icmp')
        if icmp:
            self._forward_packet(event, in_port, out_port)
            self._mirror_to_snort(event, in_port)
            return

        if flow_id not in self.blocked_flows:
            self._forward_packet(event, in_port, out_port)
            self._mirror_to_snort(event, in_port)

    def _forward_packet(self, event, in_port, out_port):
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.in_port = in_port
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)

    def _mirror_to_snort(self, event, in_port):
        if in_port == self.snort_port: return
        packet = event.parsed
        ip = packet.find('ipv4')
        if ip:
            s, d = str(ip.srcip), str(ip.dstip)
            if {s, d} == {'10.0.0.1', '10.0.0.2'}:
                msg = of.ofp_packet_out()
                msg.data = event.ofp
                msg.in_port = in_port
                msg.actions.append(of.ofp_action_output(port=self.snort_port))
                self.connection.send(msg)

    def _get_flow_id(self, packet):
        ip = packet.find('ipv4')
        if not ip: return "unknown"
        tcp = packet.find('tcp')
        udp = packet.find('udp')
        icmp = packet.find('icmp')
        if tcp: return f"{ip.srcip}|{ip.dstip}|{tcp.srcport}|{tcp.dstport}|tcp"
        if udp: return f"{ip.srcip}|{ip.dstip}|{udp.srcport}|{udp.dstport}|udp"
        if icmp: return f"{ip.srcip}|{ip.dstip}|0|0|icmp"
        return "unknown"

    def _process_windows(self):
        for flow_id, rec in list(self.flow_windows.items()):
            features = build_unsw_features(rec, self.conn_history)
            self.conn_history.add(rec)

            p_hat = self.model_manager.predict(features)
            decision_time = time.time()
            flow_start = rec.start_time

            # ══════════════════════════════════════════════════════════════════
            # 🛠 تغییر اصلی Snort-Only: در پنجره‌ها همه فلوها آزاد هستند (action='allow')
            # ══════════════════════════════════════════════════════════════════
            self.segment_buffer[flow_id] = {
                'features': features,
                'p_hat': p_hat,
                'timestamp': time.time(),
                'decision_time': decision_time,
                'flow_start': flow_start,
                'action': 'allow'
            }

        self.flow_windows.clear()

    def enforce_snort_block(self, flow_id):
        """متد اختصاصی جهت بلاک مستقیم فلو پس از دریافت فیدبک امضای اسنورت"""
        if flow_id in self.blocked_flows: return
        parts = flow_id.split('|')
        if len(parts) != 5: return
        src_ip, dst_ip, src_port, dst_port, proto = parts

        if proto == 'icmp': return

        msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x0800
        msg.match.nw_src = src_ip
        msg.match.nw_dst = dst_ip
        msg.match.nw_proto = {'tcp': 6, 'udp': 17, 'icmp': 1}.get(proto, 6)
        if proto in ('tcp', 'udp'):
            msg.match.tp_src = int(src_port)
            msg.match.tp_dst = int(dst_port)
        msg.priority = 100
        msg.hard_timeout = 300
        msg.idle_timeout = 60
        self.connection.send(msg)
        self.blocked_flows.add(flow_id)
        log.warning(f"🚫 Flow blocked via Snort Signature: {flow_id}")

def launch():
    def start_switch(event):
        OnlineLearningSwitch(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
    log.info("🚀 Online Snort-Only Monitoring Infrastructure ready.")