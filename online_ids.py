"""
online_ids.py - Real-Time SDN Online Learning Intrusion Detection System
=======================================================================
This script implements the primary Software-Defined Networking (SDN) application 
for the POX controller core, acting as a real-time Adaptive Network Intrusion 
Detection and Prevention System (IDS/IPS). It integrates streaming data extraction, 
online probabilistic prediction, and asynchronous alert validation pipelines.

EXECUTION INVOCATION:
--------------------
# sudo -E env PATH="$PATH" ./pox/pox.py openflow.of_01 online_ids

COMPONENT DEPENDENCIES & MECHANISMS:
-------------------------------------
1. Event-Driven Packet Interception (`_handle_PacketIn`):
   - intercepts raw OpenFlow `PacketIn` events triggered by network switch buffers.
   - Forwards traffic tracking data incrementally into time-segmented arrays.
   - Enforces a rigorous, hardware-level immutable bypass rule for ICMP messages: 
     all ICMP echo flows are exclusively mirrored to Snort and never dropped.
2. Sliding-Window Pipeline Processing (`_process_windows`):
   - Flushes sliding flow frames sequentially every 2 seconds (`WINDOW_DURATION = 2`).
   - Converts live streaming dimensions to 41-element standard NSL-KDD arrays.
   - Evaluates statistical tensors through the probabilistic predictor model to extract 
     conditional attack likelihood scores ($p_{hat}$).
3. Real-Time Mitigation Actions (`_enforce_policy`):
   - Modifies switch rule parameters on the fly via `ofp_flow_mod` commands if the calculated 
     probability exceeds the configured decision barrier (`TAU_THRESHOLD = 0.85`).
   - Installs dynamic hardware-level reactive flow table entries with hard timeouts.
4. Asynchronous Threaded Analytics Logging (`AsyncLogger`):
   - Leverages independent background worker loops coupled with unbuffered FIFO queues (`deque`).
   - Writes historical telemetry metrics and traffic flow updates down to persistent CSV storage 
     at 100ms batches, eliminating processing friction on critical packet-switching paths.
5. Asynchronous Validation Buffer (`FeedbackHandler`):
   - Retains unverified predictive state summaries inside `segment_buffer` lookup maps.
   - Listens to background text channels to tail and ingest delayed Snort structural signals.
   - Triggers maturity-weighted regularized updates through custom `SoftLabelHoeffdingTree` 
     blocks while systematically purging tracking records that breach timing barriers (`BUFFER_TIMEOUT = 2.0`).
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
import time, pickle, math, threading, os, json, csv
from collections import deque, defaultdict
from feature_extractor import FlowRecord, ConnectionHistory, build_nslkdd_features
from soft_tree import SoftLabelHoeffdingTree


log = core.getLogger()

# ============================================================
# پارامترهای تنظیم‌شده
# ============================================================
WINDOW_DURATION = 2
TAU_THRESHOLD   = 0.85
ALPHA_MAX       = 0.9
ALPHA_MIN       = 0.1
LAMBDA_DECAY    = 0.005
FEEDBACK_FILE   = "/tmp/pox_snort_feedback.log"
BUFFER_TIMEOUT  = 2.0
MODEL_PATH      = "/home/moho/Documents/projects/IDS/pox/ext/trained_model2.pkl"

# مسیرهای لاگ
LOG_DIR         = "/home/moho/Documents/projects/IDS/logs"
os.makedirs(LOG_DIR, exist_ok=True)
FLOW_LOG_FILE   = os.path.join(LOG_DIR, "flow_log.csv")
METRICS_LOG_FILE= os.path.join(LOG_DIR, "metrics_log.csv")
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
        # نوشتن هدر فایل
        with open(self.csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
        self.thread = threading.Thread(target=self._writer_loop, daemon=True)
        self.thread.start()

    def _writer_loop(self):
        while self.running:
            if self.queue:
                # خارج کردن همه موارد موجود در صف به صورت یکجا
                batch = []
                while self.queue:
                    batch.append(self.queue.popleft())
                with open(self.csv_file, 'a', newline='') as f:
                    writer = csv.writer(f)
                    for row in batch:
                        writer.writerow(row)
            time.sleep(0.1)  # کاهش بار CPU

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
            log.info(f"✅ Model loaded from {path}")
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
        self.detection_delays = []   # تأخیر تشخیص (زمان بین شروع جریان و تصمیم)
        self.blocking_delays = []    # تأخیر مسدودسازی (زمان بین تصمیم و اعمال)
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

        # لاگ معیارها هر ۱۰ نمونه
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
        log.info(f"📊 Metrics: P={prec:.3f} R={rec:.3f} F1={f1:.3f} FPR={fpr:.3f}")

# ============================================================
# ۴. کلاس مدیریت بازخورد (FeedbackHandler)
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
        log.info("📡 Feedback reader started...")
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

        # لاگ آلارم Snort
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
        p_hat = entry['p_hat']
        decision_time = entry['decision_time']
        flow_start = entry.get('flow_start', decision_time)
        action = entry.get('action', 'allow')

        # محاسبه آلفا و بازخورد
        n_l = self.model.get_leaf_count(features)
        alpha = ALPHA_MIN + (ALPHA_MAX - ALPHA_MIN) * math.exp(-LAMBDA_DECAY * n_l)
        y_soft = alpha * 1.0 + (1 - alpha) * p_hat
        y_hard = 1 if y_soft >= 0.5 else 0

        self.model.learn(features, y_soft)

        log.info(f"🔄 Learn (Soft): y_soft={y_soft:.3f} α={alpha:.3f} flow={matched_key}")

        y_pred = 1 if p_hat >= 0.5 else 0
        self.metrics.update(y_real=1, y_pred=y_pred,
                            decision_time=decision_time, block_time=None,
                            flow_start=flow_start)

        # به‌روزرسانی لاگ جریان با برچسب واقعی
        self.flow_logger.log([matched_key, time.time(), features.get('flag'), features.get('service'),
                              p_hat, y_pred, 1, action, decision_time, flow_start])

    def _clean_buffer(self):
        now = time.time()
        expired_keys = [k for k, v in self.buffer.items() if now - v['timestamp'] > BUFFER_TIMEOUT]
        for key in expired_keys:
            entry = self.buffer.pop(key)
            features = entry['features']
            p_hat = entry['p_hat']
            action = entry['action']
            decision_time = entry['decision_time']
            flow_start = entry.get('flow_start', decision_time)

            if action == 'block':
                # بازخورد منفی (False Positive)
                n_l = self.model.get_leaf_count(features)
                alpha = ALPHA_MIN + (ALPHA_MAX - ALPHA_MIN) * math.exp(-LAMBDA_DECAY * n_l)
                y_soft = alpha * 0.0 + (1 - alpha) * p_hat
                self.model.learn(features, y_soft)
                log.info(f"🔄 Negative Learn (Soft): y_soft={y_soft:.3f} α={alpha:.3f} flow={key} (FP)")
                y_pred = 1 if p_hat >= 0.5 else 0
                self.metrics.update(y_real=0, y_pred=y_pred,
                                    decision_time=decision_time, block_time=None,
                                    flow_start=flow_start)
                self.flow_logger.log([key, time.time(), features.get('flag'), features.get('service'),
                                    p_hat, y_pred, 0, action, decision_time, flow_start])
            else:
                # True Negative
                self.flow_logger.log([key, time.time(), features.get('flag'), features.get('service'),
                                    p_hat, 0, 0, action, decision_time, flow_start])
                
    def stop(self):
        self.running = False

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

        # راه‌اندازی لاگرها
        self.flow_logger = AsyncLogger(FLOW_LOG_FILE,
                                       ['flow_id', 'timestamp', 'flag', 'service', 'p_hat',
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
        log.info("🔌 Switch connected – online IDS active.")

   
       # ---------- Packet Handler ----------
    def _handle_PacketIn(self, event):
        packet = event.parsed
        raw_data = event.ofp.data
        in_port = event.port

        flow_id = self._get_flow_id(packet)

        # ۱. به‌روزرسانی جریان‌ها (برای همه‌ی پروتکل‌ها، از جمله ICMP)
        if flow_id != "unknown":
            if flow_id not in self.flow_windows:
                self.flow_windows[flow_id] = FlowRecord(flow_id)
            self.flow_windows[flow_id].update(packet, raw_data)

        # ۲. پردازش پنجره‌های زمانی (هر ۲ ثانیه) برای همه جریان‌ها
        # این کار باعث می‌شود مدل برای ICMP هم پیش‌بینی کند و در صورت لزوم یاد بگیرد
        if time.time() - self.last_window_time >= WINDOW_DURATION:
            self._process_windows()
            self.last_window_time = time.time()

        # ۳. به‌روزرسانی جدول MAC و تعیین پورت خروجی
        self.mac_to_port[packet.src] = in_port
        out_port = self.mac_to_port.get(packet.dst, of.OFPP_FLOOD)

        # ۴. قانون سخت‌افزاری (Hard Rule): هرگز ICMP را مسدود نکن!
        icmp = packet.find('icmp')
        if icmp:
            # حتی اگر قبلاً توسط _enforce_policy به blocked_flows اضافه شده باشد،
            # ما آن را نادیده می‌گیریم و همیشه فوروارد می‌کنیم
            self._forward_packet(event, in_port, out_port)
            self._mirror_to_snort(event, in_port)
            return  # خارج می‌شویم تا به بررسی مسدودسازی نرسد

        # ۵. برای جریان‌های TCP و UDP: فقط در صورت مسدود نبودن فوروارد کن
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
        if in_port == self.snort_port:
            return
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

    # ---------- پردازش پنجره ----------
    def _process_windows(self):
        for flow_id, rec in list(self.flow_windows.items()):
            features = build_nslkdd_features(rec, self.conn_history)
            self.conn_history.add(rec)

            p_hat = self.model_manager.predict(features)
            decision_time = time.time()
            flow_start = rec.start_time

            log.debug(f"flow={flow_id} p={p_hat:.3f} flag={features['flag']} svc={features['service']}")

            # تصمیم‌گیری
            action = 'allow'
            if p_hat >= TAU_THRESHOLD:
                log.warning(f"⚠️  Threat: {flow_id} (p={p_hat:.3f})")
                action = 'block'
                self._enforce_policy(flow_id)

            # ذخیره در بافر برای بازخورد
            self.segment_buffer[flow_id] = {
                'features': features,
                'p_hat': p_hat,
                'timestamp': time.time(),
                'decision_time': decision_time,
                'flow_start': flow_start,
                'action': action
            }

            # لاگ اولیه جریان (بدون برچسب واقعی)
            pred_label = 1 if p_hat >= 0.5 else 0
            self.flow_logger.log([flow_id, decision_time, features.get('flag'), features.get('service'),
                                  p_hat, pred_label, None, action, decision_time, flow_start])

        self.flow_windows.clear()

    # ---------- سیاست مسدودسازی ----------
    def _enforce_policy(self, flow_id):
        if flow_id in self.blocked_flows:
            return
        parts = flow_id.split('|')
        if len(parts) != 5:
            return
        src_ip, dst_ip, src_port, dst_port, proto = parts

        if proto == 'icmp': # ignore :)
            return

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
        self.connection.send(msg)
        self.blocked_flows.add(flow_id)
        log.warning(f"🚫 Flow blocked: {flow_id}")

def launch():
    def start_switch(event):
        OnlineLearningSwitch(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
    log.info("🚀 Online IDS controller ready.")
