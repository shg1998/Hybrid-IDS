# pox/ext/online_ids_core.py
from pox.core import core
import pox.openflow.libopenflow_01 as of
import time, pickle, math, threading, os, json, csv
from collections import deque
from feature_extractor import FlowRecord, ConnectionHistory, build_unsw_features

log = core.getLogger()

# ============================================================
# پیکربندی مدها و پارامترها
# ============================================================
EXECUTION_MODE = os.environ.get("IDS_MODE", "hybrid_online") # 'snort_only', 'ml_only', 'hybrid_static', 'hybrid_online'

WINDOW_DURATION = 2
TAU_MIN         = 0.2
TAU_MAX         = 0.75
TAU_DECAY       = 0.0001
ALPHA_MAX       = 0.9
ALPHA_MIN       = 0.1
LAMBDA_DECAY    = 0.005
FEEDBACK_FILE   = "/home/moho/pox_snort_feedback.log"
BUFFER_TIMEOUT  = 2.0
MODEL_PATH      = "/home/moho/Documents/projects/IDS/pox/ext/trained_model_unsw.pkl"

LOG_DIR         = "/home/moho/Documents/projects/IDS/logs"
os.makedirs(LOG_DIR, exist_ok=True)

FLOW_LOG_FILE   = os.path.join(LOG_DIR, f"flow_log_{EXECUTION_MODE}.csv")
METRICS_LOG_FILE= os.path.join(LOG_DIR, f"metrics_{EXECUTION_MODE}.csv")
SNORT_LOG_FILE  = os.path.join(LOG_DIR, "snort_alerts_log.csv")

# ============================================================
# ۱. لاگر غیرهمزمان پایداری
# ============================================================
class AsyncLogger:
    def __init__(self, csv_file, headers):
        self.csv_file = csv_file; self.headers = headers
        self.queue = deque(); self.running = True
        if not os.path.isfile(self.csv_file):
            with open(self.csv_file, 'w', newline='') as f:
                csv.writer(f).writerow(headers)
        self.thread = threading.Thread(target=self._writer_loop, daemon=True)
        self.thread.start()

    def _writer_loop(self):
        while self.running:
            if self.queue:
                batch = [self.queue.popleft() for _ in range(len(self.queue))]
                with open(self.csv_file, 'a', newline='') as f:
                    csv.writer(f).writerows(batch)
            time.sleep(0.1)

    def log(self, row): self.queue.append(row)
    def stop(self): self.running = False; self.thread.join(timeout=1)

# ============================================================
# ۲. مدیریت مدل آنلاین
# ============================================================
class ModelManager:
    def __init__(self, path):
        self.model = None; self._load_model(path)

    def _load_model(self, path):
        try:
            with open(path, 'rb') as f: self.model = pickle.load(f)
            log.info(f"✅ Model loaded: {path}")
        except Exception as e:
            log.error(f"❌ Cannot load model: {e}"); self.model = None

    def predict(self, features):
        if self.model is None: return 0.0
        return self.model.predict_proba_one(features).get(1, 0.0)

    def learn(self, features, y_soft):
        if self.model is not None and EXECUTION_MODE == 'hybrid_online':
            self.model.learn_one(features, y_soft)

    def get_leaf_count(self, features):
        try:
            return sum(self.model.debug_one(features).get('leaf_stats', {0:0, 1:0}).values())
        except: return 1

# ============================================================
# ۳. ردیاب انباشته متریک‌های علمی
# ============================================================
class MetricsTracker:
    def __init__(self, logger):
        self.tp = self.tn = self.fp = self.fn = 0
        self.detection_delays = []; self.blocking_delays = []
        self.logger = logger
        self.sample_counter = 0

    def update(self, y_real, y_pred, decision_time=None, block_time=None, flow_start=None):
        self.sample_counter += 1
        
        if y_real == 1 and y_pred == 1: self.tp += 1
        elif y_real == 0 and y_pred == 0: self.tn += 1
        elif y_real == 0 and y_pred == 1: self.fp += 1
        elif y_real == 1 and y_pred == 0: self.fn += 1
        
        if flow_start and decision_time: self.detection_delays.append(decision_time - flow_start)
        if decision_time and block_time: self.blocking_delays.append(block_time - decision_time)
        
        total = self.tp + self.tn + self.fp + self.fn
        if total > 0 and total % 10 == 0: self._log_metrics()

    def _log_metrics(self):
        total = self.tp + self.tn + self.fp + self.fn
        prec = self.tp / max(self.tp + self.fp, 1)
        rec = self.tp / max(self.tp + self.fn, 1)
        f1 = 2 * (prec * rec) / max(prec + rec, 1e-9)
        fpr = self.fp / max(self.fp + self.tn, 1)
        avg_det = sum(self.detection_delays) / max(len(self.detection_delays), 1)
        avg_blk = sum(self.blocking_delays) / max(len(self.blocking_delays), 1)
        
        self.logger.log([time.time(), self.tp, self.fp, self.fn, self.tn, round(prec,3), round(rec,3), round(f1,3), round(fpr,3), round(avg_det,3), round(avg_blk,3)])
        log.info(f"📊 [{EXECUTION_MODE}] P={prec:.3f} R={rec:.3f} F1={f1:.3f} FPR={fpr:.3f}")

# ============================================================
# ۴. مدیریت فیدبک ناهمگام
# ============================================================
class FeedbackHandler:
    def __init__(self, model_manager, segment_buffer, metrics_tracker, flow_logger, snort_logger, switch_instance):
        self.model = model_manager; self.buffer = segment_buffer; self.metrics = metrics_tracker
        self.flow_logger = flow_logger; self.snort_logger = snort_logger; self.switch = switch_instance
        self.last_pos = 0; self.running = True

    def start(self): threading.Thread(target=self._reader_loop, daemon=True).start()

    def _reader_loop(self):
        log.info(f"📡 Feedback reader active for Mode: {EXECUTION_MODE}")
        while not os.path.exists(FEEDBACK_FILE): time.sleep(2)
        open(FEEDBACK_FILE, 'a').close()
        while self.running:
            try:
                with open(FEEDBACK_FILE, 'r') as f:
                    f.seek(self.last_pos)
                    for line in f:
                        line = line.strip()
                        if line: self._process_feedback(line)
                    self.last_pos = f.tell()
                self._clean_buffer()
            except Exception as e: log.error(f"Feedback reader error: {e}")
            time.sleep(0.1)

    def _process_feedback(self, line):
        try: alert = json.loads(line)
        except: return
        self.snort_logger.log([time.time(), alert.get('src_ip'), alert.get('dst_ip'), alert.get('src_port'), alert.get('dst_port'), alert.get('protocol'), alert.get('message')])
        
        src_ip, dst_ip = alert.get('src_ip',''), alert.get('dst_ip','')
        src_port, dst_port = str(alert.get('src_port','0')), str(alert.get('dst_port','0'))
        proto = alert.get('protocol','tcp').lower()
        
        search_key = f"{src_ip}|{dst_ip}|{src_port}|{dst_port}|{proto}"
        matched_key = search_key if search_key in self.buffer else None
        if not matched_key:
            for key in list(self.buffer):
                if src_ip in key and dst_ip in key: matched_key = key; break
        if not matched_key: return

        entry = self.buffer.pop(matched_key)
        features, p_hat = entry['features'], entry['p_hat']
        decision_time = entry['decision_time']
        flow_start = entry.get('flow_start', decision_time)

        if EXECUTION_MODE in ['hybrid_online', 'hybrid_static']:
            n_l = self.model.get_leaf_count(features)
            alpha = ALPHA_MIN + (ALPHA_MAX - ALPHA_MIN) * math.exp(-LAMBDA_DECAY * n_l)
            y_soft = alpha * 1.0 + (1 - alpha) * p_hat
            self.model.learn(features, y_soft)

            if entry['action'] == 'allow':
                log.warning(f"⚠️ Snort Override: Blocking flow missed by ML! {matched_key}")
                self.switch._enforce_policy(matched_key)
                entry['action'] = 'block'
            
            y_pred = 1
            self.metrics.update(y_real=1, y_pred=y_pred, decision_time=decision_time, block_time=time.time(), flow_start=flow_start)
            self.flow_logger.log([matched_key, time.time(), features.get('proto'), features.get('service'), p_hat, y_pred, 1, entry['action'], decision_time, flow_start])

        elif EXECUTION_MODE == 'snort_only':
            log.warning(f"🚨 Snort Direct Block: {matched_key}")
            self.switch._enforce_policy(matched_key)
            self.metrics.update(y_real=1, y_pred=1, decision_time=time.time(), block_time=time.time(), flow_start=flow_start)
            self.flow_logger.log([matched_key, time.time(), features.get('proto'), features.get('service'), p_hat, 1, 1, 'block', decision_time, flow_start])

    def _clean_buffer(self):
        now = time.time()
        expired_keys = [k for k, v in list(self.buffer.items()) if now - v['timestamp'] > BUFFER_TIMEOUT]
        for key in expired_keys:
            if key not in self.buffer: continue
            entry = self.buffer.pop(key)
            features, p_hat, action = entry['features'], entry['p_hat'], entry['action']
            decision_time = entry['decision_time']
            flow_start = entry.get('flow_start', decision_time)

            if action == 'block':
                # مدیریت مثبت کاذب
                n_l = self.model.get_leaf_count(features)
                alpha = ALPHA_MIN + (ALPHA_MAX - ALPHA_MIN) * math.exp(-LAMBDA_DECAY * n_l)
                y_soft = alpha * 0.0 + (1 - alpha) * p_hat
                self.model.learn(features, y_soft)
                self.switch._remove_policy(key) # رفع بلاک خودکار در لایه دیتاسنتر
                
                y_real = 1 if "10.0.0.1" in key else 0
                y_pred = 1 if p_hat >= 0.5 else 0
                self.metrics.update(y_real=y_real, y_pred=y_pred, decision_time=decision_time, flow_start=flow_start)
                self.flow_logger.log([key, time.time(), features.get('proto'), features.get('service'), p_hat, y_pred, y_real, action, decision_time, flow_start])
            else:
                y_real = 1 if "10.0.0.1" in key else 0
                y_pred = 1 if p_hat >= 0.5 else 0
                self.metrics.update(y_real=y_real, y_pred=y_pred, decision_time=decision_time, flow_start=flow_start)
                self.flow_logger.log([key, time.time(), features.get('proto'), features.get('service'), p_hat, y_pred, y_real, action, decision_time, flow_start])

# ============================================================
# ۵. سوئیچ اصلی کنترلر
# ============================================================
class OnlineLearningSwitch(object):
    def __init__(self, connection):
        self.connection = connection
        self.mac_to_port = {}; self.flow_windows = {}; self.conn_history = ConnectionHistory()
        self.last_window_time = time.time(); self.segment_buffer = {}; self.blocked_flows = set()
        self.snort_port = 3; self.total_samples = 0
        
        core.register("online_ids_switch", self)

        self.flow_logger = AsyncLogger(FLOW_LOG_FILE, ['flow_id','timestamp','proto','service','p_hat','pred_label','real_label','action','decision_time','flow_start'])
        self.metrics_logger = AsyncLogger(METRICS_LOG_FILE, ['timestamp','TP','FP','FN','TN','Precision','Recall','F1','FPR','Avg_Det_Delay','Avg_Block_Delay'])
        self.snort_logger = AsyncLogger(SNORT_LOG_FILE, ['timestamp','src_ip','dst_ip','src_port','dst_port','protocol','message'])
        
        self.model_manager = ModelManager(MODEL_PATH)
        self.metrics = MetricsTracker(self.metrics_logger)
        self.feedback = FeedbackHandler(self.model_manager, self.segment_buffer, self.metrics, self.flow_logger, self.snort_logger, self)
        self.feedback.start()
        
        connection.addListeners(self)
        log.info(f"🔌 Switch connected – Core Engine Active Mode: [{EXECUTION_MODE}]")

    def _handle_PacketIn(self, event):
        packet = event.parsed; raw_data = event.ofp.data; in_port = event.port
        flow_id = self._get_flow_id(packet)
        
        if flow_id != "unknown":
            if flow_id not in self.flow_windows:
                self.flow_windows[flow_id] = FlowRecord(flow_id)
            self.flow_windows[flow_id].update(packet, raw_data)
            if self.flow_windows[flow_id].is_flow_ended:
                self._process_single_flow(flow_id, self.flow_windows.pop(flow_id))
                
        if time.time() - self.last_window_time >= WINDOW_DURATION:
            self._process_windows()
            self.last_window_time = time.time()

        self.mac_to_port[packet.src] = in_port
        out_port = self.mac_to_port.get(packet.dst, of.OFPP_FLOOD)
        
        icmp = packet.find('icmp')
        if icmp:
            self._forward_packet(event, in_port, out_port); self._mirror_to_snort(event, in_port); return
            
        if flow_id not in self.blocked_flows:
            self._forward_packet(event, in_port, out_port); self._mirror_to_snort(event, in_port)

    def _forward_packet(self, event, in_port, out_port):
        msg = of.ofp_packet_out(); msg.data = event.ofp; msg.in_port = in_port
        msg.actions.append(of.ofp_action_output(port=out_port)); self.connection.send(msg)

    def _mirror_to_snort(self, event, in_port):
        if in_port == self.snort_port: return
        ip = event.parsed.find('ipv4')
        if ip and {str(ip.srcip), str(ip.dstip)} == {'10.0.0.1', '10.0.0.2'}:
            msg = of.ofp_packet_out(); msg.data = event.ofp; msg.in_port = in_port
            msg.actions.append(of.ofp_action_output(port=self.snort_port)); self.connection.send(msg)

    def _get_flow_id(self, packet):
        ip = packet.find('ipv4')
        if not ip: return "unknown"
        tcp, udp, icmp = packet.find('tcp'), packet.find('udp'), packet.find('icmp')
        if tcp: return f"{ip.srcip}|{ip.dstip}|{tcp.srcport}|{tcp.dstport}|tcp"
        if udp: return f"{ip.srcip}|{ip.dstip}|{udp.srcport}|{udp.dstport}|udp"
        if icmp: return f"{ip.srcip}|{ip.dstip}|0|0|icmp"
        return "unknown"

    def _process_single_flow(self, flow_id, rec): self._extract_and_act(flow_id, rec)
    def _process_windows(self):
        for flow_id, rec in list(self.flow_windows.items()):
            self._extract_and_act(flow_id, rec)
        self.flow_windows.clear()

    def _extract_and_act(self, flow_id, rec):
        features = build_unsw_features(rec, self.conn_history)
        self.conn_history.add(rec)
        p_hat = self.model_manager.predict(features)
        decision_time, flow_start = time.time(), rec.start_time

        action = 'allow'
        
        # اتخاذ تصمیم در حالت‌های شامل یادگیری ماشین (ML-Only / Hybrid)
        if EXECUTION_MODE in ['ml_only', 'hybrid_static', 'hybrid_online']:
            self.total_samples += 1
            current_tau = TAU_MAX - (TAU_MAX - TAU_MIN) * math.exp(-TAU_DECAY * self.total_samples)
            current_tau = max(TAU_MIN, min(TAU_MAX, current_tau))
            
            if p_hat >= current_tau:
                log.warning(f"⚠️ ML Threat: {flow_id} (p={p_hat:.3f})")
                action = 'block'
                self._enforce_policy(flow_id)

        self.segment_buffer[flow_id] = {
            'features': features, 'p_hat': p_hat, 'timestamp': time.time(),
            'decision_time': decision_time, 'flow_start': flow_start, 'action': action
        }

    def _enforce_policy(self, flow_id):
        """اعمال قانون مسدودسازی جریان مخرب با تایم‌اوت مشخص"""
        if flow_id in self.blocked_flows: return
        parts = flow_id.split('|')
        if len(parts) != 5 or parts[4] == 'icmp': return
        src_ip, dst_ip, src_port, dst_port, proto = parts
        
        msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x0800
        msg.match.nw_src = src_ip; msg.match.nw_dst = dst_ip
        msg.match.nw_proto = {'tcp':6, 'udp':17, 'icmp':1}.get(proto, 6)
        if proto in ('tcp','udp'):
            msg.match.tp_src = int(src_port)
            msg.match.tp_dst = int(dst_port)
            
        msg.priority = 100
        msg.idle_timeout = 60    # آزادسازی هوشمند در صورت عدم فعالیت ترافیک
        msg.hard_timeout = 300   # انقضای قطعی قانون جهت جلوگیری از اشباع حافظه سوئیچ
        
        self.connection.send(msg)
        self.blocked_flows.add(flow_id)
        log.warning(f"🚫 Dynamically Blocked Flow: {flow_id}")

    def _remove_policy(self, flow_id):
        """حذف قانون مسدودسازی در صورت تشخیص مثبت کاذب (False Positive)"""
        if flow_id not in self.blocked_flows: return
        parts = flow_id.split('|')
        if len(parts) != 5 or parts[4] == 'icmp': return
        src_ip, dst_ip, src_port, dst_port, proto = parts
        
        msg = of.ofp_flow_mod()
        msg.command = of.OFPFC_DELETE
        msg.match.dl_type = 0x0800
        msg.match.nw_src = src_ip; msg.match.nw_dst = dst_ip
        msg.match.nw_proto = {'tcp':6, 'udp':17, 'icmp':1}.get(proto, 6)
        if proto in ('tcp','udp'):
            msg.match.tp_src = int(src_port)
            msg.match.tp_dst = int(dst_port)
            
        self.connection.send(msg)
        self.blocked_flows.discard(flow_id)
        log.warning(f"✅ Unblocked False Positive Flow: {flow_id}")

def launch():
    core.openflow.addListenerByName("ConnectionUp", lambda e: OnlineLearningSwitch(e.connection))
    log.info(f"🚀 Unified IDS Core ready in [{EXECUTION_MODE}] Mode.")