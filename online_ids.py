# pox/ext/online_ids.py (Unified 4-mode Execution Core)
#
# اصلاح‌شده طبق فیدبک استاد (بخش‌های ۱، ۲، ۵، ۶):
#  - دیگر هیچ IP-heuristic برای برچسب واقعی استفاده نمی‌شود (Ground Truth کاملاً
#    مستقل، در ground_truth.py، توسط سناریوی حمله تعیین می‌شود - نه در این فایل).
#  - این کنترلر دیگر TP/FP/FN/TN/Precision/Recall/F1/FPR را آنلاین حدس نمی‌زند؛
#    فقط تله‌متری عملیاتی خام (ml_score, ml_prediction, snort_alert,
#    final_decision) را ثبت می‌کند. محاسبه‌ی معیارهای علمی واقعی وظیفه‌ی
#    evaluate_run.py است که این لاگ خام را با ground_truth join می‌کند.
#  - ICMP اکنون واقعاً block/unblock می‌شود (قبلاً enforcement برای ICMP کلاً
#    نادیده گرفته می‌شد).
#  - همبستگی Snort-to-flow دیگر substring-match دلبخواهی نیست.
#  - وضعیت blocked_flows با رویداد واقعی FlowRemoved سوئیچ همگام می‌شود.
#  - هر اجرا یک run_id مستقل دارد که در نام فایل‌های لاگ و داخل هر ردیف ثبت می‌شود.

from pox.core import core
import pox.openflow.libopenflow_01 as of
import time, pickle, math, threading, os, json, csv
from collections import deque
from feature_extractor import FlowRecord, ConnectionHistory, build_unsw_features

log = core.getLogger()

# ============================================================
# پیکربندی مدها و پارامترها
# ============================================================
EXECUTION_MODE = os.environ.get("IDS_MODE", "hybrid_online")  # 'snort_only', 'ml_only', 'hybrid_static', 'hybrid_online'

WINDOW_DURATION = 2
TAU_MIN         = 0.2
TAU_MAX         = 0.75
TAU_DECAY       = 0.0001
ALPHA_MAX       = 0.9
ALPHA_MIN       = 0.1
LAMBDA_DECAY    = 0.005
FEEDBACK_FILE   = "/home/moho/pox_snort_feedback.log"
# بزرگ‌ترین پنجره‌ی detection_filter در snort_agent.py متعلق به SSH Brute Force
# است (count 5, seconds 10). BUFFER_TIMEOUT باید حداقل از آن بزرگ‌تر باشد وگرنه
# فلو قبل از رسیدن فیدبک اسنورت از بافر حذف می‌شود (فیدبک ۶).
BUFFER_TIMEOUT  = 12.0
# سقف "تازگی" برای fallback همبستگی Snort-to-flow (نه برای exact match، فقط
# وقتی چند فلوی هم‌زمان بین همون IP pair هستن و باید حدس زد کدومش درسته).
# در این بنچمارک همه‌ی ترافیک (نرمال و حمله) بین همون یک جفت IP رد می‌شه، پس
# بدون این سقف، fallback می‌تونه یک alert مربوط به حمله رو به یک فلوی نرمالِ
# قدیمی‌تر در بافر نسبت بده (مشاهده‌شده: FP بالا، TP نزدیک صفر روی داده‌ی
# واقعی). اگر نزدیک‌ترین کاندید هم از این مقدار قدیمی‌تر باشه، به‌جای حدسِ
# نامطمئن، skip می‌کنیم.
FALLBACK_MAX_STALENESS = 3.0
MODEL_PATH      = "/home/moho/Documents/projects/IDS/pox/ext/trained_model_unsw.pkl"

LOG_DIR         = os.environ.get("IDS_LOG_DIR", "/home/moho/Documents/projects/IDS/logs")
os.makedirs(LOG_DIR, exist_ok=True)


def _resolve_run_id():
    """run_id هر اجرا را مشخص می‌کند تا لاگ‌های هر اجرا کاملاً مستقل بمانند
    (فیدبک ۶: 'هر run باید log، feedback و run_id مستقل داشته باشد').
    اولویت با متغیر محیطی IDS_RUN_ID است که run_4state_benchmark.py هنگام
    اجرای خودکار ست می‌کند (تضمین هم‌ترازی run_id بین کنترلر و مولد ترافیک).
    برای اجرای دستی (طبق دستورالعمل قدیمی README)، اگر run_benchmarks.py
    زودتر اجرا شده باشد از current_run_id.txt خوانده می‌شود، وگرنه یک شناسه
    موقت ساخته می‌شود (که در این حالت GT join باید دستی انجام شود)."""
    run_id = os.environ.get("IDS_RUN_ID")
    if run_id:
        return run_id
    run_id_file = os.path.join(LOG_DIR, "current_run_id.txt")
    try:
        with open(run_id_file) as f:
            rid = f.read().strip()
            if rid:
                return rid
    except OSError:
        pass
    return f"unassigned_{int(time.time())}"


RUN_ID = _resolve_run_id()

FLOW_LOG_FILE        = os.path.join(LOG_DIR, f"flow_log_{EXECUTION_MODE}_{RUN_ID}.csv")
OPS_LOG_FILE         = os.path.join(LOG_DIR, f"ops_log_{EXECUTION_MODE}_{RUN_ID}.csv")
SNORT_LOG_FILE       = os.path.join(LOG_DIR, f"snort_alerts_log_{EXECUTION_MODE}_{RUN_ID}.csv")
ENFORCEMENT_LOG_FILE = os.path.join(LOG_DIR, f"enforcement_log_{EXECUTION_MODE}_{RUN_ID}.csv")

# ============================================================
# ۱. لاگر غیرهمزمان پایدار
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
            return sum(self.model.debug_one(features).get('leaf_stats', {0: 0, 1: 0}).values())
        except Exception:
            return 1

# ============================================================
# ۳. تله‌متری عملیاتی (بدون هیچ ادعای Precision/Recall/F1)
# ============================================================
class OperationalStats:
    """شمارنده‌های عملیاتی خالص که بدون نیاز به Ground Truth، آنلاین قابل
    محاسبه‌اند (چند فلو، چند block/allow، تأخیر تصمیم). این کلاس دیگر
    TP/FP/FN/TN حدس نمی‌زند - Precision/Recall/F1/FPR/MCC واقعی فقط پس از
    join با ground_truth_<run_id>.csv در evaluate_run.py محاسبه می‌شود."""

    def __init__(self, logger):
        self.logger = logger
        self.decisions = 0
        self.blocked = 0
        self.allowed = 0
        self.decision_delays = []

    def record_decision(self, action, decision_time, flow_start):
        self.decisions += 1
        if action == 'block':
            self.blocked += 1
        else:
            self.allowed += 1
        if flow_start and decision_time:
            self.decision_delays.append(decision_time - flow_start)
        if self.decisions % 10 == 0:
            self._flush()

    def _flush(self):
        avg_delay = sum(self.decision_delays) / max(len(self.decision_delays), 1)
        self.logger.log([time.time(), self.decisions, self.blocked, self.allowed, round(avg_delay, 3)])
        log.info(f"📊 [{EXECUTION_MODE}] decisions={self.decisions} blocked={self.blocked} "
                 f"allowed={self.allowed} avg_delay={avg_delay:.3f}s")

# ============================================================
# ۴. مدیریت فیدبک ناهمگام + همبستگی Snort-to-flow
# ============================================================
class FeedbackHandler:
    def __init__(self, run_id, model_manager, segment_buffer, flow_logger, snort_logger,
                 enforcement_logger, switch_instance):
        self.run_id = run_id
        self.model = model_manager
        self.buffer = segment_buffer
        self.flow_logger = flow_logger
        self.snort_logger = snort_logger
        self.enforcement_logger = enforcement_logger
        self.switch = switch_instance
        self.last_pos = 0
        self.running = True

    def start(self):
        threading.Thread(target=self._reader_loop, daemon=True).start()

    def _reader_loop(self):
        log.info(f"📡 Feedback reader active for Mode: {EXECUTION_MODE} run_id={self.run_id}")
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
            except Exception as e:
                log.error(f"Feedback reader error: {e}")
            time.sleep(0.1)

    def _find_matching_flow(self, src_ip, dst_ip, src_port, dst_port, proto):
        """اصلاح فیدبک ۶: به‌جای substring match دلبخواهی روی اولین کلید
        منطبق، ابتدا exact match (هر دو جهت، چون جهت آلارم اسنورت ممکن است
        برعکس جهت flow_id ذخیره‌شده باشد) و در نبود آن، فقط بین کاندیداهایی که
        واقعاً همان جفت IP + همان پروتکل را دارند انتخاب می‌کند - و در صورت
        ابهام واقعی (چند فلوی هم‌فاصله)، به‌جای حدس زدن از enforcement صرف‌نظر
        می‌کند تا misattribution رخ ندهد."""
        fwd_key = f"{src_ip}|{dst_ip}|{src_port}|{dst_port}|{proto}"
        rev_key = f"{dst_ip}|{src_ip}|{dst_port}|{src_port}|{proto}"
        if fwd_key in self.buffer:
            return fwd_key
        if rev_key in self.buffer:
            return rev_key

        # اصلاح: fallback فقط بین کاندیداهایی جستجو می‌کند که واقعاً «تازه»
        # هستند (FALLBACK_MAX_STALENESS). بدون این سقف، وقتی چند فلو بین همان
        # IP pair در بافرند (که در این بنچمارک همیشه همین‌طوره، چون نرمال و
        # حمله هر دو بین همان دو IP رد می‌شوند)، "نزدیک‌ترین timestamp" ممکن
        # است یک فلوی کاملاً بی‌ربط و قدیمی‌تر باشد - نه فلوی واقعی‌ای که
        # باعث این alert شده.
        now = time.time()
        candidates = []
        for key in self.buffer:
            parts = key.split('|')
            if len(parts) != 5:
                continue
            k_src, k_dst, _k_sport, _k_dport, k_proto = parts
            if k_proto != proto:
                continue
            if {k_src, k_dst} != {src_ip, dst_ip}:
                continue
            if now - self.buffer[key]['timestamp'] > FALLBACK_MAX_STALENESS:
                continue
            candidates.append(key)

        if not candidates:
            return None
        if len(candidates) == 1:
            return candidates[0]

        candidates.sort(key=lambda k: abs(self.buffer[k]['timestamp'] - now))
        if abs(self.buffer[candidates[0]]['timestamp'] - self.buffer[candidates[1]]['timestamp']) < 1e-6:
            log.warning(f"⚠️ Ambiguous Snort correlation for {src_ip}<->{dst_ip} ({proto}): "
                        f"{len(candidates)} equally-likely flows - skipping to avoid misattribution.")
            return None
        return candidates[0]

    def _process_feedback(self, line):
        try:
            alert = json.loads(line)
        except Exception:
            return
        self.snort_logger.log([self.run_id, time.time(), alert.get('src_ip'), alert.get('dst_ip'),
                                alert.get('src_port'), alert.get('dst_port'),
                                alert.get('protocol'), alert.get('message')])

        src_ip, dst_ip = alert.get('src_ip', ''), alert.get('dst_ip', '')
        src_port, dst_port = str(alert.get('src_port', '0')), str(alert.get('dst_port', '0'))
        proto = alert.get('protocol', 'tcp').lower()

        matched_key = self._find_matching_flow(src_ip, dst_ip, src_port, dst_port, proto)
        if not matched_key:
            return

        entry = self.buffer.pop(matched_key)
        features, p_hat = entry['features'], entry['p_hat']
        decision_time = entry['decision_time']
        flow_start = entry.get('flow_start', decision_time)
        ml_prediction = 1 if p_hat >= 0.5 else 0

        self.enforcement_logger.log([self.run_id, matched_key, 'snort_detection', time.time(),
                                      alert.get('message', '')])

        if EXECUTION_MODE in ('hybrid_online', 'hybrid_static'):
            n_l = self.model.get_leaf_count(features)
            alpha = ALPHA_MIN + (ALPHA_MAX - ALPHA_MIN) * math.exp(-LAMBDA_DECAY * n_l)
            y_soft = alpha * 1.0 + (1 - alpha) * p_hat
            self.model.learn(features, y_soft)

            if entry['action'] == 'allow':
                log.warning(f"⚠️ Snort Override: Blocking flow missed by ML! {matched_key}")
                self.enforcement_logger.log([self.run_id, matched_key, 'snort_override', time.time(), ''])
                self.switch._enforce_policy(matched_key)
                entry['action'] = 'block'

            self.flow_logger.log([self.run_id, matched_key, 'snort_confirmed', time.time(),
                                   features.get('proto'), features.get('service'), round(p_hat, 6),
                                   ml_prediction, True, entry['action'], flow_start])

        elif EXECUTION_MODE == 'snort_only':
            log.warning(f"🚨 Snort Direct Block: {matched_key}")
            self.switch._enforce_policy(matched_key)
            self.flow_logger.log([self.run_id, matched_key, 'snort_confirmed', time.time(),
                                   features.get('proto'), features.get('service'), round(p_hat, 6),
                                   ml_prediction, True, 'block', flow_start])

    def _clean_buffer(self):
        now = time.time()
        expired_keys = [k for k, v in list(self.buffer.items()) if now - v['timestamp'] > BUFFER_TIMEOUT]
        for key in expired_keys:
            if key not in self.buffer:
                continue
            entry = self.buffer.pop(key)
            features, p_hat, action = entry['features'], entry['p_hat'], entry['action']
            decision_time = entry['decision_time']
            flow_start = entry.get('flow_start', decision_time)
            ml_prediction = 1 if p_hat >= 0.5 else 0

            if action == 'block':
                # ML بلاک کرد ولی هیچ تأیید Snort در بازه‌ی BUFFER_TIMEOUT نرسید.
                # این فقط یک سیگنال نرم برای آموزش آنلاین است - نه Ground Truth.
                n_l = self.model.get_leaf_count(features)
                alpha = ALPHA_MIN + (ALPHA_MAX - ALPHA_MIN) * math.exp(-LAMBDA_DECAY * n_l)
                y_soft = alpha * 0.0 + (1 - alpha) * p_hat
                self.model.learn(features, y_soft)
                self.switch._remove_policy(key)
                log.info(f"🔄 Negative Learn (Soft, unconfirmed): y_soft={y_soft:.3f} flow={key}")
                self.flow_logger.log([self.run_id, key, 'buffer_expired_unblocked', time.time(),
                                       features.get('proto'), features.get('service'), round(p_hat, 6),
                                       ml_prediction, False, 'allow', flow_start])
            else:
                y_soft = 0.0
                self.model.learn(features, y_soft)
                log.info(f"🔄 Normal Learn (Soft): y_soft={y_soft:.3f} flow={key}")
                self.flow_logger.log([self.run_id, key, 'buffer_expired_normal', time.time(),
                                       features.get('proto'), features.get('service'), round(p_hat, 6),
                                       ml_prediction, False, 'allow', flow_start])

# ============================================================
# ۵. کنترلر اصلی
# ============================================================
class OnlineLearningSwitch(object):
    def __init__(self, connection):
        self.connection = connection
        self.run_id = RUN_ID
        self.mac_to_port = {}; self.flow_windows = {}; self.conn_history = ConnectionHistory()
        self.last_window_time = time.time(); self.segment_buffer = {}; self.blocked_flows = set()
        self.snort_port = 3; self.total_samples = 0
        self._pending_barriers = {}
        self._next_xid = 0x10000000  # محدوده‌ی بالا برای پرهیز از تصادم با xidهای دیگر POX

        core.register("online_ids_switch", self)

        self.flow_logger = AsyncLogger(FLOW_LOG_FILE, [
            'run_id', 'flow_id', 'stage', 'event_time', 'proto', 'service',
            'ml_score', 'ml_prediction', 'snort_alert', 'final_decision', 'flow_start'])
        self.ops_logger = AsyncLogger(OPS_LOG_FILE, [
            'timestamp', 'total_decisions', 'blocked_count', 'allowed_count', 'avg_decision_delay'])
        self.snort_logger = AsyncLogger(SNORT_LOG_FILE, [
            'run_id', 'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'message'])
        self.enforcement_logger = AsyncLogger(ENFORCEMENT_LOG_FILE, [
            'run_id', 'flow_id', 'event', 'event_time', 'detail'])

        self.model_manager = ModelManager(MODEL_PATH)
        self.stats = OperationalStats(self.ops_logger)
        self.feedback = FeedbackHandler(self.run_id, self.model_manager, self.segment_buffer,
                                         self.flow_logger, self.snort_logger, self.enforcement_logger, self)
        self.feedback.start()

        connection.addListeners(self)
        log.info(f"🔌 Switch connected – Core Engine Active Mode: [{EXECUTION_MODE}] run_id={self.run_id}")

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
        ml_prediction = 1 if p_hat >= 0.5 else 0

        action = 'allow'

        if EXECUTION_MODE in ('ml_only', 'hybrid_static', 'hybrid_online'):
            self.total_samples += 1
            current_tau = TAU_MAX - (TAU_MAX - TAU_MIN) * math.exp(-TAU_DECAY * self.total_samples)
            current_tau = max(TAU_MIN, min(TAU_MAX, current_tau))

            if p_hat >= current_tau:
                log.warning(f"⚠️ ML Threat: {flow_id} (p={p_hat:.3f})")
                action = 'block'
                self.enforcement_logger.log([self.run_id, flow_id, 'ml_detection', decision_time,
                                              f'p_hat={p_hat:.4f} tau={current_tau:.4f}'])
                self._enforce_policy(flow_id)

        self.segment_buffer[flow_id] = {
            'features': features, 'p_hat': p_hat, 'timestamp': time.time(),
            'decision_time': decision_time, 'flow_start': flow_start, 'action': action
        }
        self.stats.record_decision(action, decision_time, flow_start)
        self.flow_logger.log([self.run_id, flow_id, 'decision', decision_time, features.get('proto'),
                               features.get('service'), round(p_hat, 6), ml_prediction, False,
                               action, flow_start])

    # --------------------------------------------------------
    # Enforcement: نصب/حذف قانون + تأیید واقعی نصب (Barrier) +
    # همگام‌سازی وضعیت با رویداد واقعی FlowRemoved سوئیچ
    # --------------------------------------------------------
    def _enforce_policy(self, flow_id):
        """اعمال قانون مسدودسازی. اصلاح فیدبک ۵: دیگر برای ICMP زودهنگام
        return نمی‌کند - با match بر پایه‌ی nw_proto=ICMP + IP pair (بدون
        tp_src/tp_dst که برای ICMP بی‌معنی است)، کل ترافیک ICMP بین آن دو
        میزبان دراپ می‌شود که برای مهار ICMP Flood کافی است."""
        if flow_id in self.blocked_flows: return
        parts = flow_id.split('|')
        if len(parts) != 5: return
        src_ip, dst_ip, src_port, dst_port, proto = parts

        msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x0800
        msg.match.nw_src = src_ip; msg.match.nw_dst = dst_ip
        msg.match.nw_proto = {'tcp': 6, 'udp': 17, 'icmp': 1}.get(proto, 6)
        if proto in ('tcp', 'udp'):
            msg.match.tp_src = int(src_port)
            msg.match.tp_dst = int(dst_port)

        msg.priority = 100
        msg.idle_timeout = 60    # آزادسازی هوشمند در صورت عدم فعالیت ترافیک
        msg.hard_timeout = 300   # انقضای قطعی قانون جهت جلوگیری از اشباع حافظه سوئیچ
        # بدون این فلگ، POX هیچ‌وقت از انقضای idle/hard_timeout روی سوئیچ مطلع
        # نمی‌شود و blocked_flows پایتون از وضعیت واقعی سوئیچ drift می‌کند.
        msg.flags = of.OFPFF_SEND_FLOW_REM

        self.blocked_flows.add(flow_id)
        self.enforcement_logger.log([self.run_id, flow_id, 'policy_install_sent', time.time(), proto])
        self.connection.send(msg)

        # تأیید واقعی نصب قانون روی سوئیچ با Barrier Request/Reply (به‌جای فرض
        # کردن اینکه ارسال flow_mod به معنای موفقیت است).
        xid = self._next_xid; self._next_xid += 1
        barrier = of.ofp_barrier_request(); barrier.xid = xid
        self._pending_barriers[xid] = flow_id
        self.connection.send(barrier)

        log.warning(f"🚫 Dynamically Blocked Flow: {flow_id}")

    def _remove_policy(self, flow_id):
        """حذف قانون مسدودسازی (تصحیح False Positive). دیگر برای ICMP
        زودهنگام return نمی‌کند."""
        if flow_id not in self.blocked_flows: return
        parts = flow_id.split('|')
        if len(parts) != 5: return
        src_ip, dst_ip, src_port, dst_port, proto = parts

        msg = of.ofp_flow_mod()
        msg.command = of.OFPFC_DELETE
        msg.match.dl_type = 0x0800
        msg.match.nw_src = src_ip; msg.match.nw_dst = dst_ip
        msg.match.nw_proto = {'tcp': 6, 'udp': 17, 'icmp': 1}.get(proto, 6)
        if proto in ('tcp', 'udp'):
            msg.match.tp_src = int(src_port)
            msg.match.tp_dst = int(dst_port)

        self.connection.send(msg)
        self.blocked_flows.discard(flow_id)
        self.enforcement_logger.log([self.run_id, flow_id, 'recovery', time.time(), 'fp_correction'])
        log.warning(f"✅ Unblocked False Positive Flow: {flow_id}")

    def _handle_BarrierIn(self, event):
        flow_id = self._pending_barriers.pop(event.xid, None)
        if flow_id:
            self.enforcement_logger.log([self.run_id, flow_id, 'block_confirmed', time.time(), ''])
            log.info(f"✔️ Block confirmed by switch (barrier ack): {flow_id}")

    def _handle_FlowRemoved(self, event):
        """اصلاح فیدبک ۵: وقتی سوئیچ به‌خاطر idle_timeout/hard_timeout قانون را
        خودش حذف کرد، اینجا با خبر می‌شویم و blocked_flows/رویداد recovery
        واقعاً ثبت می‌شود - نه اینکه پایتون تا ابد فکر کند فلو هنوز بلاک است."""
        try:
            m = event.ofp.match
            proto = {6: 'tcp', 17: 'udp', 1: 'icmp'}.get(m.nw_proto, 'tcp')
            if proto in ('tcp', 'udp'):
                flow_id = f"{m.nw_src}|{m.nw_dst}|{m.tp_src}|{m.tp_dst}|{proto}"
            else:
                flow_id = f"{m.nw_src}|{m.nw_dst}|0|0|{proto}"
        except Exception:
            return

        if flow_id in self.blocked_flows:
            self.blocked_flows.discard(flow_id)
            reason = {
                of.OFPRR_IDLE_TIMEOUT: 'idle_timeout',
                of.OFPRR_HARD_TIMEOUT: 'hard_timeout',
                of.OFPRR_DELETE: 'explicit_delete',
            }.get(getattr(event.ofp, 'reason', None), 'unknown')
            self.enforcement_logger.log([self.run_id, flow_id, 'recovery', time.time(), reason])
            log.info(f"✅ Recovery (switch flow removed, reason={reason}): {flow_id}")


def launch():
    def start_switch(event):
        OnlineLearningSwitch(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
    log.info(f"🚀 Unified IDS Core ready in [{EXECUTION_MODE}] Mode. run_id={RUN_ID}")
