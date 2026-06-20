"""
feature_extractor.py  –  نگاشت دقیق ترافیک زنده SDN به NSL-KDD
=================================================================

NSL-KDD سه دسته feature دارد:

  A) ویژگی‌های پایه یک اتصال (duration, src_bytes, ...)
  B) ویژگی‌های پنجره زمانی 2 ثانیه (count, srv_count, serror_rate, ...)
     → «چند اتصال در 2 ثانیه اخیر به همان dst رفته‌اند؟»
  C) ویژگی‌های 100 اتصال اخیر به همان dst_host (dst_host_count, ...)
     → «در 100 اتصال اخیر به این host چه الگویی دیده‌ایم؟»

این فایل هر سه دسته را جداگانه پیاده‌سازی می‌کند.

نحوه استفاده در online_ids.py:
    from feature_extractor import FlowRecord, ConnectionHistory, build_nslkdd_features

    # یک بار در __init__:
    self.flow_windows  = {}
    self.conn_history  = ConnectionHistory()

    # در _update (هر پکت):
    if flow_id not in self.flow_windows:
        self.flow_windows[flow_id] = FlowRecord(flow_id)
    self.flow_windows[flow_id].update(packet, raw_data)

    # در _process_windows (هر 2 ثانیه):
    for flow_id, rec in list(self.flow_windows.items()):
        features = build_nslkdd_features(rec, self.conn_history)
        self.conn_history.add(rec)
        ...
"""

import time
from collections import deque, defaultdict


# ══════════════════════════════════════════════════════════════════
# ۱. نگاشت سرویس
# ══════════════════════════════════════════════════════════════════
class ServiceMapper:
    _TCP = {
        20: 'ftp_data', 21: 'ftp', 22: 'ssh', 23: 'telnet',
        25: 'smtp', 53: 'domain', 80: 'http', 110: 'pop_3',
        113: 'auth', 143: 'imap4', 443: 'https', 512: 'exec',
        513: 'login', 514: 'shell', 515: 'printer',
        540: 'uucp', 543: 'klogin', 544: 'kshell',
        8080: 'http_8001', 8443: 'https',
    }
    _UDP = {
        53: 'domain_u', 123: 'ntp_u', 161: 'snmp', 162: 'snmp',
    }

    @classmethod
    def get(cls, proto: str, port: int) -> str:
        if proto == 'tcp':
            return cls._TCP.get(port, 'other')
        if proto == 'udp':
            return cls._UDP.get(port, 'other')
        if proto == 'icmp':
            return 'ecr_i'
        return 'other'


# ══════════════════════════════════════════════════════════════════
# ۲. نگاشت Flag
# ══════════════════════════════════════════════════════════════════
class FlagMapper:
    @staticmethod
    def compute(syn: int, fin: int, rst: int, ack: int) -> str:
        if syn > 0 and fin > 0 and rst == 0:
            return 'SF'
        if syn > 0 and fin > 0 and rst > 0:
            return 'S3'
        if syn > 0 and ack > 0 and fin == 0 and rst == 0:
            return 'S1'
        if syn > 0 and fin == 0 and rst == 0 and ack == 0:
            return 'S0'
        if syn > 0 and rst > 0 and fin == 0:
            return 'RSTO'
        if rst > 0 and syn == 0:
            return 'REJ'
        if fin > 0 and syn == 0:
            return 'S2'
        return 'OTH'

    ERROR_FLAGS = {'S0', 'S1', 'S2', 'S3'}


# ══════════════════════════════════════════════════════════════════
# ۳. رکورد یک Flow  (دسته A)
# ══════════════════════════════════════════════════════════════════
class FlowRecord:
    __slots__ = [
        'flow_id', 'start_time',
        'pkt_count', 'src_bytes', 'dst_bytes',
        'syn_count', 'fin_count', 'rst_count', 'ack_count', 'urg_count',
        'protocol_type', 'service', 'src_ip', 'dst_ip',
        'src_port', 'dst_port', 'land','wrong_fragment',
    ]

    def __init__(self, flow_id: str):
        self.flow_id       = flow_id
        self.start_time    = time.time()
        self.pkt_count     = 0
        self.src_bytes     = 0
        self.dst_bytes     = 0
        self.syn_count     = 0
        self.fin_count     = 0
        self.rst_count     = 0
        self.ack_count     = 0
        self.urg_count     = 0
        self.protocol_type = 'tcp'
        self.service       = 'other'
        self.src_ip        = ''
        self.dst_ip        = ''
        self.src_port      = 0
        self.dst_port      = 0
        self.land          = 0
        self.wrong_fragment= 0

    def update(self, packet, raw_data: bytes):
        self.pkt_count += 1
        # self.src_bytes += len(raw_data)

        ip   = packet.find('ipv4')
        tcp  = packet.find('tcp')
        udp  = packet.find('udp')
        icmp = packet.find('icmp')

        
            
        if ip:
            if self.src_ip == '':    
                self.src_ip = str(ip.srcip)
                self.dst_ip = str(ip.dstip)
          
            if self.src_ip == self.dst_ip:
                self.land = 1
         
            if ip.srcip == self.src_ip: 
                self.src_bytes += len(raw_data)
            else:
                self.dst_bytes += len(raw_data)
    
            if ip.frag != 0 or (ip.flags & 0x2):   # MF bit
                self.wrong_fragment += 1

        if tcp:
            self.protocol_type = 'tcp'
            self.src_port = tcp.srcport
            self.dst_port = tcp.dstport
            self.service  = ServiceMapper.get('tcp', tcp.dstport)
            f = tcp.flags
            if f & 0x02: self.syn_count += 1
            if f & 0x01: self.fin_count += 1
            if f & 0x04: self.rst_count += 1
            if f & 0x10: self.ack_count += 1
            if f & 0x20: self.urg_count += 1

            # if tcp.dstport < 1024 or tcp.dstport in ServiceMapper._TCP:
            #     self.src_bytes += len(raw_data)
            # elif tcp.srcport < 1024 or tcp.srcport in ServiceMapper._TCP:
            #     self.dst_bytes += len(raw_data)
            # else:
            #     self.src_bytes += len(raw_data)

        elif udp:
            self.protocol_type = 'udp'
            self.src_port = udp.srcport
            self.dst_port = udp.dstport
            self.service  = ServiceMapper.get('udp', udp.dstport)
            # if udp.dstport < 1024 or udp.dstport in ServiceMapper._UDP:
            #     self.src_bytes += len(raw_data)
            # elif udp.srcport < 1024 or udp.srcport in ServiceMapper._UDP:
            #     self.dst_bytes += len(raw_data)
            # else:
            #     self.src_bytes += len(raw_data)

        # ✅ بهتر:
        elif icmp:
            self.protocol_type = 'icmp'
            ICMP_SERVICE_MAP = {
                0:  'ecr_i',   # echo reply
                8:  'eco_i',   # echo request
                3:  'urh_i',   # destination unreachable
                11: 'tim_i',   # time exceeded
            }
            self.service = ICMP_SERVICE_MAP.get(icmp.type, 'icmp')
            # if icmp.type == 0:
            #     self.dst_bytes += len(raw_data)
            # else:
            #     self.src_bytes += len(raw_data)
    
    @property
    def flag(self) -> str:
        return FlagMapper.compute(
            self.syn_count, self.fin_count,
            self.rst_count, self.ack_count
        )

    def base_features(self) -> dict:
        return {
            'duration':           max(time.time() - self.start_time, 0.0),
            'protocol_type':      self.protocol_type,
            'service':            self.service,
            'flag':               self.flag,
            'land':               self.land,
            'src_bytes':          self.src_bytes,
            'dst_bytes':          self.dst_bytes,     
            'wrong_fragment':     self.wrong_fragment,
            'urgent':             self.urg_count,
            'hot':                0,
            'num_failed_logins':  0,
            'logged_in':          0,
            'num_compromised':    0,
            'root_shell':         0,
            'su_attempted':       0,
            'num_root':           0,
            'num_file_creations': 0,
            'num_shells':         0,
            'num_access_files':   0,
            'num_outbound_cmds':  0,
            'is_host_login':      0,
            'is_guest_login':     0,
        }


# ══════════════════════════════════════════════════════════════════
# ۴. تاریخچه اتصالات  (دسته B و C)
# ══════════════════════════════════════════════════════════════════
class ConnectionHistory:
    WINDOW_SEC   = 2
    HOST_HISTORY = 100

    def __init__(self):
        self._time_buf: deque = deque()
        self._host_buf: dict  = defaultdict(
            lambda: deque(maxlen=self.HOST_HISTORY)
        )

    def add(self, rec: FlowRecord):
        entry = {
            'ts':       time.time(),
            'dst_ip':   rec.dst_ip,
            'src_ip':   rec.src_ip,
            'src_port': rec.src_port,
            'service':  rec.service,
            'flag':     rec.flag,
            'syn':      rec.syn_count,
            'rst':      rec.rst_count,
        }
        self._time_buf.append(entry)
        if rec.dst_ip:
            self._host_buf[rec.dst_ip].append(entry)

    def _prune(self):
        cutoff = time.time() - self.WINDOW_SEC
        while self._time_buf and self._time_buf[0]['ts'] < cutoff:
            self._time_buf.popleft()

    # ── دسته B ───────────────────────────────────────────────────
    def window_features(self, dst_ip: str, service: str) -> dict:
        self._prune()
        buf = list(self._time_buf)

        same_dst = [e for e in buf if e['dst_ip'] == dst_ip]
        same_srv = [e for e in buf if e['service'] == service]

        count = len(same_dst)
        srv_count = len(same_srv)

        def is_serror(e): return e['syn'] > 0 and e['flag'] in FlagMapper.ERROR_FLAGS
        def is_rerror(e): return e['rst'] > 0

        serror_rate = sum(1 for e in same_dst if is_serror(e)) / count if count > 0 else 0
        rerror_rate = sum(1 for e in same_dst if is_rerror(e)) / count if count > 0 else 0

        srv_serror_rate = sum(1 for e in same_srv if is_serror(e)) / srv_count if srv_count > 0 else 0
        srv_rerror_rate = sum(1 for e in same_srv if is_rerror(e)) / srv_count if srv_count > 0 else 0

        same_srv_in_dst = sum(1 for e in same_dst if e['service'] == service)
        same_srv_rate = same_srv_in_dst / count if count > 0 else 0
        diff_srv_rate = 1.0 - same_srv_rate

        srv_diff_host = sum(1 for e in same_srv if e['dst_ip'] != dst_ip)
        srv_diff_host_rate = srv_diff_host / srv_count if srv_count > 0 else 0

        return {
            'count': count,
            'srv_count': srv_count,
            'serror_rate': serror_rate,
            'srv_serror_rate': srv_serror_rate,
            'rerror_rate': rerror_rate,
            'srv_rerror_rate': srv_rerror_rate,
            'same_srv_rate': same_srv_rate,
            'diff_srv_rate': diff_srv_rate,
            'srv_diff_host_rate': srv_diff_host_rate,
        }
    # ── دسته C ───────────────────────────────────────────────────
    def host_features(self, dst_ip: str, service: str, src_port: int) -> dict:
        buf = list(self._host_buf.get(dst_ip, []))
        total = len(buf)
        same_srv = [e for e in buf if e['service'] == service]
        srv_tot = len(same_srv)

        def is_serror(e):
            return e['syn'] > 0 and e['flag'] in FlagMapper.ERROR_FLAGS

        def is_rerror(e):
            return e['rst'] > 0

        return {
            'dst_host_count': total,
            'dst_host_srv_count': srv_tot,
            'dst_host_same_srv_rate': srv_tot / total if total > 0 else 0,
            'dst_host_diff_srv_rate': 1.0 - (srv_tot / total) if total > 0 else 0,
            'dst_host_same_src_port_rate': sum(1 for e in buf if e['src_port'] == src_port) / total if total > 0 else 0,
            'dst_host_srv_diff_host_rate': len(set(e['src_ip'] for e in same_srv)) / srv_tot if srv_tot > 0 else 0,
            'dst_host_serror_rate': sum(1 for e in buf if is_serror(e)) / total if total > 0 else 0,
            'dst_host_srv_serror_rate': sum(1 for e in same_srv if is_serror(e)) / srv_tot if srv_tot > 0 else 0,
            'dst_host_rerror_rate': sum(1 for e in buf if is_rerror(e)) / total if total > 0 else 0,
            'dst_host_srv_rerror_rate': sum(1 for e in same_srv if is_rerror(e)) / srv_tot if srv_tot > 0 else 0,
        }

# ══════════════════════════════════════════════════════════════════
# ۵. تابع اصلی
# ══════════════════════════════════════════════════════════════════
def build_nslkdd_features(rec: FlowRecord, history: ConnectionHistory) -> dict:
    """41 feature کامل NSL-KDD را برمی‌گرداند."""
    f = rec.base_features()
    f.update(history.window_features(rec.dst_ip, rec.service))
    f.update(history.host_features(rec.dst_ip, rec.service, rec.src_port))
    return f