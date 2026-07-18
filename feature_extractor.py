import time
from collections import deque, defaultdict

class ServiceMapper:
    @staticmethod
    def get(proto: str, port: int) -> str:
        ports = {21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 80: 'http', 443: 'https'}
        return ports.get(port, 'other').lower()

class FlowRecord:
    __slots__ = [
        'flow_id', 'start_time', 'last_time', 'pkt_count', 'src_bytes', 'dst_bytes',
        's_pkts', 'd_pkts', 'proto', 'service', 'state', 'src_ip', 'dst_ip',
        'src_port', 'dst_port', 
        'stcpb', 'dtcpb', 'swin', 'dwin',
        'last_pkt_time', 'pkt_intervals', 'syn_time', 'synack_time', 'ack_time',
        'is_flow_ended'
    ]

    def __init__(self, flow_id: str):
        self.flow_id = flow_id
        self.start_time = time.time()
        self.last_time = time.time()
        self.pkt_count = 0
        self.src_bytes = 0
        self.dst_bytes = 0
        self.s_pkts = 0
        self.d_pkts = 0
        self.proto = 'tcp'
        self.service = 'other'
        self.state = 'CON'
        self.src_ip = ''
        self.dst_ip = ''
        self.src_port = 0
        self.dst_port = 0
        
        self.stcpb = 0
        self.dtcpb = 0
        self.swin = 0
        self.dwin = 0
        
        self.last_pkt_time = None
        self.pkt_intervals = deque(maxlen=50)
        self.syn_time = 0.0
        self.synack_time = 0.0
        self.ack_time = 0.0
        self.is_flow_ended = False

    def update(self, packet, raw_data: bytes):
        now = time.time()
        self.pkt_count += 1
        self.last_time = now

        if self.last_pkt_time:
            self.pkt_intervals.append(now - self.last_pkt_time)
        self.last_pkt_time = now

        ip = packet.find('ipv4')
        tcp = packet.find('tcp')
        udp = packet.find('udp')
        icmp = packet.find('icmp')

        if ip:
            if self.src_ip == '':
                self.src_ip = str(ip.srcip)
                self.dst_ip = str(ip.dstip)

            if str(ip.srcip) == self.src_ip:
                self.src_bytes += len(raw_data)
                self.s_pkts += 1
            else:
                self.dst_bytes += len(raw_data)
                self.d_pkts += 1

        if tcp:
            self.proto = 'tcp'
            self.src_port = tcp.srcport
            self.dst_port = tcp.dstport
            self.service = ServiceMapper.get('tcp', tcp.dstport)

            self.stcpb = getattr(tcp, 'seq', 0)
            self.dtcpb = getattr(tcp, 'ack', 0)
            self.swin = getattr(tcp, 'window', 0)
            self.dwin = getattr(tcp, 'window', 0)

            f = tcp.flags
            if f & 0x02:
                self.syn_time = now
                self.state = 'REQ'
            if (f & 0x02) and (f & 0x10):
                self.synack_time = now
                self.state = 'ACC'
            if (f & 0x10) and not (f & 0x02):
                if self.synack_time > 0:
                    self.ack_time = now
                    self.state = 'CON'
            if f & 0x01:
                self.state = 'FIN'
                self.is_flow_ended = True
            if f & 0x04:
                self.state = 'RST'
                self.is_flow_ended = True

        elif udp:
            self.proto = 'udp'
            self.src_port = udp.srcport
            self.dst_port = udp.dstport
            self.service = ServiceMapper.get('udp', udp.dstport)
            self.state = 'INT'

        elif icmp:
            self.proto = 'icmp'
            self.service = 'other'
            self.state = 'URP'

    def get_unsw_features(self, history) -> dict:
        real_duration = max(self.last_time - self.start_time, 0.001)
        duration = max(real_duration, 1.0) if self.pkt_count <= 2 else max(real_duration, 0.001)
        
        s_load = (self.src_bytes * 8) / duration if duration > 0 else 0
        d_load = (self.dst_bytes * 8) / duration if duration > 0 else 0
        s_meansz = self.src_bytes / max(self.s_pkts, 1)
        d_meansz = self.dst_bytes / max(self.d_pkts, 1)
        
        intervals = list(self.pkt_intervals)
        avg_intpkt = sum(intervals) / max(len(intervals), 1)
        jit = 0.0
        if len(intervals) > 1:
            mean = sum(intervals) / len(intervals)
            jit = sum((x - mean) ** 2 for x in intervals) / len(intervals)

        synack = max(self.synack_time - self.syn_time, 0.0) if self.syn_time and self.synack_time else 0.0
        ackdat = max(self.ack_time - self.synack_time, 0.0) if self.synack_time and self.ack_time else 0.0
        tcprtt = synack + ackdat

        f = {
            'dur': duration, 'sbytes': self.src_bytes, 'dbytes': self.dst_bytes,
            'sloss': 0, 'dloss': 0, 'Sload': s_load, 'Dload': d_load, 
            'Spkts': self.s_pkts, 'Dpkts': self.d_pkts,
            'smeansz': s_meansz, 'dmeansz': d_meansz, 'trans_depth': 1 if self.service == 'http' else 0,
            'Sjit': jit, 'Djit': jit * 0.5, 'Sintpkt': avg_intpkt, 'Dintpkt': avg_intpkt,
            'tcprtt': tcprtt, 'synack': synack, 'ackdat': ackdat,
            'is_sm_ips_ports': 1 if (self.src_ip == self.dst_ip) else 0,
            'stcpb': self.stcpb, 'dtcpb': self.dtcpb, 'swin': self.swin, 'dwin': self.dwin,
            'sttl': 0, 'dttl': 0,
            'sport': self.src_port, 'dsport': self.dst_port,
            'res_bdy_len': 0,   # ✅ اضافه شدن کلید گم‌شده
        }

        f.update(history.get_cross_features(self.src_ip, self.dst_ip, self.dst_port, self.service, self.state))
        
        f['proto'] = str(self.proto).lower().strip()
        f['service'] = str(self.service).lower().strip()
        f['state'] = str(self.state).upper().strip()
        return f

class ConnectionHistory:
    def __init__(self):
        self.buffer = deque(maxlen=500)

    def add(self, rec: FlowRecord):
        self.buffer.append({
            'src_ip': rec.src_ip, 'dst_ip': rec.dst_ip,
            'dst_port': rec.dst_port, 'service': rec.service,
            'state': rec.state, 'is_http': 1 if rec.service == 'http' else 0
        })

    def get_cross_features(self, src_ip, dst_ip, dst_port, service, state) -> dict:
        buf = list(self.buffer)
        abnormal_states = ['S0', 'S1', 'REJ', 'RSTO']
        
        return {
            'ct_srv_src': sum(1 for e in buf if e['src_ip'] == src_ip and e['service'] == service),
            'ct_srv_dst': sum(1 for e in buf if e['dst_ip'] == dst_ip and e['service'] == service),
            'ct_dst_ltm': sum(1 for e in buf if e['dst_ip'] == dst_ip),
            'ct_src_ltm': sum(1 for e in buf if e['src_ip'] == src_ip),
            'ct_src_dport_ltm': sum(1 for e in buf if e['src_ip'] == src_ip and e['dst_port'] == dst_port),
            'ct_dst_sport_ltm': sum(1 for e in buf if e['dst_ip'] == dst_ip and e['dst_port'] == dst_port),
            'ct_dst_src_ltm': sum(1 for e in buf if e['src_ip'] == src_ip and e['dst_ip'] == dst_ip),
            'ct_state_ttl': sum(1 for e in buf if e['dst_ip'] == dst_ip and e['state'] in abnormal_states),
            'ct_flw_http_mthd': sum(1 for e in buf if e['dst_ip'] == dst_ip and e['is_http'] == 1),
            'is_ftp_login': 0, 
            'ct_ftp_cmd': 0
        }

def build_unsw_features(rec: FlowRecord, history: ConnectionHistory) -> dict:
    return rec.get_unsw_features(history)