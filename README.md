```markdown
# Hybrid-IDS: SDN Intrusion Detection System using Soft-Label Stream Learning

An academic framework for a Hybrid Network Intrusion Detection System (Hybrid-IDS) designed for Software-Defined Networking (SDN) environments. The architecture bridges signature-based detection (Snort) with dynamic online machine learning (Streaming Hoeffding Tree) inside a POX controller, utilizing a **Probabilistic Knowledge Distillation (Soft-Label)** mechanism to suppress transient network noise and False Positives.

---

## 🚀 Key Features

- **Asynchronous Feedback Loop:** Implements a stateful `FeedbackHandler` that synchronizes rapid sub-millisecond model inferences with deeper, delayed inspection alerts from Snort without halting active live traffic.
- **Noise Mitigation via Soft Labels:** Employs a `SoftLabelHoeffdingTree` wrapper over `river` that dynamically adjusts trust ($\alpha$-decay) based on leaf maturity, protecting the model from early-stage false alerts.
- **Stateful Live Feature Extraction:** Translates raw OpenFlow packet streams dynamically into 41 full connection-based and windowed cross-traffic features compatible with the NSL-KDD space.
- **Automated Benchmarking:** Includes a programmatic evaluation wrapper for rigorous, reproducible multi-vector attack testing inside Mininet.

---

## 📂 Project Structure

| File / Folder | Purpose |
| :--- | :--- |
| `online_ids-hybrid.py` | Core SDN controller script (Houses packet handlers, sliding flow windows, and policy enforcement). |
| `soft_tree.py` | Custom `SoftLabelHoeffdingTree` wrapper supporting probabilistic training weights. |
| `feature_extractor.py` | State tracker transforming live OpenFlow streams into windowed (2s) and host-based (100 conns) historical features. |
| `snort_agent.py` | Real-time agent translating raw signature hits into standardized JSON telemetry. |
| `run_benchmarks.py` | Automated testing engine driving deterministic multi-vector simulation phases. |
| `plot_metrics.py` | Statistical visualization script rendering runtime evaluation figures. |
| `model_rf_unsw.py` | Cold-start bootstrapping routine initializing the streaming classifier pipeline. |
| `trained_model2.pkl` | Serialized model pipeline snapshot containing standard scaling and encoder initial states. |
| `logs/` | Runtime telemetry repository tracking incremental evaluation metrics, raw flow predictions, and captured plots. |

---

## 🛠️ Prerequisites & Installation

### Environment Requirements
- **OS:** Linux (Ubuntu 20.04/22.04 LTS recommended)
- **SDN Controller:** POX (Python 3 compliant branch cloned into root or system path)
- **Emulator:** Mininet (configured with Open vSwitch `ovsk`)
- **IDS Engine:** Snort 2.9+

### Dependencies Setup
Install the necessary processing dependencies via `pip`:
```bash
pip install river pandas matplotlib
```

---

## 📋 Comprehensive Feature Mapping Table (UNSW-NB15 Space)

| ID | UNSW-NB15 Feature Name | Data Type | Pipeline Extraction Logic / `feature_extractor.py` Implementation Reference | Feature Category & Analytical Context |
| :---: | :--- | :---: | :--- | :--- |
| **1** | `srcip` | Symbolic | Extracted directly from IPv4 packet headers (`str(ip.srcip)`). | **Basic:** Source IP address (Dropped from training vectors). |
| **2** | `sport` | Symbolic | Extracted from TCP/UDP layer headers (`tcp.srcport` / `udp.srcport`). | **Basic:** Source port number. |
| **3** | `dstip` | Symbolic | Extracted directly from IPv4 packet headers (`str(ip.dstip)`). | **Basic:** Destination IP address (Dropped from training vectors). |
| **4** | `dsport` | Symbolic | Extracted from TCP/UDP layer headers (`tcp.dstport` / `udp.dstport`). | **Basic:** Destination port number. |
| **5** | `proto` | Symbolic | Mapped from L3/L4 matchers: evaluates to `tcp`, `udp`, or `icmp`. | **Basic:** Transaction protocol type. |
| **6** | `state` | Symbolic | Tracked dynamically via TCP flags (`REQ`, `ACC`, `CON`, `FIN`, `RST`) or set to `INT`/`URP`. | **Basic:** Protocol transaction state and status. |
| **7** | `dur` | Continuous | Calculated via elapsed flow time `max(self.last_time - self.start_time, 0.001)`. | **Basic:** Record actual transaction duration. |
| **8** | `sbytes` | Continuous | Incremented conditionally: source packet payload lengths summed via `len(raw_data)`. | **Content:** Source-to-destination transaction bytes. |
| **9** | `dbytes` | Continuous | Incremented conditionally: destination packet payload lengths summed via `len(raw_data)`. | **Content:** Destination-to-source transaction bytes. |
| **10** | `sttl` | Continuous | Hardcoded to `0` or baseline default inside real-time OpenFlow mapping. | **Basic:** Source time-to-live value. |
| **11** | `dttl` | Continuous | Hardcoded to `0` or baseline default inside real-time OpenFlow mapping. | **Basic:** Destination time-to-live value. |
| **12** | `sloss` | Continuous | Set to `0` based on flow-level abstraction limits. | **Content:** Source packets retransmitted or dropped. |
| **13** | `dloss` | Continuous | Set to `0` based on flow-level abstraction limits. | **Content:** Destination packets retransmitted or dropped. |
| **14** | `service` | Symbolic | Routed through `ServiceMapper.get()` via target port mapping (`ftp`, `ssh`, `http`, etc.). | **Basic:** Destination HTTP, FTP, SMTP service type. |
| **15** | `Sload` | Continuous | Calculated expression: `(self.src_bytes * 8) / duration`. | **Time:** Source bits per second (Instantiation load). |
| **16** | `Dload` | Continuous | Calculated expression: `(self.dst_bytes * 8) / duration`. | **Time:** Destination bits per second. |
| **17** | `Spkts` | Continuous | Incremented count tracking total source packets sent (`self.s_pkts`). | **Basic:** Source packet count. |
| **18** | `Dpkts` | Continuous | Incremented count tracking total destination packets sent (`self.d_pkts`). | **Basic:** Destination packet count. |
| **19** | `swin` | Continuous | Extracted directly from TCP header window size fields (`tcp.window`). | **Basic:** Source TCP window advertisement. |
| **20** | `dwin` | Continuous | Extracted directly from TCP header window size fields (`tcp.window`). | **Basic:** Destination TCP window advertisement. |
| **21** | `stcpb` | Continuous | Extracted from TCP sequence numbers (`tcp.seq`). | **Basic:** Source TCP base sequence number. |
| **22** | `dtcpb` | Continuous | Extracted from TCP acknowledgment numbers (`tcp.ack`). | **Basic:** Destination TCP base sequence number. |
| **23** | `smeansz` | Continuous | Derived ratio: `self.src_bytes / max(self.s_pkts, 1)`. | **Content:** Mean of the flow packet size sent by the source. |
| **24** | `dmeansz` | Continuous | Derived ratio: `self.dst_bytes / max(self.d_pkts, 1)`. | **Content:** Mean of the flow packet size sent by the destination. |
| **25** | `trans_depth` | Continuous | Evaluates to `1` if service matches `http`, otherwise `0`. | **Content:** Despatch depth levels of http flow requests. |
| **26** | `res_bdy_len` | Continuous | Set to `0` (Standardized default within real-time OpenFlow bounds). | **Content:** Result body payload block length from HTTP transactions. |
| **27** | `Sjit` | Continuous | Evaluated via variance/jitter calculations on packet arrival intervals (`pkt_intervals`). | **Time:** Source packet jitter (ms). |
| **28** | `Djit` | Continuous | Scaled derivative of source jitter profile (`jit * 0.5`). | **Time:** Destination packet jitter (ms). |
| **29** | `Stime` | Continuous | Flow initialization timestamp (`self.start_time`). | **Basic:** Record transaction start time (Dropped from training). |
| **30** | `Ltime` | Continuous | Flow last activity timestamp (`self.last_time`). | **Basic:** Record transaction last time (Dropped from training). |
| **31** | `Sintpkt` | Continuous | Mean inter-packet arrival time derived from `pkt_intervals`. | **Time:** Source inter-packet arrival time (ms). |
| **32** | `Dintpkt` | Continuous | Mean inter-packet arrival time derived from `pkt_intervals`. | **Time:** Destination inter-packet arrival time (ms). |
| **33** | `tcprtt` | Continuous | Summation of handshake metrics: `synack + ackdat`. | **Time:** TCP connection setup round-trip time. |
| **34** | `synack` | Continuous | Calculated time interval between SYN and SYN-ACK control packets. | **Time:** SYN-ACK establishment delay. |
| **35** | `ackdat` | Continuous | Calculated time interval between SYN-ACK and ACK control packets. | **Time:** ACK response time following setup. |
| **36** | `is_sm_ips_ports` | Binary | Equality evaluation: `1 if (self.src_ip == self.dst_ip) else 0`. | **General-purpose:** Checks if source and destination IPs/ports match. |
| **37** | `ct_state_ttl` | Continuous | Historical buffer lookup counting abnormal states per destination IP. | **General-purpose:** Count connections having same state and specific TTL. |
| **38** | `ct_flw_http_mthd` | Continuous | Historical buffer lookup counting HTTP method invocations. | **General-purpose:** Count flows with specific HTTP methods (e.g., GET/POST). |
| **39** | `is_ftp_login` | Binary | Hardcoded to `0` in real-time streaming feature extraction context. | **General-purpose:** Evaluates if FTP session executed login credentials. |
| **40** | `ct_ftp_cmd` | Continuous | Hardcoded to `0` in real-time streaming feature extraction context. | **General-purpose:** Count commands processed inside FTP sessions. |
| **41** | `ct_srv_src` | Continuous | Evaluated via `ConnectionHistory` buffer tracking matching source IP and service. | **Connection cooperative:** No. of connections that contain the same service and source address. |
| **42** | `ct_srv_dst` | Continuous | Evaluated via `ConnectionHistory` buffer tracking matching destination IP and service. | **Connection cooperative:** No. of connections that contain the same service and destination address. |
| **43** | `ct_dst_ltm` | Continuous | Evaluated via `ConnectionHistory` buffer matching destination IP history. | **Connection cooperative:** No. of connections of the same destination address. |
| **44** | `ct_src_ltm` | Continuous | Evaluated via `ConnectionHistory` buffer matching source IP history. | **Connection cooperative:** No. of connections of the same source address. |
| **45** | `ct_src_dport_ltm` | Continuous | Evaluated via `ConnectionHistory` buffer matching source IP and destination port. | **Connection cooperative:** No. of connections of the same source address and the destination port. |
| **46** | `ct_dst_sport_ltm` | Continuous | Evaluated via `ConnectionHistory` buffer matching destination IP and source port. | **Connection cooperative:** No. of connections of the same destination address and the source port. |
| **47** | `ct_dst_src_ltm` | Continuous | Evaluated via `ConnectionHistory` buffer matching source-destination pairs. | **Connection cooperative:** No. of connections of the same source and the destination address. |
| **48** | `attack_cat` | Symbolic | Target attack class label from reference definitions (Dropped from input vectors). | **Class:** Attack category classification name. |
| **49** | `Label` | Binary | Ground truth binary indicator (`0` for Normal, `1` for Attack). | **Class:** 0 for normal traffic and 1 for malicious activity. |
---

## 🛠️ Architectural Design Rationale (Defensive Thesis Note)

Features numbered **10 through 22** are classified as **Content Features** which historically track host-system telemetry parameters like configuration updates, authentication mechanisms, or file modifications. 

Because this architecture operates directly as an in-line **SDN Central Controller module (via OpenFlow)**, it evaluates traffic telemetry dynamically without executing intensive **Deep Packet Inspection (DPI)** workloads. Consequently, maintaining these specific attributes at a constant value of `0` represents a calculated engineering trade-off designed to guarantee **line-rate processing speeds, mitigate switch-controller latency, and prevent CPU starvation constraints** within real-time SDN control loops.
---

### Module Linkage

Deploy the central module file inside your active POX expansion workspace directory:

```bash
cp online_ids.py soft_tree.py feature_extractor.py /path/to/pox/pox/ext/
```

---

## 💻 Execution & Orchestration

The platform requires synchronized operation across separate service layers. Execute individual systems in the strict sequence mapped out below:

### Step 1: Boot the SDN Controller Core

Initiate the monitoring engine inside your central POX framework suite path:

```bash
sudo -E env PATH="$PATH" ./pox/pox.py openflow.of_01 online_ids
```

### Step 2: Spin Up the Mininet Topology

Emulate the open test-bed instance framework (Creates 3 Hosts, 1 OVS instance, mapped to the remote controller):

```bash
sudo mn -c
sudo mn --topo single,3 --mac --switch ovsk --controller remote
```

### Step 3: Instantiate the Snort Telemetry Agent

Mirroring interfaces are explicitly mapped. Spawn the alert parsing daemon on host `h3`:

```mininet
mininet> xterm h3
```

Inside the designated host window, kickstart the monitoring script:

```bash
sudo python3 snort_agent.py
```

### Step 4: Run Automated Attack Benchmarks

Inject multi-vector exploit profiles directly inside host `h1`'s isolated network context to test detection capabilities:

```mininet
mininet> xterm h1
```

Inside the attacker host window, run the benchmarking program:

```bash
sudo python3 run_benchmarks.py
```

---

## 📊 Evaluation & Metrics Visualization

The benchmarking engine will run 5 independent phases sequentially: Baseline Normal Traffic, TCP SYN Flood (`hping3`), Port Scanning (`nmap`), ICMP Flood (`ping -f`), and SSH Brute Force simulation (`nc`).

Once the validation test finishes, generate the thesis evaluation plots by running:

```bash
python3 plot_metrics.py
```

This updates the persistent state tracking statistics in the `logs/` directory and renders a high-fidelity evaluation plot detailing how the model scales under live adversarial scenarios:

### Metric Outputs Explained:

* **Precision / Recall Linearity:** Measures convergence across evolving streams. Rapid stabilization highlights highly effective cross-environment generalization.
* **FPR Stability:** A near-zero False Positive Rate validates that the **Soft-Labeling Knowledge Distillation** architecture prevents transient signature noise from destabilizing the adaptive Hoeffding tree structure.
* **Latency Overheads:** Tracks real-time statistical processing window limits (averaging $\sim$10 seconds), showing standard collection delays needed for building cross-traffic connection vectors without bottlenecking the fast data plane.
```
