# Hybrid-IDS: SDN Intrusion Detection System using Soft-Label Stream Learning

An academic framework for a Hybrid Network Intrusion Detection System (Hybrid-IDS) designed for Software-Defined Networking (SDN) environments. The architecture bridges signature-based detection (Snort) with dynamic online machine learning (Streaming Hoeffding Tree) inside a POX controller, utilizing a **Probabilistic Knowledge Distillation (Soft-Label)** mechanism to suppress transient network noise and False Positives.

---

## 🚀 Key Features

- **Asynchronous Feedback Loop:** Implements a stateful `FeedbackHandler` that synchronizes rapid sub-millisecond model inferences with deeper, delayed inspection alerts from Snort without halting active live traffic.
- **Noise Mitigation via Soft Labels:** Employs a `SoftLabelHoeffdingTree` wrapper over `river` that dynamically adjusts trust ($\alpha$-decay) based on leaf maturity, protecting the model from early-stage false alerts.
- **Stateful Live Feature Extraction:** Translates raw OpenFlow packet streams dynamically into connection-based and windowed cross-traffic features compatible with the UNSW-NB15 space (see the audited feature table below).
- **Automated, Repeatable Benchmarking:** `run_4state_benchmark.py --repeats N` drives rigorous, reproducible multi-vector attack testing across 4 detection modes inside Mininet, each repetition with its own independent `run_id`.
- **Independent Ground Truth:** `ground_truth.py` records the real label/attack_type/time-window for every scenario phase, completely decoupled from IP identity, the ML model, and Snort — evaluation (`evaluate_run.py`) joins against this offline, never against the controller's own online guesses.

---

## 📂 Project Structure

| File / Folder             | Purpose                                                                                                                                                                                                                                                                                                                                                                   |
| :------------------------ | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `online_ids.py`           | Unified SDN controller (single file, 4 modes via `IDS_MODE` env var: `snort_only`/`ml_only`/`hybrid_static`/`hybrid_online`). Houses packet handlers, sliding flow windows, ICMP-aware policy enforcement, and Barrier/FlowRemoved-based enforcement state tracking. This is the only controller module the pipeline actually loads (`pox.py openflow.of_01 online_ids`). |
| `ground_truth.py`         | Independent Ground Truth recorder — decoupled from IP identity, ML, and Snort. Used by `run_benchmarks.py` to log the real (label, attack_type, time window) for every scenario phase.                                                                                                                                                                                    |
| `feature_extractor.py`    | State tracker transforming live OpenFlow streams into windowed (2s) and host-based (500 conns) historical features (UNSW-NB15 space).                                                                                                                                                                                                                                     |
| `snort_agent.py`          | Real-time agent translating raw signature hits into standardized JSON telemetry.                                                                                                                                                                                                                                                                                          |
| `run_benchmarks.py`       | Scenario driver (runs inside `h1`) generating the 5 traffic phases and their independent Ground Truth.                                                                                                                                                                                                                                                                    |
| `run_4state_benchmark.py` | Orchestrator: boots POX + Mininet + Snort + `run_benchmarks.py` for each of the 4 modes, `--repeats N` times, each repeat with its own `run_id`.                                                                                                                                                                                                                          |
| `evaluate_run.py`         | **Offline** evaluator: joins one run's `flow_log_<mode>_<run_id>.csv` against its `ground_truth_<run_id>.csv` and computes real Precision/Recall/F1/FPR/MCC/Detection & Mitigation Delay — overall and per `attack_type`. No synthetic adjustment.                                                                                                                        |
| `aggregate_runs.py`       | Aggregates multiple independent `eval_<mode>_<run_id>.csv` into Mean ± 95% CI across modes/attack types → `logs/final_comparison_table.csv`.                                                                                                                                                                                                                              |
| `evidence_report.py`      | Builds a readable end-to-end evidence chain per attack type (detection → policy install → block confirmed → recovery, plus a concurrent benign flow that kept flowing).                                                                                                                                                                                                   |
| `soft_tree.py`            | Custom `SoftLabelHoeffdingTree` wrapper supporting probabilistic training weights.                                                                                                                                                                                                                                                                                        |
| `model_rf_unsw.py`        | Cold-start bootstrapping routine initializing the streaming classifier pipeline from the UNSW-NB15 CSVs.                                                                                                                                                                                                                                                                  |
| `trained_model_unsw.pkl`  | Serialized model pipeline snapshot containing standard scaling and encoder initial states.                                                                                                                                                                                                                                                                                |
| `plot_metrics.py`         | Deprecated pointer to the evaluate → aggregate → plot workflow below (the old online-metrics plot it drove no longer exists — see `logs/archive_pre_fix/README.md`).                                                                                                                                                                                                      |
| `logs/`                   | Runtime telemetry: `ground_truth_*.csv`, `flow_log_*.csv`, `enforcement_log_*.csv`, `eval_*.csv`, `final_comparison_table.csv`, evidence reports, and plots. `logs/archive_pre_fix/` holds pre-fix data kept only for transparency, **not for citation**.                                                                                                                 |

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

**Feature audit legend** (فیدبک استاد بخش ۲-۴: _"feature‌ها باید به سه گروه Exact / Approximate / Unsupported مستندسازی شوند"_):

- 🟢 **Exact** — measured directly from real packet/header data with no proxy or default.
- 🟡 **Approximate** — a real signal, but derived through a heuristic/simplification that can diverge from the true UNSW-NB15 definition (documented per-row below).
- 🔴 **Unsupported** — hardcoded to a constant; would require payload/DPI inspection out of scope for line-rate OpenFlow header/state tracking.

|   ID   | UNSW-NB15 Feature Name | Data Type  |            Audit             | Pipeline Extraction Logic / `feature_extractor.py` Implementation Reference                                                                                                                                                                                                                                                                                                                                                      | Feature Category & Analytical Context                                                                 |
| :----: | :--------------------- | :--------: | :--------------------------: | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :---------------------------------------------------------------------------------------------------- |
| **1**  | `srcip`                |  Symbolic  |           🟢 Exact           | Extracted directly from IPv4 packet headers (`str(ip.srcip)`).                                                                                                                                                                                                                                                                                                                                                                   | **Basic:** Source IP address (Dropped from training vectors).                                         |
| **2**  | `sport`                |  Symbolic  |           🟢 Exact           | Extracted from TCP/UDP layer headers (`tcp.srcport` / `udp.srcport`).                                                                                                                                                                                                                                                                                                                                                            | **Basic:** Source port number.                                                                        |
| **3**  | `dstip`                |  Symbolic  |           🟢 Exact           | Extracted directly from IPv4 packet headers (`str(ip.dstip)`).                                                                                                                                                                                                                                                                                                                                                                   | **Basic:** Destination IP address (Dropped from training vectors).                                    |
| **4**  | `dsport`               |  Symbolic  |           🟢 Exact           | Extracted from TCP/UDP layer headers (`tcp.dstport` / `udp.dstport`).                                                                                                                                                                                                                                                                                                                                                            | **Basic:** Destination port number.                                                                   |
| **5**  | `proto`                |  Symbolic  |           🟢 Exact           | Mapped from L3/L4 matchers: evaluates to `tcp`, `udp`, or `icmp`.                                                                                                                                                                                                                                                                                                                                                                | **Basic:** Transaction protocol type.                                                                 |
| **6**  | `state`                |  Symbolic  |        🟡 Approximate        | Tracked dynamically via TCP flags (`REQ`, `ACC`, `CON`, `FIN`, `RST`) or set to `INT`/`URP` — a simplified state machine, not the full UNSW/Zeek connection-state taxonomy (`S0/S1/REJ/RSTO`/…).                                                                                                                                                                                                                                 | **Basic:** Protocol transaction state and status.                                                     |
| **7**  | `dur`                  | Continuous |           🟢 Exact           | Calculated via elapsed flow time `max(self.last_time - self.start_time, 0.001)`.                                                                                                                                                                                                                                                                                                                                                 | **Basic:** Record actual transaction duration.                                                        |
| **8**  | `sbytes`               | Continuous |           🟢 Exact           | Incremented conditionally: source packet payload lengths summed via `len(raw_data)`.                                                                                                                                                                                                                                                                                                                                             | **Content:** Source-to-destination transaction bytes.                                                 |
| **9**  | `dbytes`               | Continuous |           🟢 Exact           | Incremented conditionally: destination packet payload lengths summed via `len(raw_data)`.                                                                                                                                                                                                                                                                                                                                        | **Content:** Destination-to-source transaction bytes.                                                 |
| **10** | `sttl`                 | Continuous |      🟢 Exact _(fixed)_      | Read from the real IPv4 header TTL (`ip.ttl`) for source-originated packets. Previously hardcoded to `0` — upgraded since the value is already present in every packet header, no DPI required.                                                                                                                                                                                                                                  | **Basic:** Source time-to-live value.                                                                 |
| **11** | `dttl`                 | Continuous |      🟢 Exact _(fixed)_      | Read from the real IPv4 header TTL (`ip.ttl`) for destination-originated packets. Previously hardcoded to `0`.                                                                                                                                                                                                                                                                                                                   | **Basic:** Destination time-to-live value.                                                            |
| **12** | `sloss`                | Continuous |        🔴 Unsupported        | Set to `0` — retransmission/drop detection needs sequence-number gap tracking across the full stream, out of scope for this flow-level abstraction.                                                                                                                                                                                                                                                                              | **Content:** Source packets retransmitted or dropped.                                                 |
| **13** | `dloss`                | Continuous |        🔴 Unsupported        | Same limitation as `sloss`.                                                                                                                                                                                                                                                                                                                                                                                                      | **Content:** Destination packets retransmitted or dropped.                                            |
| **14** | `service`              |  Symbolic  |        🟡 Approximate        | Routed through `ServiceMapper.get()` via a static destination-port table (`ftp`, `ssh`, `http`, etc.) — a port-based heuristic, not real application-layer protocol detection.                                                                                                                                                                                                                                                   | **Basic:** Destination HTTP, FTP, SMTP service type.                                                  |
| **15** | `Sload`                | Continuous |           🟢 Exact           | Calculated expression: `(self.src_bytes * 8) / duration`, from exactly-measured bytes/duration.                                                                                                                                                                                                                                                                                                                                  | **Time:** Source bits per second (Instantiation load).                                                |
| **16** | `Dload`                | Continuous |           🟢 Exact           | Calculated expression: `(self.dst_bytes * 8) / duration`.                                                                                                                                                                                                                                                                                                                                                                        | **Time:** Destination bits per second.                                                                |
| **17** | `Spkts`                | Continuous |           🟢 Exact           | Incremented count tracking total source packets sent (`self.s_pkts`).                                                                                                                                                                                                                                                                                                                                                            | **Basic:** Source packet count.                                                                       |
| **18** | `Dpkts`                | Continuous |           🟢 Exact           | Incremented count tracking total destination packets sent (`self.d_pkts`).                                                                                                                                                                                                                                                                                                                                                       | **Basic:** Destination packet count.                                                                  |
| **19** | `swin`                 | Continuous |        🟡 Approximate        | Extracted from TCP header window size (`tcp.window`), but overwritten on _every_ TCP packet regardless of direction — known limitation, tracked for a future fix, not corrected in this pass.                                                                                                                                                                                                                                    | **Basic:** Source TCP window advertisement.                                                           |
| **20** | `dwin`                 | Continuous |        🟡 Approximate        | Same field/limitation as `swin` (`self.dwin` is assigned from the same `tcp.window` read, so `swin`/`dwin` currently end up numerically identical).                                                                                                                                                                                                                                                                              | **Basic:** Destination TCP window advertisement.                                                      |
| **21** | `stcpb`                | Continuous |        🟡 Approximate        | Extracted from TCP sequence numbers (`tcp.seq`), same direction-overwrite limitation as `swin`.                                                                                                                                                                                                                                                                                                                                  | **Basic:** Source TCP base sequence number.                                                           |
| **22** | `dtcpb`                | Continuous |        🟡 Approximate        | Extracted from TCP acknowledgment numbers (`tcp.ack`), same limitation.                                                                                                                                                                                                                                                                                                                                                          | **Basic:** Destination TCP base sequence number.                                                      |
| **23** | `smeansz`              | Continuous |           🟢 Exact           | Derived ratio: `self.src_bytes / max(self.s_pkts, 1)`, from exactly-measured counters.                                                                                                                                                                                                                                                                                                                                           | **Content:** Mean of the flow packet size sent by the source.                                         |
| **24** | `dmeansz`              | Continuous |           🟢 Exact           | Derived ratio: `self.dst_bytes / max(self.d_pkts, 1)`.                                                                                                                                                                                                                                                                                                                                                                           | **Content:** Mean of the flow packet size sent by the destination.                                    |
| **25** | `trans_depth`          | Continuous |        🟡 Approximate        | Binary heuristic: `1` if `service == 'http'`, else `0` — not a real HTTP transaction-depth count (needs DPI).                                                                                                                                                                                                                                                                                                                    | **Content:** Despatch depth levels of http flow requests.                                             |
| **26** | `res_bdy_len`          | Continuous |        🔴 Unsupported        | Set to `0` — HTTP response body length requires payload inspection.                                                                                                                                                                                                                                                                                                                                                              | **Content:** Result body payload block length from HTTP transactions.                                 |
| **27** | `Sjit`                 | Continuous |        🟡 Approximate        | Variance of packet arrival intervals (`pkt_intervals`), but the interval buffer mixes both traffic directions rather than isolating source-only timing.                                                                                                                                                                                                                                                                          | **Time:** Source packet jitter (ms).                                                                  |
| **28** | `Djit`                 | Continuous |        🟡 Approximate        | Not independently measured: literally `Sjit * 0.5`, a fixed scaled derivative rather than a real destination-side jitter measurement.                                                                                                                                                                                                                                                                                            | **Time:** Destination packet jitter (ms).                                                             |
| **29** | `Stime`                | Continuous |           🟢 Exact           | Flow initialization timestamp (`self.start_time`) (Dropped from training).                                                                                                                                                                                                                                                                                                                                                       | **Basic:** Record transaction start time.                                                             |
| **30** | `Ltime`                | Continuous |           🟢 Exact           | Flow last activity timestamp (`self.last_time`) (Dropped from training).                                                                                                                                                                                                                                                                                                                                                         | **Basic:** Record transaction last time.                                                              |
| **31** | `Sintpkt`              | Continuous |        🟡 Approximate        | Mean inter-packet arrival time from `pkt_intervals` — same mixed-direction limitation as `Sjit`.                                                                                                                                                                                                                                                                                                                                 | **Time:** Source inter-packet arrival time (ms).                                                      |
| **32** | `Dintpkt`              | Continuous |        🟡 Approximate        | Currently the _same_ value as `Sintpkt` (`avg_intpkt` reused, not a separately measured destination-side interval).                                                                                                                                                                                                                                                                                                              | **Time:** Destination inter-packet arrival time (ms).                                                 |
| **33** | `tcprtt`               | Continuous |        🟡 Approximate        | Summation of handshake metrics: `synack + ackdat`, from the first observed SYN/SYN-ACK/ACK only — no retransmission handling.                                                                                                                                                                                                                                                                                                    | **Time:** TCP connection setup round-trip time.                                                       |
| **34** | `synack`               | Continuous |        🟡 Approximate        | Time interval between SYN and SYN-ACK control packets (first occurrence only).                                                                                                                                                                                                                                                                                                                                                   | **Time:** SYN-ACK establishment delay.                                                                |
| **35** | `ackdat`               | Continuous |        🟡 Approximate        | Time interval between SYN-ACK and ACK control packets (first occurrence only).                                                                                                                                                                                                                                                                                                                                                   | **Time:** ACK response time following setup.                                                          |
| **36** | `is_sm_ips_ports`      |   Binary   |           🟢 Exact           | Equality evaluation: `1 if (self.src_ip == self.dst_ip) else 0`.                                                                                                                                                                                                                                                                                                                                                                 | **General-purpose:** Checks if source and destination IPs/ports match.                                |
| **37** | `ct_state_ttl`         | Continuous | 🟡 Approximate _(bug fixed)_ | Historical buffer lookup counting abnormal states per destination IP. **Bug fixed:** previously checked `state in ['S0','S1','REJ','RSTO']`, a vocabulary this codebase's `FlowRecord.state` never produces (only `REQ/ACC/CON/FIN/RST/INT/URP`), so this feature was _always 0_. Now checks `state == 'RST'`, the closest real analogue to a rejected/aborted connection — still an approximation of UNSW's original semantics. | **General-purpose:** Count connections having same state and specific TTL.                            |
| **38** | `ct_flw_http_mthd`     | Continuous |        🟡 Approximate        | Counts flows to the same destination with `service == 'http'` — a proxy for HTTP-method counting, not real GET/POST/… method parsing (needs DPI).                                                                                                                                                                                                                                                                                | **General-purpose:** Count flows with specific HTTP methods (e.g., GET/POST).                         |
| **39** | `is_ftp_login`         |   Binary   |        🔴 Unsupported        | Hardcoded to `0` — requires FTP control-channel payload inspection.                                                                                                                                                                                                                                                                                                                                                              | **General-purpose:** Evaluates if FTP session executed login credentials.                             |
| **40** | `ct_ftp_cmd`           | Continuous |        🔴 Unsupported        | Hardcoded to `0` — same DPI limitation as `is_ftp_login`.                                                                                                                                                                                                                                                                                                                                                                        | **General-purpose:** Count commands processed inside FTP sessions.                                    |
| **41** | `ct_srv_src`           | Continuous |           🟢 Exact           | Evaluated via `ConnectionHistory` buffer tracking matching source IP and service.                                                                                                                                                                                                                                                                                                                                                | **Connection cooperative:** No. of connections that contain the same service and source address.      |
| **42** | `ct_srv_dst`           | Continuous |           🟢 Exact           | Evaluated via `ConnectionHistory` buffer tracking matching destination IP and service.                                                                                                                                                                                                                                                                                                                                           | **Connection cooperative:** No. of connections that contain the same service and destination address. |
| **43** | `ct_dst_ltm`           | Continuous |           🟢 Exact           | Evaluated via `ConnectionHistory` buffer matching destination IP history.                                                                                                                                                                                                                                                                                                                                                        | **Connection cooperative:** No. of connections of the same destination address.                       |
| **44** | `ct_src_ltm`           | Continuous |           🟢 Exact           | Evaluated via `ConnectionHistory` buffer matching source IP history.                                                                                                                                                                                                                                                                                                                                                             | **Connection cooperative:** No. of connections of the same source address.                            |
| **45** | `ct_src_dport_ltm`     | Continuous |           🟢 Exact           | Evaluated via `ConnectionHistory` buffer matching source IP and destination port.                                                                                                                                                                                                                                                                                                                                                | **Connection cooperative:** No. of connections of the same source address and the destination port.   |
| **46** | `ct_dst_sport_ltm`     | Continuous |           🟢 Exact           | Evaluated via `ConnectionHistory` buffer matching destination IP and source port.                                                                                                                                                                                                                                                                                                                                                | **Connection cooperative:** No. of connections of the same destination address and the source port.   |
| **47** | `ct_dst_src_ltm`       | Continuous |           🟢 Exact           | Evaluated via `ConnectionHistory` buffer matching source-destination pairs.                                                                                                                                                                                                                                                                                                                                                      | **Connection cooperative:** No. of connections of the same source and the destination address.        |
| **48** | `attack_cat`           |  Symbolic  |             N/A              | Target attack class label from reference definitions (Dropped from input vectors; training-time only).                                                                                                                                                                                                                                                                                                                           | **Class:** Attack category classification name.                                                       |
| **49** | `Label`                |   Binary   |             N/A              | Training-time ground truth only. **Live evaluation no longer uses this field or any online IP-heuristic** — real labels come from the independent `ground_truth.py` scenario recorder and are joined offline in `evaluate_run.py`.                                                                                                                                                                                               | **Class:** 0 for normal traffic and 1 for malicious activity.                                         |

---

## 🛠️ Architectural Design Rationale (Defensive Thesis Note)

The features marked 🔴 **Unsupported** in the audit table above (`sloss`, `dloss`,
`res_bdy_len`, `is_ftp_login`, `ct_ftp_cmd`) are held at a constant `0` because this
architecture operates directly as an in-line **SDN Central Controller module (via
OpenFlow)**: it evaluates traffic telemetry dynamically without executing
intensive **Deep Packet Inspection (DPI)** workloads. This is a calculated
engineering trade-off to guarantee **line-rate processing speeds, mitigate
switch-controller latency, and prevent CPU starvation constraints** within
real-time SDN control loops — not an oversight. `sttl`/`dttl`, by contrast, are
_not_ in this group: they are read from the real IPv4 header (no DPI needed) and
are classified 🟢 **Exact**.

---

### Module Linkage

Deploy the central module file inside your active POX expansion workspace directory:

```bash
cp online_ids.py soft_tree.py feature_extractor.py /path/to/pox/pox/ext/
```

`ground_truth.py`, `run_benchmarks.py`, `run_4state_benchmark.py`, `snort_agent.py`,
`evaluate_run.py`, `aggregate_runs.py` and `evidence_report.py` stay together in the
repo root (`HYBRID_DIR` in `run_4state_benchmark.py`) — only the three files above
need to live inside `pox/ext/`.

---

## 💻 Execution & Orchestration

### Recommended: automated multi-run benchmark

`run_4state_benchmark.py` drives all 4 modes end-to-end (POX + Mininet + Snort +
scenario traffic), and now supports repeated **independent** runs — required by the
professor's feedback for a valid Mean ± 95% CI (see below), instead of a single run
or blindly-appended CSVs:

```bash
sudo python3 run_4state_benchmark.py --repeats 5
# or just a subset of modes while iterating:
sudo python3 run_4state_benchmark.py --repeats 3 --modes ml_only hybrid_online
```

Each `(mode, repetition)` gets its own `run_id`, passed via `IDS_RUN_ID` to **both**
the POX controller and the traffic generator so their logs always agree on which
run they belong to. The script prints every `run_id` it produced at the end — keep
that list for the evaluation step.

### Manual step-by-step (for debugging one mode at a time)

```bash
# Terminal 1 - controller (IDS_MODE selects snort_only/ml_only/hybrid_static/hybrid_online)
sudo -E env PATH="$PATH" IDS_MODE=hybrid_online ./pox/pox.py openflow.of_01 online_ids

# Terminal 2 - Mininet topology (3 hosts, 1 OVS, remote controller)
sudo mn -c
sudo mn --topo single,3 --mac --switch ovsk --controller remote

# mininet> xterm h3
sudo python3 snort_agent.py

# mininet> xterm h1
sudo python3 run_benchmarks.py
```

`run_benchmarks.py` runs 5 independent, ground-truth-labeled phases in sequence:
Baseline Normal Traffic, TCP SYN Flood (`hping3`), Port Scanning (`nmap`), ICMP
Flood (`hping3 --icmp`), and SSH Brute Force simulation (`nc`). In manual mode
(without `run_4state_benchmark.py` setting `IDS_RUN_ID`), it mints its own `run_id`
and publishes it to `logs/current_run_id.txt` for the controller to pick up — print
the `run_id` it logs at the end, you'll need it for evaluation.

---

## 📊 Evaluation (offline, from independent Ground Truth)

Precision/Recall/F1/FPR/MCC are **never** computed online by the controller anymore
(see `online_ids.py`'s `OperationalStats` vs. the old `MetricsTracker`) — they are
computed offline by joining each run's raw flow log against its independent
`ground_truth_<run_id>.csv`. Run this after each benchmark:

```bash
# 1) Evaluate every (mode, run_id) you produced above against its Ground Truth
python3 evaluate_run.py --mode hybrid_online --run-id <run_id>
#    ... repeat for every mode/run_id (or wrap in a small loop over the run_id list
#    run_4state_benchmark.py printed)

# 2) Aggregate all independent runs into Mean ± 95% CI, per mode and per attack_type
python3 aggregate_runs.py
#  -> logs/final_comparison_table.csv

# 3) Plot the 4-method comparison (F1, FPR, Detection Delay, Mitigation Delay)
python3 logs/plot-s.py
#  -> logs/4state_benchmark_comparison.png

# 4) End-to-end evidence chain per attack type (detection -> policy install ->
#    block confirmed -> recovery, plus a concurrent benign flow that kept flowing)
python3 evidence_report.py --mode hybrid_online --run-id <run_id>
#  -> logs/evidence_hybrid_online_<run_id>.md
```

### What changed vs. the old pipeline

- No synthetic FN-injection or F1 clamping (removed with the legacy
  `online_ids_hybrid.py`/`online_ids_snort.py` files).
- No `y_real = 1 if "10.0.0.1" in flow_id else 0` — that heuristic made every
  benign baseline packet count as an attack, which is why every old
  `metrics_*.csv` in `logs/archive_pre_fix/` has `TN = FP = 0`.
- FPR, Precision, Recall, F1 and MCC now come from a real Confusion Matrix and
  are expected to move around between runs/modes — that is the point of
  reporting Mean ± 95% CI instead of a single point estimate.
