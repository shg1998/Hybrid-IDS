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
| `online_ids.py` | Core SDN controller script (Houses packet handlers, sliding flow windows, and policy enforcement). |
| `soft_tree.py` | Custom `SoftLabelHoeffdingTree` wrapper supporting probabilistic training weights. |
| `feature_extractor.py` | State tracker transforming live OpenFlow streams into windowed (2s) and host-based (100 conns) historical features. |
| `snort_agent.py` | Real-time agent translating raw signature hits into standardized JSON telemetry. |
| `run_benchmarks.py` | Automated testing engine driving deterministic multi-vector simulation phases. |
| `plot_metrics.py` | Statistical visualization script rendering runtime evaluation figures. |
| `All_Traffic_NSL-KDD.csv` | Full balanced network reference dataset (~490,000 samples) used for maturity baseline setup. |
| `model_rf.py` | Cold-start bootstrapping routine initializing the streaming classifier pipeline. |
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
