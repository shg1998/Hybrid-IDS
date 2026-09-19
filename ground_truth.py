#!/usr/bin/env python3
"""
ground_truth.py - Independent Ground Truth recorder for benchmark scenarios.

This module produces the authoritative label for every traffic window in a
benchmark run, and it is intentionally decoupled from the SDN controller,
the ML model and Snort: it never looks at which host an IP belongs to, and
it never asks the controller/Snort/ML what they think happened. A phase's
label comes only from which traffic-generation command the scenario driver
(run_benchmarks.py) is actually running during that time window.

Downstream evaluation (evaluate_run.py) assigns a ground-truth label to a
captured flow purely by checking whether the flow's time window falls
inside one of the phase windows recorded here (plus a src/dst IP match) -
never by re-deriving the label from a fixed IP heuristic.
"""
import csv
import os
import time
import uuid

LOG_DIR = os.environ.get("IDS_LOG_DIR", "/home/moho/Documents/projects/IDS/logs")

GT_HEADERS = ['run_id', 'phase_id', 'attack_type', 'label', 'start_time', 'end_time', 'src_ip', 'dst_ip']


def new_run_id():
    """Generate a fresh, sortable, human-readable run identifier."""
    return f"{time.strftime('%Y%m%dT%H%M%S')}_{uuid.uuid4().hex[:8]}"


def resolve_run_id():
    """Resolve the run_id for this process: env var set by the orchestrator
    takes priority (guarantees the controller and the traffic generator
    agree); otherwise mint a fresh one for standalone/manual runs."""
    return os.environ.get("IDS_RUN_ID") or new_run_id()


class GroundTruthRecorder:
    """Independent scenario-level ground truth writer.

    label: 0 = normal/benign traffic, 1 = attack traffic.
    attack_type: e.g. 'normal', 'syn_flood', 'port_scan', 'icmp_flood',
                 'ssh_bruteforce'.
    """

    def __init__(self, run_id=None, log_dir=LOG_DIR):
        self.run_id = run_id or resolve_run_id()
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        self.path = os.path.join(log_dir, f"ground_truth_{self.run_id}.csv")
        self._phase_id = 0
        self._open_phase = None
        if not os.path.isfile(self.path):
            with open(self.path, 'w', newline='') as f:
                csv.writer(f).writerow(GT_HEADERS)
        # Publish run_id so a controller process without the env var
        # (e.g. started manually) can still pick it up. Uses this instance's
        # own log_dir (not the module-level default) so a caller that passes
        # a custom log_dir - e.g. tests - never touches the real deployment path.
        try:
            with open(os.path.join(log_dir, "current_run_id.txt"), 'w') as f:
                f.write(self.run_id)
        except OSError:
            pass

    def start_phase(self, attack_type, label, src_ip, dst_ip):
        """Open a new labeled time window. Closes any still-open phase first."""
        if self._open_phase is not None:
            self.end_phase()
        self._phase_id += 1
        self._open_phase = {
            'phase_id': self._phase_id,
            'attack_type': attack_type,
            'label': label,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'start_time': time.time(),
        }
        print(f"[GroundTruth] phase {self._phase_id} start: {attack_type} (label={label})")
        return self._open_phase['phase_id']

    def end_phase(self):
        """Close the currently open phase and append its record to the CSV."""
        if self._open_phase is None:
            return
        phase = self._open_phase
        phase['end_time'] = time.time()
        with open(self.path, 'a', newline='') as f:
            csv.writer(f).writerow([
                self.run_id, phase['phase_id'], phase['attack_type'], phase['label'],
                phase['start_time'], phase['end_time'], phase['src_ip'], phase['dst_ip']
            ])
        print(f"[GroundTruth] phase {phase['phase_id']} end: {phase['attack_type']} "
              f"(duration={phase['end_time'] - phase['start_time']:.1f}s)")
        self._open_phase = None

    def close(self):
        self.end_phase()