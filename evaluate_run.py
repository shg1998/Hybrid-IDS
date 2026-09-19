#!/usr/bin/env python3
"""
evaluate_run.py - ارزیابی آفلاین واقعی یک اجرا (فیدبک استاد بخش ۲ و ۳)

هیچ ضریب تنظیم مصنوعی این‌جا وجود ندارد:
  - gt_label از logs/ground_truth_<run_id>.csv می‌آید که کاملاً مستقل از
    IP-heuristic/ML/Snort توسط ground_truth.py هنگام اجرای سناریو نوشته شده
    (نگاه کنید به run_benchmarks.py).
  - y_pred از رفتار واقعیِ ثبت‌شده‌ی سیستم (آخرین final_decision هر فلو در
    logs/flow_log_<mode>_<run_id>.csv) می‌آید.
Confusion Matrix / Precision / Recall / F1 / FPR / MCC مستقیماً از join این دو
منبع محاسبه می‌شود - بدون هیچ clamp یا نوسان مصنوعی.

خروجی:
  logs/eval_<mode>_<run_id>.csv        خلاصه (overall + به‌ازای هر attack_type)
  logs/eval_flows_<mode>_<run_id>.csv  رکورد join‌شده‌ی هر فلو (برای evidence_report.py)
"""
import argparse
import csv
import math
import os
from collections import defaultdict

LOG_DIR_DEFAULT = os.environ.get("IDS_LOG_DIR", "logs")


def read_csv(path):
    if not os.path.isfile(path):
        return []
    with open(path, newline='') as f:
        return list(csv.DictReader(f))


def load_ground_truth(log_dir, run_id):
    rows = read_csv(os.path.join(log_dir, f"ground_truth_{run_id}.csv"))
    phases = []
    for r in rows:
        phases.append({
            'phase_id': r['phase_id'],
            'attack_type': r['attack_type'],
            'label': int(r['label']),
            'start_time': float(r['start_time']),
            'end_time': float(r['end_time']),
            'src_ip': r['src_ip'],
            'dst_ip': r['dst_ip'],
        })
    return phases


def match_phase(phases, flow_src, flow_dst, ref_time):
    """فازی که ref_time (زمان شروع فلو) داخلش قرار می‌گیرد و IP pair با آن
    همخوانی دارد را برمی‌گرداند (هر دو جهت پذیرفته می‌شود، چون جهت flow_id
    به این بستگی دارد که کدام پکت اول به کنترلر رسیده باشد)."""
    for p in phases:
        if p['start_time'] <= ref_time <= p['end_time'] and {p['src_ip'], p['dst_ip']} == {flow_src, flow_dst}:
            return p
    return None


# فاصله‌ی زمانی که اگر بین دو ردیفِ متوالیِ یک flow_id بیشتر باشه، دیگه یک
# "فلو" واحد در نظر گرفته نمی‌شن، بلکه دو نمونه‌ی جدا حساب می‌شن.
# چرا لازمه: flow_id مربوط به ICMP همیشه پورت‌های ثابت 0|0 داره
# (feature_extractor._get_flow_id) - یعنی *تمام* ترافیک ICMP بین یک جفت IP
# در کل طول اجرا (نه فقط یک پنجره) همین یک کلید رو دارن. بدون این جداسازی،
# اولین پینگ فاز Baseline و بعداً کل فاز icmp_flood همه زیر یک "فلو" ادغام
# می‌شدن و چون flow_start از قدیمی‌ترین ردیف گرفته می‌شه، همیشه به فاز
# 'normal' می‌چسبید - یعنی هیچ داده‌ای برای attack_type='icmp_flood' ثبت
# نمی‌شد (دقیقاً همون چیزی که در اجرای واقعی مشاهده شد).
FLOW_INSTANCE_GAP_SECONDS = 15.0


def load_flows(log_dir, mode, run_id):
    rows = read_csv(os.path.join(log_dir, f"flow_log_{mode}_{run_id}.csv"))
    rows_by_fid = defaultdict(list)
    for r in rows:
        rows_by_fid[r['flow_id']].append(r)

    flows = {}
    for fid, frows in rows_by_fid.items():
        frows.sort(key=lambda r: float(r['event_time']))
        entry = None
        prev_event_time = None
        instance_idx = 0

        for r in frows:
            event_time = float(r['event_time'])
            flow_start = float(r['flow_start']) if r.get('flow_start') not in ('', None) else event_time

            if entry is None or (event_time - prev_event_time) > FLOW_INSTANCE_GAP_SECONDS:
                instance_idx += 1
                entry = {
                    'flow_id': fid, 'proto': r['proto'], 'service': r['service'],
                    'flow_start': flow_start, 'last_event_time': event_time,
                    'final_decision': r['final_decision'],
                    'ever_blocked': False,
                    'ml_score': float(r['ml_score']) if r.get('ml_score') else 0.0,
                    'ml_prediction': int(r['ml_prediction']) if r.get('ml_prediction') not in ('', None) else 0,
                    'ever_snort_alert': False,
                }
                flows[f"{fid}#{instance_idx}"] = entry

            entry['flow_start'] = min(entry['flow_start'], flow_start)
            # اصلاح مهم: "action" را از آخرین ردیف نمی‌گیریم. اگر ML یک فلو را
            # block کند ولی Snort در بازه‌ی BUFFER_TIMEOUT تأییدش نکند - که اغلب
            # پیش می‌آید چون فلوی block‌شده دیگر به Snort mirror نمی‌شود، پس
            # هیچ‌وقت نمی‌تواند تأیید برسد - کنترلر آن را unblock می‌کند و آخرین
            # ردیف final_decision='allow' می‌شود. اگر فقط آخرین حالت را ملاک
            # TP/FP بگیریم، هر تشخیص درستِ ML که بعداً recovery خورده به‌اشتباه
            # FN حساب می‌شود. بنابراین معیار تشخیص "آیا این فلو حداقل یک‌بار
            # block شد؟" است - recovery/unblock بعدی یک مرحله‌ی جدا (بخش ۴-۳ فیدبک
            # استاد) است، نه انکار اینکه detection/block اتفاق افتاده.
            if r['final_decision'] == 'block':
                entry['ever_blocked'] = True
            if event_time >= entry['last_event_time']:
                entry['last_event_time'] = event_time
                entry['final_decision'] = r['final_decision']
                if r.get('ml_score'):
                    entry['ml_score'] = float(r['ml_score'])
                if r.get('ml_prediction') not in ('', None):
                    entry['ml_prediction'] = int(r['ml_prediction'])
            if str(r.get('snort_alert', '')).strip().lower() in ('true', '1'):
                entry['ever_snort_alert'] = True

            prev_event_time = event_time

    return list(flows.values())


def load_enforcement(log_dir, mode, run_id):
    rows = read_csv(os.path.join(log_dir, f"enforcement_log_{mode}_{run_id}.csv"))
    by_flow = defaultdict(list)
    for r in rows:
        by_flow[r['flow_id']].append((r['event'], float(r['event_time']), r.get('detail', '')))
    for fid in by_flow:
        by_flow[fid].sort(key=lambda x: x[1])
    return by_flow


def compute_delays(flow_id, flow_start, last_event_time, enforcement_by_flow):
    """اصلاح مهم: enforcement_log هم مثل flow_log با flow_id ثابت (مثلاً ICMP
    با پورت‌های همیشه 0|0) ممکن است رویدادهای مربوط به instanceهای کاملاً
    متفاوت (مثلاً یک پینگ فاز baseline و بعداً کل فاز icmp_flood) را زیر یک
    کلید جمع کند. بدون محدود کردن جستجو به بازه‌ی زمانی خودِ این instance،
    ممکن است delay بین یک flow_start قدیمی و رویداد enforcement یک instance
    کاملاً بعدی محاسبه شود - که هم بی‌معنی است هم می‌تواند منفی دربیاید
    (دقیقاً همان چیزی که در Avg_Detection_Delay منفی روی داده‌ی واقعی دیده شد)."""
    events = enforcement_by_flow.get(flow_id, [])
    window_start = flow_start - 1.0
    window_end = last_event_time + FLOW_INSTANCE_GAP_SECONDS
    relevant = [(ev, t, d) for ev, t, d in events if window_start <= t <= window_end]
    detect_time = next((t for ev, t, _ in relevant if ev in ('ml_detection', 'snort_detection')), None)
    mitigate_time = next((t for ev, t, _ in relevant if ev in ('block_confirmed', 'policy_install_sent')), None)
    detection_delay = (detect_time - flow_start) if detect_time is not None else None
    mitigation_delay = (mitigate_time - detect_time) if (detect_time is not None and mitigate_time is not None) else None
    return detection_delay, mitigation_delay


def confusion_matrix_metrics(tp, fp, fn, tn):
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = ((tp * tn) - (fp * fn)) / denom if denom else 0.0
    return precision, recall, f1, fpr, mcc


def evaluate(mode, run_id, log_dir):
    phases = load_ground_truth(log_dir, run_id)
    if not phases:
        raise SystemExit(f"❌ No ground_truth_{run_id}.csv found in {log_dir} - "
                          f"cannot evaluate without independent ground truth.")
    flows = load_flows(log_dir, mode, run_id)
    enforcement = load_enforcement(log_dir, mode, run_id)

    per_attack = defaultdict(lambda: {'tp': 0, 'fp': 0, 'fn': 0, 'tn': 0,
                                       'detection_delays': [], 'mitigation_delays': [], 'unmatched': 0})
    overall = {'tp': 0, 'fp': 0, 'fn': 0, 'tn': 0, 'detection_delays': [], 'mitigation_delays': [], 'unmatched': 0}
    joined_rows = []

    for flow in flows:
        parts = flow['flow_id'].split('|')
        if len(parts) != 5:
            continue
        f_src, f_dst = parts[0], parts[1]
        phase = match_phase(phases, f_src, f_dst, flow['flow_start'])
        if phase is None:
            overall['unmatched'] += 1
            continue

        gt_label = phase['label']
        attack_type = phase['attack_type']
        # "آیا این فلو حداقل یک‌بار block شد؟" - نه فقط آخرین وضعیتش (نگاه کنید
        # به توضیح ever_blocked در load_flows برای چرایی این تصمیم).
        y_pred = 1 if flow['ever_blocked'] else 0

        bucket = per_attack[attack_type]
        for target in (overall, bucket):
            if gt_label == 1 and y_pred == 1: target['tp'] += 1
            elif gt_label == 0 and y_pred == 0: target['tn'] += 1
            elif gt_label == 0 and y_pred == 1: target['fp'] += 1
            elif gt_label == 1 and y_pred == 0: target['fn'] += 1

        det_delay, mit_delay = compute_delays(flow['flow_id'], flow['flow_start'], flow['last_event_time'], enforcement)
        if det_delay is not None:
            overall['detection_delays'].append(det_delay)
            bucket['detection_delays'].append(det_delay)
        if mit_delay is not None:
            overall['mitigation_delays'].append(mit_delay)
            bucket['mitigation_delays'].append(mit_delay)

        joined_rows.append({
            'flow_id': flow['flow_id'], 'attack_type': attack_type, 'gt_label': gt_label,
            'y_pred': y_pred, 'ml_score': flow['ml_score'], 'ml_prediction': flow['ml_prediction'],
            'snort_alert': flow['ever_snort_alert'], 'ever_blocked': flow['ever_blocked'],
            'final_decision': flow['final_decision'],
            'detection_delay': det_delay, 'mitigation_delay': mit_delay,
        })

    return overall, per_attack, joined_rows


def _summ(d):
    p, r, f1, fpr, mcc = confusion_matrix_metrics(d['tp'], d['fp'], d['fn'], d['tn'])
    avg_det = sum(d['detection_delays']) / len(d['detection_delays']) if d['detection_delays'] else 0.0
    avg_mit = sum(d['mitigation_delays']) / len(d['mitigation_delays']) if d['mitigation_delays'] else 0.0
    return {
        'TP': d['tp'], 'FP': d['fp'], 'FN': d['fn'], 'TN': d['tn'],
        'Precision': round(p, 4), 'Recall': round(r, 4), 'F1': round(f1, 4),
        'FPR': round(fpr, 4), 'MCC': round(mcc, 4),
        'Avg_Detection_Delay': round(avg_det, 4), 'Avg_Mitigation_Delay': round(avg_mit, 4),
        'Unmatched': d['unmatched'],
    }


def main():
    ap = argparse.ArgumentParser(description="Offline evaluation of one benchmark run against independent ground truth.")
    ap.add_argument("--mode", required=True, choices=["snort_only", "ml_only", "hybrid_static", "hybrid_online"])
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--log-dir", default=LOG_DIR_DEFAULT)
    args = ap.parse_args()

    overall, per_attack, joined_rows = evaluate(args.mode, args.run_id, args.log_dir)
    overall_summary = _summ(overall)

    print(f"\n=== {args.mode} / run_id={args.run_id} — OVERALL ===")
    for k, v in overall_summary.items():
        print(f"  {k}: {v}")

    out_path = os.path.join(args.log_dir, f"eval_{args.mode}_{args.run_id}.csv")
    with open(out_path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['scope', 'TP', 'FP', 'FN', 'TN', 'Precision', 'Recall', 'F1', 'FPR', 'MCC',
                    'Avg_Detection_Delay', 'Avg_Mitigation_Delay', 'Unmatched'])
        s = overall_summary
        w.writerow(['overall', s['TP'], s['FP'], s['FN'], s['TN'], s['Precision'], s['Recall'], s['F1'],
                    s['FPR'], s['MCC'], s['Avg_Detection_Delay'], s['Avg_Mitigation_Delay'], s['Unmatched']])
        for attack_type, d in sorted(per_attack.items()):
            s = _summ(d)
            w.writerow([attack_type, s['TP'], s['FP'], s['FN'], s['TN'], s['Precision'], s['Recall'], s['F1'],
                        s['FPR'], s['MCC'], s['Avg_Detection_Delay'], s['Avg_Mitigation_Delay'], s['Unmatched']])
    print(f"\n📄 Saved: {out_path}")

    joined_path = os.path.join(args.log_dir, f"eval_flows_{args.mode}_{args.run_id}.csv")
    with open(joined_path, 'w', newline='') as f:
        if joined_rows:
            w = csv.DictWriter(f, fieldnames=list(joined_rows[0].keys()))
            w.writeheader()
            w.writerows(joined_rows)
    print(f"📄 Saved per-flow join: {joined_path}")


if __name__ == "__main__":
    main()
