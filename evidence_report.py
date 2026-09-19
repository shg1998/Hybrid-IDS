#!/usr/bin/env python3
"""
evidence_report.py - گزارش شواهد end-to-end برای هر attack_type
فیدبک استاد بخش ۴-۳: "یک evidence end-to-end انجام شود برای: detection،
policy installation، توقف flow مخرب، ادامه flow سالم، recovery."

ورودی این اسکریپت خروجی evaluate_run.py است (eval_flows_<mode>_<run_id>.csv +
enforcement_log_<mode>_<run_id>.csv) - یعنی هیچ شاهدی این‌جا از نو ساخته
نمی‌شود، فقط زنجیره‌ی رویدادهای واقعی‌ای که کنترلر قبلاً ثبت کرده به‌صورت
خوانا کنار هم چیده می‌شود.
"""
import argparse
import csv
import os
from collections import defaultdict


def read_csv(path):
    if not os.path.isfile(path):
        return []
    with open(path, newline='') as f:
        return list(csv.DictReader(f))


def load_enforcement(log_dir, mode, run_id):
    rows = read_csv(os.path.join(log_dir, f"enforcement_log_{mode}_{run_id}.csv"))
    by_flow = defaultdict(list)
    for r in rows:
        by_flow[r['flow_id']].append((r['event'], float(r['event_time']), r.get('detail', '')))
    for fid in by_flow:
        by_flow[fid].sort(key=lambda x: x[1])
    return by_flow


def build_report(mode, run_id, log_dir):
    flows_path = os.path.join(log_dir, f"eval_flows_{mode}_{run_id}.csv")
    flows = read_csv(flows_path)
    if not flows:
        raise SystemExit(f"❌ {flows_path} پیدا نشد - ابتدا evaluate_run.py را برای این run اجرا کنید.")
    enforcement = load_enforcement(log_dir, mode, run_id)

    by_attack = defaultdict(list)
    for f in flows:
        by_attack[f['attack_type']].append(f)

    normal_allowed = [f for f in by_attack.get('normal', []) if f['final_decision'] == 'allow']

    lines = [f"# Evidence Report — mode={mode} run_id={run_id}", ""]

    for attack_type, flist in sorted(by_attack.items()):
        if attack_type == 'normal':
            continue
        blocked_correct = [f for f in flist if f['gt_label'] == '1' and f['y_pred'] == '1']
        missed = [f for f in flist if f['gt_label'] == '1' and f['y_pred'] == '0']

        lines.append(f"## Attack: {attack_type}")
        lines.append(f"- Malicious flows: {len(flist)} | Blocked (TP): {len(blocked_correct)} | Missed (FN): {len(missed)}")
        lines.append("")

        if blocked_correct:
            sample = blocked_correct[0]
            fid = sample['flow_id']
            lines.append(f"### Sample malicious flow: `{fid}`")
            events = enforcement.get(fid, [])
            if events:
                lines.append("| event | time | detail |")
                lines.append("|---|---|---|")
                for ev, t, detail in events:
                    lines.append(f"| {ev} | {t:.3f} | {detail} |")
            else:
                lines.append("_(no enforcement events recorded for this flow - check enforcement_log_*.csv)_")
        else:
            lines.append("⚠️ هیچ فلوی مخربی در این run با موفقیت block نشد (احتمالاً همه FN بودند).")
        lines.append("")

        if normal_allowed:
            b = normal_allowed[0]
            lines.append(f"### Concurrent benign flow that kept flowing normally: `{b['flow_id']}`")
            lines.append(f"- final_decision = `{b['final_decision']}`, ground truth = normal (label=0)")
        else:
            lines.append("⚠️ هیچ فلوی نرمالی که allow مانده باشد پیدا نشد.")
        lines.append("")

    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Build end-to-end evidence chains per attack_type.")
    ap.add_argument("--mode", required=True, choices=["snort_only", "ml_only", "hybrid_static", "hybrid_online"])
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--log-dir", default=os.environ.get("IDS_LOG_DIR", "logs"))
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    report = build_report(args.mode, args.run_id, args.log_dir)
    out_path = args.out or os.path.join(args.log_dir, f"evidence_{args.mode}_{args.run_id}.md")
    with open(out_path, 'w') as f:
        f.write(report + "\n")
    print(f"📄 Evidence report saved: {out_path}\n")
    print(report)


if __name__ == "__main__":
    main()
