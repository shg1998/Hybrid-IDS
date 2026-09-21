# Evidence Report — mode=hybrid_online run_id=20260919T094729_64a5d9d5

## Attack: icmp_flood
- Malicious flows: 2 | Blocked (TP): 0 | Missed (FN): 2

⚠️ هیچ فلوی مخربی در این run با موفقیت block نشد (احتمالاً همه FN بودند).

### Concurrent benign flow that kept flowing normally: `10.0.0.2|10.0.0.1|80|40552|tcp`
- final_decision = `allow`, ground truth = normal (label=0)

## Attack: ssh_bruteforce
- Malicious flows: 40 | Blocked (TP): 0 | Missed (FN): 40

⚠️ هیچ فلوی مخربی در این run با موفقیت block نشد (احتمالاً همه FN بودند).

### Concurrent benign flow that kept flowing normally: `10.0.0.2|10.0.0.1|80|40552|tcp`
- final_decision = `allow`, ground truth = normal (label=0)

## Attack: syn_flood
- Malicious flows: 67955 | Blocked (TP): 4442 | Missed (FN): 63513

### Sample malicious flow: `10.0.0.2|10.0.0.1|80|2987|tcp`
| event | time | detail |
|---|---|---|
| ml_detection | 1789798697.887 | p_hat=0.9965 tau=0.2019 |
| policy_install_sent | 1789798697.887 | tcp |
| block_confirmed | 1789798697.891 |  |
| recovery | 1789798709.974 | fp_correction |

### Concurrent benign flow that kept flowing normally: `10.0.0.2|10.0.0.1|80|40552|tcp`
- final_decision = `allow`, ground truth = normal (label=0)

