# Evidence Report — mode=hybrid_online run_id=20260919T110430_1f20826a

## Attack: icmp_flood
- Malicious flows: 2 | Blocked (TP): 0 | Missed (FN): 2

⚠️ هیچ فلوی مخربی در این run با موفقیت block نشد (احتمالاً همه FN بودند).

### Concurrent benign flow that kept flowing normally: `10.0.0.2|10.0.0.1|80|39576|tcp`
- final_decision = `allow`, ground truth = normal (label=0)

## Attack: port_scan
- Malicious flows: 10720 | Blocked (TP): 38 | Missed (FN): 10682

### Sample malicious flow: `10.0.0.2|10.0.0.1|80|28359|tcp`
| event | time | detail |
|---|---|---|
| ml_detection | 1789803396.519 | p_hat=1.0000 tau=0.7459 |
| policy_install_sent | 1789803396.519 | tcp |
| block_confirmed | 1789803408.683 |  |
| recovery | 1789803426.259 | fp_correction |

### Concurrent benign flow that kept flowing normally: `10.0.0.2|10.0.0.1|80|39576|tcp`
- final_decision = `allow`, ground truth = normal (label=0)

## Attack: ssh_bruteforce
- Malicious flows: 40 | Blocked (TP): 0 | Missed (FN): 40

⚠️ هیچ فلوی مخربی در این run با موفقیت block نشد (احتمالاً همه FN بودند).

### Concurrent benign flow that kept flowing normally: `10.0.0.2|10.0.0.1|80|39576|tcp`
- final_decision = `allow`, ground truth = normal (label=0)

## Attack: syn_flood
- Malicious flows: 77218 | Blocked (TP): 4899 | Missed (FN): 72319

### Sample malicious flow: `10.0.0.2|10.0.0.1|80|1904|tcp`
| event | time | detail |
|---|---|---|
| ml_detection | 1789803319.386 | p_hat=0.9955 tau=0.2019 |
| policy_install_sent | 1789803319.386 | tcp |
| block_confirmed | 1789803319.388 |  |
| recovery | 1789803331.532 | fp_correction |

### Concurrent benign flow that kept flowing normally: `10.0.0.2|10.0.0.1|80|39576|tcp`
- final_decision = `allow`, ground truth = normal (label=0)

