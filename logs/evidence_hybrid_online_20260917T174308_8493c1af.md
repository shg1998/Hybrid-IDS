# Evidence Report — mode=hybrid_online run_id=20260917T174308_8493c1af

## Attack: icmp_flood
- Malicious flows: 2 | Blocked (TP): 0 | Missed (FN): 2

⚠️ هیچ فلوی مخربی در این run با موفقیت block نشد (احتمالاً همه FN بودند).

### Concurrent benign flow that kept flowing normally: `10.0.0.2|10.0.0.1|80|38938|tcp`
- final_decision = `allow`, ground truth = normal (label=0)

## Attack: port_scan
- Malicious flows: 34609 | Blocked (TP): 0 | Missed (FN): 34609

⚠️ هیچ فلوی مخربی در این run با موفقیت block نشد (احتمالاً همه FN بودند).

### Concurrent benign flow that kept flowing normally: `10.0.0.2|10.0.0.1|80|38938|tcp`
- final_decision = `allow`, ground truth = normal (label=0)

## Attack: ssh_bruteforce
- Malicious flows: 31 | Blocked (TP): 0 | Missed (FN): 31

⚠️ هیچ فلوی مخربی در این run با موفقیت block نشد (احتمالاً همه FN بودند).

### Concurrent benign flow that kept flowing normally: `10.0.0.2|10.0.0.1|80|38938|tcp`
- final_decision = `allow`, ground truth = normal (label=0)

## Attack: syn_flood
- Malicious flows: 58733 | Blocked (TP): 0 | Missed (FN): 58733

⚠️ هیچ فلوی مخربی در این run با موفقیت block نشد (احتمالاً همه FN بودند).

### Concurrent benign flow that kept flowing normally: `10.0.0.2|10.0.0.1|80|38938|tcp`
- final_decision = `allow`, ground truth = normal (label=0)

