# Category 2 live evaluation

- seed: `42`
- repetitions per scenario: `20`
- decision threshold: `medium`
- valid runs: `220/220`
- detector input: Hubble JSONL only; scenario IDs and labels are applied after detection

## Aggregate results

| Scope | TP | TN | FP | FN | Precision | Recall | Specificity | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| All attacks, including the intentional L7 blind spot | 100 | 80 | 20 | 20 | 0.8333 | 0.8333 | 0.8 | 0.8333 |
| Network-visible attacks only | 100 | 80 | 20 | 0 | 0.8333 | 1.0 | 0.8 | 0.9091 |
| Tiered: L3/L4 alert or L7 route-review case | 120 | 80 | 20 | 0 | 0.8571 | 1.0 | 0.8 | 0.9231 |

- Expected-rule coverage: `1.0` (140/140).
- Mean/max detection latency: `0.879` / `2.199` seconds.
- Telemetry-loss runs: `0`, parse-error runs: `0`.

The JSON summary includes 95% Wilson intervals for precision, recall, specificity, and accuracy. These intervals quantify repeat variability within this scenario set; they do not establish production prevalence or external validity.

## Per-run evidence

| Run | Truth | Visible at L3/L4 | Prediction | Rules | L7 review | Flows | Loss | Latency(s) | Valid |
| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| 001-abnormal_2-r18 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation | 0 | 405 | 0 | 1.103 | True |
| 002-benign_maintenance_probe-r4 | benign | True | attack | path-violation | 0 | 103 | 0 | 0.372 | True |
| 003-attack_allowed_path-r16 | attack | False | benign | - | 1 | 66 | 0 | N/A | True |
| 004-benign_rollout-r1 | benign | True | benign | - | 0 | 140 | 0 | N/A | True |
| 005-normal_burst-r5 | benign | True | benign | - | 0 | 822 | 0 | N/A | True |
| 006-abnormal_1-r17 | attack | True | attack | path-violation | 0 | 130 | 0 | 0.364 | True |
| 007-benign_rollout-r10 | benign | True | benign | - | 0 | 169 | 0 | N/A | True |
| 008-benign_maintenance_probe-r13 | benign | True | attack | path-violation | 0 | 141 | 0 | 0.372 | True |
| 009-benign_external_api-r5 | benign | True | benign | - | 0 | 1210 | 0 | N/A | True |
| 010-abnormal_3-r14 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation, port-sweep, sensitive-service-probe | 0 | 937 | 0 | 2.19 | True |
| 011-benign_rollout-r8 | benign | True | benign | - | 0 | 143 | 0 | N/A | True |
| 012-abnormal_2-r15 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation | 0 | 497 | 0 | 1.138 | True |
| 013-attack_allowed_path-r10 | attack | False | benign | - | 1 | 83 | 0 | N/A | True |
| 014-normal_burst-r11 | benign | True | benign | - | 0 | 849 | 0 | N/A | True |
| 015-abnormal_2-r10 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation | 0 | 413 | 0 | 1.115 | True |
| 016-normal_burst-r13 | benign | True | benign | - | 0 | 795 | 0 | N/A | True |
| 017-abnormal_3-r17 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation, port-sweep, sensitive-service-probe | 0 | 950 | 0 | 2.199 | True |
| 018-abnormal_2-r6 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation | 0 | 412 | 0 | 1.108 | True |
| 019-benign_rollout-r2 | benign | True | benign | - | 0 | 123 | 0 | N/A | True |
| 020-normal-r5 | benign | True | benign | - | 0 | 244 | 0 | N/A | True |
| 021-abnormal_2-r2 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation | 0 | 491 | 0 | 1.141 | True |
| 022-normal-r18 | benign | True | benign | - | 0 | 258 | 0 | N/A | True |
| 023-attack_allowed_path-r20 | attack | False | benign | - | 1 | 68 | 0 | N/A | True |
| 024-abnormal_4-r3 | attack | True | attack | cloud-metadata-access, correlated-lateral-movement, path-violation, port-sweep, sensitive-service-probe | 0 | 296 | 0 | 0.357 | True |
| 025-benign_maintenance_probe-r20 | benign | True | attack | path-violation | 0 | 96 | 0 | 0.354 | True |
| 026-attack_allowed_path-r2 | attack | False | benign | - | 1 | 95 | 0 | N/A | True |
| 027-abnormal_2-r11 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation | 0 | 402 | 0 | 1.114 | True |
| 028-benign_external_api-r8 | benign | True | benign | - | 0 | 710 | 0 | N/A | True |
| 029-benign_external_api-r3 | benign | True | benign | - | 0 | 913 | 0 | N/A | True |
| 030-benign_external_api-r18 | benign | True | benign | - | 0 | 645 | 0 | N/A | True |
| 031-abnormal_4-r16 | attack | True | attack | cloud-metadata-access, correlated-lateral-movement, path-violation, port-sweep, sensitive-service-probe | 0 | 277 | 0 | 0.366 | True |
| 032-abnormal_1-r1 | attack | True | attack | path-violation | 0 | 100 | 0 | 0.361 | True |
| 033-abnormal_5_beacon-r4 | attack | True | attack | periodic-beacon | 0 | 886 | 0 | 0.378 | True |
| 034-benign_maintenance_probe-r5 | benign | True | attack | path-violation | 0 | 107 | 0 | 0.356 | True |
| 035-abnormal_2-r1 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation | 0 | 404 | 0 | 1.137 | True |
| 036-normal-r13 | benign | True | benign | - | 0 | 221 | 0 | N/A | True |
| 037-benign_maintenance_probe-r1 | benign | True | attack | path-violation | 0 | 103 | 0 | 0.354 | True |
| 038-abnormal_1-r2 | attack | True | attack | path-violation | 0 | 75 | 0 | 0.355 | True |
| 039-abnormal_1-r20 | attack | True | attack | path-violation | 0 | 105 | 0 | 0.359 | True |
| 040-benign_rollout-r13 | benign | True | benign | - | 0 | 148 | 0 | N/A | True |
| 041-abnormal_1-r19 | attack | True | attack | path-violation | 0 | 124 | 0 | 0.357 | True |
| 042-abnormal_3-r15 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation, port-sweep, sensitive-service-probe | 0 | 1045 | 0 | 2.194 | True |
| 043-abnormal_4-r10 | attack | True | attack | cloud-metadata-access, correlated-lateral-movement, path-violation, port-sweep, sensitive-service-probe | 0 | 279 | 0 | 0.362 | True |
| 044-normal_burst-r8 | benign | True | benign | - | 0 | 813 | 0 | N/A | True |
| 045-attack_allowed_path-r12 | attack | False | benign | - | 1 | 86 | 0 | N/A | True |
| 046-benign_rollout-r14 | benign | True | benign | - | 0 | 104 | 0 | N/A | True |
| 047-abnormal_5_beacon-r6 | attack | True | attack | periodic-beacon | 0 | 994 | 0 | 0.37 | True |
| 048-abnormal_5_beacon-r11 | attack | True | attack | periodic-beacon | 0 | 895 | 0 | 0.37 | True |
| 049-attack_allowed_path-r1 | attack | False | benign | - | 1 | 59 | 0 | N/A | True |
| 050-abnormal_1-r8 | attack | True | attack | path-violation | 0 | 93 | 0 | 0.354 | True |
| 051-abnormal_5_beacon-r16 | attack | True | attack | periodic-beacon | 0 | 885 | 0 | 0.367 | True |
| 052-abnormal_5_beacon-r1 | attack | True | attack | periodic-beacon | 0 | 882 | 0 | 0.37 | True |
| 053-normal_burst-r2 | benign | True | benign | - | 0 | 804 | 0 | N/A | True |
| 054-abnormal_2-r4 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation | 0 | 411 | 0 | 1.112 | True |
| 055-normal-r16 | benign | True | benign | - | 0 | 232 | 0 | N/A | True |
| 056-abnormal_3-r6 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation, port-sweep, sensitive-service-probe | 0 | 943 | 0 | 2.174 | True |
| 057-abnormal_4-r15 | attack | True | attack | cloud-metadata-access, correlated-lateral-movement, path-violation, port-sweep, sensitive-service-probe | 0 | 273 | 0 | 0.361 | True |
| 058-abnormal_2-r16 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation | 0 | 422 | 0 | 1.12 | True |
| 059-attack_allowed_path-r11 | attack | False | benign | - | 1 | 77 | 0 | N/A | True |
| 060-abnormal_4-r7 | attack | True | attack | cloud-metadata-access, correlated-lateral-movement, path-violation, port-sweep, sensitive-service-probe | 0 | 281 | 0 | 0.353 | True |
| 061-attack_allowed_path-r13 | attack | False | benign | - | 1 | 74 | 0 | N/A | True |
| 062-normal-r7 | benign | True | benign | - | 0 | 232 | 0 | N/A | True |
| 063-normal-r8 | benign | True | benign | - | 0 | 225 | 0 | N/A | True |
| 064-benign_external_api-r19 | benign | True | benign | - | 0 | 743 | 0 | N/A | True |
| 065-benign_maintenance_probe-r10 | benign | True | attack | path-violation | 0 | 93 | 0 | 0.36 | True |
| 066-normal-r1 | benign | True | benign | - | 0 | 223 | 0 | N/A | True |
| 067-normal-r11 | benign | True | benign | - | 0 | 224 | 0 | N/A | True |
| 068-normal-r17 | benign | True | benign | - | 0 | 224 | 0 | N/A | True |
| 069-normal_burst-r17 | benign | True | benign | - | 0 | 810 | 0 | N/A | True |
| 070-abnormal_1-r4 | attack | True | attack | path-violation | 0 | 123 | 0 | 0.354 | True |
| 071-attack_allowed_path-r9 | attack | False | benign | - | 1 | 58 | 0 | N/A | True |
| 072-abnormal_3-r13 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation, port-sweep, sensitive-service-probe | 0 | 956 | 0 | 2.173 | True |
| 073-benign_rollout-r12 | benign | True | benign | - | 0 | 133 | 0 | N/A | True |
| 074-abnormal_2-r12 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation | 0 | 493 | 0 | 1.134 | True |
| 075-normal_burst-r9 | benign | True | benign | - | 0 | 834 | 0 | N/A | True |
| 076-benign_external_api-r17 | benign | True | benign | - | 0 | 827 | 0 | N/A | True |
| 077-abnormal_3-r20 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation, port-sweep, sensitive-service-probe | 0 | 949 | 0 | 2.196 | True |
| 078-attack_allowed_path-r3 | attack | False | benign | - | 1 | 59 | 0 | N/A | True |
| 079-benign_maintenance_probe-r16 | benign | True | attack | path-violation | 0 | 103 | 0 | 0.36 | True |
| 080-attack_allowed_path-r17 | attack | False | benign | - | 1 | 58 | 0 | N/A | True |
| 081-abnormal_4-r8 | attack | True | attack | cloud-metadata-access, correlated-lateral-movement, path-violation, port-sweep, sensitive-service-probe | 0 | 282 | 0 | 0.367 | True |
| 082-abnormal_1-r5 | attack | True | attack | path-violation | 0 | 111 | 0 | 0.361 | True |
| 083-benign_rollout-r15 | benign | True | benign | - | 0 | 104 | 0 | N/A | True |
| 084-normal_burst-r12 | benign | True | benign | - | 0 | 847 | 0 | N/A | True |
| 085-attack_allowed_path-r7 | attack | False | benign | - | 1 | 82 | 0 | N/A | True |
| 086-normal-r10 | benign | True | benign | - | 0 | 251 | 0 | N/A | True |
| 087-abnormal_4-r19 | attack | True | attack | cloud-metadata-access, correlated-lateral-movement, path-violation, port-sweep, sensitive-service-probe | 0 | 336 | 0 | 0.362 | True |
| 088-benign_maintenance_probe-r8 | benign | True | attack | path-violation | 0 | 112 | 0 | 0.359 | True |
| 089-benign_external_api-r2 | benign | True | benign | - | 0 | 714 | 0 | N/A | True |
| 090-normal-r19 | benign | True | benign | - | 0 | 213 | 0 | N/A | True |
| 091-abnormal_5_beacon-r18 | attack | True | attack | periodic-beacon | 0 | 889 | 0 | 0.371 | True |
| 092-abnormal_1-r16 | attack | True | attack | path-violation | 0 | 84 | 0 | 0.348 | True |
| 093-benign_maintenance_probe-r11 | benign | True | attack | path-violation | 0 | 104 | 0 | 0.354 | True |
| 094-attack_allowed_path-r6 | attack | False | benign | - | 1 | 74 | 0 | N/A | True |
| 095-attack_allowed_path-r19 | attack | False | benign | - | 1 | 66 | 0 | N/A | True |
| 096-abnormal_5_beacon-r20 | attack | True | attack | periodic-beacon | 0 | 895 | 0 | 0.394 | True |
| 097-benign_rollout-r5 | benign | True | benign | - | 0 | 121 | 0 | N/A | True |
| 098-benign_maintenance_probe-r12 | benign | True | attack | path-violation | 0 | 149 | 0 | 0.361 | True |
| 099-normal_burst-r10 | benign | True | benign | - | 0 | 838 | 0 | N/A | True |
| 100-attack_allowed_path-r5 | attack | False | benign | - | 1 | 94 | 0 | N/A | True |
| 101-abnormal_5_beacon-r14 | attack | True | attack | periodic-beacon | 0 | 943 | 0 | 0.366 | True |
| 102-abnormal_3-r10 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation, port-sweep, sensitive-service-probe | 0 | 947 | 0 | 2.152 | True |
| 103-abnormal_2-r17 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation | 0 | 401 | 0 | 1.148 | True |
| 104-benign_external_api-r13 | benign | True | benign | - | 0 | 901 | 0 | N/A | True |
| 105-benign_maintenance_probe-r15 | benign | True | attack | path-violation | 0 | 76 | 0 | 0.358 | True |
| 106-abnormal_4-r9 | attack | True | attack | cloud-metadata-access, correlated-lateral-movement, path-violation, port-sweep, sensitive-service-probe | 0 | 279 | 0 | 0.354 | True |
| 107-attack_allowed_path-r15 | attack | False | benign | - | 1 | 66 | 0 | N/A | True |
| 108-normal_burst-r15 | benign | True | benign | - | 0 | 814 | 0 | N/A | True |
| 109-normal-r4 | benign | True | benign | - | 0 | 224 | 0 | N/A | True |
| 110-benign_maintenance_probe-r18 | benign | True | attack | path-violation | 0 | 111 | 0 | 0.365 | True |
| 111-abnormal_4-r12 | attack | True | attack | cloud-metadata-access, correlated-lateral-movement, path-violation, port-sweep, sensitive-service-probe | 0 | 290 | 0 | 0.363 | True |
| 112-abnormal_2-r8 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation | 0 | 419 | 0 | 1.116 | True |
| 113-abnormal_4-r18 | attack | True | attack | cloud-metadata-access, correlated-lateral-movement, path-violation, port-sweep, sensitive-service-probe | 0 | 280 | 0 | 0.363 | True |
| 114-benign_external_api-r6 | benign | True | benign | - | 0 | 758 | 0 | N/A | True |
| 115-abnormal_5_beacon-r12 | attack | True | attack | periodic-beacon | 0 | 885 | 0 | 0.38 | True |
| 116-normal-r12 | benign | True | benign | - | 0 | 224 | 0 | N/A | True |
| 117-abnormal_1-r12 | attack | True | attack | path-violation | 0 | 102 | 0 | 0.354 | True |
| 118-abnormal_3-r16 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation, port-sweep, sensitive-service-probe | 0 | 950 | 0 | 2.175 | True |
| 119-benign_rollout-r11 | benign | True | benign | - | 0 | 124 | 0 | N/A | True |
| 120-abnormal_3-r7 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation, port-sweep, sensitive-service-probe | 0 | 1066 | 0 | 2.171 | True |
| 121-benign_maintenance_probe-r14 | benign | True | attack | path-violation | 0 | 86 | 0 | 0.356 | True |
| 122-abnormal_2-r3 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation | 0 | 384 | 0 | 1.157 | True |
| 123-abnormal_3-r12 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation, port-sweep, sensitive-service-probe | 0 | 950 | 0 | 2.157 | True |
| 124-normal_burst-r4 | benign | True | benign | - | 0 | 816 | 0 | N/A | True |
| 125-abnormal_4-r5 | attack | True | attack | cloud-metadata-access, correlated-lateral-movement, path-violation, port-sweep, sensitive-service-probe | 0 | 280 | 0 | 0.349 | True |
| 126-abnormal_3-r18 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation, port-sweep, sensitive-service-probe | 0 | 946 | 0 | 2.156 | True |
| 127-abnormal_1-r10 | attack | True | attack | path-violation | 0 | 77 | 0 | 0.376 | True |
| 128-abnormal_2-r19 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation | 0 | 418 | 0 | 1.126 | True |
| 129-attack_allowed_path-r14 | attack | False | benign | - | 1 | 76 | 0 | N/A | True |
| 130-benign_maintenance_probe-r2 | benign | True | attack | path-violation | 0 | 84 | 0 | 0.365 | True |
| 131-abnormal_3-r8 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation, port-sweep, sensitive-service-probe | 0 | 952 | 0 | 2.184 | True |
| 132-benign_rollout-r20 | benign | True | benign | - | 0 | 159 | 0 | N/A | True |
| 133-benign_maintenance_probe-r7 | benign | True | attack | path-violation | 0 | 149 | 0 | 0.357 | True |
| 134-abnormal_2-r14 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation | 0 | 486 | 0 | 1.116 | True |
| 135-benign_external_api-r11 | benign | True | benign | - | 0 | 790 | 0 | N/A | True |
| 136-normal_burst-r14 | benign | True | benign | - | 0 | 822 | 0 | N/A | True |
| 137-abnormal_2-r20 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation | 0 | 387 | 0 | 1.117 | True |
| 138-abnormal_1-r13 | attack | True | attack | path-violation | 0 | 105 | 0 | 0.363 | True |
| 139-attack_allowed_path-r4 | attack | False | benign | - | 1 | 57 | 0 | N/A | True |
| 140-abnormal_4-r2 | attack | True | attack | cloud-metadata-access, correlated-lateral-movement, path-violation, port-sweep, sensitive-service-probe | 0 | 301 | 0 | 0.366 | True |
| 141-benign_rollout-r7 | benign | True | benign | - | 0 | 115 | 0 | N/A | True |
| 142-abnormal_5_beacon-r5 | attack | True | attack | periodic-beacon | 0 | 1003 | 0 | 0.377 | True |
| 143-benign_rollout-r9 | benign | True | benign | - | 0 | 105 | 0 | N/A | True |
| 144-abnormal_3-r9 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation, port-sweep, sensitive-service-probe | 0 | 1075 | 0 | 2.187 | True |
| 145-benign_external_api-r4 | benign | True | benign | - | 0 | 1006 | 0 | N/A | True |
| 146-abnormal_2-r9 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation | 0 | 411 | 0 | 1.11 | True |
| 147-abnormal_3-r11 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation, port-sweep, sensitive-service-probe | 0 | 951 | 0 | 2.182 | True |
| 148-abnormal_1-r18 | attack | True | attack | path-violation | 0 | 85 | 0 | 0.358 | True |
| 149-normal-r20 | benign | True | benign | - | 0 | 232 | 0 | N/A | True |
| 150-benign_maintenance_probe-r3 | benign | True | attack | path-violation | 0 | 101 | 0 | 0.364 | True |
| 151-normal_burst-r19 | benign | True | benign | - | 0 | 802 | 0 | N/A | True |
| 152-benign_external_api-r15 | benign | True | benign | - | 0 | 936 | 0 | N/A | True |
| 153-benign_external_api-r7 | benign | True | benign | - | 0 | 776 | 0 | N/A | True |
| 154-benign_maintenance_probe-r6 | benign | True | attack | path-violation | 0 | 110 | 0 | 0.361 | True |
| 155-benign_rollout-r16 | benign | True | benign | - | 0 | 125 | 0 | N/A | True |
| 156-abnormal_3-r2 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation, port-sweep, sensitive-service-probe | 0 | 1065 | 0 | 2.172 | True |
| 157-abnormal_2-r5 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation | 0 | 404 | 0 | 1.115 | True |
| 158-abnormal_1-r14 | attack | True | attack | path-violation | 0 | 112 | 0 | 0.366 | True |
| 159-abnormal_1-r9 | attack | True | attack | path-violation | 0 | 95 | 0 | 0.357 | True |
| 160-abnormal_1-r15 | attack | True | attack | path-violation | 0 | 103 | 0 | 0.37 | True |
| 161-abnormal_5_beacon-r7 | attack | True | attack | periodic-beacon | 0 | 903 | 0 | 0.369 | True |
| 162-abnormal_5_beacon-r13 | attack | True | attack | periodic-beacon | 0 | 878 | 0 | 0.393 | True |
| 163-abnormal_5_beacon-r2 | attack | True | attack | periodic-beacon | 0 | 895 | 0 | 0.373 | True |
| 164-benign_external_api-r9 | benign | True | benign | - | 0 | 812 | 0 | N/A | True |
| 165-abnormal_5_beacon-r3 | attack | True | attack | periodic-beacon | 0 | 914 | 0 | 0.364 | True |
| 166-abnormal_2-r13 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation | 0 | 407 | 0 | 1.124 | True |
| 167-abnormal_4-r11 | attack | True | attack | cloud-metadata-access, correlated-lateral-movement, path-violation, port-sweep, sensitive-service-probe | 0 | 290 | 0 | 0.353 | True |
| 168-normal-r2 | benign | True | benign | - | 0 | 243 | 0 | N/A | True |
| 169-normal_burst-r7 | benign | True | benign | - | 0 | 821 | 0 | N/A | True |
| 170-attack_allowed_path-r18 | attack | False | benign | - | 1 | 68 | 0 | N/A | True |
| 171-normal-r9 | benign | True | benign | - | 0 | 243 | 0 | N/A | True |
| 172-benign_maintenance_probe-r9 | benign | True | attack | path-violation | 0 | 94 | 0 | 0.36 | True |
| 173-benign_rollout-r3 | benign | True | benign | - | 0 | 104 | 0 | N/A | True |
| 174-abnormal_5_beacon-r9 | attack | True | attack | periodic-beacon | 0 | 1003 | 0 | 0.374 | True |
| 175-benign_maintenance_probe-r19 | benign | True | attack | path-violation | 0 | 112 | 0 | 0.359 | True |
| 176-normal_burst-r20 | benign | True | benign | - | 0 | 823 | 0 | N/A | True |
| 177-abnormal_5_beacon-r8 | attack | True | attack | periodic-beacon | 0 | 925 | 0 | 0.365 | True |
| 178-benign_rollout-r19 | benign | True | benign | - | 0 | 122 | 0 | N/A | True |
| 179-abnormal_3-r4 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation, port-sweep, sensitive-service-probe | 0 | 1069 | 0 | 2.192 | True |
| 180-abnormal_5_beacon-r17 | attack | True | attack | periodic-beacon | 0 | 904 | 0 | 0.372 | True |
| 181-attack_allowed_path-r8 | attack | False | benign | - | 1 | 87 | 0 | N/A | True |
| 182-abnormal_3-r19 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation, port-sweep, sensitive-service-probe | 0 | 936 | 0 | 2.178 | True |
| 183-benign_rollout-r17 | benign | True | benign | - | 0 | 105 | 0 | N/A | True |
| 184-abnormal_4-r4 | attack | True | attack | cloud-metadata-access, correlated-lateral-movement, path-violation, port-sweep, sensitive-service-probe | 0 | 360 | 0 | 0.357 | True |
| 185-normal_burst-r1 | benign | True | benign | - | 0 | 814 | 0 | N/A | True |
| 186-abnormal_2-r7 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation | 0 | 443 | 0 | 1.111 | True |
| 187-abnormal_4-r14 | attack | True | attack | cloud-metadata-access, correlated-lateral-movement, path-violation, port-sweep, sensitive-service-probe | 0 | 291 | 0 | 0.351 | True |
| 188-abnormal_1-r11 | attack | True | attack | path-violation | 0 | 93 | 0 | 0.371 | True |
| 189-normal_burst-r6 | benign | True | benign | - | 0 | 804 | 0 | N/A | True |
| 190-benign_external_api-r10 | benign | True | benign | - | 0 | 921 | 0 | N/A | True |
| 191-abnormal_5_beacon-r19 | attack | True | attack | periodic-beacon | 0 | 907 | 0 | 0.363 | True |
| 192-benign_maintenance_probe-r17 | benign | True | attack | path-violation | 0 | 101 | 0 | 0.36 | True |
| 193-normal_burst-r16 | benign | True | benign | - | 0 | 833 | 0 | N/A | True |
| 194-abnormal_4-r17 | attack | True | attack | cloud-metadata-access, correlated-lateral-movement, path-violation, port-sweep, sensitive-service-probe | 0 | 275 | 0 | 0.353 | True |
| 195-abnormal_3-r5 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation, port-sweep, sensitive-service-probe | 0 | 931 | 0 | 2.18 | True |
| 196-normal-r14 | benign | True | benign | - | 0 | 240 | 0 | N/A | True |
| 197-benign_external_api-r20 | benign | True | benign | - | 0 | 997 | 0 | N/A | True |
| 198-normal-r15 | benign | True | benign | - | 0 | 223 | 0 | N/A | True |
| 199-benign_external_api-r12 | benign | True | benign | - | 0 | 858 | 0 | N/A | True |
| 200-abnormal_1-r6 | attack | True | attack | path-violation | 0 | 100 | 0 | 0.359 | True |
| 201-normal-r6 | benign | True | benign | - | 0 | 231 | 0 | N/A | True |
| 202-normal_burst-r3 | benign | True | benign | - | 0 | 838 | 0 | N/A | True |
| 203-abnormal_4-r1 | attack | True | attack | cloud-metadata-access, correlated-lateral-movement, path-violation, port-sweep, sensitive-service-probe | 0 | 274 | 0 | 0.352 | True |
| 204-benign_external_api-r1 | benign | True | benign | - | 0 | 767 | 0 | N/A | True |
| 205-abnormal_5_beacon-r10 | attack | True | attack | periodic-beacon | 0 | 904 | 0 | 0.373 | True |
| 206-benign_external_api-r14 | benign | True | benign | - | 0 | 910 | 0 | N/A | True |
| 207-normal-r3 | benign | True | benign | - | 0 | 242 | 0 | N/A | True |
| 208-abnormal_4-r13 | attack | True | attack | cloud-metadata-access, correlated-lateral-movement, path-violation, port-sweep, sensitive-service-probe | 0 | 271 | 0 | 0.355 | True |
| 209-abnormal_4-r20 | attack | True | attack | cloud-metadata-access, correlated-lateral-movement, path-violation, port-sweep, sensitive-service-probe | 0 | 300 | 0 | 0.363 | True |
| 210-benign_external_api-r16 | benign | True | benign | - | 0 | 931 | 0 | N/A | True |
| 211-abnormal_1-r3 | attack | True | attack | path-violation | 0 | 103 | 0 | 0.366 | True |
| 212-normal_burst-r18 | benign | True | benign | - | 0 | 812 | 0 | N/A | True |
| 213-benign_rollout-r4 | benign | True | benign | - | 0 | 85 | 0 | N/A | True |
| 214-benign_rollout-r6 | benign | True | benign | - | 0 | 122 | 0 | N/A | True |
| 215-abnormal_4-r6 | attack | True | attack | cloud-metadata-access, correlated-lateral-movement, path-violation, port-sweep, sensitive-service-probe | 0 | 435 | 0 | 0.358 | True |
| 216-abnormal_1-r7 | attack | True | attack | path-violation | 0 | 150 | 0 | 0.373 | True |
| 217-benign_rollout-r18 | benign | True | benign | - | 0 | 127 | 0 | N/A | True |
| 218-abnormal_3-r1 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation, port-sweep, sensitive-service-probe | 0 | 1079 | 0 | 2.174 | True |
| 219-abnormal_3-r3 | attack | True | attack | correlated-lateral-movement, destination-fanout, path-violation, port-sweep, sensitive-service-probe | 0 | 966 | 0 | 2.19 | True |
| 220-abnormal_5_beacon-r15 | attack | True | attack | periodic-beacon | 0 | 895 | 0 | 0.373 | True |

## Interpretation

`attack_allowed_path` is deliberately labeled as an attack while using only the allowed frontend-to-backend TCP/80 edge. A correct L3/L4-only detector is expected to miss it; including it prevents an inflated claim that network telemetry detects every attack.

`benign_maintenance_probe` is the opposite boundary: an authorized diagnostic action that is identical to a direct-path attack at L3/L4. It is expected to expose a false positive unless operator identity or a maintenance window is correlated.

A run with a failed script, failed Hubble query, zero parsed flows, or an event-loss marker is invalid rather than benign. Raw Hubble JSONL, detector JSON, timing, and scenario stdout/stderr are retained below `runs/` for independent review.
