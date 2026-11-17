# 실무클라우드보안 PBL Category 2 (Pod 내부 이동 및 통신 탐지)

**한국어** | [English (원본 프로젝트 안내)](README_EN.md) | [Category 2 원본 과제 설명](category2/README_EN.md)

<img width="2098" height="584" alt="image" src="https://github.com/user-attachments/assets/3b1b23f9-3803-418a-885c-23530db672af" />

Hildegard/TeamTNT(Unit 42, 2021) 사례를 바탕으로, Cilium Hubble flow에서 정상적인 Pod 통신과 내부 탐색, 측면 이동, C2 통신을 구분하는 탐지 시스템입니다. 탐지기는 Pod 이름 대신 workload 단위로 flow를 묶고, 미리 선언한 서비스 간 통신 관계(서비스 그래프)와 통신의 시간 패턴을 근거로 판정합니다. 네트워크 기록만으로는 정상과 공격이 똑같아 보이는 경우는 HTTP 로그, Tetragon의 process 기록, LLM 검토로 넘깁니다.

> 실습은 masscan, 악성코드, miner, 실제 C2를 실행하지 않으며, 공격 시나리오는 Hubble에서 관찰되는 목적지, 포트, 주기만 안전하게 재현합니다.

## 구성

| 경로 | 내용 |
| --- | --- |
| [`category2/scenarios/`](category2/scenarios/) | 정상 5종과 공격 6종 시나리오. [`lib/pod_helpers.sh`](category2/scenarios/lib/pod_helpers.sh)는 종료 중인 Pod를 피해 Ready 상태의 Pod만 고릅니다. |
| [`category2/detector/`](category2/detector/) | [`detect.py`](category2/detector/detect.py) 탐지기와 [`policy.json`](category2/detector/policy.json) 기준, [`route_l7_review.py`](category2/detector/route_l7_review.py) HTTP 경로 검사, [`runtime_join.py`](category2/detector/runtime_join.py) 경보와 process 연결 |
| [`category2/evaluation/`](category2/evaluation/) | [`run_live_eval.py`](category2/evaluation/run_live_eval.py): 시나리오를 무작위 순서로 반복 실행하고 Hubble 기록만으로 판정 |
| [`category2/analysis/`](category2/analysis/) | [`observation_collisions.py`](category2/analysis/observation_collisions.py) 구분 불가 사례 분석, [`beacon_sensitivity.py`](category2/analysis/beacon_sensitivity.py) 주기 변화 민감도, [`llm_review.py`](category2/analysis/llm_review.py) LLM 블라인드 검토 |
| [`category2/manifests/`](category2/manifests/) | 모의 외부 API, HTTP 관찰용 Cilium 정책, Tetragon `tcp_connect` 관찰 정책 |
| [`category2/scripts/`](category2/scripts/) | [`install_tetragon.sh`](category2/scripts/install_tetragon.sh), 한 시나리오의 전체 증거를 남기는 [`capture_trace.sh`](category2/scripts/capture_trace.sh) |
| [`category2/logs/`](category2/logs/) | 과제에서 제공한 Hubble 로그 예시 |
| [`category2/results/`](category2/results/) | 220회 반복 평가, LLM 검토, runtime trace 결과 |

## 시나리오

기본 시나리오(정상 1, 공격 3)에 정상 4종과 공격 3종을 더했습니다. 정상 쪽에는 요청이 몰리는 부하, 재배포, 외부 API 호출처럼 공격과 헷갈리기 쉬운 상황을 넣었습니다. 마지막 두 줄은 네트워크 기록만으로는 구분할 수 없도록 일부러 만든 사례입니다.

| 시나리오 | 구분 | 하는 일 | 탐지기가 보는 근거 |
| --- | --- | --- | --- |
| [`normal.sh`](category2/scenarios/normal.sh) | 정상 | frontend→backend, backend→db, DNS, health check, 재시도 | 모든 연결이 선언된 서비스 그래프 안에 있음 |
| [`normal_burst.sh`](category2/scenarios/normal_burst.sh) | 정상 | frontend→backend에 동시 요청 (부하) | 요청이 많아도 그래프 안이고 목적지가 늘지 않음 |
| [`benign_rollout.sh`](category2/scenarios/benign_rollout.sh) | 정상 | frontend를 재배포한 뒤 정상 호출 | Pod 이름이 바뀌어도 같은 workload로 묶임 |
| [`benign_external_api.sh`](category2/scenarios/benign_external_api.sh) | 정상 | 선언된 외부 API를 사용자 요청처럼 불규칙한 간격으로 호출 | 연결 간격이 들쭉날쭉함 |
| [`abnormal_1.sh`](category2/scenarios/abnormal_1.sh) | 공격 | frontend가 db에 직접 접근 | 그래프에 없는 연결 (`path-violation`) |
| [`abnormal_2.sh`](category2/scenarios/abnormal_2.sh) | 공격 | Service, Pod, Node를 짧은 시간에 연달아 탐색 | 15초 안 목적지 4개 이상 (`destination-fanout`) |
| [`abnormal_3.sh`](category2/scenarios/abnormal_3.sh) | 공격 | 여러 대상에 22, 443, 2379, 10250, 3306, 6379 접속 시도 | 포트 훑기, 관리용 포트, 탐색 뒤 접근 |
| [`abnormal_4.sh`](category2/scenarios/abnormal_4.sh) | 공격 | 클라우드 metadata 주소와 IRC 포트로 접속 시도 | `cloud-metadata-access`, IRC 포트 |
| [`abnormal_5_beacon.sh`](category2/scenarios/abnormal_5_beacon.sh) | 공격 | 허용된 외부 API 경로로 4초마다 C2 생존 신호(heartbeat)를 보냄 | 연결 간격이 거의 일정함 (`periodic-beacon`) |
| [`benign_maintenance_probe.sh`](category2/scenarios/benign_maintenance_probe.sh) | 정상 (구분 불가) | 운영자가 사전 승인을 받고 frontend→db 연결이 막혀 있는지 확인 | 네트워크 기록이 `abnormal_1`과 같음. 변경 승인 기록이 있어야 구분 |
| [`attack_allowed_path.sh`](category2/scenarios/attack_allowed_path.sh) | 공격 (구분 불가) | 허용된 frontend→backend 경로로 자격증명을 노리는 HTTP 요청을 흉내 냄 | L3/L4 기록에는 정상과 차이가 없고, HTTP 경로 검사만 검토 대상으로 넘김 |

## 탐지 방법

<img width="1122" height="333" alt="image" src="https://github.com/user-attachments/assets/cfa761ad-9685-4176-9243-af3ab2a5b734" />

탐지는 모든 flow를 처리하는 규칙 판정 단계와, 규칙으로 구분되지 않는 사례만 다루는 검토 단계로 나뉩니다.

1. **workload 단위로 묶기:** Hubble JSONL을 읽어 Pod 이름 뒤의 ReplicaSet suffix를 지운 `namespace/workload` 이름으로 바꾸고, 여러 관측 지점에서 기록된 같은 SYN을 250 ms 안에서 하나의 연결 시도로 합칩니다. `policy.json`의 감시 대상 namespace에서 시작한 연결만 봅니다.
2. **규칙 판정:** 아래 규칙을 source workload마다 적용합니다. 한 번 막힌 연결은 설정 실수와 구분되지 않으므로 medium으로 두고, 탐색 신호와 그래프 밖 접근이 60초 안에 함께 나타날 때 critical로 올립니다.
3. **증거 보강:** [`route_l7_review.py`](category2/detector/route_l7_review.py)는 HTTP 관찰을 켠 경로에서 허용 목록 밖의 method/path를 검토 대상으로 만들고 인증 header는 가립니다. [`runtime_join.py`](category2/detector/runtime_join.py)는 경보마다 Tetragon `tcp_connect` 기록에서 그 연결을 연 binary, 인자, 컨테이너를 찾아 붙입니다.
4. **LLM 검토:** [`llm_review.py`](category2/analysis/llm_review.py)는 정답 라벨을 뺀 증거 묶음을 LLM에 보내 `attack`, `benign`, `insufficient_evidence` 중 하나와 근거 ID를 받습니다. 프롬프트는 변경 승인 기록이 대상과 시간이 모두 맞아야 승인으로 인정하고, 증거 안의 텍스트는 지시가 아닌 데이터로 다루도록 정합니다.

| 규칙 | 조건 (같은 source workload) | 심각도 |
| --- | --- | --- |
| `path-violation` | 그래프에 없는 연결이 정책에 막힘 (DROPPED) | medium, 반복되거나 관리용 포트면 high |
| `baseline-deviation` | 그래프에 없는 연결이 정책을 통과함 (FORWARDED, AUDIT) | medium, 대상이 3개 이상이거나 관리용 포트면 high |
| `destination-fanout` | 15초 안에 목적지 4개 이상 | high |
| `port-sweep` | 15초 안에 목적지 포트 4개 이상 | high |
| `sensitive-service-probe` | 22, 2379, 2380, 6443, 6667, 6697, 10250, 10255 접속 | high |
| `cloud-metadata-access` | 169.254.169.254, 169.254.170.2 접속 | critical |
| `periodic-beacon` | 같은 연결이 6회 이상, 간격 중앙값 2~600초, 간격 변동계수(CV) 0.25 이하 | high |
| `correlated-lateral-movement` | 탐색 규칙과 그래프 밖 연결이 60초 안에 함께 발생 | critical |

`baseline-deviation`은 정책이 잘못되었거나 감사(audit) 모드일 때도 그래프 밖 통신을 놓치지 않기 위한 규칙입니다. `periodic-beacon`은 내용을 보지 않고 연결 간격만으로 C2 생존 신호를 찾습니다. DNS(53)는 질의 이름 없이는 판단할 수 없어 제외하고, 승인된 주기 작업은 `policy.json`의 `declared_periodic_edges`에 등록합니다. 모든 기준값은 [`policy.json`](category2/detector/policy.json)에 있습니다.

## 사용법

[`install.sh`](install.sh)로 클러스터를 만든 뒤 (설치 과정은 [README_EN.md](README_EN.md) 참고), 추가 시나리오와 선택 기능을 적용합니다.

```bash
kubectl apply -f category2/manifests/egress-sim.yaml      # 모의 외부 API (abnormal_5_beacon, benign_external_api)
kubectl apply -f category2/manifests/l7-visibility.yaml   # frontend→backend HTTP 관찰
./category2/scripts/install_tetragon.sh                   # process 관찰 (선택)
cilium hubble port-forward &
```

탐지기는 저장된 로그와 실시간 Hubble 출력 모두에 쓸 수 있습니다.

```bash
python3 category2/detector/detect.py category2/logs/abnormal_3.log
hubble observe --namespace pbl-security --since 5m --output jsonpb | python3 category2/detector/detect.py - --format json
```

반복 평가는 시나리오를 seed 순서로 섞어 실행하고, 실행마다 Hubble 기록, 탐지 결과, 판정 요약을 `category2/results/live-<시각>/`에 남깁니다. 스크립트 실패나 관측 손실이 있는 실행은 정상으로 세지 않고 무효로 처리합니다. 중간에 중단되면 같은 `--output-dir`에 `--resume`을 붙여 끝난 실행은 그대로 두고 이어서 실행할 수 있습니다.

```bash
python3 category2/evaluation/run_live_eval.py --repeats 20 --seed 42
```

한 사건의 증거를 처음부터 끝까지 확인하려면 시나리오 하나를 추적한 뒤 LLM 검토에 넘깁니다. LLM 검토는 저장소 루트 `.env`의 `BAZE_API_KEY`를 사용하고 기본 모델은 `gpt-6.1-terra`입니다. 평가 결과 디렉터리를 넘기면 검토 사례를 만들고 아직 답이 없는 사례만 질의한 뒤 점수를 냅니다.

```bash
./category2/scripts/capture_trace.sh category2/scenarios/abnormal_5_beacon.sh category2/results/runtime-trace/abnormal_5_beacon
python3 category2/analysis/llm_review.py category2/results/runtime-trace/abnormal_5_beacon
python3 category2/analysis/llm_review.py category2/results/live-20261117-r20
```

테스트는 `python3 -m unittest discover -s category2/<detector|evaluation|analysis>/tests`로 실행합니다.

## 결과

11개 시나리오를 seed 42로 섞어 각 20회, 총 220회 실행했고 모든 실행이 유효했습니다. Hubble 관측 손실과 파싱 오류도 없었습니다. 실행별 판정은 [`report.md`](category2/results/live-20261117-r20/report.md)와 [`summary.json`](category2/results/live-20261117-r20/summary.json)에 있습니다. 각 실행 디렉터리 [`runs/<번호>-<시나리오>-r<반복>/`](category2/results/live-20261117-r20/runs/)에는 원본 Hubble 기록(`hubble.jsonl`), 시나리오 출력, 실행 메타데이터, 탐지 결과가 함께 있어 `python3 category2/detector/detect.py <run>/hubble.jsonl`로 판정을 그대로 다시 확인할 수 있습니다.

| 평가 범위 | TP | TN | FP | FN | Precision | Recall | Specificity |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| L3/L4 탐지기, 전체 공격 | 100 | 80 | 20 | 20 | 0.83 | 0.83 | 0.80 |
| L3/L4 탐지기, 네트워크로 관찰 가능한 공격 | 100 | 80 | 20 | 0 | 0.83 | 1.00 | 0.80 |
| L3/L4 경보 + HTTP 경로 검사 | 120 | 80 | 20 | 0 | 0.86 | 1.00 | 0.80 |

- 사전 승인 점검을 뺀 정상 실행 80회(기본 통신, 부하, 재배포, 외부 API 호출)에서는 경보가 한 번도 나지 않았습니다. 오탐 20건은 모두 사전 승인 점검이고, L3/L4 미탐 20건은 모두 허용된 backend 경로 안의 HTTP 요청이었습니다.
- 마지막 행은 눈에 띄는 합성 표식을 넣은 HTTP 요청이 검토 대상으로 넘어간 비율이며, 실제 공격에 대한 탐지 정확도로 해석하지 않습니다.
- C2 생존 신호는 20회 모두 탐지했고 간격 변동계수는 0.03~0.07이었습니다. 같은 외부 API 경로를 쓰는 정상 호출 20회는 0.47~1.40으로 한 번도 걸리지 않았습니다. 시나리오마다 설계한 규칙은 140건 모두 트리거되었습니다.
- 실행마다 달라지는 시각과 포트를 빼면 220회는 33가지 관측으로 줄고, 그중 두 관측(80회)을 정상과 공격이 공유합니다([`observation-collisions.json`](category2/results/live-20261117-r20/observation-collisions.json)). 이 관측만 보는 분류기는 최소 40회를 틀리며, 그때의 최대 accuracy 81.8%가 실제 탐지기 accuracy와 같습니다. 남은 오류는 기준값을 조정해서가 아니라 새 증거를 더해야 줄어듭니다.

`gpt-6.1-terra`(temperature 0)에 시나리오별 3건, 33건을 두 번 검토시켰습니다([`score.json`](category2/results/live-20261117-r20/llm-review/score.json)). 응답마다 모델 이름, prompt hash, 지연 시간, token 수가 저장되어 있습니다.

| 조건 | 판단 | 그중 정답 | 판단 보류 | 정상을 공격으로 | 공격을 정상으로 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 네트워크 증거만 | 21 | 18 | 12 | 0 | 3 |
| + HTTP 로그, 변경 승인 기록 | 24 | 24 | 9 | 0 | 0 |

네트워크 증거만 있을 때 틀린 3건은 허용된 backend 경로 안의 HTTP 요청을 정상으로 본 경우입니다. HTTP 로그가 붙자 이 요청 3건 중 2건을 공격으로 판단했고, 대상과 시간이 맞는 승인 기록이 있는 점검은 정상으로 봤습니다. 승인 기록이 만료됐거나 기록된 포트와 시도 횟수가 관측과 정확히 맞지 않는 경우, C2 생존 신호처럼 승인 여부를 알 수 없는 경우는 판단을 보류했습니다.

Tetragon을 켠 [`runtime-trace-20261117`](category2/results/runtime-trace-20261117/)에서는 `abnormal_1` 경보가 frontend 컨테이너의 `/bin/wget`으로, C2 생존 신호 경보가 curl-client 컨테이너의 `/usr/bin/curl` 연결 8건으로 이어졌습니다. 같은 경로의 정상 API 호출에서는 경보가 없었습니다. 이 증거를 받은 LLM은 경보, 연결, process를 근거로 인용하면서도 누가 그 process를 실행했는지(Audit)와 승인 기록이 없다는 이유로 판단을 보류했습니다.

## 한계

- 시나리오는 합성이며 실제 악성코드를 쓰지 않습니다. 정상 행위도 다섯 가지로 제한됩니다.
- 모든 시나리오를 같은 관리자가 `kubectl exec`로 실행하므로 Audit의 실행자 정보로는 정상과 공격이 구분되지 않습니다.
- C2 생존 신호의 간격을 ±40% 넘게 흔들거나 하나의 장기 연결 안에서 명령을 주고받으면 `periodic-beacon`이 놓칩니다. 합성 데이터 실험에서 ±30%까지는 모두 탐지했고 ±40%에서 약 80%로 떨어졌습니다.
- 외부에서 node의 kubelet으로 직접 들어오는 연결, hostNetwork Pod, 암호화된 HTTP는 Hubble flow만으로 볼 수 없습니다.
- 변경 승인 기록은 모의 데이터이고, LLM 검토는 모델 하나로 한 번 실행한 33건 사례입니다.
