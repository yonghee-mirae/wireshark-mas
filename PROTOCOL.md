# MAS 프로토콜 분석 및 구현 노트

이 문서는 `mas.lua` / `mas_rts.lua` / `mas_tr.lua` / `mas_rts_b.lua` /
`mas_rts_c.lua` / `mas_rts_u.lua` / `mas_rts_v.lua` / `mas_rts_j.lua` /
`mas_rts_x.lua` / `mas_rts_f.lua` / `mas_rts_y.lua` / `mas_rts_z.lua` /
`mas_rts_lm.lua` / `mas_tr_90.lua`가 해석하는 와이어 프로토콜을 이후
확장·수정 시 참고할 수 있도록 정리한 것이다(파일 구조는 §6 참고). 근거는
`design/AXIS-4.1.0_Protocol_WTS_ADD.docx`(원 설계 문서), `inner/wireshark
추가.txt`/`inner/Execution_layout.txt`/`inner/Order_layout.txt`(추가 필드
스펙)와 `samples/` 아래 실제 캡처 4종(`20260915_0809_RTS.pcapng`,
`20260915_0809_RTS2.pcapng`, `20260921_nana.pcapng`, `tcp_capture.cap`)을
바이트 단위로 교차 검증한 결과다.

## 1. 전체 구조 (3계층)

```
G/W HEADER (12 bytes)
  └─ SESS 값에 따라 분기
       SESS=0x08 (RTS)         → [ RTS-HEADER(6) + RTS-DATA ] 반복
       SESS=0x01 (Transaction) → AXIS-HEADER(24) + TR-DATA
```

캡처 스트림은 `FE FE` 프레임이 NUL 패딩을 사이에 두고 연속으로 이어지는
형태다. 이 프로젝트가 완전히 디코드하는 것은 RTS TYPE 10종(§3)과
Transaction MSGK 1종(§4)뿐이며, 그 외 모든 것(다른 TYPE, 다른 MSGK, 압축,
암호화, heartbeat)은 **헤더에서 알 수 있는 정보만 표시하고 본문은 raw
data**로 남긴다(§7). 이는 요청된 설계 결정이며 버그가 아니다.

## 2. Layer 1 — G/W HEADER (12 bytes)

와이어 순서:

```
SOF(1)=0xFE  SOF(1)=0xFE  CTRL(1)  SESS(1)  CHCK(1)  RSVD(2)  LENGTH(5, ASCII 숫자)
```

- **CTRL** (설계 문서 §1.1): `0x01` Normal, `0x02` ACK, `0x03` NAK,
  **`0x04` POLL(heartbeat, 300초 타임아웃)**, `0x05` CheckSession/세션종료
  (`ctrl=0x05 + sess=0x99`).
  - **POLL은 서버-클라이언트 연결 확인용으로, 항상 추가 데이터 없이 이
    G/W HEADER 12바이트 형태로만 송수신된다.** 그 이상 해석할 내용이
    없어 헤더 인식만으로 처리가 끝나는 게 정상 동작이다 — **구현
    완료**(`mas.CTRL_POLL`로 판별, 상세창/Info 컬럼 모두 `POLL`로 표시,
    §6.2).
- **SESS**: `0x01` Transaction, **`0x08` RTS(실시간데이터)**, `0x99` 세션종료.
- **CHCK**: 비트 플래그. `0x20` 항상 세팅, **`0x02` 압축 플래그(LZO)**,
  `0x08` 연속(continuation) 데이터, `0x01` ACK 요청, `0x80` 에러메시지.
- **RSVD(2)**: 예비, 해석하지 않음.
- **LENGTH(5)**: G/W 헤더 제외한 데이터 길이 (payload 바이트 수), ASCII 5자리
  숫자. payload 뒤에는 다음 프레임 시작까지 **NUL 패딩**이 올 수 있다.

구현: `mas.lua`의 `mas.scan(buf)`가 이 계층만 담당한다. 반환값
`items = { {t="mas", off, total, ctrl, sess, chck, len, payload}, {t="data", off, len}, ... }`,
`pending = {offset, needed}` (프레임이 스트림 끝에서 잘렸을 때 재조립 요청).

**CTRL=POLL(heartbeat)이나 CHCK 압축 비트가 서는 프레임은 SESS 값과 무관하게**
raw data로 처리된다(디스패치보다 먼저 검사).

### 프레이밍 파서의 엣지케이스

- 스트림 시작에서 마주치는 바이트가 `FE FE`가 아니면 다음 `FE FE`까지 전부
  `data`(junk)로 처리하고 그 지점부터 재동기화한다.
- `FE FE`는 맞지만 LENGTH 필드가 5자리 숫자가 아니면(오염된 헤더), 그 `FE FE`
  2바이트만 `data`로 버리고 1바이트씩 전진하며 재검사한다 — 다음 루프에서
  "junk" 분기가 실제 다음 `FE FE`를 찾아 나머지 오염 구간까지 함께 `data`로
  묶는다.
- **버퍼 끝에서 `FE FE`가 아직 다 도착하지 않은 경우** (예: 마지막 1바이트가
  `0xFE`뿐인 경우)는 **junk로 확정하지 않고 `pending`으로 재조립을 기다린다.**
  이 처리가 빠지면 TCP 세그먼트 경계에 걸린 정상 프레임이 "미확인 잡음"으로
  오분류되어 유실될 수 있다.
- 헤더(12바이트) 자체가 잘렸거나, LENGTH만큼의 payload가 아직 덜 도착했으면
  `pending`으로 재조립 요청(`desegment_offset`/`desegment_len`).
- 이 동작은 스트림을 **1바이트 단위로** 재조립 시뮬레이션해도 원샷 파싱과
  100% 동일한 결과가 나오는 것으로 검증됐다(§8).

## 3. Layer 2/3 — RTS (SESS=0x08)

프레이밍은 `mas_rts.lua`가 담당한다. RTS payload는 **RTS-HEADER(6) +
RTS-DATA**의 반복이다(설계 문서 §1.3):

```
KIND(1)  DUMY(1)  TYPE(1)  LENGTH(3, ASCII 숫자)  RTS-DATA(LENGTH bytes, 끝에 NUL 포함)
```

- **KIND**: `D`=Data, `I`=RTS-Symbol 리스트. `I`는 KIND='D'와 레이아웃이
  다를 수 있는 별개의 레코드 종류라 TYPE 디스패치를 전혀 타지 않고
  `"kind: I"` 라벨 + raw data로만 표시된다(`mas_rts.lua`의 `add_rts`, TYPE
  값과 무관 — 우연히 TYPE이 구현된 값과 같아도 그 디코더로 넘어가지 않음).
- **DUMY**: 예비 (관측된 값은 항상 `'0'`).
- **TYPE**: 레코드 종류를 정하는 1글자. 실캡처에서 관측된 값:
  `B, C, D, U, Y, Z, c, m, y, V, F, J, ?`(0x3F).
- **LENGTH(3)**: RTS-DATA 길이, 최대 512.

공용 규칙(모든 TYPE에 적용, §7 참고): 서브트리는 항상 우산 proto `mas`로만
태그되고, Info 컬럼에는 `RTS`로만 집계되며, 상세창 라벨은 등록 여부와
무관하게 `"type: <TYPE> (<len> bytes)"` 형식으로 통일된다. 등록된 TYPE은
`mas.by_rts_type[TYPE] = { add = ..., init = ... }`로 디스패치되며, 필드
개수가 스펙과 안 맞으면 해당 TYPE 고유 필드는 하나도 채우지 않고 expert
info만 붙인다(디코드 성공 여부는 라벨이 아니라 `mas.rts.<TYPE>.*` 필드가
채워졌는지로만 판별).

### TYPE 구현 현황

| TYPE | 이름 | 필드 수 | 구현 파일 | 신뢰도 |
|---|---|---|---|---|
| `B` | 체결(Execution Price) | 39(NXT) / 36(KRX, §3.1) | `mas_rts_b.lua` | 높음 — 13,770건 이상(`tcp_capture.cap`의 1,777건 별도, §3.1) |
| `C` | 호가(Quote Price) | 128 | `mas_rts_c.lua` | 높음 — 979건, 항등식 교차검증 |
| `U` | 업종:등락(Sector Breadth) | 10 | `mas_rts_u.lua` | 중간 — 22건, 항등식 검증 |
| `V` | 해외:지수 | 11 | `mas_rts_v.lua` | 높음 — 260건 전건 일치 |
| `J` | 업종:시세(지수) | 13 | `mas_rts_j.lua` | 높음 — 42건 전건 일치 |
| `X` | 업종:예상지수 | 10 | `mas_rts_x.lua` | **낮음 — 실캡처 미관측, 스펙 예시로만 검증** |
| `F` | 주식:거래원 | 78 | `mas_rts_f.lua` | 낮음 — 5건뿐 |
| `Y` | 투자자QTY | 51 | `mas_rts_y.lua` | 높음 — 138건 전건 일치 |
| `Z` | 투자자AMT | 51 | `mas_rts_z.lua` | 높음 — 138건 전건 일치 |
| `m`(소문자) | 시황제목/통합뉴스 | 16 | `mas_rts_lm.lua` | 높음 — 75건 전건 일치 |
| `D`, 소문자 `c`/`y`, `?`(0x3F) | — | — | 미구현 | §7 참고 |

### 3.1 TYPE='B' 필드 레이아웃 (`inner/Execution_layout.txt`)

탭 구분 39필드, `E.FIELD_NAMES`(코드 순서 그대로):

```
issue_code sep trade_time price change change_rate ask_price bid_price
trade_volume acc_volume acc_value open_price high_price low_price prev_ratio
vwap per lp_balance lp_ratio market_cap trade_strength trade_strength_3m
trade_strength_10m trade_strength_30m trade_strength_60m trade_strength_5d
trade_strength_10d trade_strength_20d trade_strength_60d total_ask_qty
total_bid_qty ask_qty1 bid_qty1 lp_balance_change static_vi_upper
static_vi_lower trade_market nxt_vi_upper nxt_vi_lower
```

- `issue_code`는 접두어로 시장 구분: `"M."` → M(NXT?), `"N."` → N, 접두어 없음
  → `"K"`(KRX). `E.split_market()`.
- `sep`는 필드 개수/위치 정렬을 위해 `FIELD_NAMES`에는 남아 있지만 Wireshark
  필드로는 등록하지 않는다.
- **마지막 3필드(`trade_market`, `nxt_vi_upper`, `nxt_vi_lower`)는 NXT
  교차상장 종목에만 존재한다.** `issue_code`에 `"M."`/`"N."` 접두어가 붙은
  종목만 39필드 전부를 보내고, 접두어 없는(KRX 전용) 종목은 이 3필드를
  통째로 생략한 **36필드만** 보낸다(빈 문자열이 아니라 필드 자체가 없음).
  `E.decode`는 36/39 둘 다 유효로 받아들이고(`E.FIELD_NAMES_BASE_COUNT =
  36`), 36필드일 때는 저 3필드를 `rec`에서 아예 비워(nil) 상세창에도
  표시하지 않는다. `add_exec`의 필드 표시 루프도 `rec[name]`이 `nil`이면
  건너뛴다. 39/36 둘 다 아닌 진짜 손상 레코드만 `expert_badfields`로
  플래그된다.
- 파생 필드: `market`, `acc_volume_num`/`price_num`/`trade_volume_num`(정수),
  `reversed`(누적거래량 역전 탐지, 5-tuple+market+issue_code 단위, 프레임
  재방문 시에도 안정적인 idempotent 캐시).
- 필드: `mas.rts.B.<field>`(39필드 중 `sep` 제외), `mas.rts.B.market`,
  `mas.rts.B.acc_volume_num`, `mas.rts.B.price_num`,
  `mas.rts.B.trade_volume_num`, `mas.rts.B.reversed`.
- Statistics 창: **MAS/Execution Prices** — Market/Issue/Time/Price/TrdVol/
  AccVol/Reversed 컬럼, 5-tuple(Flow) 별 구분. tap 필터는 `mas.rts.B.market`.

### 3.2 TYPE='C' 필드 레이아웃 — 호가 (`mas_rts_c.lua`)

바디는 128 tab-분리 필드(127개 명명 필드 + 숨은 레코드타입 문자 `sep`='C'
1개). 매핑은 `named[0] → wire[0]`(Key=`issue_code`), `named[k] →
wire[k+1]`(k≥1, sep 1칸 건너뜀).

| wire | 필드명(영문) | 비고 |
|---|---|---|
| 0 | `issue_code` | |
| 1 | `sep`('C') | Wireshark 필드로 등록 안 함 |
| 2 | `trade_time` | `HHMMSS` |
| 3–12 | `ask_price1..10` | |
| 13–22 | `ask_qty1..10` | `= krx_ask_qty + nxt_ask_qty`(항등식 검증) |
| 23–32 | `ask_qty_chg1..10`(추정 명칭) | 존재/위치 확실, 의미(변동분/비율)는 추정 |
| 33–42 | `krx_ask_qty1..10` | |
| 43–52 | `nxt_ask_qty1..10` | |
| 53–62 | `bid_price1..10` | |
| 63–72 | `bid_qty1..10` | `= krx_bid_qty + nxt_bid_qty`(항등식 검증) |
| 73–82 | `bid_qty_chg1..10`(추정 명칭) | 존재/위치 확실, 의미는 추정 |
| 83–92 | `krx_bid_qty1..10` | |
| 93–102 | `nxt_bid_qty1..10` | |
| 103 | `total_ask_qty` | `= sum(ask_qty1..10) = krx_total_ask_qty + nxt_total_ask_qty` |
| 104 | `total_ask_qty_chg`(추정 명칭) | 존재/위치 확실, 의미는 추정 |
| 105 | `total_bid_qty` | `= sum(bid_qty1..10) = krx_total_bid_qty + nxt_total_bid_qty` |
| 106 | `total_bid_qty_chg`(추정 명칭) | 존재/위치 확실, 의미는 추정 |
| 107–113 | `expected_price`/`expected_qty`/`expected_change`/`expected_change_rate`/`expected_change_amt`/`expected_change_amt2`(추정)/`arbitrage_basis` | 장중 캡처에는 항상 0/공백(동시호가 이벤트 없음 — 미검증이 아니라 비활성 구간) |
| 114 | `net_buy_total_qty` | `= total_bid_qty - total_ask_qty`(부호 포함, 항등식 검증) |
| 115 | `expected_fill_qty_ratio` | 캡처 구간엔 항상 `0.00` |
| 116–123 | `nxt_mid_price`/`nxt_ask_mid_qty`/`nxt_bid_mid_qty`/`krx_mid_price`/`krx_ask_mid_qty`(추정 — 스펙 원문에 "KRX" 접두어 누락)/`krx_bid_mid_qty`/`nxt_mid_total_net_qty`/`mid_total_net_qty` | 캡처 구간엔 항상 0/`-0` |
| 124–125 | `krx_total_ask_qty`/`nxt_total_ask_qty` | 합이 `total_ask_qty`와 일치(항등식 검증) |
| 126–127 | `krx_total_bid_qty`/`nxt_total_bid_qty` | 합이 `total_bid_qty`와 일치(항등식 검증) |

- 구현 파일: `mas_rts_c.lua`. `Q.FIELD_NAMES`(128개), `Q.decode(body)`,
  `Q.split_market`(체결과 동일한 이슈코드 접두어 규칙).
- 필드: `mas.rts.C.<field>`(128필드 중 `sep` 제외), `mas.rts.C.market`.
- Statistics 창: 없음(요청 범위 밖).

### 3.3 TYPE='U' 필드 레이아웃 — 업종:등락 (`mas_rts_u.lua`)

개별 종목이 아니라 **시장/업종 전체의 등락 집계**(코스피·코스닥 등). 10
tab-분리 필드: `key, sep, trade_time, up_count, upper_limit_count,
flat_count, down_count, lower_limit_count, volume, value`.

- 구현 파일: `mas_rts_u.lua`. `S.FIELD_NAMES`(10개), `S.decode(body)`.
  첫 필드명이 `issue_code`가 아니라 `key`인 이유: 종목코드가 아니라
  시장/업종 키(예: `KQ001`, `K0001`)라 `split_market` 같은 접두어 분해는
  적용하지 않는다.
- 검증: `up_count + upper_limit_count + flat_count + down_count +
  lower_limit_count`가 코스피 표본에서 항상 **801**(코스피 상장종목 수),
  코스닥 표본에서 **1521~1523**(종목이 상승↔보합↔하락 카테고리를 넘나드는
  정상적인 틱 변동)과 일치.
- 필드: `mas.rts.U.<field>`(10필드 중 `sep` 제외).
- Statistics 창: 없음(요청 범위 밖).

### 3.4 TYPE='V' 필드 레이아웃 — 해외:지수 (`mas_rts_v.lua`)

CME/COMEX 선물이나 원/달러 환율 같은 **해외 지수·상품·환율**. 11
tab-분리 필드: `key, sep, trade_time, price, change, change_rate, volume,
open_price, high_price, low_price, date`(스펙: `inner/wireshark 추가.txt`).

- 구현 파일: `mas_rts_v.lua`. `V.FIELD_NAMES`(11개), `V.decode(body)`.
  `key`는 `"CME@NQ"`/`"USDKRWSMBS"`처럼 `@` 구분 심볼이라(KRX 종목코드의
  `.` 접두어 규칙과 다름) 접두어 분해는 적용하지 않는다.
- 필드: `mas.rts.V.<field>`(11필드 중 `sep` 제외).
- Statistics 창: 없음(요청 범위 밖).

### 3.5 TYPE='J' 필드 레이아웃 — 업종:시세(지수) (`mas_rts_j.lua`)

KOSPI/KOSDAQ 등 **업종 지수 자체의 시세**. 13 tab-분리 필드: `key, sep,
trade_time, index, change, change_rate, trade_volume, acc_volume, acc_value,
open_price, high_price, low_price, market_status`(스펙: `inner/wireshark
추가.txt`).

- 구현 파일: `mas_rts_j.lua`. `J.FIELD_NAMES`(13개), `J.decode(body)`.
  `key`는 §3.3/§3.4와 같은 이유로 업종 코드(예: `K2001`)라 접두어 분해를
  적용하지 않는다. `trade_volume`/`acc_volume`/`acc_value` 필드명은 §3.1의
  체결 필드 네이밍을 그대로 재사용했다(같은 "틱당 vs. 누적" 구분).
- 필드: `mas.rts.J.<field>`(13필드 중 `sep` 제외).
- Statistics 창: 없음(요청 범위 밖).

### 3.6 TYPE='X' 필드 레이아웃 — 업종:예상지수 (`mas_rts_x.lua`)

§3.5의 TYPE='J'와 같은 업종 지수지만 **"예상"(장 시작 전 등 추정치) 값**.
10 tab-분리 필드: `key, sep, trade_time, index, change, change_rate,
trade_volume, acc_volume, acc_value, market_status` — TYPE='J'와 거의 같은
구조지만 open/high/low_price 3개가 없다(추정치라 그 개념이 없는 것으로
보임).

- 구현 파일: `mas_rts_x.lua`. `X.FIELD_NAMES`(10개), `X.decode(body)`.
  `key`/`trade_volume`/`acc_volume`/`acc_value` 네이밍은 §3.5(TYPE='J')과
  동일한 이유로 그대로 재사용했다.
- **주의: 실캡처에서 TYPE='X'가 관측된 적이 없다.** 스펙 문서 자체의 예시
  행(`X0001 X 085512 -6614.54 -69.83 -1.04 630843 630843 6089856 0`,
  10필드)만으로 Wireshark Lua 스텁 디코드를 확인했다 — 필드 이름/의미는
  실측으로 검증되지 않았으니 실캡처가 확보되면 재검증할 것.
- 필드: `mas.rts.X.<field>`(10필드 중 `sep` 제외).
- Statistics 창: 없음(요청 범위 밖).

### 3.7 TYPE='F' 필드 레이아웃 — 주식:거래원 (`mas_rts_f.lua`)

종목별 **매도/매수 상위 5개 거래원(증권사) 랭킹**. 78 tab-분리 필드: 매도
거래원명/수량/금액/비중 5단×4그룹 + 매수 거래원명/수량/금액/비중 5단×4그룹
+ 외국인 매수/매도/순매수 수량·금액 6개 + 매도/매수 거래원코드 5단×2그룹 +
순매도%(코드 231~235)/순매수%(코드 236~240) 5단×2 + 매도/매수 증감
5단×2(스펙: `inner/wireshark 추가.txt`).

- 구현 파일: `mas_rts_f.lua`. `F.FIELD_NAMES`(78개), `F.decode(body)`.
  `issue_code`는 `"M.A005930"`처럼 §3.1/§3.2와 같은 마켓 접두어 규칙이라
  `split_market`을 그대로 적용한다(§3.3~§3.6의 `key`와 달리 진짜
  종목코드).
- **스펙 정정**: 원 스펙 문서는 코드 231~235와 236~240을 똑같이
  `순매수%1~5`로 표기했으나, **231~235는 실제로 `순매도%1~5`(net SELL
  %)**다 — 236~240만 `순매수%1~5`(net BUY %)가 맞다. 필드명은
  `net_sell_pct1..5`/`net_buy_pct1..5`(다른 필드와 동일하게 `ladder()`
  헬퍼로 생성).
- **주의: 실측 5건뿐**(§3.2/§3.5 등 100건대보다 신뢰도 낮음). 5건 전부
  정확히 78개 tab-구분 필드로 쪼개짐은 확인됐다.
- 필드: `mas.rts.F.<field>`(78필드 중 `sep` 제외) + `mas.rts.F.market`.
- Statistics 창: 없음(요청 범위 밖).

### 3.8 TYPE='Y' 필드 레이아웃 — 투자자QTY (`mas_rts_y.lua`)

**16개 투자자 구분별 매도/매수/순매수 수량**. 51 tab-분리 필드: `key, sep,
trade_time` + 16개 구분×3(매도QTY/매수QTY/순매수Q)(스펙: `inner/wireshark
추가.txt`).

- 구현 파일: `mas_rts_y.lua`. `Y.FIELD_NAMES`(51개), `Y.decode(body)`.
  `key`는 §3.3~§3.6과 같은 이유로 시장 키(예: `"0500000000"`)라 접두어
  분해를 적용하지 않는다.
- **네이밍 주의**: 스펙의 16개 투자자 구분 코드(`101,102,...,110,130,131,
  160,170,171,190` — 매수는 +100, 순매수는 +200)에 구분 이름이 전혀 없어서
  (예: 어느 게 "개인"/"외국인"/"기관"인지 불명) 의미를 추측하지 않고
  **스펙 코드 번호 그대로**(`sell_qty_101`, `buy_qty_201`,
  `net_buy_qty_301`, ...) 필드명을 지었다.
- 필드: `mas.rts.Y.<field>`(51필드 중 `sep` 제외).
- Statistics 창: 없음(요청 범위 밖).

### 3.9 TYPE='Z' 필드 레이아웃 — 투자자AMT (`mas_rts_z.lua`)

§3.8(TYPE='Y')과 완전히 같은 구조지만 **수량 대신 금액**. 51 tab-분리
필드: `key, sep, trade_time` + 16개 구분×3(매도AMT/매수AMT/순매수A). 스펙
코드가 TYPE='Y'의 코드 + 400(예: Y의 `101` → Z의 `501`)이라 **같은 16개
투자자 구분을 가리키는 게 거의 확실**하다(단, 필드명은 각 타입 자기 코드를
그대로 쓴다).

- 구현 파일: `mas_rts_z.lua`. `Z.FIELD_NAMES`(51개), `Z.decode(body)`.
  `key`도 §3.8과 동일하게 접두어 분해를 적용하지 않는다.
- **네이밍**: `sell_amt_501`, `buy_amt_601`, `net_buy_amt_701`, ... 처럼
  §3.8과 동일한 이유로 스펙 코드 번호(`501,502,...,510,530,531,560,570,
  571,590`)를 그대로 필드명에 썼다.
- 필드: `mas.rts.Z.<field>`(51필드 중 `sep` 제외).
- Statistics 창: 없음(요청 범위 밖).

### 3.10 TYPE='m'(소문자) 필드 레이아웃 — 시황제목/통합뉴스 (`mas_rts_lm.lua`)

**뉴스 헤드라인 + 관련 종목 정보 + 제공처 메타데이터**. 16 tab-분리
필드: `key, sep, content, issue_code, issue_name, key1, key2, time,
category, category2, provider, date, price, volume, change_sign,
key3`(스펙: `inner/wireshark 추가.txt`).

- 파일명이 `mas_rts_lm.lua`("lower m")인 이유는 §6의 소문자 TYPE 네이밍
  규칙 참고. 등록 키(`mas.by_rts_type["m"]`), 라벨(`"type: m"`), Wireshark
  필터(`mas.rts.m.*`)는 파일명과 무관하게 실제 와이어 바이트 그대로 소문자
  `m`이다.
- 구현 파일: `mas_rts_lm.lua`. `LM.FIELD_NAMES`(16개), `LM.decode(body)`.
- **필드명 주의**: `category`/`category2`가 실측에서 "한차"/"한경차이나",
  "아경"/"아시아경제"처럼 뉴스 제공처의 약칭/전체명으로 보이는 값을 담고
  있어("분류"라는 스펙 라벨의 문자 그대로 의미와는 달라 보임) 확실한
  의미를 확정하지 못했다 — 필드명은 스펙의 한글 라벨을 그대로 직역한
  것이고, 의미를 임의로 추측해 재작명하지 않았다.
- **EUC-KR 처리**: `content`(헤드라인)/`issue_name`/`category`/`category2`가
  EUC-KR이라, `mas_tr_90.lua`(주문결과)·`mas_rts_f.lua`(거래원)와 동일하게
  바디 전체를 EUC-KR→UTF-8로 변환한 뒤 tab-분리한다(탭 0x09는 멀티바이트
  시퀀스 안에 나타나지 않아 분리 결과가 그대로 맞다).
- 필드: `mas.rts.m.<field>`(16필드 중 `sep` 제외).
- Statistics 창: 없음(요청 범위 밖).

## 4. Layer 2/3 — Transaction (SESS=0x01)

프레이밍은 `mas_tr.lua`가 담당한다. Transaction payload는
**AXIS-HEADER(24) + TR-DATA**(설계 문서 §1.2):

```
MSGK(1) ACTF(1) CHKF(1) XWIN(1) YWIN(1) KEYV(2) SVCC(4) TRNM(8) LENGTH(5, ASCII)
```

- **MSGK**: 트랜잭션 종류. `0x20` Normal, `0x50` RTS, `0x80` 키교환,
  `0x81` 공인인증키, **`0x90` UMP(실시간주문체결)**, `0x91` Dialog Popup,
  `0x92` 에러, `0x5f` RTS On/Off.
- **ACTF**: 비트 플래그. **`0x02` 암호화(Xecure/XecureMobile)**,
  `0x08` 연속데이터, `0x80` 에러헤더 포함.
- **CHKF**: `0x08` 공인인증서 포함, `0x10` OOP(FID) Transaction.
- **XWIN/YWIN**: RTS 전용 윈도우 ID(주요/보조). Transaction 일반에는 큰 의미 없음.
- **SVCC(4)**: 화면번호.
- **TRNM(8)**: Transaction 명 (예: `PIBOKMAX`, `noopstok`).
- **LENGTH(5)**: AXIS 헤더 제외한 TR-DATA 길이. 실측 검증 결과 항상
  G/W LENGTH − 24와 일치.

**이 프로젝트가 디코드하는 것은 `MSGK=0x90`(UMP) + 비암호화(ACTF bit
0x02 미설정)인 경우뿐이다.** 그 외(다른 MSGK, 또는 암호화된 UMP)는
AXIS-HEADER 필드만 표시하고 TR-DATA는 `mas.data`(raw)로 남긴다(§7).

### MSGK=0x90 TR-DATA 포맷 — 코드/값 스트림 (`inner/Order_layout.txt`)

```
<code>\t<value>\t<code>\t<value>\t ... \t<code>\t<value>\t
```

- 탭으로 구분된 `코드\t값` 쌍이 **가변 개수**로 반복. 코드는 3자리 숫자 문자열.
- 각 쌍 뒤에도 탭이 붙으므로 마지막 값 뒤에 탭 하나가 더 있고, 그 뒤 NUL로
  종료된다 — `decode_order`는 홀수 개로 남는 마지막(빈) 토큰을 정상적으로 무시.
- **인코딩은 EUC-KR.** Wireshark 측에서는
  `tvb(...):string(ENC_EUC_KR)`로 UTF-8 변환 후 분리한다(탭 0x09는 EUC-KR/UTF-8
  멀티바이트 시퀀스 내부에 나타나지 않으므로 변환 후 분리해도 안전).
  `ENC_EUC_KR`을 지원하지 않는 Wireshark 빌드에서는 한글 필드(예: 종목명)가
  깨질 수 있다.
- 코드 사전은 `O.ORDER_FIELDS`(46개, 원본 `Order_layout.txt` 순서 그대로).
  중복 레이블(`처리구분`=973/983/977, `주문번호`=952/969, `원주문번호`=961/970)은
  Wireshark 필드명에 `(code)`를 접미해 구분한다(예: `process_type (973)`,
  `process_type (983)`, `process_type (977)`). 필드명은 packet detail 창
  표시 규칙에 따라 모두 소문자, 단어 조합은 `snake_case`(예: `account_no`,
  `order_method (exchange)`).
- 사전에 없는 코드는 `mas.tr.90.unknown`(문자열 `"code=value"`)으로 표시.

### Wireshark 매핑

- 코드 필드: `mas.tr.90.<code>`(46개), `mas.tr.90.unknown`. AXIS-HEADER 공용
  필드는 `mas.tr.msgk`(value-string 포함)/`mas.tr.actf`/`mas.tr.encrypted`
  (파생 bool)/`mas.tr.svcc`/`mas.tr.trnm`/`mas.tr.length`(`mas_tr.lua` 소유,
  모든 Transaction MSGK에 공통 적용).
- "실제로 디코드됐는가"는 값 필터 `mas.tr.msgk == 0x90 && !mas.tr.encrypted`
  또는 디코드 성공 시에만 채워지는 `mas.tr.90.<code>` 필드로 구분한다(§7.3).
- Statistics 창: **MAS/UMP** — Account No(950) / Order No(952) /
  Branch No(975) / Order No(969) / Order Method(951) / Issue Code(953) /
  Process Type(977) / Order Qty(957) / Order Price(958) 컬럼, 5-tuple(Flow)
  별 구분. 코드가 없는 메시지는 그 칸이 빈 값으로 표시된다.
  ⚠️ 한 프레임에 여러 주문 메시지가 섞이고 그중 일부가 코드 구성이 다르면,
  칼럼별 발생 목록을 인덱스로 zip하는 방식(`open_stream_window`) 특성상 그
  프레임 내 행이 어긋날 수 있음(§6).

## 5. Transaction MSGK 구현 현황

| MSGK | 이름 | 상태 |
|---|---|---|
| `0x90` | UMP(주문 결과) | **구현됨**(`mas_tr_90.lua`) |
| `0x20` | Normal | 미구현 — AXIS-HEADER만 표시 |
| `0x50` | RTS | 미구현 |
| `0x5f` | RTS On/Off | `mas.MSGK_NAMES`에는 있으나 디코더 없음 |
| `0x80` | 키교환 | 〃 |
| `0x81` | 공인인증키 | 〃 |
| `0x91` | Dialog Popup | 〃 |
| `0x92` | 에러 | 〃 |
| `0x14` | — | `mas.MSGK_NAMES` 사전에도 없는 값. 페이로드가 바이너리라 암호화(ACTF)로 추정되나 미확인 |

## 6. 구현 규칙

### 6.1 "숫자로 보이는 필드"는 ASCII char[]인지 real 이진값인지 구분

이 프로토콜에는 **겉보기엔 숫자인데 실제로는 두 가지 서로 다른 방식**으로
인코딩된 필드가 섞여 있다. ProtoField를 등록할 때 이 둘을 혼동하면 잘못된
값이 표시되거나(또는 Wireshark가 필드 크기 불일치로 오류를 낸다).

- **ASCII 문자 배열로 인코딩된 숫자** (예: `123` → 바이트 `'1' '2' '3'`,
  즉 `0x31 0x32 0x33`): 모든 `LENGTH` 계열 필드가 여기 해당한다 —
  G/W HEADER LENGTH(5), RTS-HEADER LENGTH(3), AXIS-HEADER LENGTH(5). 이런
  필드는 **반드시 먼저 문자열을 `tonumber()`로 파싱**해 Lua 숫자를 얻은 뒤,
  `tree:add(field, tvbrange, parsed_value)`처럼 **파싱된 값을 3번째 인자로
  명시적으로 넘겨야** 한다. `tvbrange`는 원본 ASCII 바이트를 패킷 뷰에서
  하이라이트하는 용도일 뿐, 필드의 표시값 자체는 아니다. 3번째 인자를
  생략하면 Wireshark가 그 ASCII 바이트열을 **원시 이진수로 재해석**하려
  시도해 엉뚱한 값이 나오거나(필드 타입이 요구하는 바이트 수와 어긋나면)
  오류가 난다.
  - 체결/호가 등 tab-분리 숫자 필드(`price`, `acc_volume` 등)와 주문 코드
    필드(`mas.tr.90.<code>`) 자체는 `ProtoField.string`으로 등록되어 있어
    원본 문자 그대로("+206000", "0000037389" 등) 표시된다 — 이미 char[]
    그대로 맞는 처리다. 여기서 파생된 `mas.rts.B.acc_volume_num` 등 정수
    필드만 위와 같은 명시적 파싱 규칙을 따른다.
- **진짜 1바이트 이진값(enum/플래그)**: `CTRL`, `SESS`, `CHCK`, `MSGK`,
  `ACTF` 등은 실캡처로 검증한 결과 `0x01`, `0x08`, `0x20`, `0x90` 같은
  **진짜 낮은 값의 raw 바이트**이지 ASCII 숫자 문자('0','1',...)가 아니다.
  이들은 `tvbrange`만 넘겨도(`tree:add(field, tvbrange)`) 올바르게
  해석된다 — 파싱이 필요 없다.

새 필드를 추가할 때 "숫자처럼 보이는" 필드를 만나면 이 표를 먼저 확인할 것.

### 6.2 Info 컬럼: SESS 레벨 4종(포함 메시지 수 기준) + 재조립 마커

패킷 목록 창의 Info 컬럼은 **`(#N)RTS:n Transaction:m POLL Unspecified`
형식**으로만 표시한다.

- 분류는 **디코드 성공 여부와 무관하게 G/W HEADER의 CTRL/SESS만으로** 결정된다:
  CTRL=POLL이면 `POLL`, 그 외 SESS=0x08이면 `RTS`, SESS=0x01이면
  `Transaction`. 즉 압축된 프레임이나 TYPE/MSGK가 지원 범위 밖이라 상세창의
  TYPE/MSGK 고유 필드가 하나도 채워지지 않는 프레임도 Info에서는 그대로
  `RTS`/`Transaction`에 집계된다 — Info는 "이 프레임이 어떤 종류의 MAS
  트래픽인가"만 보여주고, "내용을 이해했는가"는 상세창의 몫이다.
- **`n`/`m`은 "G/W 프레임 개수"가 아니라 "그 안에 실제로 담긴 메시지 개수"다.**
  RTS(SESS=0x08)의 payload는 `RTS-HEADER(6)+RTS-DATA`가 **반복**되는 구조라
  한 G/W 프레임에 레코드가 여러 개(구현된 TYPE + 미해독 TYPE 합산) 들어갈 수
  있으므로, `RTS:n`의 `n`은 **그 프레임(들)에 담긴 RTS-DATA 레코드 총합**이다
  (구현 여부를 구분하지 않고 더한다). 반대로 Transaction(SESS=0x01)의
  payload는 `AXIS-HEADER+TR-DATA` 하나뿐이라 한 G/W 프레임이 항상 정확히
  메시지 1개 — 그래서 `Transaction:m`의 `m`은 사실상 Transaction G/W 프레임
  개수와 같다. **payload가 압축(CHCK bit `0x02`)돼 안에 몇 개가 들었는지 알
  수 없는 경우는 그 프레임 자체를 1개로 센다**(원본을 볼 수 없으니 그
  이상 세분화할 수 없다는 뜻).
- **`RTS`/`Transaction`은 건수가 1이어도 항상 `:count`를 붙인다**(`RTS:1`도
  생략하지 않는다) — "포함된 메시지 수"라는 의미 자체가 1일 때도 유용한
  정보이기 때문이다. **`POLL`/`Unspecified`는 건수를 절대 표시하지
  않는다** — 몇 건이든 그냥 `POLL`/`Unspecified`.
- **CTRL/SESS 조합은 RTS/Transaction/POLL 세 가지 외에도 규격상 얼마든지
  나올 수 있다**(ACK/NAK/CheckSession, SESS=SessionEnd 등). 이런 프레임과,
  G/W 헤더조차 못 이루는 순수 junk 바이트는 전부 **`Unspecified`라는 네 번째
  버킷**으로 집계된다(이쪽은 프레임 단위 1개, "포함된 메시지 수" 개념이 없다).
  `Unspecified`는 다른 셋을 밀어내는 대체값이 아니라 **독립적으로 공존하는
  값**이다 — 한 프레임에 체결 RTS와 이해 못 한 잡음이 같이 있으면
  `RTS:1 Unspecified `처럼 둘 다 나온다.
- **순서는 항상 `RTS` → `Transaction` → `POLL` → `Unspecified` 고정**이다
  (프레임 안에서 바이트가 등장한 순서가 아니라, 값이 있는 라벨만 이 순서로
  나열).
- 넷 다 0건인 경우(즉 이 dissector 호출에서 아무 G/W 항목도 만들어지지 않은
  극히 드문 경우, 예: 재조립 대기 중인 미확정 바이트 1개뿐)는 Info가 그냥
  **`Unspecified`** 하나다.
- **`(#N)`은 이 프레임이 이전 프레임(N번)의 잘린 메시지를 이어받아 재조립한
  경우에만** 맨 앞에 붙는다(`carry`/`cont_from`, `pending`이 설정됐던 프레임을
  가리킴). 재조립이 아닌 일반 프레임에는 절대 붙지 않는다.

구현은 `mas.lua`의 dissector 루프에서, RTS/Transaction 프레임에 대해
`mas.by_sess[sess].add(...)`가 **담긴 메시지 개수를 반환**하도록 하고(RTS는
`mas_rts.lua`의 `add_rts`가 `#recs`를 반환, Transaction은 `mas_tr.lua`의
`add_transaction`이 반환값 없이 `nil`→기본값 1로 처리) 그 값을
`cnt.RTS`/`cnt.Transaction`에 더한다. 압축 프레임이나 핸들러가 없는 경우는
기본값 1을 그대로 쓴다. TYPE/MSGK별 3계층 디코더는 Info 라벨이나 카운팅에
전혀 관여하지 않는다 — 그건 2계층 파일(`mas_rts.lua`/`mas_tr.lua`)과
`mas.lua`만의 책임이다. **Info 표시를 바꾸려면 `mas.lua`의 이 카운팅
블록과, RTS의 경우 `mas_rts.lua`의 `add_rts` 반환값 계산 부분을 고치면
된다.**

### 6.3 필터 설계: 단일 proto(`mas`) + 필드값 기반 세부 필터

이 플러그인 전체에서 등록되는 Proto는 **`mas` 단 하나뿐**이다. TYPE/MSGK,
디코드 성공/실패와 무관하게 **모든 서브트리는 언제나 우산 proto
(`mas.proto`)로만 태그**한다. 파일마다(새 TYPE/MSGK 디코더 파일 포함) 다음
패턴을 쓴다:

```lua
mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")
...
mas.proto.fields = { <이 파일이 정의하는 ProtoField들> }
mas.proto.experts = { <이 파일이 정의하는 ProtoExpert들> }   -- 있는 파일만
```

`Proto.fields`/`Proto.experts`는 **누적(append) setter**다 — 같은 Proto에
여러 파일이 각자 다른(겹치지 않는) 필드를 여러 번 대입해도 이전에 등록된
필드가 사라지지 않고 전부 함께 등록된다(wslua 소스
`epan/wslua/wslua_proto.c`의 `Proto_set_fields`/`Proto_set_experts` 확인).
`mas.proto = mas.proto or Proto(...)` 가드 덕분에 **어느 파일이 먼저
로드되어 `mas.proto`를 실제로 만들든 상관없다**(§6의 "로드 순서 독립적"
원칙과 동일). 그 결과 Wireshark의 Enabled-Protocols 목록/필터 자동완성에
이 플러그인이 노출하는 프로토콜은 `mas` 하나뿐이다.

**왜 proto를 TYPE/MSGK별로 나누지 않는가**: `mas.rts.B`/`mas.tr.90` 같은
바깥(bare) 프로토콜 필터는 "이 프레임에 해당 프로토콜의 트리 항목이
있는가"로 판정되는데, "지원 범위 밖" 서브트리까지 같은 proto로 태그하면
그 필터가 "체결 레코드가 있는 프레임"이 아니라 "RTS 프레임이면 전부"처럼
느슨해진다. 반대로 proto를 엄격히 나누면 `mas.rts`류의 존재 필터가 압축/
0바이트/헤더 손상 프레임을 누락하는 등 헤더 **필드값** 필터
(`mas.ctrl`/`mas.sess`/`mas.rts.type`/`mas.tr.msgk`)와 조건이 미묘하게
어긋난다. 그래서 존재(bare) 기반 필터 자체를 쓰지 않고, **세부 필터는
항상 필드값으로 한다**:

- TYPE/MSGK로 거르기: `mas.rts.type == "B"`, `mas.tr.msgk == 0x90` (공용
  헤더 필드라 디코드 성공 여부와 무관하게 항상 채워짐).
- "실제로 디코드까지 성공했는가": 디코드 성공 시에만 채워지는 그 TYPE/MSGK
  고유 필드를 bare로 쓴다 — 예: `mas.rts.B.market`(체결/호가는 성공 시 항상
  채워짐), `mas.tr.90.950`(주문 결과는 코드가 메시지마다 달라 완벽한 대응
  필드는 없지만 실무적으로 충분). 리프 필드는 정확히 그 필드를 추가한
  코드 경로에서만 존재해 프로토 태깅과 같은 모호함이 생기지 않는다.
- `mas.rts_add_header`/`add_axis_header`가 채우는 공용 헤더 필드
  (`mas.rts.kind`/`mas.rts.type`/`mas.rts.reclen`, `mas.tr.msgk`/`mas.tr.actf`/
  `mas.tr.encrypted`/`mas.tr.svcc`/`mas.tr.trnm`/`mas.tr.length`)는 서브트리가
  어느 proto로 태그되든 실제 바이트에서 그대로 추출되므로 이 원칙과
  무관하게 항상 유효하다.

`mas.open_stream_window`를 호출하는 두 Statistics 창(§3.1 MAS/Execution
Prices, §4 MAS/UMP)의 tap 필터도 이 원칙에 맞춰 값 필터를 쓴다 —
`mas_rts_b.lua`는 `mas.rts.B.market`, `mas_tr_90.lua`는 `mas.tr.msgk == 0x90
&& !mas.tr.encrypted`.

**새로운 "지원 범위 밖" 표시를 추가할 때는 항상 이 패턴을 따를 것**:
서브트리는 무조건 `mas.proto`로 태그하고, 디코드 성공 표시는 라벨 문자열 +
(필요하면) 성공 시에만 채워지는 필드로만 한다. proto 태깅으로 존재
필터를 만들려는 시도는 하지 말 것.

### 6.4 인식은 포트가 아니라 내용(`mas.scan`)으로만 — Decode As 호환

인식은 순수하게 **`mas.scan`이 실제로 `FE FE` G/W 프레임을 찾아내는가**로만
판단한다. `proto.dissector` 내부에는 포트 재검사가 없다.

- `apply_port()`가 `tcp.port` 테이블에 등록하는 Preferences 포트(기본
  15201)는 **"자동으로 이 dissector를 호출시키는 트리거" 역할**만 한다(그
  포트를 쓰는 캡처를 열면 자동으로 MAS로 시도됨). 하지만 일단
  `proto.dissector`가 호출된 뒤에는 포트를 다시 확인하지 않는다.
- **Decode As는 어떤 포트/방향에 적용해도 그대로 동작**한다 — 실제로 MAS
  프레임이 있으면 정상 해석되고, 없으면 조용히 거부되는 대신
  **`Unspecified`로 표시**된다(§6.2와 동일한 원칙: 이해 못 한 내용도 일단
  claim한 뒤 Info/상세창에 정직하게 "모르겠다"고 보여준다).
- **트레이드오프**: "TCP이면서 지정된 src port에서 전송되는 것만 MAS로
  인식"하는 규칙은 없다. Preferences 포트를 쓰는 스트림은 **양방향
  모두**(클라이언트→서버 포함) dissect 대상이 되며, MAS로 보이지 않는
  내용은 `Unspecified`로 표시될 뿐 무시되지 않는다. 이는 Decode As를
  포기하지 않는 한 되돌릴 수 없는 근본적 트레이드오프다.

### 6.5 상세창 라벨: `"type: <TYPE>"` / `"msgk: <name> (0x<hex>)"`

TYPE(RTS-HEADER)과 MSGK(AXIS-HEADER)는 **디코드 성공 여부와 무관하게 항상
헤더에서 읽을 수 있는 값**이므로, 라벨이 아니라 필드값으로 성공 여부를
구분한다:

- RTS: `mas_rts.lua`의 `add_rts`가 모든 TYPE(등록/미등록 무관)의 서브트리에
  `"type: " .. r.type .. " (" .. r.len .. " bytes)"`를 붙인다 — 등록된
  TYPE의 디코더가 자기 서브트리에 붙이는 라벨과 완전히 같은 형식이다.
- Transaction: `mas_tr.lua`의 `add_transaction`이 `mas.MSGK_NAMES[msgk_byte]`
  로 `"msgk: " .. name .. " (0x" .. msgk_byte .. ")"`를 만들어 **등록
  여부·암호화 여부와 무관하게 항상** 붙인다(`mas.MSGK_NAMES`에 없는 값이면
  `msgk: ? (0x14)`처럼 이름 자리에 `?`).
- 예외 — RTS KIND='I': KIND='D'와 레이아웃이 다를 수 있는 별개의 레코드
  종류라(§3) TYPE 디스패치를 아예 타지 않고 `"kind: I"`로 라벨링된다(TYPE
  값이 우연히 구현된 값과 같아도 그 디코더로 넘어가지 않음).

`"Unspecified RTS"`/`"Unspecified Transaction"` 같은 별도 라벨은 코드
어디에도 없다. 디코드 성공 여부는 오직 그 서브트리 밑에 TYPE/MSGK 고유
필드가 실제로 채워져 있는지(예: `mas.rts.B.market`, `mas.tr.90.950`)로만
구분한다 — 라벨만 보고는 "이 레코드가 해석됐는지" 알 수 없고, 반드시
필드를 확인해야 한다. 새 TYPE/MSGK 디코더를 추가해도 이 라벨은
`mas_rts.lua`/`mas_tr.lua`가 이미 만들어 주므로 3계층 파일은 라벨을 신경
쓸 필요가 없다.

## 7. 미해독/미구현 영역과 확장 방법

| 구분 | 값 | 이유 |
|---|---|---|
| RTS 압축 | CHCK bit `0x02`(LZO) | 압축 해제 로직 자체가 없어 내부 TYPE 전혀 알 수 없음(구현 보류 결정, 아래 참고) |
| Transaction 암호화 | ACTF bit `0x02`(Xecure/XecureMobile) | 키 없음 |
| RTS TYPE `D` | 80필드 추정 | 스펙 없음 |
| RTS TYPE 소문자 `c` | 대문자 C와 별개 TYPE | 스펙 없음 |
| RTS TYPE 소문자 `y` | 대문자 Y와 별개 TYPE | 스펙 없음 |
| RTS TYPE `?`(0x3F) | 항상 14B, `ATM` 레코드(`issue_code\tsep\t값`) | 신규 발견, 스펙 없음, 용도 미상 |
| RTS KIND `I` | RTS-Symbol 리스트 | KIND='D'와 레이아웃이 다를 수 있어 TYPE 디스패치 자체를 안 탐(설계 결정) |
| Transaction MSGK `0x20`/`0x50`/`0x5f`/`0x80`/`0x81`/`0x91`/`0x92` | §5 참고 | 요청 범위 밖(주문체결·체결시세만 지원) |
| Transaction MSGK `0x14` | `mas.MSGK_NAMES` 사전에도 없음 | 암호화 추정, 미확인 |

**RTS 압축(LZO) 미구현 방침**: 설계 문서상 대량데이터 흐름은 "구간
암호화(Xecure Mobile) 후 압축(LZO)" 순서라, 압축 프레임은 암호화도 함께
걸려 있는 게 정상 동작으로 보인다(실제로 `liblzo2`의 표준 디코더로는
실캡처 압축 프레임이 풀리지 않음 — 표준 LZO가 아니거나 암호화가 섞여
있다는 뜻). 암호화가 항상 같이 걸려 있다면 압축만 풀어도 여전히
암호문이라 실익이 없으므로, **압축 해제 단독 구현은 하지 않는다.**
재개하려면 Xecure Mobile 복호화(키 교환 포함)를 먼저 확보해 "복호화 →
압축 해제" 순서로 함께 접근해야 한다.

새 TYPE/MSGK를 구현하려면:

1. 해당 레이아웃(필드 사전 또는 위치 스키마)을 확보한다.
2. `mas_rts_b.lua`/`mas_tr_90.lua`와 같은 패턴(필드명 테이블 + `decode`
   함수 + ProtoField 등록 + `add_*` 함수)으로 **새 파일**을 만들고, RTS
   TYPE이면 `mas.by_rts_type[TYPE]`에, Transaction MSGK이면
   `mas.by_msgk[MSGK]`에 등록한다(§8). `mas_rts.lua`/`mas_tr.lua`는
   건드릴 필요 없다.
3. 압축/암호화 해제가 가능해지면, `mas.lua`의 `CHCK bit 0x02`/`ACTF bit
   0x02` 분기에서 raw로 처리하기 전에 압축해제/복호화 함수를 끼워 넣고,
   그 결과를 다시 `mas.scan`(RTS의 경우 이미 페이로드 형태) 또는 해당
   스트림 모듈의 파서에 넘기면 된다.

## 8. 파일 구조와 조율 방식

"SESS 계층 프레이밍/디스패치"와 "TYPE/MSGK별 실제 디코더"를 분리한
**3계층 구조**로 설계됐다 — 각 디코더가 자기 파일 하나로 독립적으로
추가/삭제될 수 있어, 새 TYPE/MSGK를 추가할 때 2계층 파일
(`mas_rts.lua`/`mas_tr.lua`)을 건드릴 필요가 없다.

| 파일 | 계층 | 역할 |
|---|---|---|
| `mas.lua` | 1 (G/W) | G/W 헤더 프레이밍(`mas.scan`), 우산 proto(`mas`) + dissector, TCP 재조립, Info 컬럼 소유, 공용 Statistics 창(`mas.open_stream_window`) |
| `mas_rts.lua` | 2 (RTS) | SESS=0x08 등록, RTS-HEADER 파싱(`split_records`), 공용 헤더 필드(`mas.rts.*`), TYPE별 디스패치(`mas.by_rts_type`), 미등록 TYPE도 `"type: <TYPE>"` 라벨로 표시(§6.5) |
| `mas_tr.lua` | 2 (Transaction) | SESS=0x01 등록, AXIS-HEADER 파싱, 공용 헤더 필드(`mas.tr.*`), MSGK별 디스패치(`mas.by_msgk`), 미등록/암호화 MSGK도 `"msgk: <name> (0x<hex>)"` 라벨로 표시(§6.5) |
| `mas_rts_b.lua` | 3 (RTS TYPE='B') | 체결 시세 디코드, `mas.rts.B.*` 필드, MAS/Execution Prices 창. `mas.by_rts_type["B"]`에 등록 (§3.1) |
| `mas_rts_c.lua` | 3 (RTS TYPE='C') | 호가 시세 디코드, `mas.rts.C.*` 필드. `mas.by_rts_type["C"]`에 등록 (§3.2) |
| `mas_rts_u.lua` | 3 (RTS TYPE='U') | 업종:등락 디코드, `mas.rts.U.*` 필드. `mas.by_rts_type["U"]`에 등록 (§3.3) |
| `mas_rts_v.lua` | 3 (RTS TYPE='V') | 해외:지수 디코드, `mas.rts.V.*` 필드. `mas.by_rts_type["V"]`에 등록 (§3.4) |
| `mas_rts_j.lua` | 3 (RTS TYPE='J') | 업종:시세(지수) 디코드, `mas.rts.J.*` 필드. `mas.by_rts_type["J"]`에 등록 (§3.5) |
| `mas_rts_x.lua` | 3 (RTS TYPE='X') | 업종:예상지수 디코드(실캡처 미검증, §3.6), `mas.rts.X.*` 필드. `mas.by_rts_type["X"]`에 등록 |
| `mas_rts_f.lua` | 3 (RTS TYPE='F') | 주식:거래원 디코드(샘플 5건, §3.7), `mas.rts.F.*` 필드. `mas.by_rts_type["F"]`에 등록 |
| `mas_rts_y.lua` | 3 (RTS TYPE='Y') | 투자자QTY 디코드, `mas.rts.Y.*` 필드. `mas.by_rts_type["Y"]`에 등록 (§3.8) |
| `mas_rts_z.lua` | 3 (RTS TYPE='Z') | 투자자AMT 디코드, `mas.rts.Z.*` 필드. `mas.by_rts_type["Z"]`에 등록 (§3.9) |
| `mas_rts_lm.lua` | 3 (RTS TYPE='m', 소문자) | 시황제목/통합뉴스 디코드, `mas.rts.m.*` 필드. `mas.by_rts_type["m"]`에 등록 (§3.10, 파일명은 "lower m") |
| `mas_tr_90.lua` | 3 (Transaction MSGK=0x90) | 주문 결과 디코드, `mas.tr.90.*` 필드, MAS/UMP 창. `mas.by_msgk[0x90]`에 등록 |

- 조율은 `_G.mas` 공유 전역으로 이뤄지며, 각 파일이 자기 레지스트리 테이블을
  방어적으로 초기화한다(`mas.by_sess = mas.by_sess or {}` 등) — **로드 순서
  독립적**(어느 파일이 먼저 로드돼도 동작. 실제 등록은 파일 로드 시점에
  일어나지만, 등록된 함수가 호출되는 건 항상 모든 파일이 로드된 뒤인 패킷
  디섹션 시점이라 순서에 의존하지 않는다).
- 2계층 파일(`mas_rts.lua`/`mas_tr.lua`)의 `add(gw, tvb, poff, plen,
  payload, pinfo)`가 실제 Info 컬럼 집계용 반환값(포함된 메시지 수)을
  `mas.lua`에 돌려준다 — RTS는 레코드 수(`#recs`), Transaction은 프레임당 항상
  1개라 반환하지 않고 `mas.lua`가 기본값 1을 쓴다.
- 3계층 파일이 등록하는 값의 형태:
  - RTS: `mas.by_rts_type[TYPE] = { add = function(gw, tvb, poff, r, pinfo, idx) ... end, init = ... }`.
    서브트리는 항상 우산 `mas`로 태그되며(§6.3), **디코드 성공/실패에 따라
    그 TYPE 고유 필드를 채울지 말지만 3계층 파일이 직접 결정**한다(필드
    개수가 안 맞으면 필드는 하나도 안 채우고 expert info만 붙인다). 2계층
    파일은 헤더 필드 추가 헬퍼(`mas.rts_add_header`)만 제공한다.
  - Transaction: `mas.by_msgk[MSGK] = { add =
    function(sub, tvb, poff, plen, pinfo) ... end }`. 상세창 라벨(`msgk: <name>
    (0x<hex>)`)은 MSGK 등록 여부·암호화 여부와 무관하게 `mas.MSGK_NAMES`에서
    항상 동일하게 만들어지므로(§6.5) 3계층 파일은 라벨을 따로 넘기지 않는다.
    서브트리는 여기서도 항상 우산 `mas`로 태그된다(2계층 파일 `mas_tr.lua`의
    `add_transaction`이 MSGK/암호화 여부로 `will_decode`만 판단해 헤더 필드를
    채우고 3계층 파일을 부를지 결정한 뒤 넘겨준다).
- 새 메시지 타입을 추가하려면: RTS면 `mas_rts_c.lua`(TYPE='C', §3.2)처럼
  새 파일을 만들어 `mas.by_rts_type[TYPE] = {...}`를 등록하고, Transaction이면
  새 파일에서 `mas.by_msgk[해당MSGK] = {...}`를 등록하면 된다 — `mas_rts.lua`/
  `mas_tr.lua`는 건드릴 필요 없다.
- **소문자 TYPE 파일 네이밍 규칙**: 파일명 규칙은 TYPE 글자를 소문자로
  바꿔 붙이는 것인데(예: TYPE='B' → `mas_rts_b.lua`), TYPE 자체가 이미
  소문자인 경우(`m`, `c`, `y`, ...) 그대로 지으면 나중에 같은 알파벳의
  대문자 TYPE(`M`, `C`, `Y`, ...)이 나타났을 때 파일명이 겹친다. 그래서
  소문자 TYPE 파일만 `mas_rts_l<letter>.lua`("lower <letter>")로 짓는다
  (예: `mas_rts_lm.lua`). 등록 키(`mas.by_rts_type["m"]`), 라벨
  (`"type: m"`), Wireshark 필터(`mas.rts.m.*`)는 파일명과 무관하게 항상
  실제 와이어 바이트 그대로다(Wireshark 필드명은 대소문자를 구분하므로
  `mas.rts.m`과 미래의 `mas.rts.M`은 애초에 서로 다른 필터라 필터
  레벨에서는 이 규칙이 필요 없다). 소문자 `c`/`y`를 구현하게 되면
  `mas_rts_lc.lua`/`mas_rts_ly.lua`로 지을 것.
- 배포 시 **파일 열네 개**(위 표 전부) 모두 플러그인 디렉터리에
  복사해야 한다. 2계층 파일이 없으면 해당 SESS 전체가 raw data로만
  보이고, 3계층 파일이 없으면 그 TYPE/MSGK는 라벨(`type:`/`msgk:`)까지는
  그대로 나오지만 고유 필드 없이 raw data로만 보인다(§6.5).

## 9. 검증 방법론

Wireshark GUI(트리 렌더링, 표시 필터, Statistics 창의 실제 클릭 동작)를
실행할 수 없는 환경에서는 다음 방식으로 로직·프레이밍 수준까지 검증한다
(실제 Wireshark에 로드해 트리·필터·Statistics 창을 확인하는 것은 별도
남은 단계):

1. **순수 로직 검증**: `mas.scan` + `split_records`(`mas_rts.lua`) +
   각 TYPE/MSGK의 `decode` 함수를 실제 캡처 스트림 바이트에 대해 실행 —
   junk 0건, 디코드 실패 0건(또는 알려진 예외만) 확인.
2. **재조립 시뮬레이션**: 같은 스트림을 다양한 크기(1바이트 포함)로 인위
   분할해 `pending`을 따라 재조립했을 때, 원샷 파싱과 프레임 수·CTRL/SESS
   분포·디코드 성공 건수가 완전히 일치하는지 확인.
3. **합성 엣지케이스**: 순수 junk, 트레일링 단독 `0xFE`, 헤더/길이/본문
   잘림, 길이필드 오염, heartbeat/압축 플래그, 미등록 SESS, NUL 패딩 등을
   합성 스트림으로 구성해 확인.
4. **dissector 스텁 실행**: Wireshark API를 최소 스텁(Proto/ProtoField/
   Tvb/TreeItem 흉내)으로 구현해 `proto.dissector`를 실제 스트림·합성
   프레임에 대해 호출 — 크래시 없이 `mas`로 claim, Info 컬럼이 §6.2
   형식대로 정확히 나오는지, 상세창 라벨(§6.5)과 디코드 성공 시에만
   채워지는 필드값이 정확히 연동되는지 확인.

새 TYPE/MSGK를 추가하거나 기존 필드 매핑을 재검증할 때도 이 네 단계를
그대로 반복하면 된다.
