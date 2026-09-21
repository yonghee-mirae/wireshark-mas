# MAS 프로토콜 분석 및 구현 노트

이 문서는 `mas.lua` / `mas_rts.lua` / `mas_tr.lua` /
`mas_rts_b.lua` / `mas_rts_c.lua` / `mas_rts_u.lua` /
`mas_tr_90.lua`가 해석하는 와이어 프로토콜을 이후 확장·수정 시 참고할 수
있도록 정리한 것이다(파일 구조는 §6 참고). 근거는
`design/AXIS-4.1.0_Protocol_WTS_ADD.docx`(원 설계 문서, 이하 "설계 문서")와
`samples/` 아래 두 개의 실제 캡처(`20260915_0809_RTS2.pcapng`,
`20260915_0809_RTS.pcapng`)를 바이트 단위로 교차 검증한 결과다.

## 1. 전체 구조 (3계층)

```
G/W HEADER (12 bytes)
  └─ SESS 값에 따라 분기
       SESS=0x08 (RTS)         → [ RTS-HEADER(6) + RTS-DATA ] 반복
       SESS=0x01 (Transaction) → AXIS-HEADER(24) + TR-DATA
```

캡처 스트림은 `FE FE` 프레임이 NUL 패딩을 사이에 두고 연속으로 이어지는 형태이며,
이 프로젝트가 지원하는 건 다음 **네 가지 내부 프로토콜뿐**이다:

- **체결 시세 (Execution Price)** — SESS=0x08, RTS-HEADER TYPE=`B`
- **호가 시세 (Quote Price)** — SESS=0x08, RTS-HEADER TYPE=`C`
- **업종:등락 (Sector Breadth)** — SESS=0x08, RTS-HEADER TYPE=`U`
- **실시간 주문 체결 (Order Report)** — SESS=0x01, AXIS-HEADER MSGK=0x90(UMP)

그 외 모든 것(다른 TYPE, 다른 MSGK, 압축, 암호화, heartbeat)은 **헤더에서 알 수
있는 정보만 표시하고 본문은 raw data**로 남긴다. 이는 요청된 설계 결정이며 버그가
아니다.

## 2. Layer 1 — G/W HEADER (12 bytes)

와이어 순서:

```
SOF(1)=0xFE  SOF(1)=0xFE  CTRL(1)  SESS(1)  CHCK(1)  RSVD(2)  LENGTH(5, ASCII 숫자)
```

- **CTRL** (설계 문서 §1.1): `0x01` Normal, `0x02` ACK, `0x03` NAK,
  **`0x04` POLL(heartbeat, 300초 타임아웃)**, `0x05` CheckSession/세션종료
  (`ctrl=0x05 + sess=0x99`).
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

### 프레이밍 파서의 엣지케이스 (중요, 재발 방지용)

- 스트림 시작에서 마주치는 바이트가 `FE FE`가 아니면 다음 `FE FE`까지 전부
  `data`(junk)로 처리하고 그 지점부터 재동기화한다.
- `FE FE`는 맞지만 LENGTH 필드가 5자리 숫자가 아니면(오염된 헤더), 그 `FE FE`
  2바이트만 `data`로 버리고 1바이트씩 전진하며 재검사한다 — 다음 루프에서
  "junk" 분기가 실제 다음 `FE FE`를 찾아 나머지 오염 구간까지 함께 `data`로 묶는다.
- **버퍼 끝에서 `FE FE`가 아직 다 도착하지 않은 경우** (예: 마지막 1바이트가
  `0xFE`뿐인 경우)는 **junk로 확정하지 않고 `pending`으로 재조립을 기다린다.**
  이 처리가 빠지면 TCP 세그먼트 경계에 걸린 정상 프레임이 "미확인 잡음"으로
  오분류되어 유실될 수 있다 (과거 `00000` 오탐과 같은 종류의 문제).
- 헤더(12바이트) 자체가 잘렸거나, LENGTH만큼의 payload가 아직 덜 도착했으면
  `pending`으로 재조립 요청(`desegment_offset`/`desegment_len`).
- 이 동작은 스트림을 **1바이트 단위로** 재조립 시뮬레이션해도 원샷 파싱과
  100% 동일한 결과가 나오는 것으로 검증했다 (세션 내 임시 테스트, 저장소에는
  미포함 — §6 참고).

## 3. Layer 2/3 — RTS (SESS=0x08): `mas_rts.lua`(프레이밍) + `mas_rts_b.lua`(TYPE='B' 디코드)

RTS payload는 **RTS-HEADER(6) + RTS-DATA**의 반복이다 (설계 문서 §1.3):

```
KIND(1)  DUMY(1)  TYPE(1)  LENGTH(3, ASCII 숫자)  RTS-DATA(LENGTH bytes, 끝에 NUL 포함)
```

- **KIND**: `D`=Data, `I`=RTS-Symbol 리스트. `I`는 KIND='D'와 레이아웃이
  다를 수 있는 별개의 레코드 종류라 TYPE 디스패치를 전혀 타지 않고
  `"kind: I"` 라벨 + raw data로만 표시된다(`mas_rts.lua`의 `add_rts`, TYPE
  값과 무관 — 우연히 TYPE이 `B`/`C`/`U`와 같아도 그 디코더로 넘어가지 않음).
- **DUMY**: 예비 (관측된 값은 항상 `'0'`).
- **TYPE**: 레코드 종류를 정하는 1글자. 실캡처에서 관측된 값:
  `B, C, D, U, Y, Z, c, m, y, V, F` (설계 문서는 예시로 `'A'`, `'z'`도 언급).
- **LENGTH(3)**: RTS-DATA 길이, 최대 512.

**이 프로젝트가 디코드하는 것은 `TYPE='B'`(체결, Execution Price)뿐이다.**
그 외 TYPE은 KIND/TYPE/LENGTH 헤더만 표시하고 본문은 `mas.data`(raw)로 남긴다.

### TYPE='B' 필드 레이아웃 (39필드, `inner/Execution_layout.txt` 원본)

탭 구분 39필드, `E.FIELD_NAMES`(코드 순서 그대로) 참고:

```
issue_code sep trade_time price change change_rate ask_price bid_price
trade_volume acc_volume acc_value open_price high_price low_price prev_ratio
vwap per lp_balance lp_ratio market_cap trade_strength trade_strength_3m
trade_strength_10m trade_strength_30m trade_strength_60m trade_strength_5d
trade_strength_10d trade_strength_20d trade_strength_60d total_ask_qty
total_bid_qty ask_qty1 bid_qty1 lp_balance_change static_vi_upper
static_vi_lower trade_market nxt_vi_upper nxt_vi_lower
```

- `issue_code`는 접두어로 시장 구분: `"M."` → M(NXT?), `"N."` → N, 접두어 없음 →
  `"K"`(KRX). `E.split_market()`.
- `sep`는 필드 개수/위치 정렬을 위해 `FIELD_NAMES`에는 남아 있지만 Wireshark
  필드로는 등록하지 않는다(표시 불필요, 과거 요청 반영).
- 파생 필드: `market`, `acc_volume_num`/`price_num`/`trade_volume_num`(정수),
  `reversed`(누적거래량 역전 탐지, 5-tuple+market+issue_code 단위, 프레임
  재방문 시에도 안정적인 idempotent 캐시).

### Wireshark 매핑

- Proto: 없음 — `mas`(우산 proto) 하나뿐, 서브트리는 성공/실패 무관 항상 `mas`로 태그(§4.7).
- 필드: `mas.rts.b.<field>` (39필드 중 `sep` 제외), `mas.rts.b.market`,
  `mas.rts.b.acc_volume_num`, `mas.rts.b.price_num`, `mas.rts.b.trade_volume_num`,
  `mas.rts.b.reversed`. RTS-HEADER 공용 필드는 `mas.rts.kind`/`mas.rts.type`/
  `mas.rts.reclen`(`mas_rts.lua` 소유, 모든 RTS TYPE 레코드에 공통 적용).
- Info 라벨: 별도 라벨 없음 — RTS(SESS=0x08) 프레임은 TYPE·디코드 성공 여부와
  무관하게 Info 컬럼에 `RTS`로만 집계된다(§4.6 참고). "체결이 실제로
  디코드됐는가"는 상세창 라벨(`type: B`, 성공/실패 무관 동일 — §4.9)로는
  구분되지 않고, 디코드 성공 시에만 채워지는 `mas.rts.b.market` 등 필드값
  (§4.7)으로만 구분한다.
- Statistics 창: **MAS/Execution Prices** — Market/Issue/Time/Price/TrdVol/AccVol/Reversed
  컬럼, 5-tuple(Flow) 별 구분.

## 3.5. Layer 2/3 — RTS (SESS=0x08), TYPE='C': `mas_rts_c.lua`

RTS-HEADER 프레이밍은 §3과 동일(`mas_rts.lua`가 담당). TYPE='C'(호가 시세)
바디는 **128 tab-분리 필드**(127개 명명 필드 + 숨은 `sep`(`'C'`) 1개) — 전체
필드 맵과 검증 근거는 **§8**을 참고(이 섹션은 요약만).

- 구현 파일: `mas_rts_c.lua`. `Q.FIELD_NAMES`(128개, §8 순서 그대로),
  `Q.decode(body)`(39필드 체결의 `E.decode`와 동일 패턴 — 필드 개수가
  128이 아니면 `nil`), `Q.split_market`(체결과 동일한 이슈코드 접두어 규칙).
- Proto: 없음 — `mas`(우산 proto) 하나뿐, 서브트리는 성공/실패 무관 항상 `mas`로 태그(§4.7).
- 필드: `mas.rts.c.<field>` (128필드 중 `sep` 제외), `mas.rts.c.market`.
- `mas.by_rts_type["C"]`에 등록 — TYPE='B'와 마찬가지로 **디코드 성공 여부에
  따라 필드를 채울지 결정**한다(실패 시 expert info만 붙고 `mas.rts.c.*` 필드는
  전혀 추가되지 않음. §4.7 원칙과 동일). 누적 상태(reversal 같은) 없이 매 레코드
  독립적으로 디코드하므로 `init` 훅은 등록하지 않는다.
- Info 라벨: 별도 라벨 없음 — TYPE='B'와 마찬가지로 RTS(SESS=0x08) 프레임은
  Info 컬럼에 `RTS`로만 집계된다(§4.6). 상세창 라벨(`type: C`, 성공/실패
  무관 동일 — §4.9)로는 구분되지 않고, 디코드 성공 시에만 채워지는
  `mas.rts.c.market` 등 필드값으로만 디코드 성공 여부를 구분한다.
- Statistics 창: 없음(요청 범위 밖 — 필요해지면 `mas_rts_b.lua`의
  `MAS/Execution Prices` 창과 동일한 패턴으로 추가 가능).

## 3.6. Layer 2/3 — RTS (SESS=0x08), TYPE='U': `mas_rts_u.lua`

RTS-HEADER 프레이밍은 §3과 동일. TYPE='U'(업종:등락)는 개별 종목이 아니라
**시장/업종 전체의 등락 집계**(코스피·코스닥 등)로, 바디는 **10 tab-분리
필드**: `issue_code, sep, trade_time, up_count, upper_limit_count,
flat_count, down_count, lower_limit_count, volume, value`.

- 구현 파일: `mas_rts_u.lua`. `S.FIELD_NAMES`(10개), `S.decode(body)`
  (필드 개수가 10이 아니면 `nil`, TYPE='B'/'C'의 `decode`와 동일 패턴).
  `issue_code`는 종목코드가 아니라 시장/업종 키(예: `KQ001`, `K0001`)라
  `E.split_market` 같은 접두어 분해는 적용하지 않는다.
- Proto: 없음 — `mas`(우산 proto) 하나뿐, 서브트리는 성공/실패 무관 항상 `mas`로 태그(§4.7).
- 필드: `mas.rts.u.<field>` (10필드 중 `sep` 제외).
- `mas.by_rts_type["U"]`에 등록 — 디코드 성공 여부에 따라 필드를 채울지 결정
  (실패 시 expert info만 붙고 `mas.rts.u.*` 필드는 전혀 추가되지 않음. §4.7 원칙과
  동일).
- 검증: `up_count + upper_limit_count + flat_count + down_count +
  lower_limit_count`가 `K0001` 표본(6건) 전부 정확히 **801**, `KQ001`
  표본(6건)은 **1521~1523**(종목이 상승↔보합↔하락 카테고리를 넘나드는
  정상적인 틱 변동) — 각각 코스피/코스닥 상장종목 수와 부합해 필드 매핑을
  확증. 다만 표본이 종목(키) 2개·12건뿐이라 §8(979건)만큼의 통계적 신뢰도는
  아님.
- Info 라벨: 별도 라벨 없음, TYPE='B'/'C'와 동일하게 Info 컬럼엔 `RTS`로만
  집계(§4.6).
- Statistics 창: 없음(요청 범위 밖).

## 4. Layer 2/3 — Transaction (SESS=0x01): `mas_tr.lua`(프레이밍) + `mas_tr_90.lua`(MSGK=0x90 디코드)

Transaction payload는 **AXIS-HEADER(24) + TR-DATA** (설계 문서 §1.2):

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

**이 프로젝트가 디코드하는 것은 `MSGK=0x90`(UMP) + **비암호화**(ACTF bit 0x02
미설정)인 경우뿐이다.** 그 외(다른 MSGK, 또는 암호화된 UMP)는 AXIS-HEADER 필드만
표시하고 TR-DATA는 `mas.data`(raw)로 남긴다.

### MSGK=0x90 TR-DATA 포맷 — 코드/값 스트림 (`inner/Order_layout.txt` 원본)

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
- 코드 사전은 `O.ORDER_FIELDS` (46개, 원본 `Order_layout.txt` 순서 그대로).
  중복 레이블(`처리구분`=973/983/977, `주문번호`=952/969, `원주문번호`=961/970)은
  Wireshark 필드명에 `(code)`를 접미해 구분한다 (예: `process_type (973)`,
  `process_type (983)`, `process_type (977)`). 필드명은 packet detail 창
  표시 규칙에 따라 모두 소문자, 단어 조합은 `snake_case` (예: `account_no`,
  `order_method (exchange)`).
- 사전에 없는 코드는 `mas.tr.90.unknown`(문자열 `"code=value"`)으로 표시.

### Wireshark 매핑

- Proto: 없음 — `mas`(우산 proto) 하나뿐, 서브트리는 성공/실패 무관 항상 `mas`로 태그(§4.7).
- 코드 필드: `mas.tr.90.<code>` (46개), `mas.tr.90.unknown`. AXIS-HEADER 공용 필드는
  `mas.tr.msgk`(value-string 포함)/`mas.tr.actf`/`mas.tr.encrypted`(파생
  bool)/`mas.tr.svcc`/`mas.tr.trnm`/`mas.tr.length`(`mas_tr.lua`
  소유, 모든 Transaction MSGK에 공통 적용).
- Info 라벨: 별도 라벨 없음 — Transaction(SESS=0x01) 프레임은 MSGK·디코드 성공
  여부와 무관하게 Info 컬럼에 `Transaction`으로만 집계된다(§4.6 참고). "주문
  체결통보가 실제로 디코드됐는가"는 상세창 라벨(`msgk: UMP (0x90)`, 성공/실패
  무관 동일 — §4.9)로는 구분되지 않고, 값 필터
  `mas.tr.msgk == 0x90 && !mas.tr.encrypted` 또는 디코드 성공 시에만 채워지는
  `mas.tr.90.<code>` 필드로만 구분한다(§4.7).
- Statistics 창: **MAS/UMP** — Account No(950) / Order No(952) /
  Branch No(975) / Order No(969) / Order Method(951) / Issue Code(953) /
  Process Type(977) / Order Qty(957) / Order Price(958) 컬럼, 5-tuple(Flow)
  별 구분. 코드가 없는 메시지는 그 칸이 빈 값으로 표시된다.
  ⚠️ 한 프레임에 여러 주문 메시지가 섞이고 그중 일부가 코드 구성이 다르면,
  칼럼별 발생 목록을 인덱스로 zip하는 방식(`open_stream_window`) 특성상 그
  프레임 내 행이 어긋날 수 있음(§6).

## 4.5. 구현 시 주의사항 — "숫자로 보이는 필드"는 ASCII char[] 인지 real 이진값인지 구분

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
  - 39개 체결 필드(`price`, `acc_volume` 등)와 주문 코드 필드(`mas.tr.90.<code>`)
    자체는 `ProtoField.string`으로 등록되어 있어 원본 문자 그대로("+206000",
    "0000037389" 등) 표시된다 — 이미 char[] 그대로 맞는 처리다. 여기서 파생된
    `mas.rts.b.acc_volume_num` 등 정수 필드만 위와 같은 명시적 파싱 규칙을 따른다.
- **진짜 1바이트 이진값(enum/플래그)**: `CTRL`, `SESS`, `CHCK`, `MSGK`,
  `ACTF` 등은 실캡처로 검증한 결과 `0x01`, `0x08`, `0x20`, `0x90` 같은
  **진짜 낮은 값의 raw 바이트**이지 ASCII 숫자 문자('0','1',...)가 아니다.
  이들은 `tvbrange`만 넘겨도(`tree:add(field, tvbrange)`) 올바르게
  해석된다 — 파싱이 필요 없다.

**과거 발견된 버그**: AXIS-HEADER `LENGTH(5)` 필드가(당시 `mas_tr_90.lua`
소유, 2026-09-18 리팩터로 `mas_tr.lua`로 이동 — §6 참고)
`ProtoField.uint32`로 등록되어 있었는데, 파싱한 값 없이 5바이트 ASCII
tvbrange를 그대로 넘기고 있었다(같은 파일의 다른 두 LENGTH 필드는 이미 올바른
패턴을 쓰고 있었음). `add_axis_header()`에서 `tvb(poff+19,5):string()`을
`tonumber()`로 파싱한 뒤 명시적으로 넘기도록 수정했다. **새 필드를 추가할 때
"숫자처럼 보이는" 필드를 만나면 이 표를 먼저 확인할 것.**

## 4.6. Info 컬럼: SESS 레벨 4종(포함 메시지 수 기준) + 재조립 마커

패킷 목록 창의 Info 컬럼은 **`(#N)RTS:n Transaction:m POLL Unspecified`
형식**으로만 표시한다.

- 분류는 **디코드 성공 여부와 무관하게 G/W HEADER의 CTRL/SESS만으로** 결정된다:
  CTRL=POLL이면 `POLL`, 그 외 SESS=0x08이면 `RTS`, SESS=0x01이면
  `Transaction`. 즉 압축된 프레임이나 TYPE/MSGK가 지원 범위 밖이라 상세창의
  TYPE/MSGK 고유 필드가 하나도 채워지지 않는 프레임도 Info에서는 그대로
  `RTS`/`Transaction`에 집계된다 — Info는 "이 프레임이 어떤 종류의 MAS
  트래픽인가"만 보여주고, "내용을 이해했는가"는 상세창의 몫이다. §4.7/§4.9에서
  다루는 "디코드 성공 여부"(`mas.rts.b.market` 등 필드값으로 판정, 라벨은
  성공/실패 무관 동일)와는 성격이 다르니 혼동하지 말 것.
- **`n`/`m`은 "G/W 프레임 개수"가 아니라 "그 안에 실제로 담긴 메시지 개수"다.**
  RTS(SESS=0x08)의 payload는 `RTS-HEADER(6)+RTS-DATA`가 **반복**되는 구조라
  한 G/W 프레임에 레코드가 여러 개(체결 + 미해독 TYPE 합산) 들어갈 수 있으므로,
  `RTS:n`의 `n`은 **그 프레임(들)에 담긴 RTS-DATA 레코드 총합**이다(체결
  레코드와 미해독 레코드를 구분하지 않고 더한다). 반대로 Transaction
  (SESS=0x01)의 payload는 `AXIS-HEADER+TR-DATA` 하나뿐이라 한 G/W 프레임이
  항상 정확히 메시지 1개 — 그래서 `Transaction:m`의 `m`은 사실상
  Transaction G/W 프레임 개수와 같다. **payload가 압축(CHCK bit `0x02`)돼
  안에 몇 개가 들었는지 알 수 없는 경우는 그 프레임 자체를 1개로 센다**
  (원본을 볼 수 없으니 그 이상 세분화할 수 없다는 뜻).
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
기본값 1을 그대로 쓴다. TYPE='B'/MSGK=0x90 디코더(`mas_rts_b.lua`/
`mas_tr_90.lua`)는 Info 라벨이나 카운팅에 전혀 관여하지 않는다 — 그건
2계층 파일(`mas_rts.lua`/`mas_tr.lua`)과 `mas.lua`만의 책임이다.
**Info 표시를 바꾸려면 `mas.lua`의 이 카운팅 블록과, RTS의 경우
`mas_rts.lua`의 `add_rts` 반환값 계산 부분을 고치면 된다.**

## 4.7. 존재(bare) 필터는 전부 폐기 — 모든 서브트리는 언제나 우산 `mas`로만 태그, 세부 필터는 필드값으로

**과거 발견된 버그**: Wireshark에서 `mas.rts.b`(체결 시세)나 `mas.tr.90`(주문 체결
통보) 같은 바깥(bare) 프로토콜 필터는 "이 프레임에 해당 프로토콜의
`tree:add(proto_x, ...)` 트리 항목이 있는가"로 판정된다. 그런데 "Unspecified
RTS" 서브트리(TYPE≠'B')와 "Unspecified Transaction" 서브트리(MSGK≠0x90/암호화)가
**전부 `proto_ex`/`proto_or`(즉 `mas.rts.b`/`mas.tr.90`)로 태그되어 있었다** — 라벨
문자열만 "Unspecified ..."로 바꿨을 뿐, 서브트리를 만드는 `tree:add()`의
첫 인자(proto)는 그대로 둔 채였다. 결과적으로 `mas.rts.b` 필터는 "체결
레코드가 있는 프레임"이 아니라 **"RTS(SESS=0x08) 프레임이면 전부"**,
`mas.tr.90`는 **"Transaction(SESS=0x01) 프레임이면 전부"** 매칭해 사실상
`mas.sess==0x08`/`mas.sess==0x01`과 다를 바 없어져 있었다.

**1차 수정(폐기됨)**: 디코드 성공 여부에 따라 `proto_ex`(성공)/`mas.proto`(실패)
로 서브트리 proto를 직접 고르는 방식으로 바로잡았고, 이어서 레코드/트랜잭션
전체를 잡는 `mas.rts`/`mas.tr` 래퍼 proto까지 추가해 `mas` ⊃ `mas.rts`/`mas.tr`
⊃ `mas.rts.<type>`/`mas.tr.<msgk>` 3단계 존재-필터 계층을 만들었었다. 그런데
이 존재 필터는 헤더 **필드값**(`mas.ctrl`/`mas.sess`/`mas.rts.type`/`mas.tr.msgk`
등)과 조건이 미묘하게 어긋난다 — 예를 들어 `mas.rts`는 압축(LZO)되거나
payload가 0바이트이거나 RTS-HEADER 자체가 깨진 프레임에는 매칭되지 않지만
`mas.ctrl==0x01 && mas.sess==0x08` 같은 값 필터는 그런 프레임에도 매칭된다.
두 필터가 "직관적으로 같아 보이지만 실제로는 다른" 상황이 반복적으로 생겨
혼동을 유발하므로, proto 기반 존재 필터 자체를 전부 없앤다.

**최종 수정**: TYPE/MSGK, 디코드 성공/실패와 무관하게 **모든 서브트리는
언제나 우산 proto(`mas.proto`)로만 태그**하고, 한 걸음 더 나가 **이 플러그인
전체에서 등록되는 Proto가 `mas` 단 하나뿐**이도록 만들었다 — `mas.rts.b`/
`mas.rts.c`/`mas.rts.u`/`mas.tr.90`/`mas.rts`/`mas.tr` 같은 파일별 Proto
객체를 전부 없애고, 7개 파일 모두 다음 패턴을 쓴다:

```lua
mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")
...
mas.proto.fields = { <이 파일이 정의하는 ProtoField들> }
mas.proto.experts = { <이 파일이 정의하는 ProtoExpert들> }   -- 있는 파일만
```

`Proto.fields`/`Proto.experts`는 **누적(append) setter**다 — 같은 Proto에
여러 파일이 각자 다른(겹치지 않는) 필드를 여러 번 대입해도 이전에 등록된
필드가 사라지지 않고 전부 함께 등록된다(같은 필드를 두 번 등록하면 에러가
나지만, 파일마다 자기 필드만 등록하므로 해당 없음 — wslua 소스
`epan/wslua/wslua_proto.c`의 `Proto_set_fields`/`Proto_set_experts` 확인).
`mas.proto = mas.proto or Proto(...)` 가드 덕분에 **어느 파일이 먼저
로드되어 `mas.proto`를 실제로 만들든 상관없다** — §6의 "로드 순서 독립적"
원칙과 동일하게 유지된다. 그 결과 Wireshark의 Enabled-Protocols 목록/필터
자동완성에 이 플러그인이 노출하는 프로토콜은 `mas` 하나뿐이고, `mas.rts.b`
같은 이름은 필터 자동완성에도 더 이상 나타나지 않는다 — bare 필터로
매칭되는 패킷이 원천적으로 없을 뿐 아니라, 그런 이름 자체가 존재하지 않는다.

(부작용: 이전에는 Wireshark의 "Enabled Protocols" 대화상자에서 체결/호가/
주문 결과 디코더를 개별적으로 켜고 끌 수 있었지만, 이제 Proto가 하나뿐이라
그 개별 토글도 사라진다 — 필터를 `mas` 하나로 좁히기로 한 결정의 당연한
결과다.)

**세부 필터는 항상 필드값으로 한다**:
- TYPE/MSGK로 거르기: `mas.rts.type == "B"`, `mas.tr.msgk == 0x90` (공용 헤더
  필드라 디코드 성공 여부와 무관하게 항상 채워짐).
- "실제로 디코드까지 성공했는가": 디코드 성공 시에만 채워지는 그 TYPE/MSGK
  고유 필드를 bare로 쓴다 — 예: `mas.rts.b.market`(체결/호가는 성공 시 항상
  채워짐), `mas.tr.90.950`(주문 결과는 코드가 메시지마다 달라 완벽한 대응
  필드는 없지만 실무적으로 충분). 리프 필드는 정확히 그 필드를 추가한
  코드 경로에서만 존재해 프로토 태깅과 같은 모호함이 생기지 않는다.
- `mas.rts_add_header`/`add_axis_header`가 채우는 공용 헤더 필드
  (`mas.rts.kind`/`mas.rts.type`/`mas.rts.reclen`, `mas.tr.msgk`/`mas.tr.actf`/
  `mas.tr.encrypted`/`mas.tr.svcc`/`mas.tr.trnm`/`mas.tr.length`)는 서브트리가
  어느 proto로 태그되든 실제 바이트에서 그대로 추출되므로 이 변경으로
  전혀 영향받지 않는다.

`mas.open_stream_window`를 호출하는 두 Statistics 창(§3 MAS/Execution Prices,
§4 MAS/UMP)의 tap 필터도 이 원칙에 맞춰 값 필터로 바꿨다 — `mas_rts_b.lua`는
`mas.rts.b.market`, `mas_tr_90.lua`는 `mas.tr.msgk == 0x90 && !mas.tr.encrypted`.

**새로운 "Unspecified" 계열 표시를 추가할 때는 항상 이 패턴을 따를 것: 서브트리는
무조건 `mas.proto`로 태그하고, 디코드 성공 표시는 라벨 문자열 + (필요하면) 성공
시에만 채워지는 필드로만 한다. proto 태깅으로 존재 필터를 만들려는 시도는
다시 하지 말 것 — 위에서 서술한 이유로 §7의 과거 검증 기록 중 proto 태깅을
전제로 한 부분은 현재 코드와 더 이상 일치하지 않는다.**

## 4.8. 인식은 포트가 아니라 내용(`mas.scan`)으로만 — Decode As가 되려면 필수

**과거 발견된 버그**: `proto.dissector` 맨 앞에
`if pinfo.src_port ~= bound_port then return 0 end`(`bound_port` = Preferences
"TCP port" 값, 기본 15201)라는 검사가 있었다. `tcp.port` 테이블에 그 포트로
자동 바인딩된 정상 캡처(서버가 실제로 15201에서 송신)에서는 이 검사가 항상
통과해 문제가 드러나지 않았지만, **Wireshark의 "Decode As"로 다른 포트나
다른 방향에 MAS를 강제 적용하면 이 내부 검사가 그 지시를 무시하고 무조건
`return 0`으로 거부**해 아무 것도 해석되지 않았다. Decode As의 존재 이유
자체가 "정상적인 포트 매칭 규칙과 무관하게 이 스트림을 이 프로토콜로
해석하라"는 것이라, dissector 내부에 자체적인 포트 재검사를 두는 것은 원천적으로
Decode As와 상충한다.

**수정**: 이 내부 포트 검사를 완전히 제거했다. 이제 인식은 순수하게
**`mas.scan`이 실제로 `FE FE` G/W 프레임을 찾아내는가**로만 판단한다.
- `apply_port()`가 `tcp.port` 테이블에 등록하는 Preferences 포트는 **여전히
  "자동으로 이 dissector를 호출시키는 트리거" 역할**만 한다(그 포트를 쓰는
  캡처를 열면 자동으로 MAS로 시도됨). 하지만 일단 `proto.dissector`가
  호출된 뒤에는 포트를 다시 확인하지 않는다.
- **Decode As는 이제 어떤 포트/방향에 적용해도 그대로 동작**한다 — 실제로
  MAS 프레임이 있으면 정상 해석되고, 없으면 조용히 거부되는 대신
  **`Unspecified`로 표시**된다(§4.6과 동일한 원칙: 이해 못 한 내용도 일단
  claim한 뒤 Info/상세창에 정직하게 "모르겠다"고 보여준다).
- **트레이드오프**: 이전에 명시적으로 요청됐던 "TCP이면서 지정된 src port에서
  전송되는 것만 MAS로 인식" 규칙은 이제 없다. Preferences 포트를 쓰는 스트림은
  **양방향 모두**(클라이언트→서버 포함) dissect 대상이 되며, MAS로 보이지
  않는 내용은 `Unspecified`로 표시될 뿐 무시되지 않는다. 이는 의도적으로
  완화한 것 — Decode As를 포기하지 않는 한 되돌릴 수 없는 근본적 트레이드오프다.

## 4.9. 상세창 라벨도 "type: <TYPE>"/"msgk: <name> (0x<hex>)"로 통일 — "Unspecified RTS"/"Unspecified Transaction" 라벨은 더 이상 쓰지 않음

기존에는 디코드에 성공한 레코드/트랜잭션만 그 전문의 이름(`Execution Price`,
`Quote Price`, `Sector-Breadth`, `Order Report`)을 라벨로 달고, 나머지는
`Unspecified RTS`/`Unspecified Transaction`이라는 별도 라벨을 달았다. 그런데
TYPE(RTS-HEADER)과 MSGK(AXIS-HEADER)는 **디코드 성공 여부와 무관하게 항상
헤더에서 읽을 수 있는 값**이므로, §4.7과 같은 이유로 이 구분도 라벨이 아니라
필드값으로 옮겼다:

- RTS: `mas_rts.lua`의 `add_rts`가 미등록 TYPE의 서브트리에 `"type: " ..
  r.type .. " (" .. r.len .. " bytes)"`를 붙인다 — 등록된 TYPE(`mas_rts_b.lua`
  등)이 자기 서브트리에 붙이는 라벨과 **완전히 같은 형식**이다(`type: B`,
  `type: C`, `type: U`, 미등록이면 `type: D`/`type: Z`/... 그대로).
- Transaction: `mas_tr.lua`의 `add_transaction`이 `mas.MSGK_NAMES[msgk_byte]`
  로 `"msgk: " .. name .. " (0x" .. msgk_byte .. ")"`를 만들어 **등록
  여부·암호화 여부와 무관하게 항상** 붙인다(`mas.MSGK_NAMES`에 없는 값이면
  `msgk: ? (0x14)`처럼 이름 자리에 `?`).
- 예외 — RTS KIND='I': KIND='D'와 레이아웃이 다를 수 있는 별개의 레코드
  종류라(§2) TYPE 디스패치를 아예 타지 않고 `"kind: I"`로 라벨링된다(TYPE
  값이 우연히 `B`/`C`/`U`와 같아도 그 디코더로 넘어가지 않음).

**따라서 "Unspecified RTS"/"Unspecified Transaction" 문자열은 코드 어디에도
없다.** 디코드 성공 여부는 이제 오직 그 서브트리 밑에 TYPE/MSGK 고유 필드가
실제로 채워져 있는지(예: `mas.rts.b.market`, `mas.tr.90.950`)로만 구분한다 —
라벨만 보고는 "이 레코드가 해석됐는지" 알 수 없고, 반드시 필드를 확인해야
한다. 새 TYPE/MSGK 디코더를 추가해도 이 라벨은 `mas_rts.lua`/`mas_tr.lua`가
이미 만들어 주므로 3계층 파일은 라벨을 신경 쓸 필요가 없다.

## 5. 미해독 영역과 그 이유

| 영역 | 조건 | 이유 |
|---|---|---|
| RTS 압축 | CHCK bit `0x02` | LZO 압축, 라이브러리/구현 없음 → `mas.data` |
| Transaction 암호화 | ACTF bit `0x02` | Xecure/XecureMobile 구간암호화, 키 없음 → `mas.data` |
| RTS TYPE ≠ 'B'/'C'/'U' | D/Y/Z/c/m/y/V/F 등 | 레이아웃 미상, 요청 범위 밖 → KIND/TYPE/LENGTH만 표시 + `mas.data` |
| Transaction MSGK ≠ 0x90 | Normal/RTS-on-off/Dialog/Error/키교환 등 | 요청 범위 밖(주문체결·체결시세만 지원) → AXIS-HEADER만 표시 + `mas.data` |
| POLL | CTRL=`0x04` | 데이터 없음, 상세창·Info 모두 `POLL` |

이 영역들을 추후 확장하려면:
1. 해당 레이아웃(필드 사전 또는 위치 스키마)을 확보한다.
2. `mas_rts_b.lua`/`mas_tr_90.lua`와 같은 패턴(사전 테이블 +
   decode 함수 + ProtoField 등록 + `add_*` 함수)으로 **새 파일**을 만들고,
   RTS TYPE이면 `mas.by_rts_type[TYPE]`에, Transaction MSGK이면
   `mas.by_msgk[MSGK]`에 등록한다(§6). `mas_rts.lua`/`mas_tr.lua`는
   건드릴 필요 없다.
3. 압축/암호화 해제가 가능해지면, `mas.lua`의 `CHCK bit 0x02`/`ACTF bit 0x02`
   분기에서 raw로 처리하기 전에 압축해제/복호화 함수를 끼워 넣고, 그 결과를 다시
   `mas.scan`(RTS의 경우 이미 페이로드 형태) 또는 해당 스트림 모듈의 파서에
   넘기면 된다.

## 6. 파일 구조와 조율 방식

2026-09-18 리팩터: "SESS 계층 프레이밍/디스패치"와 "TYPE/MSGK별 실제 디코더"를
분리해 **3계층 구조**로 재구성했다. 이전에는 `mas_rts_b.lua`/
`mas_tr_90.lua`가 SESS 계층 프레이밍까지 함께 떠안고 있어서, 새 TYPE/MSGK
디코더를 추가하려면 `mas.by_sess[SESS]`가 핸들러 하나만 허용하는 구조와 충돌했다.
지금은 각 디코더가 자기 파일 하나로 독립적으로 추가/삭제될 수 있다 — 같은 날
바로 이어서 `mas_rts_c.lua`(TYPE='C')와 `mas_rts_u.lua`
(TYPE='U')를 기존 파일들 수정 없이 추가한 게 그 효과의 실증이다.

| 파일 | 계층 | 역할 |
|---|---|---|
| `mas.lua` | 1 (G/W) | G/W 헤더 프레이밍(`mas.scan`), 우산 proto(`mas`) + dissector, TCP 재조립, Info 컬럼 소유, 공용 Statistics 창(`mas.open_stream_window`) |
| `mas_rts.lua` | 2 (RTS) | SESS=0x08 등록, RTS-HEADER 파싱(`split_records`), 공용 헤더 필드(`mas.rts.*`), TYPE별 디스패치(`mas.by_rts_type`), 미등록 TYPE도 `"type: <TYPE>"` 라벨로 표시(§4.9) |
| `mas_tr.lua` | 2 (Transaction) | SESS=0x01 등록, AXIS-HEADER 파싱, 공용 헤더 필드(`mas.tr.*`), MSGK별 디스패치(`mas.by_msgk`), 미등록/암호화 MSGK도 `"msgk: <name> (0x<hex>)"` 라벨로 표시(§4.9) |
| `mas_rts_b.lua` | 3 (RTS TYPE='B') | 체결 시세 디코드, `mas.rts.b.*` 필드, MAS/Execution Prices 창. `mas.by_rts_type["B"]`에 등록 |
| `mas_rts_c.lua` | 3 (RTS TYPE='C') | 호가 시세 디코드, `mas.rts.c.*` 필드. `mas.by_rts_type["C"]`에 등록 (§3.5) |
| `mas_rts_u.lua` | 3 (RTS TYPE='U') | 업종:등락 디코드, `mas.rts.u.*` 필드. `mas.by_rts_type["U"]`에 등록 (§3.6) |
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
    서브트리는 항상 우산 `mas`로 태그되며(§4.7), **디코드 성공/실패에 따라
    그 TYPE 고유 필드를 채울지 말지만 3계층 파일이 직접 결정**한다(TYPE='B'라도
    필드 개수가 안 맞으면 필드는 하나도 안 채우고 expert info만 붙인다). 2계층
    파일은 헤더 필드 추가 헬퍼(`mas.rts_add_header`)만 제공한다.
  - Transaction: `mas.by_msgk[MSGK] = { add =
    function(sub, tvb, poff, plen, pinfo) ... end }`. 상세창 라벨(`msgk: <name>
    (0x<hex>)`)은 MSGK 등록 여부·암호화 여부와 무관하게 `mas.MSGK_NAMES`에서
    항상 동일하게 만들어지므로(§4.9) 3계층 파일은 라벨을 따로 넘기지 않는다.
    서브트리는 여기서도 항상 우산 `mas`로 태그된다(2계층 파일 `mas_tr.lua`의
    `add_transaction`이 MSGK/암호화 여부로 `will_decode`만 판단해 헤더 필드를
    채우고 3계층 파일을 부를지 결정한 뒤 넘겨준다).
- 새 메시지 타입을 추가하려면: RTS면 `mas_rts_c.lua`(TYPE='C', §3.5)처럼
  새 파일을 만들어 `mas.by_rts_type[TYPE] = {...}`를 등록하고, Transaction이면
  새 파일에서 `mas.by_msgk[해당MSGK] = {...}`를 등록하면 된다 — `mas_rts.lua`/
  `mas_tr.lua`는 건드릴 필요 없다.
- 배포 시 **일곱 파일 모두** 플러그인 디렉터리에 복사해야 한다. 2계층 파일이
  없으면 해당 SESS 전체가 raw data로만 보이고, 3계층 파일이 없으면 그 TYPE/
  MSGK는 라벨(`type:`/`msgk:`)까지는 그대로 나오지만 고유 필드 없이
  raw data로만 보인다(§4.9).

## 7. 검증 이력 (참고용, 저장소에는 미포함)

> **주의(2026-09-21)**: 이 아래(§7)와 §3.6/§8에 있는 과거 검증 기록 중
> "`mas.rts.c`/`mas.rts.u`/`mas.rts.b`/`mas.tr.90` 서브트리로 태그된다/존재
> 필터"류 표현은 그 당시(파일 분리 리팩터 직후) 실제로 존재했던 자식 proto
> 태깅 방식을 검증한 기록이다. 이후 §4.7에서 그 방식을 완전히 폐기했으므로
> (지금은 `mas` 하나만 등록되고 세부 판정은 필드값으로 한다), 그런 표현이
> 나오는 항목은 **당시 기준으로는 정확했지만 현재 코드와는 더 이상 일치하지
> 않는다.** 과거 기록을 그대로 남겨두고 이 주석으로 갱신 시점만 표시한다.

이번 재작성 검증은 세션 내 임시 스크립트(`/tmp` 스크래치패드)로 수행했고
저장소에는 커밋하지 않았다. 향후 정식 회귀 테스트로 승격하려면 다음을
재현하면 된다:

1. **순수 로직 검증**: `mas.scan` + `R.split_records`(`mas_rts.lua`)/`E.decode`
   (`mas_rts_b.lua`) + `O.decode_order`를 두 샘플 캡처의 실제 스트림
   바이트(포트 15201 발신)에
   대해 실행 — junk 0건, 체결 디코드 실패 0건, 주문 리포트 디코드 성공 건수
   일치 확인.
2. **재조립 시뮬레이션**: 같은 스트림을 1/7/37/173/4096바이트 청크로 인위
   분할해 `pending`을 따라 재조립했을 때, 원샷 파싱과 프레임 수·CTRL/SESS
   분포·디코드 성공 건수가 완전히 일치하는지 확인 (1바이트 단위 포함).
3. **합성 엣지케이스**: 순수 junk, 트레일링 단독 `0xFE`, 헤더/길이/본문 잘림,
   길이필드 오염, heartbeat/압축 플래그, 미등록 SESS, NUL 패딩 등 8종.
4. **dissector 스텁 실행**: Wireshark API를 최소 스텁으로 흉내내
   `proto.dissector`를 실제 스트림 전체·개별 합성 프레임에 대해 호출 —
   크래시 없이 `MAS`로 claim, Info 컬럼이 `(#N)RTS:n Transaction:m POLL
   Unspecified` 형식(고정 순서, RTS/Transaction은 담긴 메시지 수를 1이어도
   항상 `:n`로 표시 — RTS는 한 프레임 안의 레코드 합산, Transaction은 프레임당
   1, POLL/Unspecified는 건수 무관하게 항상 생략, 넷 다 없으면
   `Unspecified` 단독, `(#N)`은 재조립된 프레임에만)으로 정확히 나오는지, 상세창
   라벨(`type: B`/`msgk: UMP (0x90)`/`POLL` — §4.9 이후로는 디코드
   성공/실패와 무관하게 항상 같은 라벨)과, 디코드 성공 시에만 채워지는
   `mas.rts.b.market`/`mas.tr.90.950` 같은 필드값이 디코드 성공 여부에 정확히
   연동되는지 확인.

실제 Wireshark GUI(트리 렌더링, 표시 필터, Statistics 창의 실제 클릭 동작)는
이 환경에서 실행할 수 없어 **로직·프레이밍 수준까지만** 검증됐다. 실제
Wireshark에 로드해 트리·필터·Statistics 창을 확인하는 것이 남은 검증 단계다.

**2026-09-18 파일 분리 리팩터(§6) 검증**: 위 4번과 같은 방식의 최소 Wireshark
API 스텁(`Proto`/`ProtoField`/`Tvb`/`TreeItem`을 흉내낸 테이블)으로 다섯
파일을 실제 로드 순서(`mas.lua`→`mas_rts_b.lua`→
`mas_tr_90.lua`→`mas_rts.lua`→`mas_tr.lua`)대로 dofile한 뒤,
합성 스트림(체결 레코드 1 + 미해독 RTS TYPE 1 + 주문 리포트 1 + 미해독
Transaction 1 + heartbeat 1)에 대해 `mas.proto.dissector`를 직접 호출해
확인했다: (1) `mas.by_sess`/`mas.by_rts_type`/`mas.by_msgk` 등록이 모두
이뤄지는지, (2) 예외 없이 전체 버퍼를 소비하는지, (3) Info 컬럼이
`RTS:2 Transaction:2 POLL`로 정확히 집계되는지, (4) `mas.rts.b`/`mas.tr.90`
서브트리가 각각 정확히 1개씩만(디코드 성공 레코드만) 태그되고 나머지는
전부 우산 `mas`로 태그되는지, (5) `mas.rts.b.price`/`mas.rts.type`/
`mas.tr.length`(char[] 파싱 결과가 정수인지)/`mas.tr.90.950`/`mas.tr.90.952`
필드값이 정확한지, (6) 두 번째 프레임에서 낮은 `acc_volume`을 보내 reversal
탐지가 `mas.by_rts_type["B"].init` 훅을 거쳐도 여전히 동작하는지. 전부 통과.
저장소에는 미포함(세션 내 스크래치패드).

**2026-09-18 `mas_rts_u.lua`(TYPE='U') 검증**: `mas_rts_c.lua`
검증과 같은 방식 — 실제 캡처값(`KQ001` 레코드)으로 재구성한 합성 바디를
`S.decode`에 직접 돌려 필드값과 `up+upperLimit+flat+down+lowerLimit=1523`
항등식을 확인했고, Wireshark 스텁으로 `mas.proto.dissector`를 호출해
(1) `mas.by_rts_type["U"]` 등록, (2) 정상 레코드만 `mas.rts.u`로 태그되고
필드 개수가 안 맞는 레코드는 우산 `mas`+expert로 폴백하는지, (3) Info 컬럼
(`RTS:2`)이 정확한지 확인했다. 전부 통과. 저장소 미포함.

## 8. 호가 시세(RTS TYPE='C') 필드 맵 — ✅ 확정, ✅ 구현됨 (`mas_rts_c.lua`)

**필드 순서/이름은 폐하께서 확정해 주신 사양(127개, 아래 표)이고, 두 샘플의
TYPE='C' 레코드 979건 전체에 대해 항등식(합계 검증)으로 교차 검증까지
마쳤다.** `mas_rts_b.lua`가 TYPE='B'를 디코드하는 것과 동일한
패턴으로 `mas_rts_c.lua`를 구현해 `mas.by_rts_type["C"]`에 등록했다
(§3.5, §6).

### 필드 개수: 127(확정 사양) = 128(실측 wire 필드) − 1(숨은 sep)

두 샘플의 TYPE='C' 레코드 **979건 전부 정확히 128개의 탭 구분 필드**로
고정돼 있다(가변 아님 — field-count 분포: `{128: 979}`, 예외 0건). wire
index 1은 TYPE='B'의 `sep`와 같은 역할의 레코드타입 문자(`'C'`)로, 확정
사양의 이름 목록(Key부터 시작해 127개)에는 포함되지 않는 숨은 필드다. 그래서
매핑은 `named[0] → wire[0]`(Key=issue_code), `named[k] → wire[k+1]`(k≥1,
sep 1칸 건너뜀)이며, 이 규칙으로 정확히 `127 + 1(sep) = 128`이 채워져 실측과
완전히 맞아떨어진다.

### 검증 방법

- `named[k] → wire[k+1]` 매핑으로 979건 전체에 대해 다음 항등식을 확인했다
  (전부 예외 없이 성립):
  - `wire[13..22](매도량) == wire[33..42](K매도량) + wire[43..52](N매도량)`
    (레벨별 10쌍 전부)
  - `wire[63..72](매수량) == wire[83..92](K매수량) + wire[93..102](N매수량)`
  - `wire[124](KRX매도총잔량) + wire[125](NXT매도총잔량) == wire[103](매도총량)`
  - `wire[126](KRX매수총잔량) + wire[127](NXT매수총잔량) == wire[105](매수총량)`
  - `wire[114](순매수총잔량) == wire[105](매수총량) - wire[103](매도총량)`
    (부호 포함 일치, 예: `49302-22158=27144` → `wire[114]="+27144"`)
- `wire[2]`가 `HHMMSS` 형태(예: `"183551"`)인지 직접 확인해 `named[1]=호가시간`
  매핑(= sep 1칸 건너뛰기)이 맞는지 검증했다.
- `M.A006800`처럼 매도/매수 양쪽 다 K/N이 실제로 0이 아닌 종목 레코드를 찾아
  위 항등식이 우연이 아님을 확인했다(예: 매도 레벨1 `ask=266,
  K=225, N=41` — `225+41=266`).
- 예상체결 관련 구간(107-113, 115)은 이 캡처가 장중(비-동시호가) 구간이라
  전부 `0`/`0.00`으로 나오는데, 이는 지표가 없는 게 아니라 **해당 이벤트가
  없어 0인 것**으로 합리적으로 설명된다(비활성이라 값 자체로는 추가 검증 불가
  하지만 "미확인"은 아님 — 이름 그대로 받아들임).

### 필드 맵 (0-based, wire 총 128 = named 127 + sep 1)

| wire | named(폐하 사양) | 필드명(영문) | 확신도 |
|---|---|---|---|
| 0 | Key | `issue_code` | 확실 |
| 1 | *(없음, sep)* | `sep` ('C') | 확실 — TYPE='B'와 동일 패턴 |
| 2 | 호가시간 | `trade_time` | 확실 — `HHMMSS` 형식 직접 확인 |
| 3-12 | 매도가1-10 | `ask_price1..10` | 확실 |
| 13-22 | 매도량1-10 | `ask_qty1..10` | 확실 |
| 23-32 | 매도비1-10 | `ask_qty_chg1..10`(추정 명칭) | 확실(존재/위치) — level↑일수록 갱신 빈도 감소 패턴 확인 |
| 33-42 | K매도량1-10 | `krx_ask_qty1..10` | **확실(수식 검증)** — `ask_qty == krx_ask_qty + nxt_ask_qty` |
| 43-52 | N매도량1-10 | `nxt_ask_qty1..10` | **확실(수식 검증)** — 위와 동일 |
| 53-62 | 매수가1-10 | `bid_price1..10` | 확실 |
| 63-72 | 매수량1-10 | `bid_qty1..10` | 확실 |
| 73-82 | 매수비1-10 | `bid_qty_chg1..10`(추정 명칭) | 확실(존재/위치) |
| 83-92 | K매수량1-10 | `krx_bid_qty1..10` | **확실(수식 검증)** |
| 93-102 | N매수량1-10 | `nxt_bid_qty1..10` | **확실(수식 검증)** |
| 103 | 매도총량 | `total_ask_qty` | 확실(수식 검증) — `sum(ask_qty1..10)`과 일치, `krx_ask_qty총+nxt_ask_qty총`과도 일치 |
| 104 | 매도총비 | `total_ask_qty_chg`(추정 명칭) | 확실(존재/위치), 의미는 추정 |
| 105 | 매수총량 | `total_bid_qty` | 확실(수식 검증) |
| 106 | 매수총비 | `total_bid_qty_chg`(추정 명칭) | 확실(존재/위치), 의미는 추정 |
| 107 | 예상가격 | `expected_price` | 확실(존재/위치), 캡처 구간엔 항상 0 |
| 108 | 예상수량 | `expected_qty` | 확실(존재/위치), 항상 0 |
| 109 | 예상대비 | `expected_change` | 확실(존재/위치), 항상 0 |
| 110 | 예상등락 | `expected_change_rate` | 확실(존재/위치), 항상 `0.00` |
| 111 | 예상대전 | `expected_change_amt` | 확실(존재/위치), 항상 0 |
| 112 | 예상등전 | `expected_change_amt2`(추정 명칭) | 확실(존재/위치), 항상 공백 |
| 113 | 차익BASIS | `arbitrage_basis` | 확실(존재/위치), 항상 0 |
| 114 | 순매수총잔량 | `net_buy_total_qty` | **확실(수식 검증)** — `= total_bid_qty - total_ask_qty` (부호 포함) |
| 115 | 예상체결량비율 | `expected_fill_qty_ratio` | 확실(존재/위치), 항상 `0.00` |
| 116 | NXT중간가 | `nxt_mid_price` | 확실(존재/위치), 캡처 구간엔 `-0` |
| 117 | NXT매도중간가잔량 | `nxt_ask_mid_qty` | 확실(존재/위치), 항상 0 |
| 118 | NXT매수중간가잔량 | `nxt_bid_mid_qty` | 확실(존재/위치), 항상 0 |
| 119 | KRX중간가 | `krx_mid_price` | 확실(존재/위치), `-0` |
| 120 | 매도중간가잔량 | `krx_ask_mid_qty`(추정 — 폐하 사양 원문에 "KRX" 접두어 누락, KRX매수중간가잔량과 대구 이루는 자리) | 확실(존재/위치), 항상 0 |
| 121 | KRX매수중간가잔량 | `krx_bid_mid_qty` | 확실(존재/위치), 항상 0 |
| 122 | NXT중간가총순잔량 | `nxt_mid_total_net_qty` | 확실(존재/위치), 항상 0 |
| 123 | 중간가총순잔량 | `mid_total_net_qty` | 확실(존재/위치), 항상 0 |
| 124 | KRX매도총잔량 | `krx_total_ask_qty` | **확실(수식 검증)** — `+ wire[125] == wire[103]` |
| 125 | NXT매도총잔량 | `nxt_total_ask_qty` | **확실(수식 검증)** |
| 126 | KRX매수총잔량 | `krx_total_bid_qty` | **확실(수식 검증)** — `+ wire[127] == wire[105]` |
| 127 | NXT매수총잔량 | `nxt_total_bid_qty` | **확실(수식 검증)** |

### 남은 의문 (경미, 구현을 막지 않음)

- 23-32/73-82("~비")와 104/106("총비")의 정확한 의미(변동분 vs 비율 vs 증감)는
  이름만으로 확정하기 애매하나, **위치와 존재 자체는 확실**하므로 필드명은
  일단 `_chg` 접미사로 잠정 등록하고 실제 트래픽에서 재확인하면 됨.
- 120번(`매도중간가잔량`)은 폐하 원문에 "KRX" 접두어가 빠진 것으로 보이나
  119/121과의 대구 구조상 KRX쪽으로 추정 — 확정 규격 재확인 시 정정 가능.
- TYPE='D'(80필드, 1,146건)는 여전히 분석 범위 밖(별도 시세 유형으로 추정).

### 구현 완료 (2026-09-18)

2026-09-18 `mas_rts_c.lua`로 구현했다. `mas_rts_b.lua`와
동일한 패턴(필드명 테이블 + `decode` 함수 + ProtoField 등록 + `add_*`
핸들러)이며, `Q.TYPE_QUOTE = "C"`를 정의해 `mas.by_rts_type["C"] = { add =
add_quote }`로 등록했다(§6, `mas_rts.lua`는 수정하지 않았음 — 이 refactor
설계의 목적 그대로 새 파일 하나만 추가). 검증: `Q.decode`를 실제 캡처값
(M.A006800 기준)으로 재구성한 합성 바디에 돌려 필드값이 정확히 나오는지, 그리고
Wireshark API 스텁으로 `mas.proto.dissector`를 호출해 (1) `mas.rts.c` 서브트리가
디코드 성공 레코드에만 태그되는지(필드 개수가 안 맞는 손상된 레코드는 우산
`mas` + expert info로 폴백), (2) `mas.rts.b`/기존 동작에 회귀가 없는지, (3) Info
컬럼(`RTS:n`)이 TYPE='C' 레코드도 정확히 카운트하는지 확인했다(전부 통과,
저장소 미포함). Statistics 창(MAS/Quote)은 요청 범위 밖이라 만들지 않았다 —
필요하면 §3.5 참고해 `mas_rts_b.lua`의 `MAS/Execution Prices` 창과 동일한
패턴으로 추가.

## 9. 샘플 전체 전문 종류 조사 (2026-09-18)

두 샘플(`20260915_0809_RTS2.pcapng`, `20260915_0809_RTS.pcapng`)을 합쳐 G/W
프레임 전체(2,910개)를 스캔해서 실제로 어떤 CTRL/SESS/TYPE/MSGK 조합이
등장하는지 집계한 결과. `mas.lua`/스트림 모듈과 별개로 Python으로 직접
프레이밍을 재현해 검증했다(스크래치패드, 저장소에는 미포함).

### 9.1 G/W HEADER 레벨 (CTRL/SESS 조합)

| CTRL | SESS | 압축(CHCK&0x02) | 개수 | 비고 |
|---|---|---|---|---|
| Normal | RTS(0x08) | 아니오 | 1,525 | 파싱 가능 |
| Normal | RTS(0x08) | **예(LZO)** | 1,210 | 미해독 — `mas.lua`는 `[compressed]`로만 표시 |
| Normal | Transaction(0x01) | 아니오 | 116 | |
| ACK | Transaction(0x01) | 아니오 | 7 | |
| POLL(heartbeat) | — | — | 52 | |

### 9.2 RTS 내부 TYPE (비압축 1,525개 프레임 안의 RTS-DATA 레코드 수, 프레임당 레코드 다수 포함 가능)

| TYPE | 레코드 수 | 샘플 길이 | 상태 |
|---|---|---|---|
| **B** | 13,494 | 231B | 체결(Execution Price) — 구현됨 |
| D | 1,146 | 403B | 미확인, §8에서 언급한 80필드 변형(NXT 전용 또는 시간외 호가로 추정) |
| **C** | 979 | 593B | 호가(Quote) 128필드 — §8/§3.5, 구현됨(`mas_rts_c.lua`) |
| c | 281 | 212B | 미확인 |
| V | 160 | 80B | 미확인 |
| Y | 105 | 152B | 미확인 |
| Z | 105 | 158B | 미확인 |
| m | 56 | 164B | 미확인 |
| U | 12 | 45B | 업종:등락(Sector Breadth) — §3.6, 구현됨(`mas_rts_u.lua`) |
| F | 3 | 446B | 미확인 |
| y | 2 | 369B | 미확인 |

압축된 1,210개 RTS 프레임(LZO)은 미해독이라 이 표에 반영되지 않았다 — 실제로는
더 많은 TYPE이 존재할 수 있다.

### 9.3 Transaction 내부 MSGK (AXIS-HEADER)

| MSGK | 개수 | 상태 |
|---|---|---|
| 0x20 (Normal) | 102 | 미구현 — AXIS-HEADER만 표시 |
| 0x50 (RTS) | 7 | 미구현 |
| **0x90 (UMP/Order Report)** | 6 | 구현됨 |
| 0x14 | 1 | `mas.MSGK_NAMES`(`mas_tr.lua` 소유) 사전에 없는 값. 페이로드가
바이너리라 암호화(ACTF)로 추정되나 미확인 — 라벨은 이름 자리에 `?`가 붙어
`msgk: ? (0x14)`로 정상 표시됨(§4.9, 버그 아님) |

### 9.4 결론

현재 `mas.lua` 플러그인이 완전히 해독하는 것은 **RTS TYPE='B'(체결)**,
**RTS TYPE='C'(호가)**, **RTS TYPE='U'(업종:등락)**, **Transaction
MSGK=0x90(주문 결과)** 네 가지이며, 나머지(RTS의 다른 TYPE 8종 + 압축 프레임,
Transaction의 다른 MSGK 3종)는 모두 헤더 정보 + raw data로만 표시된다. 이는
§1에서 명시한 설계 결정과 일치하며 새로 발견된 버그는 없다.
