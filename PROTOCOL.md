# MAS 프로토콜 분석 및 구현 노트

이 문서는 `mas.lua` / `mas_execution_price.lua` / `mas_order_report.lua`가 해석하는
와이어 프로토콜을 이후 확장·수정 시 참고할 수 있도록 정리한 것이다. 근거는
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
이 프로젝트가 지원하는 건 다음 **두 가지 내부 프로토콜뿐**이다:

- **체결 시세 (Execution Price)** — SESS=0x08, RTS-HEADER TYPE=`B`
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

## 3. Layer 2-A — RTS (SESS=0x08), `mas_execution_price.lua`

RTS payload는 **RTS-HEADER(6) + RTS-DATA**의 반복이다 (설계 문서 §1.3):

```
KIND(1)  DUMY(1)  TYPE(1)  LENGTH(3, ASCII 숫자)  RTS-DATA(LENGTH bytes, 끝에 NUL 포함)
```

- **KIND**: `D`=Data, `I`=RTS-Symbol 리스트. (`I`는 현재 별도 처리 없음)
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

- Proto: `mas.ep` ("MAS Execution Price")
- 필드: `mas.ep.<field>` (39필드 중 `sep` 제외), `mas.ep.market`,
  `mas.ep.acc_volume_num`, `mas.ep.price_num`, `mas.ep.trade_volume_num`,
  `mas.ep.reversed`, RTS-HEADER용 `mas.ep.kind`/`mas.ep.type`/`mas.ep.reclen`.
- Info 라벨: 별도 라벨 없음 — RTS(SESS=0x08) 프레임은 TYPE·디코드 성공 여부와
  무관하게 Info 컬럼에 `RTS`로만 집계된다(§4.6 참고). "체결이 실제로
  디코드됐는가"는 상세창의 `Execution Price` vs `Unspecified RTS` 라벨과
  `mas.ep` 존재 필터(§4.7)로 구분한다.
- Statistics 창: **MAS/Execution** — Market/Issue/Time/Price/TrdVol/AccVol/Reversed
  컬럼, 5-tuple(Flow) 별 구분.

## 4. Layer 2-B — Transaction (SESS=0x01), `mas_order_report.lua`

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
- 사전에 없는 코드는 `mas.or.unknown`(문자열 `"code=value"`)으로 표시.

### Wireshark 매핑

- Proto: `mas.or` ("MAS Order Report")
- AXIS-HEADER 필드: `mas.or.msgk`(value-string 포함), `mas.or.actf`,
  `mas.or.encrypted`(파생 bool), `mas.or.svcc`, `mas.or.trnm`, `mas.or.length`.
- 코드 필드: `mas.or.<code>` (46개), `mas.or.unknown`.
- Info 라벨: 별도 라벨 없음 — Transaction(SESS=0x01) 프레임은 MSGK·디코드 성공
  여부와 무관하게 Info 컬럼에 `Transaction`으로만 집계된다(§4.6 참고). "주문
  체결통보가 실제로 디코드됐는가"는 상세창의 `Order Report` vs
  `Unspecified Transaction` 라벨과 `mas.or` 존재 필터(§4.7)로 구분한다.
- Statistics 창: **MAS/Order** — Account No(950) / Order No(952) /
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
  - 39개 체결 필드(`price`, `acc_volume` 등)와 주문 코드 필드(`mas.or.<code>`)
    자체는 `ProtoField.string`으로 등록되어 있어 원본 문자 그대로("+206000",
    "0000037389" 등) 표시된다 — 이미 char[] 그대로 맞는 처리다. 여기서 파생된
    `mas.ep.acc_volume_num` 등 정수 필드만 위와 같은 명시적 파싱 규칙을 따른다.
- **진짜 1바이트 이진값(enum/플래그)**: `CTRL`, `SESS`, `CHCK`, `MSGK`,
  `ACTF` 등은 실캡처로 검증한 결과 `0x01`, `0x08`, `0x20`, `0x90` 같은
  **진짜 낮은 값의 raw 바이트**이지 ASCII 숫자 문자('0','1',...)가 아니다.
  이들은 `tvbrange`만 넘겨도(`tree:add(field, tvbrange)`) 올바르게
  해석된다 — 파싱이 필요 없다.

**과거 발견된 버그**: `mas_order_report.lua`의 AXIS-HEADER `LENGTH(5)` 필드가
`ProtoField.uint32`로 등록되어 있었는데, 파싱한 값 없이 5바이트 ASCII
tvbrange를 그대로 넘기고 있었다(같은 파일의 다른 두 LENGTH 필드는 이미 올바른
패턴을 쓰고 있었음). `add_axis_header()`에서 `tvb(poff+19,5):string()`을
`tonumber()`로 파싱한 뒤 명시적으로 넘기도록 수정했다. **새 필드를 추가할 때
"숫자처럼 보이는" 필드를 만나면 이 표를 먼저 확인할 것.**

## 4.6. Info 컬럼: SESS 레벨 4종(포함 메시지 수 기준) + 재조립 마커

패킷 목록 창의 Info 컬럼은 **`(#N)RTS:n Transaction:m Heartbeat Unspecified`
형식**으로만 표시한다.

- 분류는 **디코드 성공 여부와 무관하게 G/W HEADER의 CTRL/SESS만으로** 결정된다:
  CTRL=POLL이면 `Heartbeat`, 그 외 SESS=0x08이면 `RTS`, SESS=0x01이면
  `Transaction`. 즉 압축된 프레임이나 TYPE/MSGK가 지원 범위 밖이라 상세창에
  `Unspecified RTS`/`Unspecified Transaction`으로 표시되는 프레임도 Info에서는
  그대로 `RTS`/`Transaction`에 집계된다 — Info는 "이 프레임이 어떤 종류의
  MAS 트래픽인가"만 보여주고, "내용을 이해했는가"는 상세창의 몫이다.
  §4.7에서 다루는 `mas.ep`/`mas.or` 존재 필터(디코드 성공 여부 기준)와는
  성격이 다르니 혼동하지 말 것.
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
  정보이기 때문이다. **`Heartbeat`/`Unspecified`는 건수를 절대 표시하지
  않는다** — 몇 건이든 그냥 `Heartbeat`/`Unspecified`.
- **CTRL/SESS 조합은 RTS/Transaction/Heartbeat 세 가지 외에도 규격상 얼마든지
  나올 수 있다**(ACK/NAK/CheckSession, SESS=SessionEnd 등). 이런 프레임과,
  G/W 헤더조차 못 이루는 순수 junk 바이트는 전부 **`Unspecified`라는 네 번째
  버킷**으로 집계된다(이쪽은 프레임 단위 1개, "포함된 메시지 수" 개념이 없다).
  `Unspecified`는 다른 셋을 밀어내는 대체값이 아니라 **독립적으로 공존하는
  값**이다 — 한 프레임에 체결 RTS와 이해 못 한 잡음이 같이 있으면
  `RTS:1 Unspecified `처럼 둘 다 나온다.
- **순서는 항상 `RTS` → `Transaction` → `Heartbeat` → `Unspecified` 고정**이다
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
`mas_execution_price.lua`의 `add_rts`가 `#recs`를 반환, Transaction은
`mas_order_report.lua`의 `add_transaction`이 반환값 없이 `nil`→기본값 1로
처리) 그 값을 `cnt.RTS`/`cnt.Transaction`에 더한다. 압축 프레임이나 핸들러가
없는 경우는 기본값 1을 그대로 쓴다. 스트림 모듈은 더 이상 Info 라벨 자체에
관여하지 않으며, 예전에 있던 `note(label, c)` 콜백 파라미터는 완전히
제거했다. **Info 표시를 바꾸려면 `mas.lua`의 이 카운팅 블록과, RTS의 경우
`add_rts`의 반환값 계산 부분을 고치면 된다.**

## 4.7. `mas.ep`/`mas.or` 존재 필터는 반드시 "진짜 디코드 성공"에만 매칭돼야 한다

**과거 발견된 버그**: Wireshark에서 `mas.ep`(체결 시세)나 `mas.or`(주문 체결
통보) 같은 바깥(bare) 프로토콜 필터는 "이 프레임에 해당 프로토콜의
`tree:add(proto_x, ...)` 트리 항목이 있는가"로 판정된다. 그런데
`mas_execution_price.lua`의 "Unspecified RTS" 서브트리(TYPE≠'B')와
`mas_order_report.lua`의 "Unspecified Transaction" 서브트리(MSGK≠0x90/암호화)가
**전부 `proto_ex`/`proto_or`(즉 `mas.ep`/`mas.or`)로 태그되어 있었다** — 라벨
문자열만 "Unspecified ..."로 바꿨을 뿐, 서브트리를 만드는 `tree:add()`의
첫 인자(proto)는 그대로 둔 채였다. 결과적으로 `mas.ep` 필터는 "체결
레코드가 있는 프레임"이 아니라 **"RTS(SESS=0x08) 프레임이면 전부"**,
`mas.or`는 **"Transaction(SESS=0x01) 프레임이면 전부"** 매칭해 사실상
`mas.sess==0x08`/`mas.sess==0x01`과 다를 바 없어져 있었다. 같은 이유로
`add_exec`은 TYPE='B'이지만 39필드 디코드에 실패한 경우(손상된 레코드)에도
`proto_ex`를 그대로 썼다.

**수정**: 미해독/디코드 실패 서브트리는 자식 proto 대신 **우산 proto
(`mas.proto`, `mas.lua`에서 `mas.proto = proto`로 공개)**로 태그한다.
- `mas_execution_price.lua`: `add_exec`은 **먼저 `E.decode()`를 호출한 뒤**
  성공 여부에 따라 `proto_ex`(성공) 또는 `mas.proto`(실패)로 서브트리를
  만든다. "Unspecified RTS" 분기(TYPE≠'B')도 `mas.proto`를 쓴다.
- `mas_order_report.lua`: MSGK/ACTF를 미리 확인한 `will_decode` 불리언으로
  `proto_or`(디코드 예정) vs `mas.proto`(미해독)를 선택해 서브트리를 만든다.

이렇게 해도 **개별 필드 필터는 영향이 없다** — 예를 들어 `mas.ep.type`이나
`mas.or.msgk` 같은 필드는 서브트리가 어느 proto에 속하든 실제 바이트에서
정확히 추출되어 항상 채워지므로 그대로 정확히 동작한다(RTS-HEADER/
AXIS-HEADER는 레코드/트랜잭션 공통 헤더라 TYPE·MSGK와 무관하게 항상 존재).
바뀌는 것은 오직 **"필드 접두어 없이 바로 쓰는 존재 필터(`mas.ep`, `mas.or`
자체)"**뿐이다. **새로운 "Unspecified" 계열 표시를 추가할 때는 항상 이
패턴(디코드 성공 여부를 먼저 판정 → 그 결과로 proto 선택 → 서브트리 생성)을
따를 것.**

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

## 5. 미해독 영역과 그 이유

| 영역 | 조건 | 이유 |
|---|---|---|
| RTS 압축 | CHCK bit `0x02` | LZO 압축, 라이브러리/구현 없음 → `mas.data` |
| Transaction 암호화 | ACTF bit `0x02` | Xecure/XecureMobile 구간암호화, 키 없음 → `mas.data` |
| RTS TYPE ≠ 'B' | C/D/U/Y/Z/c/m/y/V/F 등 | 레이아웃 미상, 요청 범위 밖 → KIND/TYPE/LENGTH만 표시 + `mas.data` |
| Transaction MSGK ≠ 0x90 | Normal/RTS-on-off/Dialog/Error/키교환 등 | 요청 범위 밖(주문체결·체결시세만 지원) → AXIS-HEADER만 표시 + `mas.data` |
| Heartbeat | CTRL=`0x04` | 데이터 없음, 상세창·Info 모두 `Heartbeat` |

이 영역들을 추후 확장하려면:
1. 해당 레이아웃(필드 사전 또는 위치 스키마)을 확보한다.
2. `mas_execution_price.lua`(RTS TYPE 추가) 또는 `mas_order_report.lua`
   (다른 MSGK 추가)에 위 코드/체결 모듈과 같은 패턴(사전 테이블 + decode 함수 +
   ProtoField 등록 + `add_*` 함수)으로 핸들러를 늘린다.
3. 압축/암호화 해제가 가능해지면, `mas.lua`의 `CHCK bit 0x02`/`ACTF bit 0x02`
   분기에서 raw로 처리하기 전에 압축해제/복호화 함수를 끼워 넣고, 그 결과를 다시
   `mas.scan`(RTS의 경우 이미 페이로드 형태) 또는 해당 스트림 모듈의 파서에
   넘기면 된다.

## 6. 파일 구조와 조율 방식

| 파일 | 역할 |
|---|---|
| `mas.lua` | G/W 헤더 프레이밍(`mas.scan`), 우산 proto(`mas`) + dissector, TCP 재조립, Info 컬럼 소유, 공용 Statistics 창(`mas.open_stream_window`) |
| `mas_execution_price.lua` | RTS(SESS=0x08) 핸들러: RTS-HEADER 파싱, TYPE='B' 디코드, MAS/Execution 창 |
| `mas_order_report.lua` | Transaction(SESS=0x01) 핸들러: AXIS-HEADER 파싱, MSGK=0x90 디코드, MAS/Order 창 |

- 조율은 `_G.mas` 공유 전역으로 이뤄지며, 각 스트림 모듈이
  `mas.by_sess[SESS값] = { add = ..., init = ... }`을 스스로 등록한다 — **로드
  순서 독립적**(어느 파일이 먼저 로드돼도 동작).
- `add(gw, tvb, poff, plen, payload, pinfo, note)`의 `note(label, count)`
  콜백으로 각 핸들러가 Info 컬럼에 표시할 라벨/건수를 직접 기록한다(한 프레임에
  체결과 기타 TYPE이 섞여도 정확히 집계됨).
- 배포 시 **세 파일 모두** 플러그인 디렉터리에 복사해야 한다. `mas.lua`만
  있으면 SESS별 핸들러가 없어 해당 데이터가 전부 raw로만 보인다.

## 7. 검증 이력 (참고용, 저장소에는 미포함)

이번 재작성 검증은 세션 내 임시 스크립트(`/tmp` 스크래치패드)로 수행했고
저장소에는 커밋하지 않았다. 향후 정식 회귀 테스트로 승격하려면 다음을
재현하면 된다:

1. **순수 로직 검증**: `mas.scan` + `E.decode`/`E.split_records` +
   `O.decode_order`를 두 샘플 캡처의 실제 스트림 바이트(포트 15201 발신)에
   대해 실행 — junk 0건, 체결 디코드 실패 0건, 주문 리포트 디코드 성공 건수
   일치 확인.
2. **재조립 시뮬레이션**: 같은 스트림을 1/7/37/173/4096바이트 청크로 인위
   분할해 `pending`을 따라 재조립했을 때, 원샷 파싱과 프레임 수·CTRL/SESS
   분포·디코드 성공 건수가 완전히 일치하는지 확인 (1바이트 단위 포함).
3. **합성 엣지케이스**: 순수 junk, 트레일링 단독 `0xFE`, 헤더/길이/본문 잘림,
   길이필드 오염, heartbeat/압축 플래그, 미등록 SESS, NUL 패딩 등 8종.
4. **dissector 스텁 실행**: Wireshark API를 최소 스텁으로 흉내내
   `proto.dissector`를 실제 스트림 전체·개별 합성 프레임에 대해 호출 —
   크래시 없이 `MAS`로 claim, Info 컬럼이 `(#N)RTS:n Transaction:m Heartbeat
   Unspecified` 형식(고정 순서, RTS/Transaction은 담긴 메시지 수를 1이어도
   항상 `:n`로 표시 — RTS는 한 프레임 안의 레코드 합산, Transaction은 프레임당
   1, Heartbeat/Unspecified는 건수 무관하게 항상 생략, 넷 다 없으면
   `Unspecified` 단독, `(#N)`은 재조립된 프레임에만)으로 정확히 나오는지, 상세창 라벨
   (`Execution Price`/`Order Report`/`Unspecified RTS`/`Unspecified
   Transaction`/`Heartbeat`)과 `mas.ep`/`mas.or` 존재 필터가 디코드 성공
   여부에 정확히 연동되는지 확인.

실제 Wireshark GUI(트리 렌더링, 표시 필터, Statistics 창의 실제 클릭 동작)는
이 환경에서 실행할 수 없어 **로직·프레이밍 수준까지만** 검증됐다. 실제
Wireshark에 로드해 트리·필터·Statistics 창을 확인하는 것이 남은 검증 단계다.
