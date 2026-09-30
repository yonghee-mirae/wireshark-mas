-- MAS Transaction MSGK=0x90 (UMP, 실시간주문체결통보 / Order Report) decoder: a variable EUC-KR
-- code<TAB>value<TAB>... stream whose fields are identified by numeric code (ORDER_FIELDS). The only MSGK decoded here.

local mas = _G.mas or {}
_G.mas = mas
mas.by_msgk = mas.by_msgk or {}

local O = {}   -- module table: pure helpers (returned for tests)

O.MSGK_ORDER = 0x90   -- UMP: the only MSGK this module decodes

-- Split on tabs, stripping trailing NULs from each token; also returns each token's 0-based
-- byte range within `s` for per-token highlighting.
local function split_with_offsets(s)
  local toks, offsets = {}, {}
  local start = 1
  while true do
    local sep = s:find("\t", start, true)
    local e = sep and (sep - 1) or #s
    local raw = s:sub(start, e)
    local se = #raw
    while se > 0 and raw:byte(se) == 0 do se = se - 1 end
    toks[#toks + 1] = raw:sub(1, se)
    offsets[#offsets + 1] = { off = start - 1, len = se }
    if not sep then break end
    start = sep + 1
  end
  return toks, offsets
end

-- Order code dictionary, in layout order: { code, Korean name }.
-- The body is a variable stream of code/value pairs, so fields are identified by code, not
-- position; the code in the display label disambiguates duplicate names.
O.ORDER_FIELDS = {
  { "950", "계좌번호" },  { "975", "지점번호" },
  { "953", "종목단축코드" },  { "954", "주문통보TITLE" },
  { "955", "TITLE END FLAG" },  { "956", "종목명" },
  { "980", "매수/매도 체결구분" },  { "960", "매수매도 구분" },
  { "963", "매매구분" },  { "981", "주문조건" },
  { "973", "처리구분" },  { "983", "처리구분" },
  { "977", "처리구분" },  { "987", "주문구분" },
  { "995", "공매도여부" },  { "479", "보드ID" },
  { "370", "대출율" },  { "635", "기준가" },
  { "903", "신용구분" },  { "929", "신용구분TEXT" },
  { "902", "신용대출일" },  { "951", "주문방법(거래소)" },
  { "988", "리밸런싱여부/거래소정정여부" },  { "982", "자동취소구분값" },
  { "994", "신용주문구분" },  { "952", "주문번호" },
  { "961", "원주문번호" },  { "957", "주문수량" },
  { "958", "주문가격" },  { "978", "체결수량 합계" },
  { "964", "체결금액 합계" },  { "959", "미체결수량 합계" },
  { "984", "취소수량 합계" },  { "989", "거부수량 합계" },
  { "985", "스탑가격" },  { "986", "스탑상태" },
  { "966", "체결일련번호" },  { "965", "체결시간" },
  { "962", "거래소구분" },  { "969", "주문번호" },
  { "970", "원주문번호" },  { "967", "체결가격" },
  { "968", "체결수량" },  { "974", "미체결수량" },
  { "971", "거부수량" },  { "972", "취소수량" },
}

-- code -> Korean name.
O.ORDER_NAMES = {}
for _, f in ipairs(O.ORDER_FIELDS) do O.ORDER_NAMES[f[1]] = f[2] end

-- Decode an order-report TR-DATA body (tab-separated code/value pairs; a trailing NUL/empty
-- token is ignored) into a list of { code, name, value, code_off, value_off }; `name` is nil
-- for a code outside the dictionary. `body` is the UTF-8 text used for values; `raw_body`
-- (the untranscoded wire bytes) gives the offsets, which differ once a multibyte value
-- changes length.
function O.decode_order(body, raw_body)
  local toks, offsets = split_with_offsets(body)
  if raw_body then
    local raw_toks, raw_offsets = split_with_offsets(raw_body)
    if #raw_toks == #toks then offsets = raw_offsets end
  end
  local rec = {}
  for k = 1, #toks - 1, 2 do
    local code = toks[k]
    rec[#rec + 1] = { code = code, name = O.ORDER_NAMES[code], value = toks[k + 1],
                      code_off = offsets[k], value_off = offsets[k + 1] }
  end
  return rec
end

if _G.Proto then
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")   -- the only protocol

  -- One string field per dictionary code (mas.tr.90.<code>, label "(<code>)<name>"); an unknown
  -- code falls back to mas.tr.90.unknown.
  local pf = { unknown = ProtoField.string("mas.tr.90.unknown", "unknown_code") }
  local fields = { pf.unknown }
  for _, f in ipairs(O.ORDER_FIELDS) do
    local code, name = f[1], f[2]
    pf[code] = ProtoField.string("mas.tr.90." .. code, "(" .. code .. ")" .. name)
    fields[#fields + 1] = pf[code]
  end
  mas.proto.fields = fields

  -- Decode TR-DATA (poff/plen = the whole payload, AXIS-HEADER included) into `sub`. Values are
  -- EUC-KR, so the body is transcoded to UTF-8 before splitting (needs EUC-KR string support).
  local function add_order_body(sub, tvb, poff, plen, pinfo)
    local doff, dlen = poff + 24, plen - 24
    local raw = (dlen > 0) and tvb(doff, dlen):raw() or ""
    local utf8 = (dlen > 0) and tvb(doff, dlen):string(ENC_EUC_KR) or ""
    for _, p in ipairs(O.decode_order(utf8, raw)) do
      local f = pf[p.code]
      if f then
        local o = p.value_off
        sub:add(f, tvb(doff + o.off, o.len), p.value)
      else
        local co, vo = p.code_off, p.value_off
        sub:add(pf.unknown, tvb(doff + co.off, (vo.off + vo.len) - co.off), p.code .. "=" .. p.value)
      end
    end
  end

  mas.by_msgk[O.MSGK_ORDER] = { add = add_order_body }
end

return O
