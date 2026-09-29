-- MAS RTS TYPE='u'(소문자) 필드 레이아웃 — 해외주식 체결 (After Market)
--
-- Filename is `mas_rts_lu.lua` ("lower u") because `mas_rts_u.lua` is TYPE='U'
-- (same reasoning as mas_rts_ls.lua). The registration key
-- (mas.by_rts_type["u"]) and Wireshark FILTER prefix (`mas.rts.u.*`) use the
-- literal wire byte "u".
--
-- One RTS-DATA record's DATA is a 31-field tab-separated body (key + 30 spec
-- fields, design/field_spec.md), same layout family as TYPE='s' but with the
-- After-market price block instead of the regular-session block. Like 's',
-- the body ends with one stray tab before the NUL. `change` (724) is a
-- 코드+수치 field: first char is the 전일대비구분 code (same as `change_sign`
-- 735), the rest is the magnitude (see mas_rts_ls.lua).
--
-- Pure helpers (decode/decode_coded, required by tests) + Wireshark registration.
-- Coordinates with core via _G.mas.

local mas = _G.mas or {}
_G.mas = mas
mas.by_rts_type = mas.by_rts_type or {}

local U = {}   -- module table: pure helpers (returned for tests)

U.TYPE_OVERSEAS_AFTER_EXEC = "u"

U.CHANGE_SIGN = { ["1"] = 1, ["2"] = 1, ["3"] = 0, ["4"] = -1, ["5"] = -1 }

-- Field order (0-based index 0..30), for RTS TYPE='u'.
U.FIELD_NAMES = {
  "key", "type_echo", "realtime_gubun", "price_decimal_places", "business_date",
  "data_date_kr", "data_time_kr", "market_gubun", "change_sign", "volume_gubun",
  "trade_gubun", "base_price", "price", "change", "change_rate",
  "open_price", "high_price", "low_price", "bid_price", "ask_price",
  "trade_volume", "trade_value_k", "acc_volume", "acc_value_k",
  "open_change_rate", "high_change_rate", "low_change_rate", "vwap",
  "prev_day_ratio", "trade_strength", "chart_skip_gubun",
}

-- Decode a 코드+수치 field ("2500" -> 500, "5250" -> -250); nil if malformed.
function U.decode_coded(tok)
  if not tok or #tok < 1 then return nil end
  local sign = U.CHANGE_SIGN[tok:sub(1, 1)]
  if not sign then return nil end
  local mag = tonumber(tok:sub(2))
  if not mag then return nil end
  return sign * mag
end

-- Strip trailing NUL bytes, then one stray trailing tab.
local function rstrip_nul_and_tab(s)
  local e = #s
  while e > 0 and s:byte(e) == 0 do e = e - 1 end
  if e > 0 and s:byte(e) == 9 then e = e - 1 end
  return s:sub(1, e)
end

-- Split a tab-separated TYPE='u' body into a record keyed by FIELD_NAMES.
-- Returns nil if field count != 31. `rec.__offsets[name] = {off, len}` is each
-- field's 0-based byte range within `body` (for per-field highlighting).
function U.decode(body)
  local cleaned = rstrip_nul_and_tab(body)
  local fields, offsets = {}, {}
  local start = 1
  while true do
    local sep = cleaned:find("\t", start, true)
    local e = sep and (sep - 1) or #cleaned
    fields[#fields + 1] = cleaned:sub(start, e)
    offsets[#offsets + 1] = { off = start - 1, len = e - start + 1 }
    if not sep then break end
    start = sep + 1
  end
  if #fields ~= #U.FIELD_NAMES then return nil end

  local rec = { __offsets = {} }
  for k = 1, #U.FIELD_NAMES do
    local name = U.FIELD_NAMES[k]
    rec[name] = fields[k]
    rec.__offsets[name] = offsets[k]
  end
  return rec
end

-- 전일대비구분 code -> Korean meaning, for the (code;meaning) note on 코드+수치 fields.
U.CHANGE_LABEL = { ["1"] = "상한", ["2"] = "상승", ["3"] = "보합", ["4"] = "하한", ["5"] = "하락" }

-- 코드+수치 필드 (design/field_spec.md): returns the value without its leading
-- code plus the "code;meaning" note, e.g. "22.6700" -> "2.6700", "2;상승".
-- Returns nil for an unknown code (caller shows the raw value).
function U.split_coded(tok)
  local label = U.CHANGE_LABEL[tok:sub(1, 1)]
  if label then return tok:sub(2), tok:sub(1, 1) .. ";" .. label end
end

local CODE_VALUE_FIELDS = { change = true }

-- Spec code + detail-pane label per field, from design/field_spec.md:
-- FIELD_SPEC[name] = { filter suffix (mas.rts.u.<suffix>), label }. The wire's
-- leading key (not in the spec) is "key"; `sep` is never displayed.
U.FIELD_SPEC = {
  key = { "key", "key" },
  realtime_gubun = { "888", "(888)실시간구분" }, price_decimal_places = { "480", "(480)가격소수점자리수" },
  business_date = { "310", "(310)영업일자" }, data_date_kr = { "146", "(146)자료일자(한국)" },
  data_time_kr = { "034", "(034)자료시간(한국)" }, market_gubun = { "672", "(672)장구분" },
  change_sign = { "735", "(735)After전일대비구분" }, volume_gubun = { "387", "(387)체결량구분" },
  trade_gubun = { "035", "(035)체결구분" }, base_price = { "635", "(635)기준가" },
  price = { "723", "(723)After현재가" }, change = { "724", "(724)After전일대비" },
  change_rate = { "733", "(733)After등락율" }, open_price = { "029", "(029)시가" },
  high_price = { "030", "(030)고가" }, low_price = { "031", "(031)저가" },
  bid_price = { "026", "(026)매수호가" }, ask_price = { "025", "(025)매도호가" },
  trade_volume = { "032", "(032)단위거래량" }, trade_value_k = { "722", "(722)단위거래대금(천)" },
  acc_volume = { "027", "(027)누적거래량" }, acc_value_k = { "028", "(028)누적거래대금(천)" },
  open_change_rate = { "488", "(488)시가대비등락율" }, high_change_rate = { "487", "(487)고가대비등락율" },
  low_change_rate = { "489", "(489)저가대비등락율" }, vwap = { "252", "(252)가중평균가" },
  prev_day_ratio = { "251", "(251)전일거래비" }, trade_strength = { "388", "(388)체결강도" },
  chart_skip_gubun = { "676", "(676)차트 Tick,N분 SKIP구분" },
}

if _G.Proto then
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  local pf = {}
  for _, name in ipairs(U.FIELD_NAMES) do
    if U.FIELD_SPEC[name] then  -- RTS-TYPE(000) is never displayed
      pf[name] = ProtoField.string("mas.rts.u." .. U.FIELD_SPEC[name][1], U.FIELD_SPEC[name][2])
    end
  end

  local fields = {}
  for _, f in pairs(pf) do fields[#fields + 1] = f end
  mas.proto.fields = fields

  local expert_badfields =
    ProtoExpert.new("mas.rts.u.expert.fields", "Unexpected overseas after-market execution field count",
      expert.group.MALFORMED, expert.severity.WARN)
  mas.proto.experts = { expert_badfields }

  local function add_overseas_after_exec(tree, tvb, poff, r, pinfo, msg_index)
    local rec = U.decode(r.body)
    local sub = tree:add(mas.proto, tvb(poff + r.off, 6 + r.len),
      "type: " .. U.TYPE_OVERSEAS_AFTER_EXEC .. " (" .. r.len .. " bytes)")
    mas.rts_add_header(sub, tvb, poff, r)
    if not rec then
      sub:add_proto_expert_info(expert_badfields)
      return false
    end
    local base = poff + r.off + 6   -- body start within tvb
    for _, name in ipairs(U.FIELD_NAMES) do
      if pf[name] then
        local o = rec.__offsets[name]
        local shown, note = rec[name]
        if CODE_VALUE_FIELDS[name] then shown, note = U.split_coded(rec[name]) end
        local ti = sub:add(pf[name], tvb(base + o.off, o.len), shown or rec[name])
        if note then ti:append_text(" (" .. note .. ")") end
      end
    end
    return true
  end

  mas.by_rts_type[U.TYPE_OVERSEAS_AFTER_EXEC] = { add = add_overseas_after_exec }
end

return U
