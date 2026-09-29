-- MAS RTS TYPE='s'(소문자) 필드 레이아웃 — 해외주식 체결 (Overseas Stock Execution)
--
-- Filename note: this TYPE is lowercase 's'. The FILENAME convention
-- lowercases the TYPE letter (e.g. TYPE='B' -> mas_rts_b.lua), which would
-- collide with a hypothetical future TYPE='S' (uppercase) — so this
-- already-lowercase TYPE is named `mas_rts_ls.lua` ("lower s") instead of
-- `mas_rts_s.lua`, reserving the latter for TYPE='S' if it ever turns up
-- (same reasoning as mas_rts_lm.lua for TYPE='m'). This is filename-only:
-- the registration key (mas.by_rts_type["s"]) and the Wireshark FILTER
-- prefix (`mas.rts.s.*`) both use the literal wire byte "s" as-is.
--
-- One RTS-DATA record's DATA (see mas_rts.lua for RTS-HEADER framing) is a
-- 41-field tab-separated body (spec: design/field_spec.md). This is the only
-- RTS TYPE this module decodes; every other TYPE is left to mas_rts.lua's
-- generic "type: <TYPE>"-only handling.
--
-- 024(전일대비)/743(정규장 전일대비)/753(주간 정규장대비) are **코드+수치**
-- fields: the first character is the same code as 149/742/752(전일대비구분:
-- 1=상한/2=상승/3=보합/4=하한/5=하락), the rest is the ASCII decimal
-- magnitude with no separator (e.g. "22.6700" = code '2'(상승) + magnitude
-- "2.6700"). Confirmed against all 11 real TYPE='s' records in
-- samples/tcp_capture.cap: base_price + decode_coded(change) == price
-- exactly, for every record (4 distinct symbols).
--
-- The wire body ends with one stray tab before the terminating NUL (last
-- field's value + "\t" + "\x00", confirmed on all 11 records) — decode()
-- strips that in addition to the trailing NUL(s).
--
-- Pure helpers (decode/decode_coded, required by tests) + Wireshark registration.
-- Coordinates with core via _G.mas.

local mas = _G.mas or {}
_G.mas = mas
mas.by_rts_type = mas.by_rts_type or {}

local S = {}   -- module table: pure helpers (returned for tests)

S.TYPE_OVERSEAS_EXEC = "s"   -- the only RTS TYPE this module decodes

-- 전일대비구분 code -> sign, shared by 149/742/752 and the 코드+수치 fields.
S.CHANGE_SIGN = { ["1"] = 1, ["2"] = 1, ["3"] = 0, ["4"] = -1, ["5"] = -1 }

-- Field order (0-based index 0..40), for RTS TYPE='s' (Overseas Stock Execution).
S.FIELD_NAMES = {
  "key", "type_echo", "realtime_gubun", "price_decimal_places", "business_date",
  "data_date_kr", "data_time_kr", "market_gubun", "change_sign", "volume_gubun",
  "trade_gubun", "base_price", "price", "change", "change_rate",
  "open_price", "high_price", "low_price", "bid_price", "ask_price",
  "trade_volume", "trade_value_k", "acc_volume", "acc_value_k",
  "open_change_rate", "high_change_rate", "low_change_rate", "vwap",
  "prev_day_ratio", "trade_strength",
  "regular_price", "regular_change_sign", "regular_change", "regular_change_rate",
  "regular_open_price", "regular_high_price", "regular_low_price",
  "day_regular_diff_sign", "day_regular_diff", "day_regular_diff_rate",
  "chart_skip_gubun",
}

-- Decode a 코드+수치 field ("2500" -> 500 상승, "5250" -> -250 하락). Returns
-- nil if the leading character isn't a known 전일대비구분 code or the
-- remainder isn't numeric.
function S.decode_coded(tok)
  if not tok or #tok < 1 then return nil end
  local sign = S.CHANGE_SIGN[tok:sub(1, 1)]
  if not sign then return nil end
  local mag = tonumber(tok:sub(2))
  if not mag then return nil end
  return sign * mag
end

-- Strip trailing NUL bytes, then one stray trailing tab (see module note above).
local function rstrip_nul_and_tab(s)
  local e = #s
  while e > 0 and s:byte(e) == 0 do e = e - 1 end
  if e > 0 and s:byte(e) == 9 then e = e - 1 end
  return s:sub(1, e)
end

-- Split a tab-separated TYPE='s' body into a record keyed by FIELD_NAMES.
-- Returns nil if field count != 41. `rec.__offsets[name] = {off, len}` gives
-- each field's own 0-based byte range within `body` (not `cleaned` — the
-- stripped trailing NUL(s)/tab are always at the very end, so positions up to
-- that point are identical in both), so the detail pane can highlight just
-- that field's bytes instead of the whole record (see add_overseas_exec).
function S.decode(body)
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
  if #fields ~= #S.FIELD_NAMES then return nil end

  local rec = { __offsets = {} }
  for k = 1, #S.FIELD_NAMES do
    local name = S.FIELD_NAMES[k]
    rec[name] = fields[k]
    rec.__offsets[name] = offsets[k]
  end
  return rec
end

-- 전일대비구분 code -> Korean meaning, for the (code;meaning) note on 코드+수치 fields.
S.CHANGE_LABEL = { ["1"] = "상한", ["2"] = "상승", ["3"] = "보합", ["4"] = "하한", ["5"] = "하락" }

-- 코드+수치 필드 (design/field_spec.md): returns the value without its leading
-- code plus the "code;meaning" note, e.g. "22.6700" -> "2.6700", "2;상승".
-- Returns nil for an unknown code (caller shows the raw value).
function S.split_coded(tok)
  local label = S.CHANGE_LABEL[tok:sub(1, 1)]
  if label then return tok:sub(2), tok:sub(1, 1) .. ";" .. label end
end

local CODE_VALUE_FIELDS = { change = true, regular_change = true, day_regular_diff = true }

-- Spec code + detail-pane label per field, from design/field_spec.md:
-- FIELD_SPEC[name] = { filter suffix (mas.rts.s.<suffix>), label }. The wire's
-- leading key (not in the spec) is "key"; `sep` is never displayed.
S.FIELD_SPEC = {
  key = { "key", "key" },
  realtime_gubun = { "888", "(888)실시간구분" }, price_decimal_places = { "480", "(480)가격소수점자리수" },
  business_date = { "310", "(310)영업일자" }, data_date_kr = { "146", "(146)자료일자(한국)" },
  data_time_kr = { "034", "(034)자료시간(한국)" }, market_gubun = { "672", "(672)장구분" },
  change_sign = { "149", "(149)전일대비구분" }, volume_gubun = { "387", "(387)체결량구분" },
  trade_gubun = { "035", "(035)체결구분" }, base_price = { "635", "(635)기준가" },
  price = { "023", "(023)현재가" }, change = { "024", "(024)전일대비" },
  change_rate = { "033", "(033)등락율" }, open_price = { "029", "(029)시가" },
  high_price = { "030", "(030)고가" }, low_price = { "031", "(031)저가" },
  bid_price = { "026", "(026)매수호가" }, ask_price = { "025", "(025)매도호가" },
  trade_volume = { "032", "(032)단위거래량" }, trade_value_k = { "722", "(722)단위거래대금(천)" },
  acc_volume = { "027", "(027)누적거래량" }, acc_value_k = { "028", "(028)누적거래대금(천)" },
  open_change_rate = { "488", "(488)시가대비등락율" }, high_change_rate = { "487", "(487)고가대비등락율" },
  low_change_rate = { "489", "(489)저가대비등락율" }, vwap = { "252", "(252)가중평균가" },
  prev_day_ratio = { "251", "(251)전일거래비" }, trade_strength = { "388", "(388)체결강도" },
  regular_price = { "736", "(736)정규장 현재가" }, regular_change_sign = { "742", "(742)정규장 전일대비구분" },
  regular_change = { "743", "(743)정규장 전일대비" }, regular_change_rate = { "739", "(739)정규장 등락율" },
  regular_open_price = { "729", "(729)정규장 시가" }, regular_high_price = { "730", "(730)정규장 고가" },
  regular_low_price = { "731", "(731)정규장 저가" }, day_regular_diff_sign = { "752", "(752)주간 정규장대비구분" },
  day_regular_diff = { "753", "(753)주간 정규장대비" }, day_regular_diff_rate = { "754", "(754)주간 정규장대비등락율" },
  chart_skip_gubun = { "676", "(676)차트 Tick,N분 SKIP구분" },
}

if _G.Proto then
  -- No dedicated Proto here — `mas` is the only registered protocol (§4.7).
  -- Fields are appended to the shared mas.proto (cumulative; see PROTOCOL.md §6).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  -- Register a string field per FIELD_NAMES entry, plus derived signed
  -- numeric fields for the 3 코드+수치 fields (change/regular_change/
  -- day_regular_diff) since their raw string form isn't directly usable.
  local pf = {}
  for _, name in ipairs(S.FIELD_NAMES) do
    if S.FIELD_SPEC[name] then  -- RTS-TYPE(000) is never displayed
      pf[name] = ProtoField.string("mas.rts.s." .. S.FIELD_SPEC[name][1], S.FIELD_SPEC[name][2])
    end
  end

  local fields = {}
  for _, f in pairs(pf) do fields[#fields + 1] = f end
  mas.proto.fields = fields

  local expert_badfields =
    ProtoExpert.new("mas.rts.s.expert.fields", "Unexpected overseas-execution field count",
      expert.group.MALFORMED, expert.severity.WARN)
  mas.proto.experts = { expert_badfields }

  -- Decode a TYPE='s' overseas-execution record body into the tree. The
  -- subtree is always tagged with the umbrella `mas` proto (see PROTOCOL.md
  -- §4.7) — a malformed body (wrong field count) is flagged via
  -- expert_badfields instead; "did this decode?" is a field-value question,
  -- not a presence-filter one (mirrors add_index/add_exec).
  local function add_overseas_exec(tree, tvb, poff, r, pinfo, msg_index)
    local rec = S.decode(r.body)
    local sub = tree:add(mas.proto, tvb(poff + r.off, 6 + r.len),
      "type: " .. S.TYPE_OVERSEAS_EXEC .. " (" .. r.len .. " bytes)")
    mas.rts_add_header(sub, tvb, poff, r)
    if not rec then
      sub:add_proto_expert_info(expert_badfields)
      return false
    end
    local base = poff + r.off + 6   -- body start within tvb
    for _, name in ipairs(S.FIELD_NAMES) do
      if pf[name] then
        local o = rec.__offsets[name]
        local shown, note = rec[name]
        if CODE_VALUE_FIELDS[name] then shown, note = S.split_coded(rec[name]) end
        local ti = sub:add(pf[name], tvb(base + o.off, o.len), shown or rec[name])
        if note then ti:append_text(" (" .. note .. ")") end
      end
    end
    return true
  end

  -- Register as the TYPE='s' decoder; mas_rts.lua's generic dispatcher calls
  -- this for every TYPE='s' record and falls back to a bare "type: <TYPE>"
  -- label itself for any other TYPE.
  mas.by_rts_type[S.TYPE_OVERSEAS_EXEC] = { add = add_overseas_exec }
end

return S
