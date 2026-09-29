-- MAS RTS TYPE='q'(소문자) 필드 레이아웃 — 해외주식 호가 (Overseas Stock Quote)
--
-- Filename note: this TYPE is lowercase 'q'. The FILENAME convention
-- lowercases the TYPE letter (e.g. TYPE='B' -> mas_rts_b.lua), which would
-- collide with a hypothetical future TYPE='Q' (uppercase) — so this
-- already-lowercase TYPE is named `mas_rts_lq.lua` ("lower q") instead of
-- `mas_rts_q.lua`, reserving the latter for TYPE='Q' if it ever turns up
-- (same reasoning as mas_rts_lm.lua/mas_rts_ls.lua). This is filename-only:
-- the registration key (mas.by_rts_type["q"]) and the Wireshark FILTER
-- prefix (`mas.rts.q.*`) both use the literal wire byte "q" as-is.
--
-- One RTS-DATA record's DATA (see mas_rts.lua for RTS-HEADER framing) is a
-- 72-field tab-separated body (spec: design/field_spec.md). This is the only
-- RTS TYPE this module decodes; every other TYPE is left to mas_rts.lua's
-- generic "type: <TYPE>"-only handling.
--
-- Confirmed against all 42 real TYPE='q' records in
-- samples/GlobalPart_RTS.pcapng (symbol DTSLA): total_ask_qty ==
-- sum(ask_qty1..10) and total_bid_qty == sum(bid_qty1..10) held exactly for
-- every record. total_ask_qty_chg/total_bid_qty_chg (잔량변화, quantity
-- CHANGE at that price level — negative values are normal) only summed to
-- the visible top-10 ladder in 39/42 and 35/42 records; the rest is
-- explained by book activity beyond the 10 visible levels still moving the
-- aggregate total, not a field-mapping issue. No stray trailing tab before
-- the terminating NUL (unlike TYPE='s').
--
-- Pure helpers (decode, required by tests) + Wireshark registration.
-- Coordinates with core via _G.mas.

local mas = _G.mas or {}
_G.mas = mas
mas.by_rts_type = mas.by_rts_type or {}

local Q = {}   -- module table: pure helpers (returned for tests)

Q.TYPE_OVERSEAS_QUOTE = "q"   -- the only RTS TYPE this module decodes

-- Build a "<prefix><1..n>" name list, e.g. ladder("ask_price", 10) ->
-- {"ask_price1", ..., "ask_price10"} (see mas_rts_c.lua for the same helper).
local function ladder(prefix, n)
  local t = {}
  for i = 1, n do t[i] = prefix .. i end
  return t
end

-- Field order (0-based index 0..71), for RTS TYPE='q' (Overseas Stock Quote).
Q.FIELD_NAMES = {}
local function append(t) for _, v in ipairs(t) do Q.FIELD_NAMES[#Q.FIELD_NAMES + 1] = v end end
append({ "key", "type_echo", "realtime_gubun", "price_decimal_places", "business_date",
         "data_date_kr", "data_time_kr", "base_price" })
append(ladder("ask_price", 10))
append(ladder("bid_price", 10))
append(ladder("ask_qty", 10))
append(ladder("bid_qty", 10))
append(ladder("ask_qty_chg", 10))
append(ladder("bid_qty_chg", 10))
append({ "total_ask_qty", "total_bid_qty", "total_ask_qty_chg", "total_bid_qty_chg" })

-- Split a tab-separated string into fields, stripping trailing NUL bytes from
-- each (see mas_rts_b for the version note). Also returns each field's own
-- 0-based byte range within `s` (post-NUL-strip length) so the detail pane
-- can highlight just that field's bytes instead of the whole record (see
-- add_overseas_quote).
local function split_with_offsets(s)
  local fields, offsets = {}, {}
  local start = 1
  while true do
    local sep = s:find("\t", start, true)
    local e = sep and (sep - 1) or #s
    local raw = s:sub(start, e)
    local se = #raw
    while se > 0 and raw:byte(se) == 0 do se = se - 1 end
    fields[#fields + 1] = raw:sub(1, se)
    offsets[#offsets + 1] = { off = start - 1, len = se }
    if not sep then break end
    start = sep + 1
  end
  return fields, offsets
end

-- Split a tab-separated TYPE='q' body into a record keyed by FIELD_NAMES.
-- Returns nil if field count != 72. `rec.__offsets[name] = {off, len}` gives
-- each field's own byte range within `body`.
function Q.decode(body)
  local fields, offsets = split_with_offsets(body)
  if #fields ~= #Q.FIELD_NAMES then return nil end

  local rec = { __offsets = {} }
  for k = 1, #Q.FIELD_NAMES do
    local name = Q.FIELD_NAMES[k]
    rec[name] = fields[k]
    rec.__offsets[name] = offsets[k]
  end
  return rec
end

-- Spec code + detail-pane label per field, from design/field_spec.md:
-- FIELD_SPEC[name] = { filter suffix (mas.rts.q.<suffix>), label }. The wire's
-- leading key (not in the spec) is "key"; `sep` is never displayed.
Q.FIELD_SPEC = {
  key = { "key", "key" },
  realtime_gubun = { "888", "(888)실시간구분" }, price_decimal_places = { "480", "(480)가격소수점자리수" },
  business_date = { "310", "(310)영업일자" }, data_date_kr = { "647", "(647)자료일자(한국)" },
  data_time_kr = { "040", "(040)자료시간(한국)" }, base_price = { "635", "(635)기준가" },
  ask_price1 = { "051", "(051)매도호가1" }, ask_price2 = { "052", "(052)매도호가2" },
  ask_price3 = { "053", "(053)매도호가3" }, ask_price4 = { "054", "(054)매도호가4" },
  ask_price5 = { "055", "(055)매도호가5" }, ask_price6 = { "056", "(056)매도호가6" },
  ask_price7 = { "057", "(057)매도호가7" }, ask_price8 = { "058", "(058)매도호가8" },
  ask_price9 = { "059", "(059)매도호가9" }, ask_price10 = { "060", "(060)매도호가10" },
  bid_price1 = { "071", "(071)매수호가1" }, bid_price2 = { "072", "(072)매수호가2" },
  bid_price3 = { "073", "(073)매수호가3" }, bid_price4 = { "074", "(074)매수호가4" },
  bid_price5 = { "075", "(075)매수호가5" }, bid_price6 = { "076", "(076)매수호가6" },
  bid_price7 = { "077", "(077)매수호가7" }, bid_price8 = { "078", "(078)매수호가8" },
  bid_price9 = { "079", "(079)매수호가9" }, bid_price10 = { "080", "(080)매수호가10" },
  ask_qty1 = { "041", "(041)매도호가잔량1" }, ask_qty2 = { "042", "(042)매도호가잔량2" },
  ask_qty3 = { "043", "(043)매도호가잔량3" }, ask_qty4 = { "044", "(044)매도호가잔량4" },
  ask_qty5 = { "045", "(045)매도호가잔량5" }, ask_qty6 = { "046", "(046)매도호가잔량6" },
  ask_qty7 = { "047", "(047)매도호가잔량7" }, ask_qty8 = { "048", "(048)매도호가잔량8" },
  ask_qty9 = { "049", "(049)매도호가잔량9" }, ask_qty10 = { "050", "(050)매도호가잔량10" },
  bid_qty1 = { "061", "(061)매수호가잔량1" }, bid_qty2 = { "062", "(062)매수호가잔량2" },
  bid_qty3 = { "063", "(063)매수호가잔량3" }, bid_qty4 = { "064", "(064)매수호가잔량4" },
  bid_qty5 = { "065", "(065)매수호가잔량5" }, bid_qty6 = { "066", "(066)매수호가잔량6" },
  bid_qty7 = { "067", "(067)매수호가잔량7" }, bid_qty8 = { "068", "(068)매수호가잔량8" },
  bid_qty9 = { "069", "(069)매수호가잔량9" }, bid_qty10 = { "070", "(070)매수호가잔량10" },
  ask_qty_chg1 = { "211", "(211)매도호가잔량변화1" }, ask_qty_chg2 = { "212", "(212)매도호가잔량변화2" },
  ask_qty_chg3 = { "213", "(213)매도호가잔량변화3" }, ask_qty_chg4 = { "214", "(214)매도호가잔량변화4" },
  ask_qty_chg5 = { "215", "(215)매도호가잔량변화5" }, ask_qty_chg6 = { "216", "(216)매도호가잔량변화6" },
  ask_qty_chg7 = { "217", "(217)매도호가잔량변화7" }, ask_qty_chg8 = { "218", "(218)매도호가잔량변화8" },
  ask_qty_chg9 = { "219", "(219)매도호가잔량변화9" }, ask_qty_chg10 = { "220", "(220)매도호가잔량변화10" },
  bid_qty_chg1 = { "221", "(221)매수호가잔량변화1" }, bid_qty_chg2 = { "222", "(222)매수호가잔량변화2" },
  bid_qty_chg3 = { "223", "(223)매수호가잔량변화3" }, bid_qty_chg4 = { "224", "(224)매수호가잔량변화4" },
  bid_qty_chg5 = { "225", "(225)매수호가잔량변화5" }, bid_qty_chg6 = { "226", "(226)매수호가잔량변화6" },
  bid_qty_chg7 = { "227", "(227)매수호가잔량변화7" }, bid_qty_chg8 = { "228", "(228)매수호가잔량변화8" },
  bid_qty_chg9 = { "229", "(229)매수호가잔량변화9" }, bid_qty_chg10 = { "230", "(230)매수호가잔량변화10" },
  total_ask_qty = { "101", "(101)총매도호가잔량" }, total_bid_qty = { "106", "(106)총매수호가잔량" },
  total_ask_qty_chg = { "103", "(103)총매도호가잔량변화" }, total_bid_qty_chg = { "108", "(108)총매수호가잔량변화" },
}

if _G.Proto then
  -- No dedicated Proto here — `mas` is the only registered protocol (§4.7).
  -- Fields are appended to the shared mas.proto (cumulative; see PROTOCOL.md §6).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  -- Register a string field per FIELD_NAMES entry.
  local pf = {}
  for _, name in ipairs(Q.FIELD_NAMES) do
    if Q.FIELD_SPEC[name] then  -- RTS-TYPE(000) is never displayed
      pf[name] = ProtoField.string("mas.rts.q." .. Q.FIELD_SPEC[name][1], Q.FIELD_SPEC[name][2])
    end
  end

  local fields = {}
  for _, f in pairs(pf) do fields[#fields + 1] = f end
  mas.proto.fields = fields

  local expert_badfields =
    ProtoExpert.new("mas.rts.q.expert.fields", "Unexpected overseas-quote field count",
      expert.group.MALFORMED, expert.severity.WARN)
  mas.proto.experts = { expert_badfields }

  -- Decode a TYPE='q' overseas-quote record body into the tree. The subtree
  -- is always tagged with the umbrella `mas` proto (see PROTOCOL.md §4.7) —
  -- a malformed body (wrong field count) is flagged via expert_badfields
  -- instead; "did this decode?" is a field-value question, not a
  -- presence-filter one (mirrors add_overseas_exec/add_quote).
  local function add_overseas_quote(tree, tvb, poff, r, pinfo, msg_index)
    local rec = Q.decode(r.body)
    local sub = tree:add(mas.proto, tvb(poff + r.off, 6 + r.len),
      "type: " .. Q.TYPE_OVERSEAS_QUOTE .. " (" .. r.len .. " bytes)")
    mas.rts_add_header(sub, tvb, poff, r)
    if not rec then
      sub:add_proto_expert_info(expert_badfields)
      return false
    end
    local base = poff + r.off + 6   -- body start within tvb
    for _, name in ipairs(Q.FIELD_NAMES) do
      if pf[name] then
        local o = rec.__offsets[name]
        sub:add(pf[name], tvb(base + o.off, o.len), rec[name])
      end
    end
    return true
  end

  -- Register as the TYPE='q' decoder; mas_rts.lua's generic dispatcher calls
  -- this for every TYPE='q' record and falls back to a bare "type: <TYPE>"
  -- label itself for any other TYPE.
  mas.by_rts_type[Q.TYPE_OVERSEAS_QUOTE] = { add = add_overseas_quote }
end

return Q
