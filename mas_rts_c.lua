-- MAS RTS TYPE='C' (호가 시세, Quote Price) decoder.
--
-- One RTS-DATA record's DATA (see mas_rts.lua for RTS-HEADER framing) is a
-- 128-field tab-separated body (127 named fields + 1 hidden record-type
-- marker, same "sep" role as in TYPE='B' — see PROTOCOL.md §8). This is the
-- only RTS TYPE this module decodes; every other TYPE is left to
-- mas_rts.lua's generic "type: <TYPE>"-only handling.
--
-- Field order/names are the confirmed spec cross-checked against
-- samples/*.pcapng (PROTOCOL.md §8): ask/bid price+qty ladders (10 levels
-- each), per-level qty change, KRX/NXT venue-split qty ladders, aggregate
-- totals, expected(indicative)-price fields, and KRX/NXT mid-price/총잔량
-- breakdowns. Several identity checks (e.g. ask_qty == krx_ask_qty +
-- nxt_ask_qty) held across all 979 sampled records.
--
-- Pure helpers (decode, required by tests) + Wireshark registration.
-- Coordinates with core via _G.mas.

local mas = _G.mas or {}
_G.mas = mas
mas.by_rts_type = mas.by_rts_type or {}

local Q = {}   -- module table: pure helpers (returned for tests)

Q.TYPE_QUOTE = "C"   -- the only RTS TYPE this module decodes

-- issue_code prefix -> market. No dot means KRX(K). Same convention as
-- mas_rts_b.lua's E.split_market.
local MARKET = { M = "M", N = "N" }

function Q.split_market(issue_code)
  local prefix, base = issue_code:match("^([^.]*)%.(.*)$")
  if base then
    return MARKET[prefix] or prefix, base
  end
  return "K", issue_code
end

-- Build a "<prefix><1..n>" name list, e.g. ladder("ask_price", 10) ->
-- {"ask_price1", ..., "ask_price10"}.
local function ladder(prefix, n)
  local t = {}
  for i = 1, n do t[i] = prefix .. i end
  return t
end

-- Field order (0-based index 0..127), for RTS TYPE='C' (Quote Price).
Q.FIELD_NAMES = {}
local function append(t) for _, v in ipairs(t) do Q.FIELD_NAMES[#Q.FIELD_NAMES + 1] = v end end
append({ "issue_code", "sep", "trade_time" })
append(ladder("ask_price", 10))
append(ladder("ask_qty", 10))
append(ladder("ask_qty_chg", 10))
append(ladder("krx_ask_qty", 10))
append(ladder("nxt_ask_qty", 10))
append(ladder("bid_price", 10))
append(ladder("bid_qty", 10))
append(ladder("bid_qty_chg", 10))
append(ladder("krx_bid_qty", 10))
append(ladder("nxt_bid_qty", 10))
append({
  "total_ask_qty", "total_ask_qty_chg", "total_bid_qty", "total_bid_qty_chg",
  "expected_price", "expected_qty", "expected_change", "expected_change_rate",
  "expected_change_amt", "expected_change_amt2", "arbitrage_basis",
  "net_buy_total_qty", "expected_fill_qty_ratio",
  "nxt_mid_price", "nxt_ask_mid_qty", "nxt_bid_mid_qty",
  "krx_mid_price", "krx_ask_mid_qty", "krx_bid_mid_qty",
  "nxt_mid_total_net_qty", "mid_total_net_qty",
  "krx_total_ask_qty", "nxt_total_ask_qty", "krx_total_bid_qty", "nxt_total_bid_qty",
})

-- Split a tab-separated string into fields, stripping trailing NUL bytes from
-- each (see mas_rts_b for the version note). Also returns each field's own
-- 0-based byte range within `s` (post-NUL-strip length) so the detail pane
-- can highlight just that field's bytes instead of the whole record (see
-- add_quote).
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

-- Split a tab-separated TYPE='C' body into a record keyed by FIELD_NAMES.
-- Returns nil if field count != 128. Trailing NULs are stripped; issue_code
-- -> (market, base). `rec.__offsets[name] = {off, len}` gives each field's
-- own byte range within `body`.
function Q.decode(body)
  local fields, offsets = split_with_offsets(body)
  if #fields ~= #Q.FIELD_NAMES then return nil end

  local rec = { __offsets = {} }
  for k = 1, #Q.FIELD_NAMES do
    rec[Q.FIELD_NAMES[k]] = fields[k]
    rec.__offsets[Q.FIELD_NAMES[k]] = offsets[k]
  end
  rec.market, rec.issue_code = Q.split_market(rec.issue_code)
  return rec
end

-- Spec code + detail-pane label per field, from design/field_spec.md:
-- FIELD_SPEC[name] = { filter suffix (mas.rts.C.<suffix>), label }. The wire's
-- leading key (not in the spec) is "key"; `sep` is never displayed.
Q.FIELD_SPEC = {
  issue_code = { "key", "key" }, trade_time = { "1040", "(1040)호가시간" },
  ask_price1 = { "1051", "(1051)매도가1" }, ask_price2 = { "1052", "(1052)매도가2" },
  ask_price3 = { "1053", "(1053)매도가3" }, ask_price4 = { "1054", "(1054)매도가4" },
  ask_price5 = { "1055", "(1055)매도가5" }, ask_price6 = { "1056", "(1056)매도가6" },
  ask_price7 = { "1057", "(1057)매도가7" }, ask_price8 = { "1058", "(1058)매도가8" },
  ask_price9 = { "1059", "(1059)매도가9" }, ask_price10 = { "1060", "(1060)매도가10" },
  ask_qty1 = { "1041", "(1041)매도량1" }, ask_qty2 = { "1042", "(1042)매도량2" },
  ask_qty3 = { "1043", "(1043)매도량3" }, ask_qty4 = { "1044", "(1044)매도량4" },
  ask_qty5 = { "1045", "(1045)매도량5" }, ask_qty6 = { "1046", "(1046)매도량6" },
  ask_qty7 = { "1047", "(1047)매도량7" }, ask_qty8 = { "1048", "(1048)매도량8" },
  ask_qty9 = { "1049", "(1049)매도량9" }, ask_qty10 = { "1050", "(1050)매도량10" },
  ask_qty_chg1 = { "1081", "(1081)매도비1" }, ask_qty_chg2 = { "1082", "(1082)매도비2" },
  ask_qty_chg3 = { "1083", "(1083)매도비3" }, ask_qty_chg4 = { "1084", "(1084)매도비4" },
  ask_qty_chg5 = { "1085", "(1085)매도비5" }, ask_qty_chg6 = { "1086", "(1086)매도비6" },
  ask_qty_chg7 = { "1087", "(1087)매도비7" }, ask_qty_chg8 = { "1088", "(1088)매도비8" },
  ask_qty_chg9 = { "1089", "(1089)매도비9" }, ask_qty_chg10 = { "1090", "(1090)매도비10" },
  krx_ask_qty1 = { "1241", "(1241)K매도량1" }, krx_ask_qty2 = { "1242", "(1242)K매도량2" },
  krx_ask_qty3 = { "1243", "(1243)K매도량3" }, krx_ask_qty4 = { "1244", "(1244)K매도량4" },
  krx_ask_qty5 = { "1245", "(1245)K매도량5" }, krx_ask_qty6 = { "1246", "(1246)K매도량6" },
  krx_ask_qty7 = { "1247", "(1247)K매도량7" }, krx_ask_qty8 = { "1248", "(1248)K매도량8" },
  krx_ask_qty9 = { "1249", "(1249)K매도량9" }, krx_ask_qty10 = { "1250", "(1250)K매도량10" },
  nxt_ask_qty1 = { "1441", "(1441)N매도량1" }, nxt_ask_qty2 = { "1442", "(1442)N매도량2" },
  nxt_ask_qty3 = { "1443", "(1443)N매도량3" }, nxt_ask_qty4 = { "1444", "(1444)N매도량4" },
  nxt_ask_qty5 = { "1445", "(1445)N매도량5" }, nxt_ask_qty6 = { "1446", "(1446)N매도량6" },
  nxt_ask_qty7 = { "1447", "(1447)N매도량7" }, nxt_ask_qty8 = { "1448", "(1448)N매도량8" },
  nxt_ask_qty9 = { "1449", "(1449)N매도량9" }, nxt_ask_qty10 = { "1450", "(1450)N매도량10" },
  bid_price1 = { "1071", "(1071)매수가1" }, bid_price2 = { "1072", "(1072)매수가2" },
  bid_price3 = { "1073", "(1073)매수가3" }, bid_price4 = { "1074", "(1074)매수가4" },
  bid_price5 = { "1075", "(1075)매수가5" }, bid_price6 = { "1076", "(1076)매수가6" },
  bid_price7 = { "1077", "(1077)매수가7" }, bid_price8 = { "1078", "(1078)매수가8" },
  bid_price9 = { "1079", "(1079)매수가9" }, bid_price10 = { "1080", "(1080)매수가10" },
  bid_qty1 = { "1061", "(1061)매수량1" }, bid_qty2 = { "1062", "(1062)매수량2" },
  bid_qty3 = { "1063", "(1063)매수량3" }, bid_qty4 = { "1064", "(1064)매수량4" },
  bid_qty5 = { "1065", "(1065)매수량5" }, bid_qty6 = { "1066", "(1066)매수량6" },
  bid_qty7 = { "1067", "(1067)매수량7" }, bid_qty8 = { "1068", "(1068)매수량8" },
  bid_qty9 = { "1069", "(1069)매수량9" }, bid_qty10 = { "1070", "(1070)매수량10" },
  bid_qty_chg1 = { "1091", "(1091)매수비1" }, bid_qty_chg2 = { "1092", "(1092)매수비2" },
  bid_qty_chg3 = { "1093", "(1093)매수비3" }, bid_qty_chg4 = { "1094", "(1094)매수비4" },
  bid_qty_chg5 = { "1095", "(1095)매수비5" }, bid_qty_chg6 = { "1096", "(1096)매수비6" },
  bid_qty_chg7 = { "1097", "(1097)매수비7" }, bid_qty_chg8 = { "1098", "(1098)매수비8" },
  bid_qty_chg9 = { "1099", "(1099)매수비9" }, bid_qty_chg10 = { "1100", "(1100)매수비10" },
  krx_bid_qty1 = { "1261", "(1261)K매수량1" }, krx_bid_qty2 = { "1262", "(1262)K매수량2" },
  krx_bid_qty3 = { "1263", "(1263)K매수량3" }, krx_bid_qty4 = { "1264", "(1264)K매수량4" },
  krx_bid_qty5 = { "1265", "(1265)K매수량5" }, krx_bid_qty6 = { "1266", "(1266)K매수량6" },
  krx_bid_qty7 = { "1267", "(1267)K매수량7" }, krx_bid_qty8 = { "1268", "(1268)K매수량8" },
  krx_bid_qty9 = { "1269", "(1269)K매수량9" }, krx_bid_qty10 = { "1270", "(1270)K매수량10" },
  nxt_bid_qty1 = { "1461", "(1461)N매수량1" }, nxt_bid_qty2 = { "1462", "(1462)N매수량2" },
  nxt_bid_qty3 = { "1463", "(1463)N매수량3" }, nxt_bid_qty4 = { "1464", "(1464)N매수량4" },
  nxt_bid_qty5 = { "1465", "(1465)N매수량5" }, nxt_bid_qty6 = { "1466", "(1466)N매수량6" },
  nxt_bid_qty7 = { "1467", "(1467)N매수량7" }, nxt_bid_qty8 = { "1468", "(1468)N매수량8" },
  nxt_bid_qty9 = { "1469", "(1469)N매수량9" }, nxt_bid_qty10 = { "1470", "(1470)N매수량10" },
  total_ask_qty = { "1101", "(1101)매도총량" }, total_ask_qty_chg = { "1104", "(1104)매도총비" },
  total_bid_qty = { "1106", "(1106)매수총량" }, total_bid_qty_chg = { "1109", "(1109)매수총비" },
  expected_price = { "1111", "(1111)예상가격" }, expected_qty = { "1112", "(1112)예상수량" },
  expected_change = { "1113", "(1113)예상대비" }, expected_change_rate = { "1114", "(1114)예상등락" },
  expected_change_amt = { "1115", "(1115)예상대전" }, expected_change_amt2 = { "1116", "(1116)예상등전" },
  arbitrage_basis = { "1204", "(1204)차익BASIS" }, net_buy_total_qty = { "1180", "(1180)순매수총잔량" },
  expected_fill_qty_ratio = { "1819", "(1819)예상체결량비율" }, nxt_mid_price = { "1950", "(1950)NXT중간가" },
  nxt_ask_mid_qty = { "1951", "(1951)NXT매도중간가잔량" }, nxt_bid_mid_qty = { "1952", "(1952)NXT매수중간가잔량" },
  krx_mid_price = { "1953", "(1953)KRX중간가" }, krx_ask_mid_qty = { "1954", "(1954)KRX매도중간가잔량" },
  krx_bid_mid_qty = { "1955", "(1955)KRX매수중간가잔량" }, nxt_mid_total_net_qty = { "1956", "(1956)NXT중간가총순잔량" },
  mid_total_net_qty = { "1957", "(1957)KRX중간가총순잔량" }, krx_total_ask_qty = { "1102", "(1102)KRX매도총잔량" },
  nxt_total_ask_qty = { "1103", "(1103)NXT매도총잔량" }, krx_total_bid_qty = { "1107", "(1107)KRX매수총잔량" },
  nxt_total_bid_qty = { "1108", "(1108)NXT매수총잔량" },
}

if _G.Proto then
  -- No dedicated Proto here — `mas` is the only registered protocol (§4.7).
  -- Fields are appended to the shared mas.proto (cumulative; see PROTOCOL.md §6).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  -- Register a string field per FIELD_NAMES entry (sep omitted), plus market.
  local pf = {}
  for _, name in ipairs(Q.FIELD_NAMES) do
    if name ~= "sep" then  -- separator field: kept in FIELD_NAMES for decode, not displayed
      pf[name] = ProtoField.string("mas.rts.C." .. Q.FIELD_SPEC[name][1], Q.FIELD_SPEC[name][2])
    end
  end
  pf.market = ProtoField.string("mas.rts.C.market", "거래소")

  local fields = {}
  for _, f in pairs(pf) do fields[#fields + 1] = f end
  mas.proto.fields = fields

  local expert_badfields =
    ProtoExpert.new("mas.rts.C.expert.fields", "Unexpected quote field count",
      expert.group.MALFORMED, expert.severity.WARN)
  mas.proto.experts = { expert_badfields }

  -- Decode a TYPE='C' quote record body into the tree. The subtree is always
  -- tagged with the umbrella `mas` proto (see PROTOCOL.md §4.7) — a malformed
  -- TYPE='C' body (wrong field count) is flagged via expert_badfields instead;
  -- "did this decode?" is a field-value question (e.g. bare `mas.rts.C.market`),
  -- not a presence-filter one (mirrors add_exec in mas_rts_b.lua).
  local function add_quote(tree, tvb, poff, r, pinfo, msg_index)
    local rec = Q.decode(r.body)
    local sub = tree:add(mas.proto, tvb(poff + r.off, 6 + r.len),
      "type: " .. Q.TYPE_QUOTE .. " (" .. r.len .. " bytes)")
    mas.rts_add_header(sub, tvb, poff, r)
    if not rec then
      sub:add_proto_expert_info(expert_badfields)
      return false
    end
    local base = poff + r.off + 6   -- body start within tvb
    local ic_off = rec.__offsets.issue_code
    sub:add(pf.market, tvb(base + ic_off.off, ic_off.len), rec.market)   -- shown right after length, before issue_code
    for _, name in ipairs(Q.FIELD_NAMES) do
      if pf[name] then
        local o = rec.__offsets[name]
        sub:add(pf[name], tvb(base + o.off, o.len), rec[name])
      end
    end
    return true
  end

  -- Register as the TYPE='C' decoder; mas_rts.lua's generic dispatcher calls
  -- this for every TYPE='C' record and falls back to a bare "type: <TYPE>"
  -- label itself for any other TYPE.
  mas.by_rts_type[Q.TYPE_QUOTE] = { add = add_quote }
end

return Q
