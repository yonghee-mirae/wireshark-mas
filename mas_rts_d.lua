-- MAS RTS TYPE='D' (주식 호가잔량 (Stock Quote Depth)) decoder.
--
-- One RTS-DATA record's DATA (see mas_rts.lua for RTS-HEADER framing) is a 80-field
-- tab-separated body: key, the hidden record-type marker (000), then the spec
-- fields (design/field_spec.md).
-- Field layout confirmed against samples/20260915_0809_RTS.pcap (1142 records).
--
-- Pure helpers (decode, required by tests) + Wireshark registration.
-- Coordinates with core via _G.mas.

local mas = _G.mas or {}
_G.mas = mas
mas.by_rts_type = mas.by_rts_type or {}

local DQ = {}   -- module table: pure helpers (returned for tests)

DQ.TYPE_DQ = "D"   -- the only RTS TYPE this module decodes

-- key prefix -> market. No dot means KRX(K). Same convention as mas_rts_c.lua.
local MARKET = { M = "M", N = "N" }

function DQ.split_market(key)
  local prefix, base = key:match("^([^.]*)%.(.*)$")
  if base then
    return MARKET[prefix] or prefix, base
  end
  return "K", key
end

-- Field order (0-based index 0..79).
DQ.FIELD_NAMES = {
  "key", "type_echo", "quote_time", "ask_price1", "ask_price2",
  "ask_price3", "ask_price4", "ask_price5", "ask_price6", "ask_price7",
  "ask_price8", "ask_price9", "ask_price10", "ask_qty1", "ask_qty2",
  "ask_qty3", "ask_qty4", "ask_qty5", "ask_qty6", "ask_qty7",
  "ask_qty8", "ask_qty9", "ask_qty10", "ask_qty_chg1", "ask_qty_chg2",
  "ask_qty_chg3", "ask_qty_chg4", "ask_qty_chg5", "ask_qty_chg6", "ask_qty_chg7",
  "ask_qty_chg8", "ask_qty_chg9", "ask_qty_chg10", "bid_price1", "bid_price2",
  "bid_price3", "bid_price4", "bid_price5", "bid_price6", "bid_price7",
  "bid_price8", "bid_price9", "bid_price10", "bid_qty1", "bid_qty2",
  "bid_qty3", "bid_qty4", "bid_qty5", "bid_qty6", "bid_qty7",
  "bid_qty8", "bid_qty9", "bid_qty10", "bid_qty_chg1", "bid_qty_chg2",
  "bid_qty_chg3", "bid_qty_chg4", "bid_qty_chg5", "bid_qty_chg6", "bid_qty_chg7",
  "bid_qty_chg8", "bid_qty_chg9", "bid_qty_chg10", "total_ask_qty", "total_ask_qty_chg",
  "total_bid_qty", "total_bid_qty_chg", "expected_price", "expected_qty", "expected_change",
  "expected_change_rate", "expected_change_amt", "expected_change_amt2", "arbitrage_basis", "net_buy_total_qty",
  "expected_fill_qty_ratio", "mid_price", "ask_mid_qty", "bid_mid_qty", "mid_total_net_qty",
}

-- Split a tab-separated string into fields, stripping trailing NUL bytes from
-- each. Also returns each field's own 0-based byte range within `s`
-- (post-NUL-strip length) for per-field highlighting.
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

-- Split a tab-separated TYPE='D' body into a record keyed by FIELD_NAMES.
-- Returns nil if field count != 80. `rec.__offsets[name] = {off, len}` gives each
-- field's own byte range within the wire body.
function DQ.decode(body)
  body = body
  local fields, offsets = split_with_offsets(body)
  if #fields ~= #DQ.FIELD_NAMES then return nil end

  local rec = { __offsets = {} }
  for k = 1, #DQ.FIELD_NAMES do
    rec[DQ.FIELD_NAMES[k]] = fields[k]
    rec.__offsets[DQ.FIELD_NAMES[k]] = offsets[k]
  end
  rec.market, rec.key = DQ.split_market(rec.key)
  return rec
end

-- Spec code + detail-pane label per field, from design/field_spec.md:
-- FIELD_SPEC[name] = { filter suffix (mas.rts.D.<suffix>), label }. The wire's
-- leading key (not in the spec) is "key"; `type_echo` (000) is never displayed.
DQ.FIELD_SPEC = {
  key = { "key", "key" }, quote_time = { "040", "(040)호가시간" },
  ask_price1 = { "051", "(051)매도가1" }, ask_price2 = { "052", "(052)매도가2" },
  ask_price3 = { "053", "(053)매도가3" }, ask_price4 = { "054", "(054)매도가4" },
  ask_price5 = { "055", "(055)매도가5" }, ask_price6 = { "056", "(056)매도가6" },
  ask_price7 = { "057", "(057)매도가7" }, ask_price8 = { "058", "(058)매도가8" },
  ask_price9 = { "059", "(059)매도가9" }, ask_price10 = { "060", "(060)매도가10" },
  ask_qty1 = { "041", "(041)매도량1" }, ask_qty2 = { "042", "(042)매도량2" },
  ask_qty3 = { "043", "(043)매도량3" }, ask_qty4 = { "044", "(044)매도량4" },
  ask_qty5 = { "045", "(045)매도량5" }, ask_qty6 = { "046", "(046)매도량6" },
  ask_qty7 = { "047", "(047)매도량7" }, ask_qty8 = { "048", "(048)매도량8" },
  ask_qty9 = { "049", "(049)매도량9" }, ask_qty10 = { "050", "(050)매도량10" },
  ask_qty_chg1 = { "081", "(081)매도비1" }, ask_qty_chg2 = { "082", "(082)매도비2" },
  ask_qty_chg3 = { "083", "(083)매도비3" }, ask_qty_chg4 = { "084", "(084)매도비4" },
  ask_qty_chg5 = { "085", "(085)매도비5" }, ask_qty_chg6 = { "086", "(086)매도비6" },
  ask_qty_chg7 = { "087", "(087)매도비7" }, ask_qty_chg8 = { "088", "(088)매도비8" },
  ask_qty_chg9 = { "089", "(089)매도비9" }, ask_qty_chg10 = { "090", "(090)매도비10" },
  bid_price1 = { "071", "(071)매수가1" }, bid_price2 = { "072", "(072)매수가2" },
  bid_price3 = { "073", "(073)매수가3" }, bid_price4 = { "074", "(074)매수가4" },
  bid_price5 = { "075", "(075)매수가5" }, bid_price6 = { "076", "(076)매수가6" },
  bid_price7 = { "077", "(077)매수가7" }, bid_price8 = { "078", "(078)매수가8" },
  bid_price9 = { "079", "(079)매수가9" }, bid_price10 = { "080", "(080)매수가10" },
  bid_qty1 = { "061", "(061)매수량1" }, bid_qty2 = { "062", "(062)매수량2" },
  bid_qty3 = { "063", "(063)매수량3" }, bid_qty4 = { "064", "(064)매수량4" },
  bid_qty5 = { "065", "(065)매수량5" }, bid_qty6 = { "066", "(066)매수량6" },
  bid_qty7 = { "067", "(067)매수량7" }, bid_qty8 = { "068", "(068)매수량8" },
  bid_qty9 = { "069", "(069)매수량9" }, bid_qty10 = { "070", "(070)매수량10" },
  bid_qty_chg1 = { "091", "(091)매수비1" }, bid_qty_chg2 = { "092", "(092)매수비2" },
  bid_qty_chg3 = { "093", "(093)매수비3" }, bid_qty_chg4 = { "094", "(094)매수비4" },
  bid_qty_chg5 = { "095", "(095)매수비5" }, bid_qty_chg6 = { "096", "(096)매수비6" },
  bid_qty_chg7 = { "097", "(097)매수비7" }, bid_qty_chg8 = { "098", "(098)매수비8" },
  bid_qty_chg9 = { "099", "(099)매수비9" }, bid_qty_chg10 = { "100", "(100)매수비10" },
  total_ask_qty = { "101", "(101)매도총량" }, total_ask_qty_chg = { "104", "(104)매도총비" },
  total_bid_qty = { "106", "(106)매수총량" }, total_bid_qty_chg = { "109", "(109)매수총비" },
  expected_price = { "111", "(111)예상가격" }, expected_qty = { "112", "(112)예상수량" },
  expected_change = { "113", "(113)예상대비" }, expected_change_rate = { "114", "(114)예상등락" },
  expected_change_amt = { "115", "(115)예상대전" }, expected_change_amt2 = { "116", "(116)예상등전" },
  arbitrage_basis = { "204", "(204)차익BASIS" }, net_buy_total_qty = { "180", "(180)순매수총잔량" },
  expected_fill_qty_ratio = { "819", "(819)예상체결량비율" }, mid_price = { "920", "(920)중간가" },
  ask_mid_qty = { "921", "(921)매도중간가잔량" }, bid_mid_qty = { "922", "(922)매수중간가잔량" },
  mid_total_net_qty = { "923", "(923)중간가 순잔량" },
}

if _G.Proto then
  -- No dedicated Proto here — `mas` is the only registered protocol (§4.7).
  -- Fields are appended to the shared mas.proto (cumulative; see PROTOCOL.md §6).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  local pf = {}
  for _, name in ipairs(DQ.FIELD_NAMES) do
    if DQ.FIELD_SPEC[name] then  -- RTS-TYPE(000) is never displayed
      pf[name] = ProtoField.string("mas.rts.D." .. DQ.FIELD_SPEC[name][1], DQ.FIELD_SPEC[name][2])
    end
  end
  pf.market = ProtoField.string("mas.rts.D.market", "거래소")

  local fields = {}
  for _, f in pairs(pf) do fields[#fields + 1] = f end
  mas.proto.fields = fields

  local expert_badfields =
    ProtoExpert.new("mas.rts.D.expert.fields", "Unexpected TYPE D field count",
      expert.group.MALFORMED, expert.severity.WARN)
  mas.proto.experts = { expert_badfields }

  -- Decode a TYPE='D' record body into the tree. The subtree is always tagged
  -- with the umbrella `mas` proto (see PROTOCOL.md §4.7); a wrong field count is
  -- flagged via expert_badfields instead.
  local function add_record(tree, tvb, poff, r, pinfo, msg_index)
    local base = poff + r.off + 6   -- body start within tvb
    local rec = DQ.decode(r.body)
    local sub = tree:add(mas.proto, tvb(poff + r.off, 6 + r.len),
      "type: " .. DQ.TYPE_DQ .. " (" .. r.len .. " bytes)")
    mas.rts_add_header(sub, tvb, poff, r)
    if not rec then
      sub:add_proto_expert_info(expert_badfields)
      return false
    end
    local k_off = rec.__offsets.key
    sub:add(pf.market, tvb(base + k_off.off, k_off.len), rec.market)   -- shown before key
    for _, name in ipairs(DQ.FIELD_NAMES) do
      if pf[name] then
        local o = rec.__offsets[name]
        sub:add(pf[name], tvb(base + o.off, o.len), rec[name])
      end
    end
    return true
  end

  -- Register as the TYPE='D' decoder; mas_rts.lua's generic dispatcher calls
  -- this for every such record.
  mas.by_rts_type[DQ.TYPE_DQ] = { add = add_record }
end

return DQ