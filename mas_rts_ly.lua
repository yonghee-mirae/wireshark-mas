-- MAS RTS TYPE='y' (DRFN 종목검색 (Stock Screening Signal)) decoder.
--
-- Filename `mas_rts_ly.lua`: the leading "l" marks a lowercase TYPE (see mas_rts_lm.lua); the
-- registration key and the Wireshark FILTER prefix (`mas.rts.y.*`) use the literal wire byte.
--
-- One RTS-DATA record's DATA (see mas_rts.lua for RTS-HEADER framing) is a 54-field
-- tab-separated body: key, the hidden record-type marker (000), then the spec
-- fields (design/field_spec.md).
-- The wire has one trailing field beyond the spec (`extra`, meaning unknown).
-- The body ends with one stray tab before the NUL, stripped in decode().
-- Field layout confirmed against samples/*.pcap (11 records).
--
-- Pure helpers (decode, required by tests) + Wireshark registration.
-- Coordinates with core via _G.mas.

local mas = _G.mas or {}
_G.mas = mas
mas.by_rts_type = mas.by_rts_type or {}

local LY = {}   -- module table: pure helpers (returned for tests)

LY.TYPE_LY = "y"   -- the only RTS TYPE this module decodes

-- Field order (0-based index 0..53).
LY.FIELD_NAMES = {
  "key", "type_echo", "head1", "head2", "issue_code",
  "issue_name", "price", "change", "change_rate", "open_price",
  "high_price", "low_price", "base_price", "acc_volume", "acc_value",
  "trade_volume", "trade_strength", "shares", "market_cap", "sector_gubun",
  "ask_price", "bid_price", "ask_qty", "bid_qty", "total_ask_qty",
  "total_bid_qty", "total_ask_qty_chg", "total_bid_qty_chg", "upper_limit", "lower_limit",
  "prev_volume", "prev_value", "high_52w", "high_52w_ratio", "low_52w",
  "low_52w_ratio", "year_high", "year_low", "foreign_sum", "foreign_hold_ratio",
  "foreign_qty", "d_foreign_ratio", "d_inst_ratio", "per", "eps",
  "foreign_exhaust_rate", "credit_balance_ratio", "capital", "avg_volume_20d", "avg_value_20d",
  "settle_month", "filler1", "filler2", "extra",
}

-- Strip trailing NUL bytes, then one stray trailing tab.
local function rstrip_nul_and_tab(s)
  local e = #s
  while e > 0 and s:byte(e) == 0 do e = e - 1 end
  if e > 0 and s:byte(e) == 9 then e = e - 1 end
  return s:sub(1, e)
end

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

-- Split a tab-separated TYPE='y' body into a record keyed by FIELD_NAMES.
-- Returns nil if field count != 54. `rec.__offsets[name] = {off, len}` gives each
-- field's own byte range within the wire body.
-- `body` is expected to already be UTF-8 (EUC-KR fields are transcoded by the
-- caller; tab never occurs inside a multibyte sequence). `raw_body`, if given,
-- is the untranscoded wire bytes, used only for the byte offsets.
function LY.decode(body, raw_body)
  body = rstrip_nul_and_tab(body)
  local fields, offsets = split_with_offsets(body)
  if #fields ~= #LY.FIELD_NAMES then return nil end

  local rec = { __offsets = {} }
  for k = 1, #LY.FIELD_NAMES do
    rec[LY.FIELD_NAMES[k]] = fields[k]
    rec.__offsets[LY.FIELD_NAMES[k]] = offsets[k]
  end

  if raw_body then
    local _, raw_offsets = split_with_offsets(rstrip_nul_and_tab(raw_body))
    if #raw_offsets == #LY.FIELD_NAMES then
      for k = 1, #LY.FIELD_NAMES do
        rec.__offsets[LY.FIELD_NAMES[k]] = raw_offsets[k]
      end
    end
  end
  return rec
end

-- Spec code + detail-pane label per field, from design/field_spec.md:
-- FIELD_SPEC[name] = { filter suffix (mas.rts.y.<suffix>), label }. The wire's
-- leading key (not in the spec) is "key"; `type_echo` (000) is never displayed.
LY.FIELD_SPEC = {
  key = { "key", "key" }, head1 = { "600", "(600)HEAD_1" },
  head2 = { "601", "(601)HEAD_2" }, issue_code = { "301", "(301)종목코드" },
  issue_name = { "022", "(022)종목명" }, price = { "023", "(023)현재가" },
  change = { "024", "(024)전일대비" }, change_rate = { "033", "(033)등락률" },
  open_price = { "029", "(029)시가" }, high_price = { "030", "(030)고가" },
  low_price = { "031", "(031)저가" }, base_price = { "635", "(635)기준가" },
  acc_volume = { "027", "(027)거래량" }, acc_value = { "028", "(028)거래대금" },
  trade_volume = { "032", "(032)체결량" }, trade_strength = { "387", "(387)체결강도" },
  shares = { "316", "(316)주식수" }, market_cap = { "299", "(299)시가종액" },
  sector_gubun = { "381", "(381)업종구분" }, ask_price = { "025", "(025)매도호가" },
  bid_price = { "026", "(026)매수호가" }, ask_qty = { "041", "(041)매도잔량" },
  bid_qty = { "042", "(042)매수잔량" }, total_ask_qty = { "101", "(101)매도총잔량" },
  total_bid_qty = { "102", "(102)매수총잔량" }, total_ask_qty_chg = { "104", "(104)매도총잔량증감" },
  total_bid_qty_chg = { "109", "(109)매수총잔량증감" }, upper_limit = { "311", "(311)상한가" },
  lower_limit = { "312", "(312)하한가" }, prev_volume = { "314", "(314)전일거래량" },
  prev_value = { "315", "(315)전일거래대금" }, high_52w = { "530", "(530)52주최고가" },
  high_52w_ratio = { "546", "(546)52주최고가 대비율" }, low_52w = { "531", "(531)52주최저가" },
  low_52w_ratio = { "547", "(547)52주최저가 대비율" }, year_high = { "532", "(532)연중최고가" },
  year_low = { "533", "(533)연중최저가" }, foreign_sum = { "185", "(185)외국계합" },
  foreign_hold_ratio = { "402", "(402)외인보유비중" }, foreign_qty = { "500", "(500)외인수량" },
  d_foreign_ratio = { "403", "(403)D외인비" }, d_inst_ratio = { "405", "(405)D기관비" },
  per = { "355", "(355)PER" }, eps = { "568", "(568)EPS" },
  foreign_exhaust_rate = { "401", "(401)외국인소진율" }, credit_balance_ratio = { "577", "(577)신용잔고비율" },
  capital = { "333", "(333)자본금" }, avg_volume_20d = { "701", "(701)20일평균거래량" },
  avg_value_20d = { "706", "(706)20일평균거래대금" }, settle_month = { "335", "(335)결산월" },
  filler1 = { "611", "(611)filler1" }, filler2 = { "612", "(612)filler2" },
  extra = { "extra", "extra" },
}

if _G.Proto then
  -- No dedicated Proto here — `mas` is the only registered protocol (§4.7).
  -- Fields are appended to the shared mas.proto (cumulative; see PROTOCOL.md §6).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  local pf = {}
  for _, name in ipairs(LY.FIELD_NAMES) do
    if LY.FIELD_SPEC[name] then  -- RTS-TYPE(000) is never displayed
      pf[name] = ProtoField.string("mas.rts.y." .. LY.FIELD_SPEC[name][1], LY.FIELD_SPEC[name][2])
    end
  end

  local fields = {}
  for _, f in pairs(pf) do fields[#fields + 1] = f end
  mas.proto.fields = fields

  local expert_badfields =
    ProtoExpert.new("mas.rts.y.expert.fields", "Unexpected TYPE y field count",
      expert.group.MALFORMED, expert.severity.WARN)
  mas.proto.experts = { expert_badfields }

  -- Decode a TYPE='y' record body into the tree. The subtree is always tagged
  -- with the umbrella `mas` proto (see PROTOCOL.md §4.7); a wrong field count is
  -- flagged via expert_badfields instead.
  local function add_record(tree, tvb, poff, r, pinfo, msg_index)
    local base = poff + r.off + 6   -- body start within tvb
    local raw = (r.len > 0) and tvb(base, r.len):raw() or ""
    local utf8 = (r.len > 0) and tvb(base, r.len):string(ENC_EUC_KR) or ""
    local rec = LY.decode(utf8, raw)
    local sub = tree:add(mas.proto, tvb(poff + r.off, 6 + r.len),
      "type: " .. LY.TYPE_LY .. " (" .. r.len .. " bytes)")
    mas.rts_add_header(sub, tvb, poff, r)
    if not rec then
      sub:add_proto_expert_info(expert_badfields)
      return false
    end
    for _, name in ipairs(LY.FIELD_NAMES) do
      if pf[name] then
        local o = rec.__offsets[name]
        sub:add(pf[name], tvb(base + o.off, o.len), rec[name])
      end
    end
    return true
  end

  -- Register as the TYPE='y' decoder; mas_rts.lua's generic dispatcher calls
  -- this for every such record.
  mas.by_rts_type[LY.TYPE_LY] = { add = add_record }
end

return LY