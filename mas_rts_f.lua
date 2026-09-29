-- MAS RTS TYPE='F' (주식:거래원, Trading-house/Broker Ranking) decoder.
--
-- One RTS-DATA record's DATA (see mas_rts.lua for RTS-HEADER framing) is a
-- 78-field tab-separated body: top-5 sell/buy broker rankings (name, qty,
-- amount, share%), foreign net-buy totals, broker codes, net-sell/net-buy %
-- ladders, and qty-change ladders. This is the only RTS TYPE this module
-- decodes; every other TYPE is left to mas_rts.lua's generic
-- "type: <TYPE>"-only handling.
--
-- Field order/names are the spec given in design/field_spec.md, confirmed
-- against samples/20260921_nana.pcapng (2 sampled records, both exactly 78
-- tab-separated fields — a small sample, so treat with somewhat lower
-- confidence than mas_rts_v.lua/mas_rts_j.lua, though the field-count match
-- is exact on both). Broker-name fields are EUC-KR text (see add_broker).
--
-- Pure helpers (decode, required by tests) + Wireshark registration.
-- Coordinates with core via _G.mas.

local mas = _G.mas or {}
_G.mas = mas
mas.by_rts_type = mas.by_rts_type or {}

local F = {}   -- module table: pure helpers (returned for tests)

F.TYPE_BROKER = "F"   -- the only RTS TYPE this module decodes

-- issue_code prefix -> market. No dot means KRX(K). Same convention as
-- mas_rts_b.lua's E.split_market.
local MARKET = { M = "M", N = "N" }

function F.split_market(issue_code)
  local prefix, base = issue_code:match("^([^.]*)%.(.*)$")
  if base then
    return MARKET[prefix] or prefix, base
  end
  return "K", issue_code
end

-- Build a "<prefix><1..n>" name list, e.g. ladder("sell_qty", 5) ->
-- {"sell_qty1", ..., "sell_qty5"}.
local function ladder(prefix, n)
  local t = {}
  for i = 1, n do t[i] = prefix .. i end
  return t
end

-- Field order (0-based index 0..77), for RTS TYPE='F' (Broker Ranking).
-- Codes 231-235 are 순매도%1..5 (net SELL %) and 236-240 are 순매수%1..5
-- (net BUY %) — the original spec text mislabeled 231-235 as "순매수%" too
-- (identical to 236-240). Now that sell/buy disambiguate the two groups on
-- their own, no code-number suffix is needed — named via ladder() like
-- every other 1..5 field, same as sell_pct/buy_pct above.
F.FIELD_NAMES = {}
local function append(t) for _, v in ipairs(t) do F.FIELD_NAMES[#F.FIELD_NAMES + 1] = v end end
append({ "issue_code", "sep" })
append(ladder("sell_broker", 5))
append(ladder("sell_qty", 5))
append(ladder("sell_amt", 5))
append(ladder("sell_pct", 5))
append(ladder("buy_broker", 5))
append(ladder("buy_qty", 5))
append(ladder("buy_amt", 5))
append(ladder("buy_pct", 5))
append({
  "foreign_buy_qty", "foreign_sell_qty", "foreign_net_buy_qty",
  "foreign_buy_amt", "foreign_sell_amt", "foreign_net_buy_amt",
})
append(ladder("sell_code", 5))
append(ladder("buy_code", 5))
append(ladder("net_sell_pct", 5))
append(ladder("net_buy_pct", 5))
append(ladder("sell_chg", 5))
append(ladder("buy_chg", 5))

-- Split a tab-separated string into fields, stripping trailing NUL bytes from
-- each (see mas_rts_b for the version note). Also returns each field's own
-- 0-based byte range within `s` (post-NUL-strip length).
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

-- Split a tab-separated TYPE='F' body into a record keyed by FIELD_NAMES.
-- Returns nil if field count != 78. Trailing NULs are stripped; issue_code
-- -> (market, base), same convention as mas_rts_b.lua/mas_rts_c.lua.
--
-- `body` is the (possibly EUC-KR->UTF-8 transcoded, see add_broker) text used
-- for field VALUES. `raw_body`, if given, is the untranscoded wire bytes,
-- used only to compute `rec.__offsets[name] = {off, len}` (each field's byte
-- range within the tvb) for the detail pane's per-field highlight — tab
-- (0x09) never occurs inside a multibyte EUC-KR/UTF-8 sequence, so both
-- splits have the same field count/order, but the transcoded text's own byte
-- offsets don't match the tvb's raw bytes once a multibyte field changes
-- length, hence needing the separate raw_body split.
function F.decode(body, raw_body)
  local fields, offsets = split_with_offsets(body)
  if #fields ~= #F.FIELD_NAMES then return nil end

  local rec = { __offsets = {} }
  for k = 1, #F.FIELD_NAMES do
    rec[F.FIELD_NAMES[k]] = fields[k]
    rec.__offsets[F.FIELD_NAMES[k]] = offsets[k]
  end
  rec.market, rec.issue_code = F.split_market(rec.issue_code)

  if raw_body then
    local raw_fields, raw_offsets = split_with_offsets(raw_body)
    if #raw_fields == #F.FIELD_NAMES then
      for k = 1, #F.FIELD_NAMES do
        rec.__offsets[F.FIELD_NAMES[k]] = raw_offsets[k]
      end
    end
  end
  return rec
end

-- Spec code + detail-pane label per field, from design/field_spec.md:
-- FIELD_SPEC[name] = { filter suffix (mas.rts.F.<suffix>), label }. The wire's
-- leading key (not in the spec) is "key"; `sep` is never displayed.
F.FIELD_SPEC = {
  issue_code = { "key", "key" }, sell_broker1 = { "121", "(121)매도원1" },
  sell_broker2 = { "122", "(122)매도원2" }, sell_broker3 = { "123", "(123)매도원3" },
  sell_broker4 = { "124", "(124)매도원4" }, sell_broker5 = { "125", "(125)매도원5" },
  sell_qty1 = { "131", "(131)매도량1" }, sell_qty2 = { "132", "(132)매도량2" },
  sell_qty3 = { "133", "(133)매도량3" }, sell_qty4 = { "134", "(134)매도량4" },
  sell_qty5 = { "135", "(135)매도량5" }, sell_amt1 = { "136", "(136)매도금1" },
  sell_amt2 = { "137", "(137)매도금2" }, sell_amt3 = { "138", "(138)매도금3" },
  sell_amt4 = { "139", "(139)매도금4" }, sell_amt5 = { "140", "(140)매도금5" },
  sell_pct1 = { "141", "(141)매도중1" }, sell_pct2 = { "142", "(142)매도중2" },
  sell_pct3 = { "143", "(143)매도중3" }, sell_pct4 = { "144", "(144)매도중4" },
  sell_pct5 = { "145", "(145)매도중5" }, buy_broker1 = { "151", "(151)매수원1" },
  buy_broker2 = { "152", "(152)매수원2" }, buy_broker3 = { "153", "(153)매수원3" },
  buy_broker4 = { "154", "(154)매수원4" }, buy_broker5 = { "155", "(155)매수원5" },
  buy_qty1 = { "161", "(161)매수량1" }, buy_qty2 = { "162", "(162)매수량2" },
  buy_qty3 = { "163", "(163)매수량3" }, buy_qty4 = { "164", "(164)매수량4" },
  buy_qty5 = { "165", "(165)매수량5" }, buy_amt1 = { "166", "(166)매수금1" },
  buy_amt2 = { "167", "(167)매수금2" }, buy_amt3 = { "168", "(168)매수금3" },
  buy_amt4 = { "169", "(169)매수금4" }, buy_amt5 = { "170", "(170)매수금5" },
  buy_pct1 = { "171", "(171)매수중1" }, buy_pct2 = { "172", "(172)매수중2" },
  buy_pct3 = { "173", "(173)매수중3" }, buy_pct4 = { "174", "(174)매수중4" },
  buy_pct5 = { "175", "(175)매수중5" }, foreign_buy_qty = { "182", "(182)외국매수량" },
  foreign_sell_qty = { "187", "(187)외국매도량" }, foreign_net_buy_qty = { "185", "(185)외국순매수량" },
  foreign_buy_amt = { "184", "(184)외국매수금" }, foreign_sell_amt = { "189", "(189)외국매도금" },
  foreign_net_buy_amt = { "190", "(190)외국순매수금" }, sell_code1 = { "126", "(126)매도코드1" },
  sell_code2 = { "127", "(127)매도코드2" }, sell_code3 = { "128", "(128)매도코드3" },
  sell_code4 = { "129", "(129)매도코드4" }, sell_code5 = { "130", "(130)매도코드5" },
  buy_code1 = { "156", "(156)매수코드1" }, buy_code2 = { "157", "(157)매수코드2" },
  buy_code3 = { "158", "(158)매수코드3" }, buy_code4 = { "159", "(159)매수코드4" },
  buy_code5 = { "160", "(160)매수코드5" }, net_sell_pct1 = { "231", "(231)순매도%1" },
  net_sell_pct2 = { "232", "(232)순매도%2" }, net_sell_pct3 = { "233", "(233)순매도%3" },
  net_sell_pct4 = { "234", "(234)순매도%4" }, net_sell_pct5 = { "235", "(235)순매도%5" },
  net_buy_pct1 = { "236", "(236)순매수%1" }, net_buy_pct2 = { "237", "(237)순매수%2" },
  net_buy_pct3 = { "238", "(238)순매수%3" }, net_buy_pct4 = { "239", "(239)순매수%4" },
  net_buy_pct5 = { "240", "(240)순매수%5" }, sell_chg1 = { "276", "(276)매도증감1" },
  sell_chg2 = { "277", "(277)매도증감2" }, sell_chg3 = { "278", "(278)매도증감3" },
  sell_chg4 = { "279", "(279)매도증감4" }, sell_chg5 = { "280", "(280)매도증감5" },
  buy_chg1 = { "286", "(286)매수증감1" }, buy_chg2 = { "287", "(287)매수증감2" },
  buy_chg3 = { "288", "(288)매수증감3" }, buy_chg4 = { "289", "(289)매수증감4" },
  buy_chg5 = { "290", "(290)매수증감5" },
}

if _G.Proto then
  -- No dedicated Proto here — `mas` is the only registered protocol (§4.7).
  -- Fields are appended to the shared mas.proto (cumulative; see PROTOCOL.md §6).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  -- Register a string field per FIELD_NAMES entry (sep omitted), plus market.
  local pf = {}
  for _, name in ipairs(F.FIELD_NAMES) do
    if name ~= "sep" then  -- separator field: kept in FIELD_NAMES for decode, not displayed
      pf[name] = ProtoField.string("mas.rts.F." .. F.FIELD_SPEC[name][1], F.FIELD_SPEC[name][2])
    end
  end
  pf.market = ProtoField.string("mas.rts.F.market", "거래소")

  local fields = {}
  for _, f in pairs(pf) do fields[#fields + 1] = f end
  mas.proto.fields = fields

  local expert_badfields =
    ProtoExpert.new("mas.rts.F.expert.fields", "Unexpected broker-ranking field count",
      expert.group.MALFORMED, expert.severity.WARN)
  mas.proto.experts = { expert_badfields }

  -- Decode a TYPE='F' broker-ranking record body into the tree. The subtree
  -- is always tagged with the umbrella `mas` proto (see PROTOCOL.md §4.7) —
  -- a malformed TYPE='F' body (wrong field count) is flagged via
  -- expert_badfields instead; "did this decode?" is a field-value question,
  -- not a presence-filter one (mirrors add_exec/add_quote).
  --
  -- Broker names (sell_broker*/buy_broker*) are EUC-KR, so the body is
  -- transcoded to UTF-8 before splitting — same reasoning as
  -- mas_tr_90.lua's add_order_body (tab, 0x09, never occurs inside a
  -- multibyte sequence, so the split stays correct). The numeric/code
  -- fields are pure ASCII and pass through unchanged. (Requires a Wireshark
  -- build with EUC-KR string support.)
  local function add_broker(tree, tvb, poff, r, pinfo, msg_index)
    local base = poff + r.off + 6   -- body start within tvb
    local raw = (r.len > 0) and tvb(base, r.len):raw() or ""
    local utf8 = (r.len > 0) and tvb(base, r.len):string(ENC_EUC_KR) or ""
    local rec = F.decode(utf8, raw)
    local sub = tree:add(mas.proto, tvb(poff + r.off, 6 + r.len),
      "type: " .. F.TYPE_BROKER .. " (" .. r.len .. " bytes)")
    mas.rts_add_header(sub, tvb, poff, r)
    if not rec then
      sub:add_proto_expert_info(expert_badfields)
      return false
    end
    local ic_off = rec.__offsets.issue_code
    sub:add(pf.market, tvb(base + ic_off.off, ic_off.len), rec.market)   -- shown right after length, before issue_code
    for _, name in ipairs(F.FIELD_NAMES) do
      if pf[name] then
        local o = rec.__offsets[name]
        sub:add(pf[name], tvb(base + o.off, o.len), rec[name])
      end
    end
    return true
  end

  -- Register as the TYPE='F' decoder; mas_rts.lua's generic dispatcher calls
  -- this for every TYPE='F' record and falls back to a bare "type: <TYPE>"
  -- label itself for any other TYPE.
  mas.by_rts_type[F.TYPE_BROKER] = { add = add_broker }
end

return F
