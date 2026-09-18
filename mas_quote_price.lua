-- MAS RTS TYPE='C' (호가 시세, Quote Price) decoder.
--
-- One RTS-DATA record's DATA (see mas_rts.lua for RTS-HEADER framing) is a
-- 128-field tab-separated body (127 named fields + 1 hidden record-type
-- marker, same "sep" role as in TYPE='B' — see PROTOCOL.md §8). This is the
-- only RTS TYPE this module decodes; every other TYPE is left to
-- mas_rts.lua's generic "Unspecified RTS" handling.
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
-- mas_execution_price.lua's E.split_market.
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

-- Strip trailing NUL bytes (see mas_execution_price for the version note).
local function rstrip_nul(s)
  local e = #s
  while e > 0 and s:byte(e) == 0 do e = e - 1 end
  return s:sub(1, e)
end

-- Split a tab-separated TYPE='C' body into a record keyed by FIELD_NAMES.
-- Returns nil if field count != 128. Trailing NULs are stripped; issue_code
-- -> (market, base).
function Q.decode(body)
  local fields = {}
  local start = 1
  while true do
    local sep = body:find("\t", start, true)
    if sep then
      fields[#fields + 1] = body:sub(start, sep - 1)
      start = sep + 1
    else
      fields[#fields + 1] = body:sub(start)
      break
    end
  end
  if #fields ~= #Q.FIELD_NAMES then return nil end

  local rec = {}
  for k = 1, #Q.FIELD_NAMES do
    rec[Q.FIELD_NAMES[k]] = rstrip_nul(fields[k])
  end
  rec.market, rec.issue_code = Q.split_market(rec.issue_code)
  return rec
end

if _G.Proto then
  local proto_qp = Proto("mas.qp", "MAS Quote Price")   -- filter: mas.qp

  -- Register a string field per FIELD_NAMES entry (sep omitted), plus market.
  local pf = {}
  for _, name in ipairs(Q.FIELD_NAMES) do
    if name ~= "sep" then  -- separator field: kept in FIELD_NAMES for decode, not displayed
      pf[name] = ProtoField.string("mas.qp." .. name, name)
    end
  end
  pf.market = ProtoField.string("mas.qp.market", "market")

  local fields = {}
  for _, f in pairs(pf) do fields[#fields + 1] = f end
  proto_qp.fields = fields

  local expert_badfields =
    ProtoExpert.new("mas.qp.expert.fields", "Unexpected quote field count",
      expert.group.MALFORMED, expert.severity.WARN)
  proto_qp.experts = { expert_badfields }

  -- Decode a TYPE='C' quote record body into the tree. Decode first so the
  -- subtree's own protocol is proto_qp (mas.qp) ONLY on success; a malformed
  -- TYPE='C' body (wrong field count) is tagged with the umbrella `mas`
  -- instead, so the mas.qp presence filter means "a real quote record here"
  -- (mirrors add_exec in mas_execution_price.lua — see PROTOCOL.md §4.7).
  local function add_quote(tree, tvb, poff, r, pinfo, msg_index)
    local rec = Q.decode(r.body)
    local sub = tree:add(rec and proto_qp or mas.proto, tvb(poff + r.off, 6 + r.len),
      "Quote Price (" .. r.len .. " bytes)")
    mas.rts_add_header(sub, tvb, poff, r)
    if not rec then
      sub:add_proto_expert_info(expert_badfields)
      return false
    end
    local base = poff + r.off + 6   -- body start within tvb
    for _, name in ipairs(Q.FIELD_NAMES) do
      if pf[name] then sub:add(pf[name], tvb(base, r.len), rec[name]) end
    end
    sub:add(pf.market, tvb(base, r.len), rec.market)
    return true
  end

  -- Register as the TYPE='C' decoder; mas_rts.lua's generic dispatcher calls
  -- this for every TYPE='C' record and falls back to "Unspecified RTS" itself
  -- for any other TYPE.
  mas.by_rts_type[Q.TYPE_QUOTE] = { add = add_quote }
end

return Q
