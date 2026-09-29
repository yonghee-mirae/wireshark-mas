-- MAS RTS TYPE='Y' (투자자QTY, Investor Type Quantity) decoder.
--
-- One RTS-DATA record's DATA (see mas_rts.lua for RTS-HEADER framing) is a
-- 51-field tab-separated body: 16 investor-type categories, each with
-- sell/buy/net-buy quantity. This is the only RTS TYPE this module decodes;
-- every other TYPE is left to mas_rts.lua's generic "type: <TYPE>"-only
-- handling.
--
-- Field order/names are the spec given in design/field_spec.md, confirmed
-- against samples/20260921_nana.pcapng (33 sampled records) and
-- samples/20260915_0809_RTS2.pcapng (52 sampled records) — both always
-- exactly 51 tab-separated fields.
--
-- Pure helpers (decode, required by tests) + Wireshark registration.
-- Coordinates with core via _G.mas.

local mas = _G.mas or {}
_G.mas = mas
mas.by_rts_type = mas.by_rts_type or {}

local Y = {}   -- module table: pure helpers (returned for tests)

Y.TYPE_INVESTOR_QTY = "Y"   -- the only RTS TYPE this module decodes

-- The spec's 16 investor-category codes (매도QTY base code; 매수QTY = base+100,
-- 순매수Q = base+200 — the gaps here are the spec's own code numbers, not a
-- sequential 1..16 index, and the spec gives no name for each category, so
-- fields are identified by these codes directly rather than a guessed
-- investor-type name (mirrors mas_rts_f.lua's net_buy_pct_231.. handling of
-- unnamed spec codes).
local CATEGORY_CODES = { 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 130, 131, 160, 170, 171, 190 }

-- Field order (0-based index 0..50), for RTS TYPE='Y' (Investor Qty).
Y.FIELD_NAMES = {}
local function append(t) for _, v in ipairs(t) do Y.FIELD_NAMES[#Y.FIELD_NAMES + 1] = v end end
append({ "key", "sep", "trade_time" })
for _, c in ipairs(CATEGORY_CODES) do
  append({ "sell_qty_" .. c, "buy_qty_" .. (c + 100), "net_buy_qty_" .. (c + 200) })
end

-- Split a tab-separated string into fields, stripping trailing NUL bytes from
-- each (see mas_rts_b for the version note). Also returns each field's own
-- 0-based byte range within `s` (post-NUL-strip length) so the detail pane
-- can highlight just that field's bytes instead of the whole record (see
-- add_investor_qty).
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

-- Split a tab-separated TYPE='Y' body into a record keyed by FIELD_NAMES.
-- Returns nil if field count != 51. Trailing NULs are stripped. Unlike
-- TYPE='B'/'C'/'F', `key` here is a market key (e.g. "0500000000"), not a
-- stock issue code, so no market-prefix split is applied (see mas_rts_u.lua
-- for the same "key" convention). `rec.__offsets[name] = {off, len}` gives
-- each field's own byte range within `body`.
function Y.decode(body)
  local fields, offsets = split_with_offsets(body)
  if #fields ~= #Y.FIELD_NAMES then return nil end

  local rec = { __offsets = {} }
  for k = 1, #Y.FIELD_NAMES do
    rec[Y.FIELD_NAMES[k]] = fields[k]
    rec.__offsets[Y.FIELD_NAMES[k]] = offsets[k]
  end
  return rec
end

-- Spec code + detail-pane label per field, from design/field_spec.md:
-- FIELD_SPEC[name] = { filter suffix (mas.rts.Y.<suffix>), label }. The wire's
-- leading key (not in the spec) is "key"; `sep` is never displayed.
Y.FIELD_SPEC = {
  key = { "key", "key" }, trade_time = { "034", "(034)처리시간" },
  sell_qty_101 = { "101", "(101)매도QTY" }, buy_qty_201 = { "201", "(201)매수QTY" },
  net_buy_qty_301 = { "301", "(301)순매수Q" }, sell_qty_102 = { "102", "(102)매도QTY" },
  buy_qty_202 = { "202", "(202)매수QTY" }, net_buy_qty_302 = { "302", "(302)순매수Q" },
  sell_qty_103 = { "103", "(103)매도QTY" }, buy_qty_203 = { "203", "(203)매수QTY" },
  net_buy_qty_303 = { "303", "(303)순매수Q" }, sell_qty_104 = { "104", "(104)매도QTY" },
  buy_qty_204 = { "204", "(204)매수QTY" }, net_buy_qty_304 = { "304", "(304)순매수Q" },
  sell_qty_105 = { "105", "(105)매도QTY" }, buy_qty_205 = { "205", "(205)매수QTY" },
  net_buy_qty_305 = { "305", "(305)순매수Q" }, sell_qty_106 = { "106", "(106)매도QTY" },
  buy_qty_206 = { "206", "(206)매수QTY" }, net_buy_qty_306 = { "306", "(306)순매수Q" },
  sell_qty_107 = { "107", "(107)매도QTY" }, buy_qty_207 = { "207", "(207)매수QTY" },
  net_buy_qty_307 = { "307", "(307)순매수Q" }, sell_qty_108 = { "108", "(108)매도QTY" },
  buy_qty_208 = { "208", "(208)매수QTY" }, net_buy_qty_308 = { "308", "(308)순매수Q" },
  sell_qty_109 = { "109", "(109)매도QTY" }, buy_qty_209 = { "209", "(209)매수QTY" },
  net_buy_qty_309 = { "309", "(309)순매수Q" }, sell_qty_110 = { "110", "(110)매도QTY" },
  buy_qty_210 = { "210", "(210)매수QTY" }, net_buy_qty_310 = { "310", "(310)순매수Q" },
  sell_qty_130 = { "130", "(130)매도QTY" }, buy_qty_230 = { "230", "(230)매수QTY" },
  net_buy_qty_330 = { "330", "(330)순매수Q" }, sell_qty_131 = { "131", "(131)매도QTY" },
  buy_qty_231 = { "231", "(231)매수QTY" }, net_buy_qty_331 = { "331", "(331)순매수Q" },
  sell_qty_160 = { "160", "(160)매도QTY" }, buy_qty_260 = { "260", "(260)매수QTY" },
  net_buy_qty_360 = { "360", "(360)순매수Q" }, sell_qty_170 = { "170", "(170)매도QTY" },
  buy_qty_270 = { "270", "(270)매수QTY" }, net_buy_qty_370 = { "370", "(370)순매수Q" },
  sell_qty_171 = { "171", "(171)매도QTY" }, buy_qty_271 = { "271", "(271)매수QTY" },
  net_buy_qty_371 = { "371", "(371)순매수Q" }, sell_qty_190 = { "190", "(190)매도QTY" },
  buy_qty_290 = { "290", "(290)매수QTY" }, net_buy_qty_390 = { "390", "(390)순매수Q" },
}

if _G.Proto then
  -- No dedicated Proto here — `mas` is the only registered protocol (§4.7).
  -- Fields are appended to the shared mas.proto (cumulative; see PROTOCOL.md §6).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  -- Register a string field per FIELD_NAMES entry (sep omitted).
  local pf = {}
  for _, name in ipairs(Y.FIELD_NAMES) do
    if name ~= "sep" then  -- separator field: kept in FIELD_NAMES for decode, not displayed
      pf[name] = ProtoField.string("mas.rts.Y." .. Y.FIELD_SPEC[name][1], Y.FIELD_SPEC[name][2])
    end
  end

  local fields = {}
  for _, f in pairs(pf) do fields[#fields + 1] = f end
  mas.proto.fields = fields

  local expert_badfields =
    ProtoExpert.new("mas.rts.Y.expert.fields", "Unexpected investor-qty field count",
      expert.group.MALFORMED, expert.severity.WARN)
  mas.proto.experts = { expert_badfields }

  -- Decode a TYPE='Y' investor-qty record body into the tree. The subtree
  -- is always tagged with the umbrella `mas` proto (see PROTOCOL.md §4.7) —
  -- a malformed TYPE='Y' body (wrong field count) is flagged via
  -- expert_badfields instead; "did this decode?" is a field-value question,
  -- not a presence-filter one (mirrors add_breadth/add_broker).
  local function add_investor_qty(tree, tvb, poff, r, pinfo, msg_index)
    local rec = Y.decode(r.body)
    local sub = tree:add(mas.proto, tvb(poff + r.off, 6 + r.len),
      "type: " .. Y.TYPE_INVESTOR_QTY .. " (" .. r.len .. " bytes)")
    mas.rts_add_header(sub, tvb, poff, r)
    if not rec then
      sub:add_proto_expert_info(expert_badfields)
      return false
    end
    local base = poff + r.off + 6   -- body start within tvb
    for _, name in ipairs(Y.FIELD_NAMES) do
      if pf[name] then
        local o = rec.__offsets[name]
        sub:add(pf[name], tvb(base + o.off, o.len), rec[name])
      end
    end
    return true
  end

  -- Register as the TYPE='Y' decoder; mas_rts.lua's generic dispatcher calls
  -- this for every TYPE='Y' record and falls back to a bare "type: <TYPE>"
  -- label itself for any other TYPE.
  mas.by_rts_type[Y.TYPE_INVESTOR_QTY] = { add = add_investor_qty }
end

return Y
