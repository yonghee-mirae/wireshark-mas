-- MAS RTS TYPE='Y' (투자자QTY, Investor Type Quantity) decoder.
--
-- One RTS-DATA record's DATA (see mas_rts.lua for RTS-HEADER framing) is a
-- 51-field tab-separated body: 16 investor-type categories, each with
-- sell/buy/net-buy quantity. This is the only RTS TYPE this module decodes;
-- every other TYPE is left to mas_rts.lua's generic "type: <TYPE>"-only
-- handling.
--
-- Field order/names are the spec given in inner/wireshark 추가.txt, confirmed
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

-- Strip trailing NUL bytes (see mas_rts_b for the version note).
local function rstrip_nul(s)
  local e = #s
  while e > 0 and s:byte(e) == 0 do e = e - 1 end
  return s:sub(1, e)
end

-- Split a tab-separated TYPE='Y' body into a record keyed by FIELD_NAMES.
-- Returns nil if field count != 51. Trailing NULs are stripped. Unlike
-- TYPE='B'/'C'/'F', `key` here is a market key (e.g. "0500000000"), not a
-- stock issue code, so no market-prefix split is applied (see mas_rts_u.lua
-- for the same "key" convention).
function Y.decode(body)
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
  if #fields ~= #Y.FIELD_NAMES then return nil end

  local rec = {}
  for k = 1, #Y.FIELD_NAMES do
    rec[Y.FIELD_NAMES[k]] = rstrip_nul(fields[k])
  end
  return rec
end

if _G.Proto then
  -- No dedicated Proto here — `mas` is the only registered protocol (§4.7).
  -- Fields are appended to the shared mas.proto (cumulative; see PROTOCOL.md §6).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  -- Register a string field per FIELD_NAMES entry (sep omitted).
  local pf = {}
  for _, name in ipairs(Y.FIELD_NAMES) do
    if name ~= "sep" then  -- separator field: kept in FIELD_NAMES for decode, not displayed
      pf[name] = ProtoField.string("mas.rts.Y." .. name, name)
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
      if pf[name] then sub:add(pf[name], tvb(base, r.len), rec[name]) end
    end
    return true
  end

  -- Register as the TYPE='Y' decoder; mas_rts.lua's generic dispatcher calls
  -- this for every TYPE='Y' record and falls back to a bare "type: <TYPE>"
  -- label itself for any other TYPE.
  mas.by_rts_type[Y.TYPE_INVESTOR_QTY] = { add = add_investor_qty }
end

return Y
