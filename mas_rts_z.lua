-- MAS RTS TYPE='Z' (투자자AMT, Investor Type Amount) decoder.
--
-- One RTS-DATA record's DATA (see mas_rts.lua for RTS-HEADER framing) is a
-- 51-field tab-separated body: the same 16 investor-type categories as
-- mas_rts_y.lua (TYPE='Y'), each with sell/buy/net-buy AMOUNT instead of
-- quantity (spec codes are TYPE='Y''s codes + 400 — e.g. Y's sell code 101 ->
-- Z's 501 — confirming both types share the same 16-category breakdown).
-- This is the only RTS TYPE this module decodes; every other TYPE is left to
-- mas_rts.lua's generic "type: <TYPE>"-only handling.
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

local Z = {}   -- module table: pure helpers (returned for tests)

Z.TYPE_INVESTOR_AMT = "Z"   -- the only RTS TYPE this module decodes

-- The spec's 16 investor-category codes (매도AMT base code; 매수AMT = base+100,
-- 순매수A = base+200) — see mas_rts_y.lua for why these are used directly
-- instead of a guessed investor-type name.
local CATEGORY_CODES = { 501, 502, 503, 504, 505, 506, 507, 508, 509, 510, 530, 531, 560, 570, 571, 590 }

-- Field order (0-based index 0..50), for RTS TYPE='Z' (Investor Amount).
Z.FIELD_NAMES = {}
local function append(t) for _, v in ipairs(t) do Z.FIELD_NAMES[#Z.FIELD_NAMES + 1] = v end end
append({ "key", "sep", "trade_time" })
for _, c in ipairs(CATEGORY_CODES) do
  append({ "sell_amt_" .. c, "buy_amt_" .. (c + 100), "net_buy_amt_" .. (c + 200) })
end

-- Strip trailing NUL bytes (see mas_rts_b for the version note).
local function rstrip_nul(s)
  local e = #s
  while e > 0 and s:byte(e) == 0 do e = e - 1 end
  return s:sub(1, e)
end

-- Split a tab-separated TYPE='Z' body into a record keyed by FIELD_NAMES.
-- Returns nil if field count != 51. Trailing NULs are stripped. Unlike
-- TYPE='B'/'C'/'F', `key` here is a market key, not a stock issue code, so
-- no market-prefix split is applied (see mas_rts_u.lua for the same "key"
-- convention).
function Z.decode(body)
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
  if #fields ~= #Z.FIELD_NAMES then return nil end

  local rec = {}
  for k = 1, #Z.FIELD_NAMES do
    rec[Z.FIELD_NAMES[k]] = rstrip_nul(fields[k])
  end
  return rec
end

if _G.Proto then
  -- No dedicated Proto here — `mas` is the only registered protocol (§4.7).
  -- Fields are appended to the shared mas.proto (cumulative; see PROTOCOL.md §6).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  -- Register a string field per FIELD_NAMES entry (sep omitted).
  local pf = {}
  for _, name in ipairs(Z.FIELD_NAMES) do
    if name ~= "sep" then  -- separator field: kept in FIELD_NAMES for decode, not displayed
      pf[name] = ProtoField.string("mas.rts.Z." .. name, name)
    end
  end

  local fields = {}
  for _, f in pairs(pf) do fields[#fields + 1] = f end
  mas.proto.fields = fields

  local expert_badfields =
    ProtoExpert.new("mas.rts.Z.expert.fields", "Unexpected investor-amt field count",
      expert.group.MALFORMED, expert.severity.WARN)
  mas.proto.experts = { expert_badfields }

  -- Decode a TYPE='Z' investor-amt record body into the tree. The subtree
  -- is always tagged with the umbrella `mas` proto (see PROTOCOL.md §4.7) —
  -- a malformed TYPE='Z' body (wrong field count) is flagged via
  -- expert_badfields instead; "did this decode?" is a field-value question,
  -- not a presence-filter one (mirrors add_breadth/add_broker).
  local function add_investor_amt(tree, tvb, poff, r, pinfo, msg_index)
    local rec = Z.decode(r.body)
    local sub = tree:add(mas.proto, tvb(poff + r.off, 6 + r.len),
      "type: " .. Z.TYPE_INVESTOR_AMT .. " (" .. r.len .. " bytes)")
    mas.rts_add_header(sub, tvb, poff, r)
    if not rec then
      sub:add_proto_expert_info(expert_badfields)
      return false
    end
    local base = poff + r.off + 6   -- body start within tvb
    for _, name in ipairs(Z.FIELD_NAMES) do
      if pf[name] then sub:add(pf[name], tvb(base, r.len), rec[name]) end
    end
    return true
  end

  -- Register as the TYPE='Z' decoder; mas_rts.lua's generic dispatcher calls
  -- this for every TYPE='Z' record and falls back to a bare "type: <TYPE>"
  -- label itself for any other TYPE.
  mas.by_rts_type[Z.TYPE_INVESTOR_AMT] = { add = add_investor_amt }
end

return Z
