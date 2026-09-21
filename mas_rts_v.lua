-- MAS RTS TYPE='V' (해외:지수, Overseas Index) decoder.
--
-- One RTS-DATA record's DATA (see mas_rts.lua for RTS-HEADER framing) is an
-- 11-field tab-separated body. This is the only RTS TYPE this module
-- decodes; every other TYPE is left to mas_rts.lua's generic
-- "type: <TYPE>"-only handling.
--
-- Field order/names are the spec given in inner/wireshark 추가.txt, confirmed
-- against samples/20260921_nana.pcapng (100 sampled records, all exactly 11
-- tab-separated fields).
--
-- Pure helpers (decode, required by tests) + Wireshark registration.
-- Coordinates with core via _G.mas.

local mas = _G.mas or {}
_G.mas = mas
mas.by_rts_type = mas.by_rts_type or {}

local V = {}   -- module table: pure helpers (returned for tests)

V.TYPE_INDEX = "V"   -- the only RTS TYPE this module decodes

-- Field order (0-based index 0..10), for RTS TYPE='V' (Overseas Index).
-- `key` is a foreign symbol (e.g. "CME@NQ", "USDKRWSMBS"), not a KRX stock
-- issue code, so no market-prefix split is applied (see mas_rts_u.lua for
-- the same "key" convention).
V.FIELD_NAMES = {
  "key", "sep", "trade_time",
  "price", "change", "change_rate", "volume",
  "open_price", "high_price", "low_price", "date",
}

-- Strip trailing NUL bytes (see mas_rts_b for the version note).
local function rstrip_nul(s)
  local e = #s
  while e > 0 and s:byte(e) == 0 do e = e - 1 end
  return s:sub(1, e)
end

-- Split a tab-separated TYPE='V' body into a record keyed by FIELD_NAMES.
-- Returns nil if field count != 11. Trailing NULs are stripped.
function V.decode(body)
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
  if #fields ~= #V.FIELD_NAMES then return nil end

  local rec = {}
  for k = 1, #V.FIELD_NAMES do
    rec[V.FIELD_NAMES[k]] = rstrip_nul(fields[k])
  end
  return rec
end

if _G.Proto then
  -- No dedicated Proto here — `mas` is the only registered protocol (§4.7).
  -- Fields are appended to the shared mas.proto (cumulative; see PROTOCOL.md §6).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  -- Register a string field per FIELD_NAMES entry (sep omitted).
  local pf = {}
  for _, name in ipairs(V.FIELD_NAMES) do
    if name ~= "sep" then  -- separator field: kept in FIELD_NAMES for decode, not displayed
      pf[name] = ProtoField.string("mas.rts.V." .. name, name)
    end
  end

  local fields = {}
  for _, f in pairs(pf) do fields[#fields + 1] = f end
  mas.proto.fields = fields

  local expert_badfields =
    ProtoExpert.new("mas.rts.V.expert.fields", "Unexpected overseas-index field count",
      expert.group.MALFORMED, expert.severity.WARN)
  mas.proto.experts = { expert_badfields }

  -- Decode a TYPE='V' overseas-index record body into the tree. The subtree
  -- is always tagged with the umbrella `mas` proto (see PROTOCOL.md §4.7) —
  -- a malformed TYPE='V' body (wrong field count) is flagged via
  -- expert_badfields instead; "did this decode?" is a field-value question,
  -- not a presence-filter one (mirrors add_quote/add_breadth).
  local function add_index(tree, tvb, poff, r, pinfo, msg_index)
    local rec = V.decode(r.body)
    local sub = tree:add(mas.proto, tvb(poff + r.off, 6 + r.len),
      "type: " .. V.TYPE_INDEX .. " (" .. r.len .. " bytes)")
    mas.rts_add_header(sub, tvb, poff, r)
    if not rec then
      sub:add_proto_expert_info(expert_badfields)
      return false
    end
    local base = poff + r.off + 6   -- body start within tvb
    for _, name in ipairs(V.FIELD_NAMES) do
      if pf[name] then sub:add(pf[name], tvb(base, r.len), rec[name]) end
    end
    return true
  end

  -- Register as the TYPE='V' decoder; mas_rts.lua's generic dispatcher calls
  -- this for every TYPE='V' record and falls back to a bare "type: <TYPE>"
  -- label itself for any other TYPE.
  mas.by_rts_type[V.TYPE_INDEX] = { add = add_index }
end

return V
