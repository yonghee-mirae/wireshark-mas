-- MAS RTS TYPE='X' (업종:예상지수, Expected Sector Index) decoder.
--
-- One RTS-DATA record's DATA (see mas_rts.lua for RTS-HEADER framing) is a
-- 10-field tab-separated body. This is the only RTS TYPE this module
-- decodes; every other TYPE is left to mas_rts.lua's generic
-- "type: <TYPE>"-only handling.
--
-- Field order/names are the spec given in inner/wireshark 추가.txt. Unlike
-- mas_rts_j.lua (TYPE='J', live sector index), this has no open/high/low
-- price fields — just the expected index value + change + volume + market
-- status. NOT cross-checked against a real capture (none observed so far in
-- samples/*.pcapng) — only the spec's own example row (10 fields, matches
-- #FIELD_NAMES below). Treat with lower confidence than mas_rts_v.lua/
-- mas_rts_j.lua until a real sample turns up.
--
-- Pure helpers (decode, required by tests) + Wireshark registration.
-- Coordinates with core via _G.mas.

local mas = _G.mas or {}
_G.mas = mas
mas.by_rts_type = mas.by_rts_type or {}

local X = {}   -- module table: pure helpers (returned for tests)

X.TYPE_EXPECTED_INDEX = "X"   -- the only RTS TYPE this module decodes

-- Field order (0-based index 0..9), for RTS TYPE='X' (Expected Sector Index).
-- `key` is a sector/index code (e.g. "X0001"), not a KRX stock issue code,
-- so no market-prefix split is applied (see mas_rts_u.lua/mas_rts_j.lua for
-- the same "key" convention). `trade_volume`/`acc_volume`/`acc_value` reuse
-- the mas_rts_j.lua naming for the same per-tick vs. cumulative distinction.
X.FIELD_NAMES = {
  "key", "sep", "trade_time",
  "index", "change", "change_rate", "trade_volume", "acc_volume", "acc_value",
  "market_status",
}

-- Strip trailing NUL bytes (see mas_rts_b for the version note).
local function rstrip_nul(s)
  local e = #s
  while e > 0 and s:byte(e) == 0 do e = e - 1 end
  return s:sub(1, e)
end

-- Split a tab-separated TYPE='X' body into a record keyed by FIELD_NAMES.
-- Returns nil if field count != 10. Trailing NULs are stripped.
function X.decode(body)
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
  if #fields ~= #X.FIELD_NAMES then return nil end

  local rec = {}
  for k = 1, #X.FIELD_NAMES do
    rec[X.FIELD_NAMES[k]] = rstrip_nul(fields[k])
  end
  return rec
end

if _G.Proto then
  -- No dedicated Proto here — `mas` is the only registered protocol (§4.7).
  -- Fields are appended to the shared mas.proto (cumulative; see PROTOCOL.md §6).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  -- Register a string field per FIELD_NAMES entry (sep omitted).
  local pf = {}
  for _, name in ipairs(X.FIELD_NAMES) do
    if name ~= "sep" then  -- separator field: kept in FIELD_NAMES for decode, not displayed
      pf[name] = ProtoField.string("mas.rts.X." .. name, name)
    end
  end

  local fields = {}
  for _, f in pairs(pf) do fields[#fields + 1] = f end
  mas.proto.fields = fields

  local expert_badfields =
    ProtoExpert.new("mas.rts.X.expert.fields", "Unexpected expected-sector-index field count",
      expert.group.MALFORMED, expert.severity.WARN)
  mas.proto.experts = { expert_badfields }

  -- Decode a TYPE='X' expected-sector-index record body into the tree. The
  -- subtree is always tagged with the umbrella `mas` proto (see PROTOCOL.md
  -- §4.7) — a malformed TYPE='X' body (wrong field count) is flagged via
  -- expert_badfields instead; "did this decode?" is a field-value question,
  -- not a presence-filter one (mirrors add_sector_index/add_index).
  local function add_expected_index(tree, tvb, poff, r, pinfo, msg_index)
    local rec = X.decode(r.body)
    local sub = tree:add(mas.proto, tvb(poff + r.off, 6 + r.len),
      "type: " .. X.TYPE_EXPECTED_INDEX .. " (" .. r.len .. " bytes)")
    mas.rts_add_header(sub, tvb, poff, r)
    if not rec then
      sub:add_proto_expert_info(expert_badfields)
      return false
    end
    local base = poff + r.off + 6   -- body start within tvb
    for _, name in ipairs(X.FIELD_NAMES) do
      if pf[name] then sub:add(pf[name], tvb(base, r.len), rec[name]) end
    end
    return true
  end

  -- Register as the TYPE='X' decoder; mas_rts.lua's generic dispatcher calls
  -- this for every TYPE='X' record and falls back to a bare "type: <TYPE>"
  -- label itself for any other TYPE.
  mas.by_rts_type[X.TYPE_EXPECTED_INDEX] = { add = add_expected_index }
end

return X
