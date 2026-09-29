-- MAS RTS TYPE='X' (업종:예상지수, Expected Sector Index) decoder.
--
-- One RTS-DATA record's DATA (see mas_rts.lua for RTS-HEADER framing) is a
-- 10-field tab-separated body. This is the only RTS TYPE this module
-- decodes; every other TYPE is left to mas_rts.lua's generic
-- "type: <TYPE>"-only handling.
--
-- Field order/names are the spec given in design/field_spec.md. Unlike
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

-- Split a tab-separated string into fields, stripping trailing NUL bytes from
-- each (see mas_rts_b for the version note). Also returns each field's own
-- 0-based byte range within `s` (post-NUL-strip length) so the detail pane
-- can highlight just that field's bytes instead of the whole record (see
-- add_expected_index).
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

-- Split a tab-separated TYPE='X' body into a record keyed by FIELD_NAMES.
-- Returns nil if field count != 10. Trailing NULs are stripped.
-- `rec.__offsets[name] = {off, len}` gives each field's own byte range
-- within `body`.
function X.decode(body)
  local fields, offsets = split_with_offsets(body)
  if #fields ~= #X.FIELD_NAMES then return nil end

  local rec = { __offsets = {} }
  for k = 1, #X.FIELD_NAMES do
    rec[X.FIELD_NAMES[k]] = fields[k]
    rec.__offsets[X.FIELD_NAMES[k]] = offsets[k]
  end
  return rec
end

-- Spec code + detail-pane label per field, from design/field_spec.md:
-- FIELD_SPEC[name] = { filter suffix (mas.rts.X.<suffix>), label }. The wire's
-- leading key (not in the spec) is "key"; `sep` is never displayed.
X.FIELD_SPEC = {
  key = { "key", "key" }, trade_time = { "034", "(034)시간" },
  index = { "023", "(023)지수" }, change = { "024", "(024)전일대비" },
  change_rate = { "033", "(033)등락율" }, trade_volume = { "032", "(032)체결량" },
  acc_volume = { "027", "(027)거래량" }, acc_value = { "028", "(028)거래대금" },
  market_status = { "490", "(490)장상태구분" },
}

if _G.Proto then
  -- No dedicated Proto here — `mas` is the only registered protocol (§4.7).
  -- Fields are appended to the shared mas.proto (cumulative; see PROTOCOL.md §6).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  -- Register a string field per FIELD_NAMES entry (sep omitted).
  local pf = {}
  for _, name in ipairs(X.FIELD_NAMES) do
    if name ~= "sep" then  -- separator field: kept in FIELD_NAMES for decode, not displayed
      pf[name] = ProtoField.string("mas.rts.X." .. X.FIELD_SPEC[name][1], X.FIELD_SPEC[name][2])
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
      if pf[name] then
        local o = rec.__offsets[name]
        sub:add(pf[name], tvb(base + o.off, o.len), rec[name])
      end
    end
    return true
  end

  -- Register as the TYPE='X' decoder; mas_rts.lua's generic dispatcher calls
  -- this for every TYPE='X' record and falls back to a bare "type: <TYPE>"
  -- label itself for any other TYPE.
  mas.by_rts_type[X.TYPE_EXPECTED_INDEX] = { add = add_expected_index }
end

return X
