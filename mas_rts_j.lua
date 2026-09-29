-- MAS RTS TYPE='J' (업종:시세/지수, Sector Index) decoder.
--
-- One RTS-DATA record's DATA (see mas_rts.lua for RTS-HEADER framing) is a
-- 13-field tab-separated body. This is the only RTS TYPE this module
-- decodes; every other TYPE is left to mas_rts.lua's generic
-- "type: <TYPE>"-only handling.
--
-- Field order/names are the spec given in design/field_spec.md, confirmed
-- against samples/20260921_nana.pcapng (42 sampled records, all exactly 13
-- tab-separated fields). `trade_volume`/`acc_volume`/`acc_value` reuse the
-- mas_rts_b.lua execution-price naming for the same per-tick vs. cumulative
-- distinction (체결량 vs. 거래량/거래대금).
--
-- Pure helpers (decode, required by tests) + Wireshark registration.
-- Coordinates with core via _G.mas.

local mas = _G.mas or {}
_G.mas = mas
mas.by_rts_type = mas.by_rts_type or {}

local J = {}   -- module table: pure helpers (returned for tests)

J.TYPE_SECTOR_INDEX = "J"   -- the only RTS TYPE this module decodes

-- Field order (0-based index 0..12), for RTS TYPE='J' (Sector Index).
-- `key` is a sector/index code (e.g. "K2001"), not a KRX stock issue code,
-- so no market-prefix split is applied (see mas_rts_u.lua for the same
-- "key" convention).
J.FIELD_NAMES = {
  "key", "sep", "trade_time",
  "index", "change", "change_rate", "trade_volume", "acc_volume", "acc_value",
  "open_price", "high_price", "low_price", "market_status",
}

-- Split a tab-separated string into fields, stripping trailing NUL bytes from
-- each (see mas_rts_b for the version note). Also returns each field's own
-- 0-based byte range within `s` (post-NUL-strip length) so the detail pane
-- can highlight just that field's bytes instead of the whole record (see
-- add_sector_index).
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

-- Split a tab-separated TYPE='J' body into a record keyed by FIELD_NAMES.
-- Returns nil if field count != 13. Trailing NULs are stripped.
-- `rec.__offsets[name] = {off, len}` gives each field's own byte range
-- within `body`.
function J.decode(body)
  local fields, offsets = split_with_offsets(body)
  if #fields ~= #J.FIELD_NAMES then return nil end

  local rec = { __offsets = {} }
  for k = 1, #J.FIELD_NAMES do
    rec[J.FIELD_NAMES[k]] = fields[k]
    rec.__offsets[J.FIELD_NAMES[k]] = offsets[k]
  end
  return rec
end

-- Spec code + detail-pane label per field, from design/field_spec.md:
-- FIELD_SPEC[name] = { filter suffix (mas.rts.J.<suffix>), label }. The wire's
-- leading key (not in the spec) is "key"; `sep` is never displayed.
J.FIELD_SPEC = {
  key = { "key", "key" }, trade_time = { "034", "(034)시간" },
  index = { "023", "(023)지수" }, change = { "024", "(024)전일대비" },
  change_rate = { "033", "(033)등락율" }, trade_volume = { "032", "(032)체결량" },
  acc_volume = { "027", "(027)거래량" }, acc_value = { "028", "(028)거래대금" },
  open_price = { "029", "(029)시가" }, high_price = { "030", "(030)고가" },
  low_price = { "031", "(031)저가" }, market_status = { "490", "(490)장상태구분" },
}

if _G.Proto then
  -- No dedicated Proto here — `mas` is the only registered protocol (§4.7).
  -- Fields are appended to the shared mas.proto (cumulative; see PROTOCOL.md §6).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  -- Register a string field per FIELD_NAMES entry (sep omitted).
  local pf = {}
  for _, name in ipairs(J.FIELD_NAMES) do
    if name ~= "sep" then  -- separator field: kept in FIELD_NAMES for decode, not displayed
      pf[name] = ProtoField.string("mas.rts.J." .. J.FIELD_SPEC[name][1], J.FIELD_SPEC[name][2])
    end
  end

  local fields = {}
  for _, f in pairs(pf) do fields[#fields + 1] = f end
  mas.proto.fields = fields

  local expert_badfields =
    ProtoExpert.new("mas.rts.J.expert.fields", "Unexpected sector-index field count",
      expert.group.MALFORMED, expert.severity.WARN)
  mas.proto.experts = { expert_badfields }

  -- Decode a TYPE='J' sector-index record body into the tree. The subtree
  -- is always tagged with the umbrella `mas` proto (see PROTOCOL.md §4.7) —
  -- a malformed TYPE='J' body (wrong field count) is flagged via
  -- expert_badfields instead; "did this decode?" is a field-value question,
  -- not a presence-filter one (mirrors add_quote/add_breadth/add_index).
  local function add_sector_index(tree, tvb, poff, r, pinfo, msg_index)
    local rec = J.decode(r.body)
    local sub = tree:add(mas.proto, tvb(poff + r.off, 6 + r.len),
      "type: " .. J.TYPE_SECTOR_INDEX .. " (" .. r.len .. " bytes)")
    mas.rts_add_header(sub, tvb, poff, r)
    if not rec then
      sub:add_proto_expert_info(expert_badfields)
      return false
    end
    local base = poff + r.off + 6   -- body start within tvb
    for _, name in ipairs(J.FIELD_NAMES) do
      if pf[name] then
        local o = rec.__offsets[name]
        sub:add(pf[name], tvb(base + o.off, o.len), rec[name])
      end
    end
    return true
  end

  -- Register as the TYPE='J' decoder; mas_rts.lua's generic dispatcher calls
  -- this for every TYPE='J' record and falls back to a bare "type: <TYPE>"
  -- label itself for any other TYPE.
  mas.by_rts_type[J.TYPE_SECTOR_INDEX] = { add = add_sector_index }
end

return J
