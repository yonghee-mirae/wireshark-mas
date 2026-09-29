-- MAS RTS TYPE='S' (선물 투자자별순매수 (Futures Investor Net Buy)) decoder.
--
-- One RTS-DATA record's DATA (see mas_rts.lua for RTS-HEADER framing) is a 5-field
-- tab-separated body: key, the hidden record-type marker (000), then the spec
-- fields (design/field_spec.md).
-- The spec's (260)종목코드 is the wire's leading key, not a separate field.
-- Field layout confirmed against samples/tcp_capture.cap (8 records).
--
-- Pure helpers (decode, required by tests) + Wireshark registration.
-- Coordinates with core via _G.mas.

local mas = _G.mas or {}
_G.mas = mas
mas.by_rts_type = mas.by_rts_type or {}

local SI = {}   -- module table: pure helpers (returned for tests)

SI.TYPE_SI = "S"   -- the only RTS TYPE this module decodes

-- Field order (0-based index 0..4).
SI.FIELD_NAMES = {
  "key", "type_echo", "investor_gubun", "investor_qty", "investor_amt",
}

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

-- Split a tab-separated TYPE='S' body into a record keyed by FIELD_NAMES.
-- Returns nil if field count != 5. `rec.__offsets[name] = {off, len}` gives each
-- field's own byte range within the wire body.
function SI.decode(body)
  body = body
  local fields, offsets = split_with_offsets(body)
  if #fields ~= #SI.FIELD_NAMES then return nil end

  local rec = { __offsets = {} }
  for k = 1, #SI.FIELD_NAMES do
    rec[SI.FIELD_NAMES[k]] = fields[k]
    rec.__offsets[SI.FIELD_NAMES[k]] = offsets[k]
  end
  return rec
end

-- Spec code + detail-pane label per field, from design/field_spec.md:
-- FIELD_SPEC[name] = { filter suffix (mas.rts.S.<suffix>), label }. The wire's
-- leading key (not in the spec) is "key"; `type_echo` (000) is never displayed.
SI.FIELD_SPEC = {
  key = { "key", "key" }, investor_gubun = { "261", "(261)투자자구분" },
  investor_qty = { "262", "(262)투자자계약수" }, investor_amt = { "263", "(263)투자자계약금" },
}

if _G.Proto then
  -- No dedicated Proto here — `mas` is the only registered protocol (§4.7).
  -- Fields are appended to the shared mas.proto (cumulative; see PROTOCOL.md §6).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  local pf = {}
  for _, name in ipairs(SI.FIELD_NAMES) do
    if SI.FIELD_SPEC[name] then  -- RTS-TYPE(000) is never displayed
      pf[name] = ProtoField.string("mas.rts.S." .. SI.FIELD_SPEC[name][1], SI.FIELD_SPEC[name][2])
    end
  end

  local fields = {}
  for _, f in pairs(pf) do fields[#fields + 1] = f end
  mas.proto.fields = fields

  local expert_badfields =
    ProtoExpert.new("mas.rts.S.expert.fields", "Unexpected TYPE S field count",
      expert.group.MALFORMED, expert.severity.WARN)
  mas.proto.experts = { expert_badfields }

  -- Decode a TYPE='S' record body into the tree. The subtree is always tagged
  -- with the umbrella `mas` proto (see PROTOCOL.md §4.7); a wrong field count is
  -- flagged via expert_badfields instead.
  local function add_record(tree, tvb, poff, r, pinfo, msg_index)
    local base = poff + r.off + 6   -- body start within tvb
    local rec = SI.decode(r.body)
    local sub = tree:add(mas.proto, tvb(poff + r.off, 6 + r.len),
      "type: " .. SI.TYPE_SI .. " (" .. r.len .. " bytes)")
    mas.rts_add_header(sub, tvb, poff, r)
    if not rec then
      sub:add_proto_expert_info(expert_badfields)
      return false
    end
    for _, name in ipairs(SI.FIELD_NAMES) do
      if pf[name] then
        local o = rec.__offsets[name]
        sub:add(pf[name], tvb(base + o.off, o.len), rec[name])
      end
    end
    return true
  end

  -- Register as the TYPE='S' decoder; mas_rts.lua's generic dispatcher calls
  -- this for every such record.
  mas.by_rts_type[SI.TYPE_SI] = { add = add_record }
end

return SI