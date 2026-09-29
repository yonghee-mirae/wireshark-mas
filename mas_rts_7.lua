-- MAS RTS TYPE='7' (프리/애프터마켓 시장현황 (Pre/After-market Status)) decoder.
--
-- One RTS-DATA record's DATA (see mas_rts.lua for RTS-HEADER framing) is a 13-field
-- tab-separated body: key, the hidden record-type marker (000), then the spec
-- fields (design/field_spec.md).
-- Field layout confirmed against samples/tcp_capture.cap (5 records).
--
-- Pure helpers (decode, required by tests) + Wireshark registration.
-- Coordinates with core via _G.mas.

local mas = _G.mas or {}
_G.mas = mas
mas.by_rts_type = mas.by_rts_type or {}

local M7 = {}   -- module table: pure helpers (returned for tests)

M7.TYPE_M7 = "7"   -- the only RTS TYPE this module decodes

-- Field order (0-based index 0..12).
M7.FIELD_NAMES = {
  "key", "type_echo", "trade_time", "exchange_gubun", "market_gubun",
  "sector_gubun", "change_rate", "prev_session_ratio", "upper_limit_count", "up_count",
  "flat_count", "down_count", "lower_limit_count",
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

-- Split a tab-separated TYPE='7' body into a record keyed by FIELD_NAMES.
-- Returns nil if field count != 13. `rec.__offsets[name] = {off, len}` gives each
-- field's own byte range within the wire body.
function M7.decode(body)
  body = body
  local fields, offsets = split_with_offsets(body)
  if #fields ~= #M7.FIELD_NAMES then return nil end

  local rec = { __offsets = {} }
  for k = 1, #M7.FIELD_NAMES do
    rec[M7.FIELD_NAMES[k]] = fields[k]
    rec.__offsets[M7.FIELD_NAMES[k]] = offsets[k]
  end
  return rec
end

-- Spec code + detail-pane label per field, from design/field_spec.md:
-- FIELD_SPEC[name] = { filter suffix (mas.rts.7.<suffix>), label }. The wire's
-- leading key (not in the spec) is "key"; `type_echo` (000) is never displayed.
M7.FIELD_SPEC = {
  key = { "key", "key" }, trade_time = { "034", "(034)시간" },
  exchange_gubun = { "303", "(303)거래소구분" }, market_gubun = { "302", "(302)마켓구분" },
  sector_gubun = { "301", "(301)업종구분" }, change_rate = { "033", "(033)등락율" },
  prev_session_ratio = { "024", "(024)전장대비율" }, upper_limit_count = { "251", "(251)상한종목" },
  up_count = { "252", "(252)상승종목" }, flat_count = { "253", "(253)보합종목" },
  down_count = { "255", "(255)하락종목" }, lower_limit_count = { "254", "(254)하한종목" },
}

if _G.Proto then
  -- No dedicated Proto here — `mas` is the only registered protocol (§4.7).
  -- Fields are appended to the shared mas.proto (cumulative; see PROTOCOL.md §6).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  local pf = {}
  for _, name in ipairs(M7.FIELD_NAMES) do
    if M7.FIELD_SPEC[name] then  -- RTS-TYPE(000) is never displayed
      pf[name] = ProtoField.string("mas.rts.7." .. M7.FIELD_SPEC[name][1], M7.FIELD_SPEC[name][2])
    end
  end

  local fields = {}
  for _, f in pairs(pf) do fields[#fields + 1] = f end
  mas.proto.fields = fields

  local expert_badfields =
    ProtoExpert.new("mas.rts.7.expert.fields", "Unexpected TYPE 7 field count",
      expert.group.MALFORMED, expert.severity.WARN)
  mas.proto.experts = { expert_badfields }

  -- Decode a TYPE='7' record body into the tree. The subtree is always tagged
  -- with the umbrella `mas` proto (see PROTOCOL.md §4.7); a wrong field count is
  -- flagged via expert_badfields instead.
  local function add_record(tree, tvb, poff, r, pinfo, msg_index)
    local base = poff + r.off + 6   -- body start within tvb
    local rec = M7.decode(r.body)
    local sub = tree:add(mas.proto, tvb(poff + r.off, 6 + r.len),
      "type: " .. M7.TYPE_M7 .. " (" .. r.len .. " bytes)")
    mas.rts_add_header(sub, tvb, poff, r)
    if not rec then
      sub:add_proto_expert_info(expert_badfields)
      return false
    end
    for _, name in ipairs(M7.FIELD_NAMES) do
      if pf[name] then
        local o = rec.__offsets[name]
        sub:add(pf[name], tvb(base + o.off, o.len), rec[name])
      end
    end
    return true
  end

  -- Register as the TYPE='7' decoder; mas_rts.lua's generic dispatcher calls
  -- this for every such record.
  mas.by_rts_type[M7.TYPE_M7] = { add = add_record }
end

return M7