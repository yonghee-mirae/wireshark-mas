-- MAS RTS TYPE='W' (투자자매매) decoder.
--
-- One RTS-DATA record's DATA (see mas_rts.lua for RTS-HEADER framing) is a 15-field
-- tab-separated body: key, the hidden record-type marker (000), then the spec
-- fields (design/field_spec.md).
-- UNVERIFIED: no captured samples exist for this TYPE. The layout comes from
-- design/field_spec.md only; the framing (key + hidden marker + spec fields) and
-- plain char-array values are assumed. Field names are the spec codes (f<code>).
--
-- Pure helpers (decode, required by tests) + Wireshark registration.
-- Coordinates with core via _G.mas.

local mas = _G.mas or {}
_G.mas = mas
mas.by_rts_type = mas.by_rts_type or {}

local M = {}   -- module table: pure helpers (returned for tests)

M.TYPE_M = "W"   -- the only RTS TYPE this module decodes

-- Field order (0-based index 0..14).
M.FIELD_NAMES = {
  "key", "type_echo", "f034", "f333", "f334",
  "f335", "f336", "f337", "f338", "f339",
  "f340", "f341", "f342", "f343", "f344",
}

-- Strip trailing NUL bytes, then one stray trailing tab.
local function rstrip_nul_and_tab(s)
  local e = #s
  while e > 0 and s:byte(e) == 0 do e = e - 1 end
  if e > 0 and s:byte(e) == 9 then e = e - 1 end
  return s:sub(1, e)
end

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

-- Split a tab-separated TYPE='W' body into a record keyed by FIELD_NAMES.
-- Returns nil if field count != 15. `rec.__offsets[name] = {off, len}` gives each
-- field's own byte range within the wire body.
-- `body` is expected to already be UTF-8 (EUC-KR fields are transcoded by the
-- caller; tab never occurs inside a multibyte sequence). `raw_body`, if given,
-- is the untranscoded wire bytes, used only for the byte offsets.
function M.decode(body, raw_body)
  local fields, offsets = split_with_offsets(body)
  if #fields ~= #M.FIELD_NAMES then
    -- Some TYPEs end with one stray tab before the NUL; retry without it.
    body = rstrip_nul_and_tab(body)
    raw_body = raw_body and rstrip_nul_and_tab(raw_body)
    fields, offsets = split_with_offsets(body)
    if #fields ~= #M.FIELD_NAMES then return nil end
  end

  local rec = { __offsets = {} }
  for k = 1, #M.FIELD_NAMES do
    rec[M.FIELD_NAMES[k]] = fields[k]
    rec.__offsets[M.FIELD_NAMES[k]] = offsets[k]
  end

  if raw_body then
    local _, raw_offsets = split_with_offsets(raw_body)
    if #raw_offsets == #M.FIELD_NAMES then
      for k = 1, #M.FIELD_NAMES do
        rec.__offsets[M.FIELD_NAMES[k]] = raw_offsets[k]
      end
    end
  end
  return rec
end

-- Spec code + detail-pane label per field, from design/field_spec.md:
-- FIELD_SPEC[name] = { filter suffix (mas.rts.W.<suffix>), label }. The wire's
-- leading key (not in the spec) is "key"; `type_echo` (000) is never displayed.
M.FIELD_SPEC = {
  key = { "key", "key" }, f034 = { "034", "(034)처리시간" },
  f333 = { "333", "(333)매도수량" }, f334 = { "334", "(334)매수수량" },
  f335 = { "335", "(335)전매수량" }, f336 = { "336", "(336)환매수량" },
  f337 = { "337", "(337)매도미결" }, f338 = { "338", "(338)매수미결" },
  f339 = { "339", "(339)매도대금" }, f340 = { "340", "(340)매수대금" },
  f341 = { "341", "(341)전매대금" }, f342 = { "342", "(342)환매대금" },
  f343 = { "343", "(343)순매수수량" }, f344 = { "344", "(344)순매수금액" },
}

if _G.Proto then
  -- No dedicated Proto here — `mas` is the only registered protocol (§4.7).
  -- Fields are appended to the shared mas.proto (cumulative; see PROTOCOL.md §6).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  local pf = {}
  for _, name in ipairs(M.FIELD_NAMES) do
    if M.FIELD_SPEC[name] then  -- RTS-TYPE(000) is never displayed
      pf[name] = ProtoField.string("mas.rts.W." .. M.FIELD_SPEC[name][1], M.FIELD_SPEC[name][2])
    end
  end

  local fields = {}
  for _, f in pairs(pf) do fields[#fields + 1] = f end
  mas.proto.fields = fields

  local expert_badfields =
    ProtoExpert.new("mas.rts.W.expert.fields", "Unexpected TYPE W field count",
      expert.group.MALFORMED, expert.severity.WARN)
  mas.proto.experts = { expert_badfields }

  -- Decode a TYPE='W' record body into the tree. The subtree is always tagged
  -- with the umbrella `mas` proto (see PROTOCOL.md §4.7); a wrong field count is
  -- flagged via expert_badfields instead.
  local function add_record(tree, tvb, poff, r, pinfo, msg_index)
    local base = poff + r.off + 6   -- body start within tvb
    local raw = (r.len > 0) and tvb(base, r.len):raw() or ""
    local utf8 = (r.len > 0) and tvb(base, r.len):string(ENC_EUC_KR) or ""
    local rec = M.decode(utf8, raw)
    local sub = tree:add(mas.proto, tvb(poff + r.off, 6 + r.len),
      "type: " .. M.TYPE_M .. " (" .. r.len .. " bytes)")
    mas.rts_add_header(sub, tvb, poff, r)
    if not rec then
      sub:add_proto_expert_info(expert_badfields)
      return false
    end
    for _, name in ipairs(M.FIELD_NAMES) do
      if pf[name] then
        local o = rec.__offsets[name]
        sub:add(pf[name], tvb(base + o.off, o.len), rec[name])
      end
    end
    return true
  end

  -- Register as the TYPE='W' decoder; mas_rts.lua's generic dispatcher calls
  -- this for every such record.
  mas.by_rts_type[M.TYPE_M] = { add = add_record }
end

return M