-- MAS RTS TYPE='o' (주식옵션:체결) decoder.
--
-- Filename `mas_rts_lo.lua`: the leading "l" marks a lowercase TYPE (see mas_rts_lm.lua); the
-- registration key and the Wireshark FILTER prefix (`mas.rts.o.*`) use the literal wire byte.
--
-- One RTS-DATA record's DATA (see mas_rts.lua for RTS-HEADER framing) is a 41-field
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

M.TYPE_M = "o"   -- the only RTS TYPE this module decodes

-- Field order (0-based index 0..40).
M.FIELD_NAMES = {
  "key", "type_echo", "f034", "f023", "f024",
  "f033", "f025", "f026", "f032", "f027",
  "f028", "f029", "f030", "f031", "f201",
  "f202", "f203", "f204", "f205", "f206",
  "f207", "f388", "f387", "f448", "f249",
  "f462", "f358", "f037", "f038", "f193",
  "f194", "f411", "f412", "f414", "f415",
  "f416", "f243", "f244", "f245", "f246",
  "f247",
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

-- Split a tab-separated TYPE='o' body into a record keyed by FIELD_NAMES.
-- Returns nil if field count != 41. `rec.__offsets[name] = {off, len}` gives each
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
-- FIELD_SPEC[name] = { filter suffix (mas.rts.o.<suffix>), label }. The wire's
-- leading key (not in the spec) is "key"; `type_echo` (000) is never displayed.
M.FIELD_SPEC = {
  key = { "key", "key" }, f034 = { "034", "(034)체결시간" },
  f023 = { "023", "(023)현재가" }, f024 = { "024", "(024)전일대비" },
  f033 = { "033", "(033)등락율" }, f025 = { "025", "(025)매도호가" },
  f026 = { "026", "(026)매수호가" }, f032 = { "032", "(032)체결량" },
  f027 = { "027", "(027)거래량" }, f028 = { "028", "(028)거래대금" },
  f029 = { "029", "(029)시가" }, f030 = { "030", "(030)고가" },
  f031 = { "031", "(031)저가" }, f201 = { "201", "(201)미결약정" },
  f202 = { "202", "(202)이론가" }, f203 = { "203", "(203)이론BASIS" },
  f204 = { "204", "(204)시장BASIS" }, f205 = { "205", "(205)괴리율" },
  f206 = { "206", "(206)미결대비" }, f207 = { "207", "(207)괴리치" },
  f388 = { "388", "(388)3분체결강도" }, f387 = { "387", "(387)체결강도" },
  f448 = { "448", "(448)미결증감" }, f249 = { "249", "(249)전일거래량비" },
  f462 = { "462", "(462)기초자산값" }, f358 = { "358", "(358)이론대비" },
  f037 = { "037", "(037)도-체결량" }, f038 = { "038", "(038)수-체결량" },
  f193 = { "193", "(193)도-체결합" }, f194 = { "194", "(194)수-체결합" },
  f411 = { "411", "(411)실시간상한가" }, f412 = { "412", "(412)실시간하한가" },
  f414 = { "414", "(414)협의대량누적체결량" }, f415 = { "415", "(415)상한가단계폭" },
  f416 = { "416", "(416)하한가단계폭" }, f243 = { "243", "(243)델타" },
  f244 = { "244", "(244)감마" }, f245 = { "245", "(245)세타" },
  f246 = { "246", "(246)베가" }, f247 = { "247", "(247)로" },
}

if _G.Proto then
  -- No dedicated Proto here — `mas` is the only registered protocol (§4.7).
  -- Fields are appended to the shared mas.proto (cumulative; see PROTOCOL.md §6).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  local pf = {}
  for _, name in ipairs(M.FIELD_NAMES) do
    if M.FIELD_SPEC[name] then  -- RTS-TYPE(000) is never displayed
      pf[name] = ProtoField.string("mas.rts.o." .. M.FIELD_SPEC[name][1], M.FIELD_SPEC[name][2])
    end
  end

  local fields = {}
  for _, f in pairs(pf) do fields[#fields + 1] = f end
  mas.proto.fields = fields

  local expert_badfields =
    ProtoExpert.new("mas.rts.o.expert.fields", "Unexpected TYPE o field count",
      expert.group.MALFORMED, expert.severity.WARN)
  mas.proto.experts = { expert_badfields }

  -- Decode a TYPE='o' record body into the tree. The subtree is always tagged
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

  -- Register as the TYPE='o' decoder; mas_rts.lua's generic dispatcher calls
  -- this for every such record.
  mas.by_rts_type[M.TYPE_M] = { add = add_record }
end

return M