-- MAS RTS TYPE='P' (옵션:호가) decoder.
--
-- One RTS-DATA record's DATA (see mas_rts.lua for RTS-HEADER framing) is a 75-field
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

M.TYPE_M = "P"   -- the only RTS TYPE this module decodes

-- Field order (0-based index 0..74).
M.FIELD_NAMES = {
  "key", "type_echo", "f040", "f025", "f026",
  "f051", "f052", "f053", "f054", "f055",
  "f041", "f042", "f043", "f044", "f045",
  "f211", "f212", "f213", "f214", "f215",
  "f071", "f072", "f073", "f074", "f075",
  "f061", "f062", "f063", "f064", "f065",
  "f221", "f222", "f223", "f224", "f225",
  "f101", "f103", "f106", "f108", "f117",
  "f118", "f119", "f081", "f082", "f083",
  "f084", "f085", "f091", "f092", "f093",
  "f094", "f095", "f104", "f109", "f276",
  "f277", "f278", "f279", "f280", "f286",
  "f287", "f288", "f289", "f290", "f296",
  "f297", "f111", "f113", "f114", "f180",
  "f411", "f412", "f415", "f416", "f112",
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

-- Split a tab-separated TYPE='P' body into a record keyed by FIELD_NAMES.
-- Returns nil if field count != 75. `rec.__offsets[name] = {off, len}` gives each
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
-- FIELD_SPEC[name] = { filter suffix (mas.rts.P.<suffix>), label }. The wire's
-- leading key (not in the spec) is "key"; `type_echo` (000) is never displayed.
M.FIELD_SPEC = {
  key = { "key", "key" }, f040 = { "040", "(040)호가시간" },
  f025 = { "025", "(025)매도호가" }, f026 = { "026", "(026)매수호가" },
  f051 = { "051", "(051)매도가1" }, f052 = { "052", "(052)매도가2" },
  f053 = { "053", "(053)매도가3" }, f054 = { "054", "(054)매도가4" },
  f055 = { "055", "(055)매도가5" }, f041 = { "041", "(041)매도량1" },
  f042 = { "042", "(042)매도량2" }, f043 = { "043", "(043)매도량3" },
  f044 = { "044", "(044)매도량4" }, f045 = { "045", "(045)매도량5" },
  f211 = { "211", "(211)매도건1" }, f212 = { "212", "(212)매도건2" },
  f213 = { "213", "(213)매도건3" }, f214 = { "214", "(214)매도건4" },
  f215 = { "215", "(215)매도건5" }, f071 = { "071", "(071)매수가1" },
  f072 = { "072", "(072)매수가2" }, f073 = { "073", "(073)매수가3" },
  f074 = { "074", "(074)매수가4" }, f075 = { "075", "(075)매수가5" },
  f061 = { "061", "(061)매수량1" }, f062 = { "062", "(062)매수량2" },
  f063 = { "063", "(063)매수량3" }, f064 = { "064", "(064)매수량4" },
  f065 = { "065", "(065)매수량5" }, f221 = { "221", "(221)매수건1" },
  f222 = { "222", "(222)매수건2" }, f223 = { "223", "(223)매수건3" },
  f224 = { "224", "(224)매수건4" }, f225 = { "225", "(225)매수건5" },
  f101 = { "101", "(101)매도총량" }, f103 = { "103", "(103)매도총건" },
  f106 = { "106", "(106)매수총량" }, f108 = { "108", "(108)매수총비" },
  f117 = { "117", "(117)예상가격" }, f118 = { "118", "(118)예상대비" },
  f119 = { "119", "(119)예상등락" }, f081 = { "081", "(081)매도비1" },
  f082 = { "082", "(082)매도비2" }, f083 = { "083", "(083)매도비3" },
  f084 = { "084", "(084)매도비4" }, f085 = { "085", "(085)매도비5" },
  f091 = { "091", "(091)매수비1" }, f092 = { "092", "(092)매수비2" },
  f093 = { "093", "(093)매수비3" }, f094 = { "094", "(094)매수비4" },
  f095 = { "095", "(095)매수비5" }, f104 = { "104", "(104)매도총비" },
  f109 = { "109", "(109)매수총비" }, f276 = { "276", "(276)매도비1" },
  f277 = { "277", "(277)매도비2" }, f278 = { "278", "(278)매도비3" },
  f279 = { "279", "(279)매도비4" }, f280 = { "280", "(280)매도비5" },
  f286 = { "286", "(286)매수비1" }, f287 = { "287", "(287)매수비2" },
  f288 = { "288", "(288)매수비3" }, f289 = { "289", "(289)매수비4" },
  f290 = { "290", "(290)매수비5" }, f296 = { "296", "(296)매도총비" },
  f297 = { "297", "(297)매수총비" }, f111 = { "111", "(111)예상가격" },
  f113 = { "113", "(113)예상대비" }, f114 = { "114", "(114)예상등락" },
  f180 = { "180", "(180)순매수총잔량" }, f411 = { "411", "(411)실시간상한가" },
  f412 = { "412", "(412)실시간하한가" }, f415 = { "415", "(415)상한가단계폭" },
  f416 = { "416", "(416)하한가단계폭" }, f112 = { "112", "(112)예상체결수량" },
}

if _G.Proto then
  -- No dedicated Proto here — `mas` is the only registered protocol (§4.7).
  -- Fields are appended to the shared mas.proto (cumulative; see PROTOCOL.md §6).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  local pf = {}
  for _, name in ipairs(M.FIELD_NAMES) do
    if M.FIELD_SPEC[name] then  -- RTS-TYPE(000) is never displayed
      pf[name] = ProtoField.string("mas.rts.P." .. M.FIELD_SPEC[name][1], M.FIELD_SPEC[name][2])
    end
  end

  local fields = {}
  for _, f in pairs(pf) do fields[#fields + 1] = f end
  mas.proto.fields = fields

  local expert_badfields =
    ProtoExpert.new("mas.rts.P.expert.fields", "Unexpected TYPE P field count",
      expert.group.MALFORMED, expert.severity.WARN)
  mas.proto.experts = { expert_badfields }

  -- Decode a TYPE='P' record body into the tree. The subtree is always tagged
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

  -- Register as the TYPE='P' decoder; mas_rts.lua's generic dispatcher calls
  -- this for every such record.
  mas.by_rts_type[M.TYPE_M] = { add = add_record }
end

return M