-- MAS RTS TYPE='M' (프로그램매매) decoder.
--
-- One RTS-DATA record's DATA (see mas_rts.lua for RTS-HEADER framing) is a 51-field
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

M.TYPE_M = "M"   -- the only RTS TYPE this module decodes

-- Field order (0-based index 0..50).
M.FIELD_NAMES = {
  "key", "type_echo", "f034", "f303", "f304",
  "f305", "f306", "f307", "f308", "f309",
  "f310", "f311", "f312", "f313", "f314",
  "f315", "f316", "f317", "f318", "f319",
  "f320", "f321", "f322", "f323", "f324",
  "f325", "f326", "f327", "f328", "f329",
  "f330", "f331", "f332", "f333", "f334",
  "f335", "f336", "f337", "f338", "f339",
  "f340", "f341", "f342", "f343", "f344",
  "f345", "f346", "f347", "f348", "f349",
  "f350",
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

-- Split a tab-separated TYPE='M' body into a record keyed by FIELD_NAMES.
-- Returns nil if field count != 51. `rec.__offsets[name] = {off, len}` gives each
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
-- FIELD_SPEC[name] = { filter suffix (mas.rts.M.<suffix>), label }. The wire's
-- leading key (not in the spec) is "key"; `type_echo` (000) is never displayed.
M.FIELD_SPEC = {
  key = { "key", "key" }, f034 = { "034", "(034)처리시간" },
  f303 = { "303", "(303)차도잔량" }, f304 = { "304", "(304)차수잔량" },
  f305 = { "305", "(305)비도잔량" }, f306 = { "306", "(306)비수잔량" },
  f307 = { "307", "(307)차도수량" }, f308 = { "308", "(308)차수수량" },
  f309 = { "309", "(309)비도수량" }, f310 = { "310", "(310)비수수량" },
  f311 = { "311", "(311)차도위량" }, f312 = { "312", "(312)차도자량" },
  f313 = { "313", "(313)차수위량" }, f314 = { "314", "(314)차수자량" },
  f315 = { "315", "(315)비도위량" }, f316 = { "316", "(316)비도자량" },
  f317 = { "317", "(317)비수위량" }, f318 = { "318", "(318)비수자수" },
  f319 = { "319", "(319)차도위금" }, f320 = { "320", "(320)차도자금" },
  f321 = { "321", "(321)차수위금" }, f322 = { "322", "(322)차수자금" },
  f323 = { "323", "(323)비도위금" }, f324 = { "324", "(324)비도자금" },
  f325 = { "325", "(325)비수위금" }, f326 = { "326", "(326)비수자금" },
  f327 = { "327", "(327)(전)순매수금액" }, f328 = { "328", "(328)(전)순매수수량" },
  f329 = { "329", "(329)(차)순매수금액" }, f330 = { "330", "(330)(차)순매수수량" },
  f331 = { "331", "(331)(비)순매수금액" }, f332 = { "332", "(332)(비)순매수수량" },
  f333 = { "333", "(333)(전)위순매수금" }, f334 = { "334", "(334)(전)자순매수금" },
  f335 = { "335", "(335)(차)위순매수금" }, f336 = { "336", "(336)(차)자순매수금" },
  f337 = { "337", "(337)(비)위순매수금" }, f338 = { "338", "(338)(비)자순매수금" },
  f339 = { "339", "(339)(전)매도량합" }, f340 = { "340", "(340)(전)매도금액합" },
  f341 = { "341", "(341)(전)매수량합" }, f342 = { "342", "(342)(전)매수금액합" },
  f343 = { "343", "(343)(차)매도량합" }, f344 = { "344", "(344)(차)매도금액합" },
  f345 = { "345", "(345)(차)매수량합" }, f346 = { "346", "(346)(차)매수금액합" },
  f347 = { "347", "(347)(비)매도량합" }, f348 = { "348", "(348)(비)매도금액합" },
  f349 = { "349", "(349)(비)매수량합" }, f350 = { "350", "(350)(비)매수금액합" },
}

if _G.Proto then
  -- No dedicated Proto here — `mas` is the only registered protocol (§4.7).
  -- Fields are appended to the shared mas.proto (cumulative; see PROTOCOL.md §6).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  local pf = {}
  for _, name in ipairs(M.FIELD_NAMES) do
    if M.FIELD_SPEC[name] then  -- RTS-TYPE(000) is never displayed
      pf[name] = ProtoField.string("mas.rts.M." .. M.FIELD_SPEC[name][1], M.FIELD_SPEC[name][2])
    end
  end

  local fields = {}
  for _, f in pairs(pf) do fields[#fields + 1] = f end
  mas.proto.fields = fields

  local expert_badfields =
    ProtoExpert.new("mas.rts.M.expert.fields", "Unexpected TYPE M field count",
      expert.group.MALFORMED, expert.severity.WARN)
  mas.proto.experts = { expert_badfields }

  -- Decode a TYPE='M' record body into the tree. The subtree is always tagged
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

  -- Register as the TYPE='M' decoder; mas_rts.lua's generic dispatcher calls
  -- this for every such record.
  mas.by_rts_type[M.TYPE_M] = { add = add_record }
end

return M