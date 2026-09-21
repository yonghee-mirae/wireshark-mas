-- MAS RTS TYPE='m' (lowercase; 시황제목/통합뉴스, Market Commentary Headline)
-- decoder.
--
-- Filename note: this TYPE is lowercase 'm'. The FILENAME convention
-- lowercases the TYPE letter (e.g. TYPE='B' -> mas_rts_b.lua), which would
-- collide with a hypothetical future TYPE='M' (uppercase) — so this
-- already-lowercase TYPE is named `mas_rts_lm.lua` ("lower m") instead of
-- `mas_rts_m.lua`, reserving the latter for TYPE='M' if it ever turns up.
-- This is filename-only: the registration key (mas.by_rts_type["m"]) and the
-- Wireshark FILTER prefix (`mas.rts.m.*`) both use the literal wire byte
-- "m" as-is, with no "l" trick — Wireshark display-filter field names are
-- case-sensitive (confirmed against the WSUG docs), so `mas.rts.m` and a
-- future `mas.rts.M` would already be distinct filters without one.
--
-- One RTS-DATA record's DATA (see mas_rts.lua for RTS-HEADER framing) is a
-- 16-field tab-separated body: a news headline plus optional related-stock
-- info and provider metadata. This is the only RTS TYPE this module
-- decodes; every other TYPE is left to mas_rts.lua's generic
-- "type: <TYPE>"-only handling.
--
-- Field order/names are the spec given in inner/wireshark 추가.txt, confirmed
-- against samples/20260921_nana.pcapng (19 sampled records) and
-- samples/20260915_0809_RTS2.pcapng (4 sampled records) — both always
-- exactly 16 tab-separated fields. Field names are literal transliterations
-- of the spec's own Korean column labels rather than a guessed English
-- gloss — e.g. `category`/`category2` hold values that look like a news
-- provider's short code/full name (e.g. "한차"/"한경차이나"), not an
-- obvious "classification", so the semantics are not fully confirmed.
--
-- Pure helpers (decode, required by tests) + Wireshark registration.
-- Coordinates with core via _G.mas.

local mas = _G.mas or {}
_G.mas = mas
mas.by_rts_type = mas.by_rts_type or {}

local LM = {}   -- module table: pure helpers (returned for tests)

LM.TYPE_NEWS = "m"   -- the only RTS TYPE this module decodes (lowercase)

-- Field order (0-based index 0..15), for RTS TYPE='m' (Market Commentary).
LM.FIELD_NAMES = {
  "key", "sep",
  "content", "issue_code", "issue_name", "key1", "key2", "time",
  "category", "category2", "provider", "date", "price", "volume",
  "change_sign", "key3",
}

-- Strip trailing NUL bytes (see mas_rts_b for the version note).
local function rstrip_nul(s)
  local e = #s
  while e > 0 and s:byte(e) == 0 do e = e - 1 end
  return s:sub(1, e)
end

-- Split a tab-separated TYPE='m' body into a record keyed by FIELD_NAMES.
-- Returns nil if field count != 16. Trailing NULs are stripped. `body` is
-- expected to already be UTF-8 (see add_news below) — encoding doesn't
-- affect the split since tab (0x09) never occurs inside a multibyte
-- sequence in either EUC-KR or UTF-8.
function LM.decode(body)
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
  if #fields ~= #LM.FIELD_NAMES then return nil end

  local rec = {}
  for k = 1, #LM.FIELD_NAMES do
    rec[LM.FIELD_NAMES[k]] = rstrip_nul(fields[k])
  end
  return rec
end

if _G.Proto then
  -- No dedicated Proto here — `mas` is the only registered protocol (§4.7).
  -- Fields are appended to the shared mas.proto (cumulative; see PROTOCOL.md §6).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  -- Register a string field per FIELD_NAMES entry (sep omitted).
  local pf = {}
  for _, name in ipairs(LM.FIELD_NAMES) do
    if name ~= "sep" then  -- separator field: kept in FIELD_NAMES for decode, not displayed
      pf[name] = ProtoField.string("mas.rts.m." .. name, name)
    end
  end

  local fields = {}
  for _, f in pairs(pf) do fields[#fields + 1] = f end
  mas.proto.fields = fields

  local expert_badfields =
    ProtoExpert.new("mas.rts.m.expert.fields", "Unexpected market-commentary field count",
      expert.group.MALFORMED, expert.severity.WARN)
  mas.proto.experts = { expert_badfields }

  -- Decode a TYPE='m' market-commentary record body into the tree. The
  -- subtree is always tagged with the umbrella `mas` proto (see
  -- PROTOCOL.md §4.7) — a malformed TYPE='m' body (wrong field count) is
  -- flagged via expert_badfields instead; "did this decode?" is a
  -- field-value question, not a presence-filter one.
  --
  -- The headline/issue_name/category* fields are EUC-KR, so the body is
  -- transcoded to UTF-8 before splitting — same reasoning as
  -- mas_tr_90.lua's add_order_body and mas_rts_f.lua's add_broker (tab,
  -- 0x09, never occurs inside a multibyte sequence, so the split stays
  -- correct). (Requires a Wireshark build with EUC-KR string support.)
  local function add_news(tree, tvb, poff, r, pinfo, msg_index)
    local base = poff + r.off + 6   -- body start within tvb
    local utf8 = (r.len > 0) and tvb(base, r.len):string(ENC_EUC_KR) or ""
    local rec = LM.decode(utf8)
    local sub = tree:add(mas.proto, tvb(poff + r.off, 6 + r.len),
      "type: " .. LM.TYPE_NEWS .. " (" .. r.len .. " bytes)")
    mas.rts_add_header(sub, tvb, poff, r)
    if not rec then
      sub:add_proto_expert_info(expert_badfields)
      return false
    end
    for _, name in ipairs(LM.FIELD_NAMES) do
      if pf[name] then sub:add(pf[name], tvb(base, r.len), rec[name]) end
    end
    return true
  end

  -- Register as the TYPE='m' decoder; mas_rts.lua's generic dispatcher calls
  -- this for every TYPE='m' record and falls back to a bare "type: <TYPE>"
  -- label itself for any other TYPE.
  mas.by_rts_type[LM.TYPE_NEWS] = { add = add_news }
end

return LM
