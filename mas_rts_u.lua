-- MAS RTS TYPE='U' (업종:등락, Sector Breadth) decoder.
--
-- One RTS-DATA record's DATA (see mas_rts.lua for RTS-HEADER framing) is a
-- 10-field tab-separated body: market/sector-wide advance-decline counts,
-- not a per-stock quote. This is the only RTS TYPE this module decodes;
-- every other TYPE is left to mas_rts.lua's generic "type: <TYPE>"-only
-- handling.
--
-- Field order/names are the confirmed spec (PROTOCOL.md §8.5), cross-checked
-- against samples/*.pcapng: `up_count + upper_limit_count + flat_count +
-- down_count + lower_limit_count` held constant at exactly 801 across all 6
-- sampled "K0001" records and stayed within 1521-1523 across all 6 sampled
-- "KQ001" records (both plausibly the KOSPI/KOSDAQ listed-company counts).
--
-- Pure helpers (decode, required by tests) + Wireshark registration.
-- Coordinates with core via _G.mas.

local mas = _G.mas or {}
_G.mas = mas
mas.by_rts_type = mas.by_rts_type or {}

local S = {}   -- module table: pure helpers (returned for tests)

S.TYPE_BREADTH = "U"   -- the only RTS TYPE this module decodes

-- Field order (0-based index 0..9), for RTS TYPE='U' (Sector Breadth).
S.FIELD_NAMES = {
  "key", "sep", "trade_time",
  "up_count", "upper_limit_count", "flat_count", "down_count", "lower_limit_count",
  "volume", "value",
}

-- Strip trailing NUL bytes (see mas_rts_b for the version note).
local function rstrip_nul(s)
  local e = #s
  while e > 0 and s:byte(e) == 0 do e = e - 1 end
  return s:sub(1, e)
end

-- Split a tab-separated TYPE='U' body into a record keyed by FIELD_NAMES.
-- Returns nil if field count != 10. Trailing NULs are stripped. Unlike
-- TYPE='B'/'C', `key` here is a market/sector key (e.g. "KQ001", "K0001"),
-- not a stock issue code, so no market-prefix split is applied (hence the
-- field name is `key`, not `issue_code`).
function S.decode(body)
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
  if #fields ~= #S.FIELD_NAMES then return nil end

  local rec = {}
  for k = 1, #S.FIELD_NAMES do
    rec[S.FIELD_NAMES[k]] = rstrip_nul(fields[k])
  end
  return rec
end

if _G.Proto then
  -- No dedicated Proto here — `mas` is the only registered protocol (§4.7).
  -- Fields are appended to the shared mas.proto (cumulative; see PROTOCOL.md §6).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  -- Register a string field per FIELD_NAMES entry (sep omitted).
  local pf = {}
  for _, name in ipairs(S.FIELD_NAMES) do
    if name ~= "sep" then  -- separator field: kept in FIELD_NAMES for decode, not displayed
      pf[name] = ProtoField.string("mas.rts.U." .. name, name)
    end
  end

  local fields = {}
  for _, f in pairs(pf) do fields[#fields + 1] = f end
  mas.proto.fields = fields

  local expert_badfields =
    ProtoExpert.new("mas.rts.U.expert.fields", "Unexpected sector breadth field count",
      expert.group.MALFORMED, expert.severity.WARN)
  mas.proto.experts = { expert_badfields }

  -- Decode a TYPE='U' sector-breadth record body into the tree. The subtree is
  -- always tagged with the umbrella `mas` proto (see PROTOCOL.md §4.7) — a
  -- malformed TYPE='U' body (wrong field count) is flagged via expert_badfields
  -- instead; "did this decode?" is a field-value question, not a
  -- presence-filter one (mirrors add_exec/add_quote).
  local function add_breadth(tree, tvb, poff, r, pinfo, msg_index)
    local rec = S.decode(r.body)
    local sub = tree:add(mas.proto, tvb(poff + r.off, 6 + r.len),
      "type: " .. S.TYPE_BREADTH .. " (" .. r.len .. " bytes)")
    mas.rts_add_header(sub, tvb, poff, r)
    if not rec then
      sub:add_proto_expert_info(expert_badfields)
      return false
    end
    local base = poff + r.off + 6   -- body start within tvb
    for _, name in ipairs(S.FIELD_NAMES) do
      if pf[name] then sub:add(pf[name], tvb(base, r.len), rec[name]) end
    end
    return true
  end

  -- Register as the TYPE='U' decoder; mas_rts.lua's generic dispatcher calls
  -- this for every TYPE='U' record and falls back to a bare "type: <TYPE>"
  -- label itself for any other TYPE.
  mas.by_rts_type[S.TYPE_BREADTH] = { add = add_breadth }
end

return S
