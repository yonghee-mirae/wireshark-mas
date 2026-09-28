-- MAS RTS TYPE='q'(소문자) 필드 레이아웃 — 해외주식 호가 (Overseas Stock Quote)
--
-- Filename note: this TYPE is lowercase 'q'. The FILENAME convention
-- lowercases the TYPE letter (e.g. TYPE='B' -> mas_rts_b.lua), which would
-- collide with a hypothetical future TYPE='Q' (uppercase) — so this
-- already-lowercase TYPE is named `mas_rts_lq.lua` ("lower q") instead of
-- `mas_rts_q.lua`, reserving the latter for TYPE='Q' if it ever turns up
-- (same reasoning as mas_rts_lm.lua/mas_rts_ls.lua). This is filename-only:
-- the registration key (mas.by_rts_type["q"]) and the Wireshark FILTER
-- prefix (`mas.rts.q.*`) both use the literal wire byte "q" as-is.
--
-- One RTS-DATA record's DATA (see mas_rts.lua for RTS-HEADER framing) is a
-- 72-field tab-separated body (spec: protocols/해외.txt). This is the only
-- RTS TYPE this module decodes; every other TYPE is left to mas_rts.lua's
-- generic "type: <TYPE>"-only handling.
--
-- Confirmed against all 42 real TYPE='q' records in
-- samples/GlobalPart_RTS.pcapng (symbol DTSLA): total_ask_qty ==
-- sum(ask_qty1..10) and total_bid_qty == sum(bid_qty1..10) held exactly for
-- every record. total_ask_qty_chg/total_bid_qty_chg (잔량변화, quantity
-- CHANGE at that price level — negative values are normal) only summed to
-- the visible top-10 ladder in 39/42 and 35/42 records; the rest is
-- explained by book activity beyond the 10 visible levels still moving the
-- aggregate total, not a field-mapping issue. No stray trailing tab before
-- the terminating NUL (unlike TYPE='s').
--
-- Pure helpers (decode, required by tests) + Wireshark registration.
-- Coordinates with core via _G.mas.

local mas = _G.mas or {}
_G.mas = mas
mas.by_rts_type = mas.by_rts_type or {}

local Q = {}   -- module table: pure helpers (returned for tests)

Q.TYPE_OVERSEAS_QUOTE = "q"   -- the only RTS TYPE this module decodes

-- Build a "<prefix><1..n>" name list, e.g. ladder("ask_price", 10) ->
-- {"ask_price1", ..., "ask_price10"} (see mas_rts_c.lua for the same helper).
local function ladder(prefix, n)
  local t = {}
  for i = 1, n do t[i] = prefix .. i end
  return t
end

-- Field order (0-based index 0..71), for RTS TYPE='q' (Overseas Stock Quote).
Q.FIELD_NAMES = {}
local function append(t) for _, v in ipairs(t) do Q.FIELD_NAMES[#Q.FIELD_NAMES + 1] = v end end
append({ "key", "type_echo", "realtime_gubun", "price_decimal_places", "business_date",
         "data_date_kr", "data_time_kr", "base_price" })
append(ladder("ask_price", 10))
append(ladder("bid_price", 10))
append(ladder("ask_qty", 10))
append(ladder("bid_qty", 10))
append(ladder("ask_qty_chg", 10))
append(ladder("bid_qty_chg", 10))
append({ "total_ask_qty", "total_bid_qty", "total_ask_qty_chg", "total_bid_qty_chg" })

-- Split a tab-separated string into fields, stripping trailing NUL bytes from
-- each (see mas_rts_b for the version note). Also returns each field's own
-- 0-based byte range within `s` (post-NUL-strip length) so the detail pane
-- can highlight just that field's bytes instead of the whole record (see
-- add_overseas_quote).
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

-- Split a tab-separated TYPE='q' body into a record keyed by FIELD_NAMES.
-- Returns nil if field count != 72. `rec.__offsets[name] = {off, len}` gives
-- each field's own byte range within `body`.
function Q.decode(body)
  local fields, offsets = split_with_offsets(body)
  if #fields ~= #Q.FIELD_NAMES then return nil end

  local rec = { __offsets = {} }
  for k = 1, #Q.FIELD_NAMES do
    local name = Q.FIELD_NAMES[k]
    rec[name] = fields[k]
    rec.__offsets[name] = offsets[k]
  end
  return rec
end

if _G.Proto then
  -- No dedicated Proto here — `mas` is the only registered protocol (§4.7).
  -- Fields are appended to the shared mas.proto (cumulative; see PROTOCOL.md §6).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  -- Register a string field per FIELD_NAMES entry.
  local pf = {}
  for _, name in ipairs(Q.FIELD_NAMES) do
    pf[name] = ProtoField.string("mas.rts.q." .. name, name)
  end

  local fields = {}
  for _, f in pairs(pf) do fields[#fields + 1] = f end
  mas.proto.fields = fields

  local expert_badfields =
    ProtoExpert.new("mas.rts.q.expert.fields", "Unexpected overseas-quote field count",
      expert.group.MALFORMED, expert.severity.WARN)
  mas.proto.experts = { expert_badfields }

  -- Decode a TYPE='q' overseas-quote record body into the tree. The subtree
  -- is always tagged with the umbrella `mas` proto (see PROTOCOL.md §4.7) —
  -- a malformed body (wrong field count) is flagged via expert_badfields
  -- instead; "did this decode?" is a field-value question, not a
  -- presence-filter one (mirrors add_overseas_exec/add_quote).
  local function add_overseas_quote(tree, tvb, poff, r, pinfo, msg_index)
    local rec = Q.decode(r.body)
    local sub = tree:add(mas.proto, tvb(poff + r.off, 6 + r.len),
      "type: " .. Q.TYPE_OVERSEAS_QUOTE .. " (" .. r.len .. " bytes)")
    mas.rts_add_header(sub, tvb, poff, r)
    if not rec then
      sub:add_proto_expert_info(expert_badfields)
      return false
    end
    local base = poff + r.off + 6   -- body start within tvb
    for _, name in ipairs(Q.FIELD_NAMES) do
      local o = rec.__offsets[name]
      sub:add(pf[name], tvb(base + o.off, o.len), rec[name])
    end
    return true
  end

  -- Register as the TYPE='q' decoder; mas_rts.lua's generic dispatcher calls
  -- this for every TYPE='q' record and falls back to a bare "type: <TYPE>"
  -- label itself for any other TYPE.
  mas.by_rts_type[Q.TYPE_OVERSEAS_QUOTE] = { add = add_overseas_quote }
end

return Q
