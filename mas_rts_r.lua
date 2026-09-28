-- MAS RTS TYPE='R'(대문자) 필드 레이아웃 — 해외선물옵션 호가
-- (Overseas Futures/Options Quote).
--
-- Filename note: TYPE='R' is uppercase, so it takes the plain
-- `mas_rts_r.lua` name (§8's "l-prefix" rule only applies to TYPEs that are
-- already lowercase, to avoid colliding with a future uppercase twin — that
-- collision doesn't exist here). This means lowercase TYPE='r'/'e'
-- (해외선물옵션 체결, unrelated message — see mas_rts_lre.lua) had to take
-- `mas_rts_lre.lua` instead of the plain name, since 'R' claimed it first.
--
-- One RTS-DATA record's DATA (see mas_rts.lua for RTS-HEADER framing) is a
-- 39-field tab-separated body. protocols/해외.txt's spec lists 72 fields
-- total, but every one of 274 real TYPE='R' records (symbol CLX26,
-- samples/GlobalPart_RTS.pcapng) is **exactly** 39 fields — the spec's
-- fields from 117(예상가격) onward (34 fields: 예상가격/예상대비/예상등락,
-- two 매도비/매수비 ratio groups, 순매수총잔량, 실시간상한/하한가,
-- 예상체결수량) never appear on the wire in any sample (same "spec richer
-- than wire" situation as mas_rts_lq.lua/mas_rts_lre.lua) — only the
-- verified 39-field body is implemented here, per mas_rts_b.lua's 36/39
-- precedent for an unconfirmed tail.
--
-- Identities verified 274/274 (100%, no partial mismatches):
--   ask_price == ask_price1, bid_price == bid_price1,
--   total_ask_qty == sum(ask_qty1..5), total_ask_count == sum(ask_count1..5),
--   total_bid_qty == sum(bid_qty1..5), total_bid_count == sum(bid_count1..5).
-- Ask/bid price ladders are monotonic (in magnitude) across all 5 levels in
-- every record, 0 violations.
--
-- Price-type fields (`ask_price`/`bid_price`/`ask_price1..5`/`bid_price1..5`)
-- are **sign+magnitude**, same convention as mas_rts_lre.lua/mas_rts_b.lua:
-- the leading character is a vs-기준가 flag, not the field's own math sign
-- (a real price is never negative). Displayed as-is (plain string, exact
-- wire bytes) — no derived/stripped numeric field, matching mas_rts_lre.lua.
--
-- Pure helpers (decode, required by tests) + Wireshark registration.
-- Coordinates with core via _G.mas.

local mas = _G.mas or {}
_G.mas = mas
mas.by_rts_type = mas.by_rts_type or {}

local R = {}   -- module table: pure helpers (returned for tests)

R.TYPE_OVERSEAS_FUT_QUOTE = "R"   -- the only RTS TYPE this module decodes

-- Build a "<prefix><1..n>" name list (see mas_rts_c.lua/mas_rts_lq.lua for
-- the same helper).
local function ladder(prefix, n)
  local t = {}
  for i = 1, n do t[i] = prefix .. i end
  return t
end

-- Field order (0-based index 0..38), for RTS TYPE='R' (Overseas
-- Futures/Options Quote).
R.FIELD_NAMES = {}
local function append(t) for _, v in ipairs(t) do R.FIELD_NAMES[#R.FIELD_NAMES + 1] = v end end
append({ "key", "type_echo", "quote_time", "ask_price", "bid_price" })
append(ladder("ask_price", 5))
append(ladder("ask_qty", 5))
append(ladder("ask_count", 5))
append(ladder("bid_price", 5))
append(ladder("bid_qty", 5))
append(ladder("bid_count", 5))
append({ "total_ask_qty", "total_ask_count", "total_bid_qty", "total_bid_count" })

-- Split a tab-separated string into fields, stripping trailing NUL bytes from
-- each (see mas_rts_b for the version note). Also returns each field's own
-- 0-based byte range within `s` (post-NUL-strip length) so the detail pane
-- can highlight just that field's bytes instead of the whole record.
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

-- Split a tab-separated TYPE='R' body into a record keyed by FIELD_NAMES.
-- Returns nil if field count != 39. `rec.__offsets[name] = {off, len}` gives
-- each field's own byte range within `body`.
function R.decode(body)
  local fields, offsets = split_with_offsets(body)
  if #fields ~= #R.FIELD_NAMES then return nil end

  local rec = { __offsets = {} }
  for k = 1, #R.FIELD_NAMES do
    local name = R.FIELD_NAMES[k]
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
  for _, name in ipairs(R.FIELD_NAMES) do
    pf[name] = ProtoField.string("mas.rts.R." .. name, name)
  end

  local fields = {}
  for _, f in pairs(pf) do fields[#fields + 1] = f end
  mas.proto.fields = fields

  local expert_badfields =
    ProtoExpert.new("mas.rts.R.expert.fields", "Unexpected overseas-futures-quote field count",
      expert.group.MALFORMED, expert.severity.WARN)
  mas.proto.experts = { expert_badfields }

  -- Decode a TYPE='R' overseas-futures/options-quote record body into the
  -- tree. The subtree is always tagged with the umbrella `mas` proto (see
  -- PROTOCOL.md §4.7) — a malformed body (wrong field count) is flagged via
  -- expert_badfields instead; "did this decode?" is a field-value question,
  -- not a presence-filter one (mirrors add_overseas_quote).
  local function add_overseas_fut_quote(tree, tvb, poff, r, pinfo, msg_index)
    local rec = R.decode(r.body)
    local sub = tree:add(mas.proto, tvb(poff + r.off, 6 + r.len),
      "type: " .. R.TYPE_OVERSEAS_FUT_QUOTE .. " (" .. r.len .. " bytes)")
    mas.rts_add_header(sub, tvb, poff, r)
    if not rec then
      sub:add_proto_expert_info(expert_badfields)
      return false
    end
    local base = poff + r.off + 6   -- body start within tvb
    for _, name in ipairs(R.FIELD_NAMES) do
      local o = rec.__offsets[name]
      sub:add(pf[name], tvb(base + o.off, o.len), rec[name])
    end
    return true
  end

  -- Register as the TYPE='R' decoder; mas_rts.lua's generic dispatcher calls
  -- this for every TYPE='R' record and falls back to a bare "type: <TYPE>"
  -- label itself for any other TYPE.
  mas.by_rts_type[R.TYPE_OVERSEAS_FUT_QUOTE] = { add = add_overseas_fut_quote }
end

return R
