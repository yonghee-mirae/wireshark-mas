-- MAS RTS TYPE='B' (체결, Execution Price) decoder.
--
-- One RTS-DATA record's DATA (see mas_rts.lua for RTS-HEADER framing) is a
-- 39-field tab-separated body. This is the only RTS TYPE this plugin decodes;
-- every other TYPE is left to mas_rts.lua's generic "type: <TYPE>"-only handling.
--
-- Pure helpers (decode/reversal, required by tests) + Wireshark registration +
-- the MAS/Execution Prices Statistics window. Coordinates with core via _G.mas.

local mas = _G.mas or {}
_G.mas = mas
mas.by_rts_type = mas.by_rts_type or {}

local E = {}   -- module table: pure helpers (returned for tests)

E.TYPE_EXEC = "B"   -- the only RTS TYPE this module decodes

-- issue_code prefix -> market. No dot means KRX(K).
local MARKET = { M = "M", N = "N" }

-- "M.A035420" -> ("M","A035420"); "A009150" -> ("K","A009150").
function E.split_market(issue_code)
  local prefix, base = issue_code:match("^([^.]*)%.(.*)$")
  if base then
    return MARKET[prefix] or prefix, base
  end
  return "K", issue_code
end

-- schema.py FIELDS order (index 0..38), for RTS TYPE='B' (Execution Price).
E.FIELD_NAMES = {
  "issue_code", "sep", "trade_time", "price", "change", "change_rate",
  "ask_price", "bid_price", "trade_volume", "acc_volume", "acc_value",
  "open_price", "high_price", "low_price", "prev_ratio", "vwap", "per",
  "lp_balance", "lp_ratio", "market_cap", "trade_strength",
  "trade_strength_3m", "trade_strength_10m", "trade_strength_30m",
  "trade_strength_60m", "trade_strength_5d", "trade_strength_10d",
  "trade_strength_20d", "trade_strength_60d", "total_ask_qty",
  "total_bid_qty", "ask_qty1", "bid_qty1", "lp_balance_change",
  "static_vi_upper", "static_vi_lower", "trade_market", "nxt_vi_upper",
  "nxt_vi_lower",
}

-- Strip trailing NUL bytes. Version-agnostic: Lua 5.2+ does not treat %z as a
-- NUL-byte pattern class (that was Lua 5.1/LuaJIT-only), so a plain byte scan is
-- used instead of a gsub("%z+$", "") pattern.
local function rstrip_nul(s)
  local e = #s
  while e > 0 and s:byte(e) == 0 do e = e - 1 end
  return s:sub(1, e)
end

-- The last 3 fields (trade_market, nxt_vi_upper, nxt_vi_lower) are NXT-only:
-- confirmed against samples/tcp_capture.cap (port 8961, 1,777 TYPE='B'
-- records) that every record whose issue_code has no market prefix (plain
-- KRX-only issue, not NXT-cross-listed) is exactly 36 fields — those 3
-- trailing fields are omitted entirely, not blank/zero-filled — while every
-- "M."/"N."-prefixed (NXT-cross-listed) issue is exactly 39 fields, with no
-- exceptions across 1,777 records. Earlier samples (20260915_0809_RTS*.pcapng,
-- 20260921_nana.pcapng) never exposed this because every TYPE='B' record in
-- them happened to be NXT-cross-listed (39 fields), so the decoder only
-- required exactly 39 until this was found.
E.FIELD_NAMES_BASE_COUNT = 36

-- Split a tab-separated TYPE='B' body into a record keyed by FIELD_NAMES.
-- Returns nil if field count isn't 36 or 39 (see above). Trailing NULs are
-- stripped; issue_code -> (market, base). With 36 fields, the 3 NXT-only
-- keys are simply absent from `rec` (nil), not empty strings.
function E.decode(body)
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
  if #fields ~= E.FIELD_NAMES_BASE_COUNT and #fields ~= #E.FIELD_NAMES then return nil end

  local rec = {}
  for k = 1, #fields do
    rec[E.FIELD_NAMES[k]] = rstrip_nul(fields[k])
  end
  rec.market, rec.issue_code = E.split_market(rec.issue_code)
  return rec
end

-- Stateful reversal detector. eval() is idempotent per seq_index so that
-- Wireshark's multi-pass dissection yields stable results. Grouping is scoped
-- to (flow, market, issue_code) so analysis only compares messages sharing the
-- same 5-tuple. Returns (reversed, prev_frame): when reversed, prev_frame is
-- the frame number of the group's preceding (higher acc_volume) message.
function E.new_reversal()
  local self = { last = {}, last_frame = {}, cache = {} }

  function self:eval(seq_index, frame, flow, market, issue_code, acc_str)
    local c = self.cache[seq_index]
    if c ~= nil then return c.rev, c.prev or nil end
    local key = flow .. "\0" .. market .. "\0" .. issue_code
    local acc = tonumber(acc_str)
    local prev = self.last[key]
    local rev = (prev ~= nil and acc ~= nil and acc < prev) or false
    local prev_frame = rev and self.last_frame[key] or nil
    if acc ~= nil then
      self.last[key] = acc
      self.last_frame[key] = frame
    end
    self.cache[seq_index] = { rev = rev, prev = prev_frame or false }
    return rev, prev_frame
  end

  function self:reset()
    self.last = {}; self.last_frame = {}; self.cache = {}
  end

  return self
end

if _G.Proto then
  -- No dedicated Proto here — `mas` is the only registered protocol (§4.7).
  -- Fields are appended to the shared mas.proto (cumulative; see PROTOCOL.md §6).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  -- Register 39 string fields as mas.rts.B.<key> (sep omitted), plus derived fields.
  -- RTS-HEADER (KIND/TYPE/LENGTH) fields live in mas_rts.lua (mas.rts.*), shared
  -- across every RTS TYPE decoder.
  local pf = {}
  for _, name in ipairs(E.FIELD_NAMES) do
    if name ~= "sep" then  -- separator field: kept in FIELD_NAMES for decode, not displayed
      pf[name] = ProtoField.string("mas.rts.B." .. name, name)
    end
  end
  pf.market       = ProtoField.string("mas.rts.B.market", "market")
  pf.acc_volume_num   = ProtoField.int64("mas.rts.B.acc_volume_num", "acc_volume(int)")
  pf.price_num        = ProtoField.int64("mas.rts.B.price_num", "price(int)")
  pf.trade_volume_num = ProtoField.int64("mas.rts.B.trade_volume_num", "trade_volume(int)")
  pf.reversed     = ProtoField.bool("mas.rts.B.reversed", "reversed")

  local fields = {}
  for _, f in pairs(pf) do fields[#fields + 1] = f end
  mas.proto.fields = fields

  local expert_badfields =
    ProtoExpert.new("mas.rts.B.expert.fields", "Unexpected execution field count",
      expert.group.MALFORMED, expert.severity.WARN)
  mas.proto.experts = { expert_badfields }

  local reversal = E.new_reversal()

  -- Decode a TYPE='B' execution record body into the tree, incl. reversal detection.
  -- The subtree is always tagged with the umbrella `mas` proto (see PROTOCOL.md
  -- §4.7) — a malformed TYPE='B' body (wrong field count) is flagged via
  -- expert_badfields instead; "did this decode?" is a field-value question
  -- (e.g. bare `mas.rts.B.price`), not a presence-filter one.
  -- Registered into mas.by_rts_type[E.TYPE_EXEC] below; called by mas_rts.lua's
  -- generic RTS dispatcher with the signature it expects.
  local function add_exec(tree, tvb, poff, r, pinfo, msg_index)
    local rec = E.decode(r.body)
    local sub = tree:add(mas.proto, tvb(poff + r.off, 6 + r.len),
      "type: " .. E.TYPE_EXEC .. " (" .. r.len .. " bytes)")
    mas.rts_add_header(sub, tvb, poff, r)
    if not rec then
      sub:add_proto_expert_info(expert_badfields)
      return false
    end
    local base = poff + r.off + 6   -- body start within tvb
    sub:add(pf.market, tvb(base, r.len), rec.market)   -- shown right after length, before issue_code
    for _, name in ipairs(E.FIELD_NAMES) do
      -- rec[name] is nil for the 3 NXT-only trailing fields on a 36-field
      -- (non-NXT-listed) record — must skip explicitly, not just check
      -- pf[name], or TreeItem:add() falls back to showing the raw tvbrange
      -- (the whole record body) under that field instead of omitting it.
      if pf[name] and rec[name] then sub:add(pf[name], tvb(base, r.len), rec[name]) end
    end
    local an = tonumber(rec.acc_volume);   if an then sub:add(pf.acc_volume_num, tvb(base, r.len), Int64(an)) end
    local pn = tonumber(rec.price);        if pn then sub:add(pf.price_num, tvb(base, r.len), Int64(pn)) end
    local tn = tonumber(rec.trade_volume); if tn then sub:add(pf.trade_volume_num, tvb(base, r.len), Int64(tn)) end

    local seq = pinfo.number * 1000 + msg_index
    local rev, prev_frame = reversal:eval(
      seq, pinfo.number, mas.stream_key(pinfo), rec.market, rec.issue_code, rec.acc_volume)
    local ti = sub:add(pf.reversed, tvb(base, r.len), rev)
    if rev and prev_frame then ti:append_text(string.format(" (#%d)", prev_frame)) end
    return true
  end

  -- Register as the TYPE='B' decoder; mas_rts.lua's generic dispatcher calls
  -- this for every TYPE='B' record and falls back to a bare "type: <TYPE>"
  -- label itself for any other TYPE.
  mas.by_rts_type[E.TYPE_EXEC] = { add = add_exec, init = function() reversal:reset() end }
end

if gui_enabled() then
  -- Column spec: { field = mas.rts.B field suffix, header, width, map = optional formatter }.
  local EXEC_COLUMNS = {
    { field = "market",       header = "Market",   width = 6 },
    { field = "issue_code",   header = "Issue",    width = 9 },
    { field = "trade_time",   header = "Time",     width = 8 },
    { field = "price",        header = "Price",    width = 10 },
    { field = "trade_volume", header = "TrdVol",   width = 8 },
    { field = "acc_volume",   header = "AccVol",   width = 10 },
    { field = "reversed",     header = "Reversed", width = 8,
      map = function(v) return v and "Y" or "" end },
  }
  local extractors = {}
  for i, c in ipairs(EXEC_COLUMNS) do extractors[i] = Field.new("mas.rts.B." .. c.field) end

  register_menu("MAS/Execution Prices", function()
    -- Tap filter is field-value-based (see PROTOCOL.md §4.7): `mas.rts.B` is no
    -- longer tagged on any subtree, but `mas.rts.B.market` is always added
    -- whenever a TYPE='B' body actually decoded, so it's an equivalent
    -- "decode succeeded" presence check.
    mas.open_stream_window("MAS - Execution Prices", "mas.rts.B.market", EXEC_COLUMNS, extractors)
  end, MENU_STAT_UNSORTED)
end

return E
