-- MAS RTS (실시간시세, G/W SESS=0x08) stream module.
--
-- RTS payload (the G/W frame's LENGTH-bytes body) is a repeated RTS-DATA record:
--   KIND(1) DUMY(1) TYPE(1) LENGTH(3 ASCII) DATA(LENGTH, trailing NUL included)
-- KIND: 'D' data / 'I' symbol list. TYPE selects the record layout; of these, only
-- TYPE='B' (체결, Execution Price, 39 tab-separated fields) is decoded here — the
-- only inner protocol this plugin supports besides order report. Every other TYPE
-- is shown as raw data, with KIND/TYPE/LENGTH displayed from the RTS-HEADER.
--
-- Pure helpers (decode/reversal, required by tests) + Wireshark registration +
-- the MAS/Execution Statistics window. Coordinates with core via _G.mas.

local mas = _G.mas or {}
_G.mas = mas
mas.by_sess = mas.by_sess or {}

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

-- Split a tab-separated TYPE='B' body into a record keyed by FIELD_NAMES. Returns
-- nil if field count != 39. Trailing NULs are stripped; issue_code -> (market, base).
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
  if #fields ~= #E.FIELD_NAMES then return nil end

  local rec = {}
  for k = 1, #E.FIELD_NAMES do
    rec[E.FIELD_NAMES[k]] = rstrip_nul(fields[k])
  end
  rec.market, rec.issue_code = E.split_market(rec.issue_code)
  return rec
end

-- Split an RTS payload into RTS-DATA records: { {kind,dumy,type,len,body,off}, ... }.
-- `off` is the 0-based offset of the record within the payload. Stops (without
-- error) at the first malformed record; callers show the remainder as raw data.
function E.split_records(payload)
  local recs = {}
  local i, n = 0, #payload
  while i + 6 <= n do
    local ls = payload:sub(i + 4, i + 6)
    if not ls:match("^%d%d%d$") then break end
    local L = tonumber(ls)
    if i + 6 + L > n then break end
    recs[#recs + 1] = {
      kind = payload:sub(i + 1, i + 1), dumy = payload:sub(i + 2, i + 2),
      type = payload:sub(i + 3, i + 3), len = L,
      body = payload:sub(i + 7, i + 6 + L), off = i,
    }
    i = i + 6 + L
  end
  return recs, i   -- i = bytes consumed; payload:sub(i+1) is any unparsed tail
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
  local proto_ex = Proto("mas.ep", "MAS Execution Price")   -- filter: mas.ep

  -- RTS-HEADER fields (common to every RTS-DATA record).
  local pf_h = {
    kind = ProtoField.string("mas.ep.kind", "kind"),
    type = ProtoField.string("mas.ep.type", "type"),
    len  = ProtoField.uint32("mas.ep.reclen", "length"),
  }

  -- Register 39 string fields as mas.ep.<key> (sep omitted), plus derived fields.
  local pf = { kind = pf_h.kind, type = pf_h.type, reclen = pf_h.len }
  for _, name in ipairs(E.FIELD_NAMES) do
    if name ~= "sep" then  -- separator field: kept in FIELD_NAMES for decode, not displayed
      pf[name] = ProtoField.string("mas.ep." .. name, name)
    end
  end
  pf.market       = ProtoField.string("mas.ep.market", "market")
  pf.acc_volume_num   = ProtoField.int64("mas.ep.acc_volume_num", "acc_volume(int)")
  pf.price_num        = ProtoField.int64("mas.ep.price_num", "price(int)")
  pf.trade_volume_num = ProtoField.int64("mas.ep.trade_volume_num", "trade_volume(int)")
  pf.reversed     = ProtoField.bool("mas.ep.reversed", "reversed")

  local fields = {}
  for _, f in pairs(pf) do fields[#fields + 1] = f end
  proto_ex.fields = fields

  local expert_badfields =
    ProtoExpert.new("mas.ep.expert.fields", "Unexpected execution field count",
      expert.group.MALFORMED, expert.severity.WARN)
  proto_ex.experts = { expert_badfields }

  local reversal = E.new_reversal()

  -- Add one RTS-DATA record's header fields (KIND/TYPE/LENGTH) under `sub`.
  local function add_record_header(sub, tvb, poff, r)
    sub:add(pf.kind, tvb(poff + r.off, 1))
    sub:add(pf.type, tvb(poff + r.off + 2, 1))
    sub:add(pf.reclen, tvb(poff + r.off + 3, 3), r.len)
  end

  -- Decode a TYPE='B' execution record body into the tree, incl. reversal detection.
  -- Decode first so the subtree's own protocol is proto_ex (mas.ep) ONLY on success;
  -- a malformed TYPE='B' body (wrong field count) is tagged with the umbrella `mas`
  -- instead, so the mas.ep presence filter means "a real execution record here".
  local function add_exec(tree, tvb, poff, r, pinfo, msg_index)
    local rec = E.decode(r.body)
    local sub = tree:add(rec and proto_ex or mas.proto, tvb(poff + r.off, 6 + r.len),
      "Execution Price (" .. r.len .. " bytes)")
    add_record_header(sub, tvb, poff, r)
    if not rec then
      sub:add_proto_expert_info(expert_badfields)
      return false
    end
    local base = poff + r.off + 6   -- body start within tvb
    for _, name in ipairs(E.FIELD_NAMES) do
      if pf[name] then sub:add(pf[name], tvb(base, r.len), rec[name]) end
    end
    sub:add(pf.market, tvb(base, r.len), rec.market)
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

  -- SESS=0x08 (RTS) handler: split the payload into RTS-DATA records; decode
  -- TYPE='B' as execution, everything else (other TYPE, unparsed tail) as data
  -- with its RTS-HEADER fields still shown. Returns the number of RTS-DATA
  -- records contained (Execution Price and Unspecified RTS both count) — a
  -- single RTS G/W frame's payload is a repeated RTS-HEADER+RTS-DATA, so this
  -- is what mas.lua's Info column reports for "RTS:n", not a flat 1-per-frame.
  local function add_rts(gw, tvb, poff, plen, payload, pinfo)
    local recs, consumed = E.split_records(payload)
    for idx, r in ipairs(recs) do
      if r.type == E.TYPE_EXEC then
        add_exec(gw, tvb, poff, r, pinfo, idx)
      else
        -- Not TYPE='B': tag with the umbrella `mas`, not proto_ex, so mas.ep stays
        -- a "genuine execution record here" presence filter.
        local sub = gw:add(mas.proto, tvb(poff + r.off, 6 + r.len),
          "Unspecified RTS (" .. r.len .. " bytes)")
        add_record_header(sub, tvb, poff, r)
        if r.len > 0 then sub:add(mas.pf_data, tvb(poff + r.off + 6, r.len)) end
      end
    end
    if consumed < plen then gw:add(mas.pf_data, tvb(poff + consumed, plen - consumed)) end
    return #recs
  end

  mas.by_sess[mas.SESS_RTS] = { add = add_rts, init = function() reversal:reset() end }
end

if gui_enabled() then
  -- Column spec: { field = mas.ep field suffix, header, width, map = optional formatter }.
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
  for i, c in ipairs(EXEC_COLUMNS) do extractors[i] = Field.new("mas.ep." .. c.field) end

  register_menu("MAS/Execution", function()
    mas.open_stream_window("MAS - Execution", "mas.ep", EXEC_COLUMNS, extractors)
  end, MENU_STAT_UNSORTED)
end

return E
