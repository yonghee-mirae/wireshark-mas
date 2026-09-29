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

-- `change`(전일대비) is a **코드+수치** field, same convention as
-- mas_rts_ls.lua's `change`/mas_rts_lre.lua's `change` (field_spec.md):
-- leading char is the 1..5 전일대비구분 code, rest is the ASCII decimal
-- magnitude with no separator (e.g. "212900" = code '2'(상승) + magnitude
-- "12900"). Confirmed against all 1777 real TYPE='B' records
-- (samples/tcp_capture.cap): every record's `change` starts with a digit
-- 1..5 (0 exceptions), and `|price| - decode_coded(change)` matches
-- `|price|/(1+change_rate/100)`(기준가, derived independently from the
-- rate field) within rounding noise from change_rate's 2-decimal precision.
-- Dictionary duplicated locally per this project's per-file convention.
E.CHANGE_SIGN = { ["1"] = 1, ["2"] = 1, ["3"] = 0, ["4"] = -1, ["5"] = -1 }

-- Decode a 코드+수치 field ("212900" -> 12900 상승, "59800" -> -9800 하락).
-- Returns nil if the leading character isn't a known 전일대비구분 code or the
-- remainder isn't numeric. Same convention as mas_rts_ls.lua's S.decode_coded.
function E.decode_coded(tok)
  if not tok or #tok < 1 then return nil end
  local sign = E.CHANGE_SIGN[tok:sub(1, 1)]
  if not sign then return nil end
  local mag = tonumber(tok:sub(2))
  if not mag then return nil end
  return sign * mag
end

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

-- Split a tab-separated string into fields, stripping trailing NUL bytes from
-- each (version-agnostic: Lua 5.2+ does not treat %z as a NUL-byte pattern
-- class, that was Lua 5.1/LuaJIT-only, so a plain byte scan is used instead of
-- a gsub("%z+$", "") pattern). Also returns each field's own 0-based byte
-- range within `s` (post-NUL-strip length) so the detail pane can highlight
-- just that field's bytes instead of the whole record (see add_exec).
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
-- `rec.__offsets[name] = {off, len}` gives each field's own 0-based byte
-- range within `body`, for the detail pane's per-field highlight.
function E.decode(body)
  local fields, offsets = split_with_offsets(body)
  if #fields ~= E.FIELD_NAMES_BASE_COUNT and #fields ~= #E.FIELD_NAMES then return nil end

  local rec = { __offsets = {} }
  for k = 1, #fields do
    rec[E.FIELD_NAMES[k]] = fields[k]
    rec.__offsets[E.FIELD_NAMES[k]] = offsets[k]
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

-- 전일대비구분 code -> Korean meaning, for the (code;meaning) note on 코드+수치 fields.
E.CHANGE_LABEL = { ["1"] = "상한", ["2"] = "상승", ["3"] = "보합", ["4"] = "하한", ["5"] = "하락" }

-- 코드+수치 필드 (design/field_spec.md): returns the value without its leading
-- code plus the "code;meaning" note, e.g. "22.6700" -> "2.6700", "2;상승".
-- Returns nil for an unknown code (caller shows the raw value).
function E.split_coded(tok)
  local label = E.CHANGE_LABEL[tok:sub(1, 1)]
  if label then return tok:sub(2), tok:sub(1, 1) .. ";" .. label end
end

local CODE_VALUE_FIELDS = { change = true }

-- Spec code + detail-pane label per field, from design/field_spec.md:
-- FIELD_SPEC[name] = { filter suffix (mas.rts.B.<suffix>), label }. The wire's
-- leading key (not in the spec) is "key"; `sep` is never displayed.
E.FIELD_SPEC = {
  issue_code = { "key", "key" }, trade_time = { "034", "(034)체결시간" },
  price = { "023", "(023)현재가" }, change = { "024", "(024)전일대비" },
  change_rate = { "033", "(033)등락율" }, ask_price = { "025", "(025)매도호가" },
  bid_price = { "026", "(026)매수호가" }, trade_volume = { "032", "(032)체결량" },
  acc_volume = { "027", "(027)거래량" }, acc_value = { "028", "(028)거래대금" },
  open_price = { "029", "(029)시가" }, high_price = { "030", "(030)고가" },
  low_price = { "031", "(031)저가" }, prev_ratio = { "251", "(251)전대비율" },
  vwap = { "252", "(252)가중평균" }, per = { "355", "(355)PER" },
  lp_balance = { "273", "(273)LP잔량" }, lp_ratio = { "274", "(274)LP비율" },
  market_cap = { "299", "(299)시가총액" }, trade_strength = { "387", "(387)체결강도" },
  trade_strength_3m = { "388", "(388)3M체결강도" }, trade_strength_10m = { "270", "(270)10M체결강도" },
  trade_strength_30m = { "271", "(271)30M체결강도" }, trade_strength_60m = { "272", "(272)60M체결강도" },
  trade_strength_5d = { "266", "(266)5일평균체강" }, trade_strength_10d = { "267", "(267)10일평균체강" },
  trade_strength_20d = { "268", "(268)20일평균체강" }, trade_strength_60d = { "269", "(269)60일평균체강" },
  total_ask_qty = { "036", "(036)매도총량" }, total_bid_qty = { "039", "(039)매수총량" },
  ask_qty1 = { "241", "(241)매도량1" }, bid_qty1 = { "242", "(242)매수량1" },
  lp_balance_change = { "275", "(275)LP잔량대비" }, static_vi_upper = { "720", "(720)정적VI예상상한가" },
  static_vi_lower = { "721", "(721)정적VI예상하한가" }, trade_market = { "820", "(820)체결시장구분" },
  nxt_vi_upper = { "718", "(718)NXT VI예상상한가" }, nxt_vi_lower = { "719", "(719)NXT 정적VI예상하한가" },
}

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
      pf[name] = ProtoField.string("mas.rts.B." .. E.FIELD_SPEC[name][1], E.FIELD_SPEC[name][2])
    end
  end
  pf.market       = ProtoField.string("mas.rts.B.market", "거래소")
  pf.reversed     = ProtoField.bool("mas.rts.B.reversed", "역전")

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
    local ic_off = rec.__offsets.issue_code
    sub:add(pf.market, tvb(base + ic_off.off, ic_off.len), rec.market)   -- shown right after length, before issue_code
    for _, name in ipairs(E.FIELD_NAMES) do
      -- rec[name] is nil for the 3 NXT-only trailing fields on a 36-field
      -- (non-NXT-listed) record — must skip explicitly, not just check
      -- pf[name], or TreeItem:add() falls back to showing the raw tvbrange
      -- (the whole record body) under that field instead of omitting it.
      if pf[name] and rec[name] then
        local o = rec.__offsets[name]
        local shown, note = rec[name]
        if CODE_VALUE_FIELDS[name] then shown, note = E.split_coded(rec[name]) end
        local ti = sub:add(pf[name], tvb(base + o.off, o.len), shown or rec[name])
        if note then ti:append_text(" (" .. note .. ")") end
      end
    end
    local av_off = rec.__offsets.acc_volume

    local seq = pinfo.number * 1000 + msg_index
    local rev, prev_frame = reversal:eval(
      seq, pinfo.number, mas.stream_key(pinfo), rec.market, rec.issue_code, rec.acc_volume)
    local ti = sub:add(pf.reversed, tvb(base + av_off.off, av_off.len), rev)
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
    { field = "market",       header = "거래소",         width = 8 },
    { field = "key",          header = "key",            width = 9 },
    { field = "034",          header = "(034)체결시간",  width = 18 },
    { field = "023",          header = "(023)현재가",    width = 16 },
    { field = "032",          header = "(032)체결량",    width = 16 },
    { field = "027",          header = "(027)거래량",    width = 16 },
    { field = "reversed",     header = "역전",           width = 8,
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
