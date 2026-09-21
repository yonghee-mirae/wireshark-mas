-- MAS Transaction MSGK=0x90 (UMP, 실시간주문체결통보 / Order Report) decoder.
--
-- TR-DATA for MSGK=0x90 (see mas_tr.lua for AXIS-HEADER framing) is a
-- variable, self-describing EUC-KR code/value stream (code\tvalue\t...), each
-- field identified by a numeric code (see ORDER_FIELDS). This is the only
-- Transaction MSGK this plugin decodes; every other MSGK is left to
-- mas_tr.lua's generic "msgk: <name> (0x<hex>)"-only handling.
--
-- Pure helpers (decode_order + dictionary, required by tests) + Wireshark
-- registration + the MAS/UMP Statistics window. Coordinates via _G.mas.

local mas = _G.mas or {}
_G.mas = mas
mas.by_msgk = mas.by_msgk or {}

local O = {}   -- module table: pure helpers (returned for tests)

O.MSGK_ORDER = 0x90   -- UMP: the only MSGK this module decodes

-- Strip trailing NUL bytes (see mas_rts_b for the version note).
local function rstrip_nul(s)
  local e = #s
  while e > 0 and s:byte(e) == 0 do e = e - 1 end
  return s:sub(1, e)
end

-- Order code dictionary, in layout order: { code, english name }. The body is a
-- self-describing, variable stream of code/value pairs, so a field is identified
-- by its numeric code (not by position as in the execution record). Duplicate
-- labels are disambiguated by the code appended in the display name.
O.ORDER_FIELDS = {
  { "950", "account_no" },              { "975", "branch_no" },
  { "953", "issue_short_code" },        { "954", "order_notice_title" },
  { "955", "title_end_flag" },          { "956", "issue_name" },
  { "980", "buy_sell_fill_type" },      { "960", "buy_sell_type" },
  { "963", "trade_type" },              { "981", "order_condition" },
  { "973", "process_type" },            { "983", "process_type" },
  { "977", "process_type" },            { "987", "order_type" },
  { "995", "short_sell_flag" },         { "479", "board_id" },
  { "370", "loan_rate" },               { "635", "base_price" },
  { "903", "credit_type" },             { "929", "credit_type_text" },
  { "902", "credit_loan_date" },        { "951", "order_method (exchange)" },
  { "988", "rebalancing_exchange_amend_flag" }, { "982", "auto_cancel_type" },
  { "994", "credit_loan_order_type" }, { "952", "order_no" },
  { "961", "original_order_no" },       { "957", "order_qty" },
  { "958", "order_price" },             { "978", "total_filled_qty" },
  { "964", "total_filled_amount" },     { "959", "total_unfilled_qty" },
  { "984", "total_cancelled_qty" },     { "989", "total_rejected_qty" },
  { "985", "stop_price" },              { "986", "stop_status" },
  { "966", "fill_serial_no" },          { "965", "fill_time" },
  { "962", "exchange_type" },           { "969", "order_no" },
  { "970", "original_order_no" },       { "967", "fill_price" },
  { "968", "fill_qty" },                { "974", "unfilled_qty" },
  { "971", "rejected_qty" },            { "972", "cancelled_qty" },
}

-- code -> english name lookup, built from ORDER_FIELDS.
O.ORDER_NAMES = {}
for _, f in ipairs(O.ORDER_FIELDS) do O.ORDER_NAMES[f[1]] = f[2] end

-- Decode an order-report TR-DATA body into an ordered list of { code, name, value }.
-- The body is a tab-separated, alternating code/value stream (each pair followed
-- by its own tab, so a trailing NUL/empty token after the last pair is normal and
-- ignored); codes are variable and self-describing. `name` is nil for a code
-- outside the dictionary.
function O.decode_order(body)
  local toks, start = {}, 1
  while true do
    local sep = body:find("\t", start, true)
    if sep then
      toks[#toks + 1] = body:sub(start, sep - 1)
      start = sep + 1
    else
      toks[#toks + 1] = body:sub(start)
      break
    end
  end
  local rec = {}
  for k = 1, #toks - 1, 2 do
    local code = toks[k]
    rec[#rec + 1] = { code = code, name = O.ORDER_NAMES[code],
                      value = rstrip_nul(toks[k + 1]) }
  end
  return rec
end

if _G.Proto then
  -- No dedicated Proto here — `mas` is the only registered protocol (§4.7).
  -- Fields are appended to the shared mas.proto (cumulative; see PROTOCOL.md §6).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  -- One string field per dictionary code (filter mas.tr.90.<code>, display
  -- "<english name> (<code>)"). Codes are variable per message; an unknown code
  -- falls back to mas.tr.90.unknown. AXIS-HEADER fields live in mas_tr.lua
  -- (mas.tr.*), shared across every Transaction MSGK decoder.
  local pf = { unknown = ProtoField.string("mas.tr.90.unknown", "unknown_code") }
  local fields = { pf.unknown }
  for _, f in ipairs(O.ORDER_FIELDS) do
    local code, name = f[1], f[2]
    pf[code] = ProtoField.string("mas.tr.90." .. code, name .. " (" .. code .. ")")
    fields[#fields + 1] = pf[code]
  end
  mas.proto.fields = fields

  -- Decode TR-DATA (poff/plen = the whole Transaction payload, AXIS-HEADER
  -- included, matching what mas_tr.lua's dispatcher already has) into
  -- `sub`. Values are EUC-KR, so the body is transcoded to UTF-8 before
  -- splitting; tab (0x09) never occurs inside a multibyte sequence, so the split
  -- stays correct. (Requires a Wireshark build with EUC-KR string support.)
  -- Registered into mas.by_msgk[O.MSGK_ORDER] below; called by
  -- mas_tr.lua's generic Transaction dispatcher.
  local function add_order_body(sub, tvb, poff, plen, pinfo)
    local doff, dlen = poff + 24, plen - 24
    local utf8 = (dlen > 0) and tvb(doff, dlen):string(ENC_EUC_KR) or ""
    for _, p in ipairs(O.decode_order(utf8)) do
      local f = pf[p.code]
      if f then
        sub:add(f, tvb(poff, plen), p.value)
      else
        sub:add(pf.unknown, tvb(poff, plen), p.code .. "=" .. p.value)
      end
    end
  end

  -- Register as the MSGK=0x90 (UMP) decoder; mas_tr.lua's generic
  -- dispatcher calls this for every unencrypted MSGK=0x90 message and falls
  -- back to a bare "msgk: <name> (0x<hex>)" label itself for any other MSGK
  -- (or if encrypted).
  mas.by_msgk[O.MSGK_ORDER] = { add = add_order_body }
end

if gui_enabled() then
  -- Order window: lists messages per 5-tuple. A code missing from a given
  -- message renders as a blank cell (open_stream_window already does this via
  -- `(v == nil) and "" or tostring(v)`) — columns need not all be present. If a
  -- frame carries several order reports and they don't all carry the same
  -- codes, per-column occurrence lists can still misalign across those messages
  -- (a documented limitation of the shared zip-by-index Statistics window).
  local ORDER_COLUMNS = {
    { field = "950", header = "Account No (950)",      width = 18 },
    { field = "952", header = "Order No (952)",         width = 14 },
    { field = "975", header = "Branch No (975)",        width = 12 },
    { field = "969", header = "Order No (969)",         width = 14 },
    { field = "951", header = "Order Method (951)",     width = 14 },
    { field = "953", header = "Issue Code (953)",       width = 12 },
    { field = "977", header = "Process Type (977)",     width = 18 },
    { field = "957", header = "Order Qty (957)",        width = 10 },
    { field = "958", header = "Order Price (958)",      width = 12 },
  }
  local extractors = {}
  for i, c in ipairs(ORDER_COLUMNS) do extractors[i] = Field.new("mas.tr.90." .. c.field) end

  register_menu("MAS/UMP", function()
    -- Tap filter is field-value-based (see PROTOCOL.md §4.7): `mas.tr.90` is no
    -- longer tagged on any subtree, so this reproduces `will_decode` (MSGK=0x90,
    -- unencrypted) directly from the always-present AXIS-HEADER fields instead.
    mas.open_stream_window("MAS - UMP", "mas.tr.msgk == 0x90 && !mas.tr.encrypted",
      ORDER_COLUMNS, extractors)
  end, MENU_STAT_UNSORTED)
end

return O
