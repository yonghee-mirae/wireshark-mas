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

-- Split a tab-separated string into tokens, stripping trailing NUL bytes from
-- each (see mas_rts_b for the version note). Also returns each token's own
-- 0-based byte range within `s` (post-NUL-strip length), so the detail pane
-- can highlight just that token's bytes (see add_order_body).
local function split_with_offsets(s)
  local toks, offsets = {}, {}
  local start = 1
  while true do
    local sep = s:find("\t", start, true)
    local e = sep and (sep - 1) or #s
    local raw = s:sub(start, e)
    local se = #raw
    while se > 0 and raw:byte(se) == 0 do se = se - 1 end
    toks[#toks + 1] = raw:sub(1, se)
    offsets[#offsets + 1] = { off = start - 1, len = se }
    if not sep then break end
    start = sep + 1
  end
  return toks, offsets
end

-- Order code dictionary, in layout order: { code, Korean name } (names copied
-- verbatim from design/field_spec.md). The body is a
-- self-describing, variable stream of code/value pairs, so a field is identified
-- by its numeric code (not by position as in the execution record). Duplicate
-- labels are disambiguated by the code appended in the display name.
O.ORDER_FIELDS = {
  { "950", "계좌번호" },  { "975", "지점번호" },
  { "953", "종목단축코드" },  { "954", "주문통보TITLE" },
  { "955", "TITLE END FLAG" },  { "956", "종목명" },
  { "980", "매수/매도 체결구분" },  { "960", "매수매도 구분" },
  { "963", "매매구분" },  { "981", "주문조건" },
  { "973", "처리구분" },  { "983", "처리구분" },
  { "977", "처리구분" },  { "987", "주문구분" },
  { "995", "공매도여부" },  { "479", "보드ID" },
  { "370", "대출율" },  { "635", "기준가" },
  { "903", "신용구분" },  { "929", "신용구분TEXT" },
  { "902", "신용대출일" },  { "951", "주문방법(거래소)" },
  { "988", "리밸런싱여부/거래소정정여부" },  { "982", "자동취소구분값" },
  { "994", "신용주문구분" },  { "952", "주문번호" },
  { "961", "원주문번호" },  { "957", "주문수량" },
  { "958", "주문가격" },  { "978", "체결수량 합계" },
  { "964", "체결금액 합계" },  { "959", "미체결수량 합계" },
  { "984", "취소수량 합계" },  { "989", "거부수량 합계" },
  { "985", "스탑가격" },  { "986", "스탑상태" },
  { "966", "체결일련번호" },  { "965", "체결시간" },
  { "962", "거래소구분" },  { "969", "주문번호" },
  { "970", "원주문번호" },  { "967", "체결가격" },
  { "968", "체결수량" },  { "974", "미체결수량" },
  { "971", "거부수량" },  { "972", "취소수량" },
}

-- code -> Korean name lookup, built from ORDER_FIELDS.
O.ORDER_NAMES = {}
for _, f in ipairs(O.ORDER_FIELDS) do O.ORDER_NAMES[f[1]] = f[2] end

-- Decode an order-report TR-DATA body into an ordered list of
-- { code, name, value, code_off, value_off }. The body is a tab-separated,
-- alternating code/value stream (each pair followed by its own tab, so a
-- trailing NUL/empty token after the last pair is normal and ignored); codes
-- are variable and self-describing. `name` is nil for a code outside the
-- dictionary.
--
-- `body` is the (possibly EUC-KR->UTF-8 transcoded, see add_order_body) text
-- used for VALUES. `raw_body`, if given, is the untranscoded wire bytes, used
-- only to compute `code_off`/`value_off` (each token's byte range within the
-- tvb) for the detail pane's per-field highlight — tab (0x09) never occurs
-- inside a multibyte EUC-KR/UTF-8 sequence, so both splits have the same
-- token count/order, but the transcoded text's own byte offsets don't match
-- the tvb's raw bytes once a multibyte value changes length (same reasoning
-- as mas_rts_f.lua's F.decode).
function O.decode_order(body, raw_body)
  local toks, offsets = split_with_offsets(body)
  if raw_body then
    local raw_toks, raw_offsets = split_with_offsets(raw_body)
    if #raw_toks == #toks then offsets = raw_offsets end
  end
  local rec = {}
  for k = 1, #toks - 1, 2 do
    local code = toks[k]
    rec[#rec + 1] = { code = code, name = O.ORDER_NAMES[code], value = toks[k + 1],
                      code_off = offsets[k], value_off = offsets[k + 1] }
  end
  return rec
end

if _G.Proto then
  -- No dedicated Proto here — `mas` is the only registered protocol (§4.7).
  -- Fields are appended to the shared mas.proto (cumulative; see PROTOCOL.md §6).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  -- One string field per dictionary code (filter mas.tr.90.<code>, display
  -- "(<code>)<Korean name>"). Codes are variable per message; an unknown code
  -- falls back to mas.tr.90.unknown. AXIS-HEADER fields live in mas_tr.lua
  -- (mas.tr.*), shared across every Transaction MSGK decoder.
  local pf = { unknown = ProtoField.string("mas.tr.90.unknown", "unknown_code") }
  local fields = { pf.unknown }
  for _, f in ipairs(O.ORDER_FIELDS) do
    local code, name = f[1], f[2]
    pf[code] = ProtoField.string("mas.tr.90." .. code, "(" .. code .. ")" .. name)
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
    local raw = (dlen > 0) and tvb(doff, dlen):raw() or ""
    local utf8 = (dlen > 0) and tvb(doff, dlen):string(ENC_EUC_KR) or ""
    for _, p in ipairs(O.decode_order(utf8, raw)) do
      local f = pf[p.code]
      if f then
        local o = p.value_off
        sub:add(f, tvb(doff + o.off, o.len), p.value)
      else
        local co, vo = p.code_off, p.value_off
        sub:add(pf.unknown, tvb(doff + co.off, (vo.off + vo.len) - co.off), p.code .. "=" .. p.value)
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
    { field = "950", header = "(950)계좌번호",      width = 18 },
    { field = "952", header = "(952)주문번호",      width = 14 },
    { field = "975", header = "(975)지점번호",      width = 12 },
    { field = "969", header = "(969)주문번호",      width = 14 },
    { field = "951", header = "(951)주문방법(거래소)", width = 20 },
    { field = "953", header = "(953)종목단축코드",  width = 16 },
    { field = "977", header = "(977)처리구분",      width = 14 },
    { field = "957", header = "(957)주문수량",      width = 12 },
    { field = "958", header = "(958)주문가격",      width = 12 },
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
