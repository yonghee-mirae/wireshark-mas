-- MAS RTS TYPE='K' (선물 체결 (Futures Execution)) decoder.
--
-- One RTS-DATA record's DATA (see mas_rts.lua for RTS-HEADER framing) is a 37-field
-- tab-separated body: key, the hidden record-type marker (000), then the spec
-- fields (design/field_spec.md).
-- Field layout confirmed against samples/tcp_capture.cap (88 records).
--
-- Pure helpers (decode, required by tests) + Wireshark registration.
-- Coordinates with core via _G.mas.

local mas = _G.mas or {}
_G.mas = mas
mas.by_rts_type = mas.by_rts_type or {}

local K = {}   -- module table: pure helpers (returned for tests)

K.TYPE_K = "K"   -- the only RTS TYPE this module decodes

-- Field order (0-based index 0..36).
K.FIELD_NAMES = {
  "key", "type_echo", "trade_time", "price", "change",
  "change_rate", "ask_price", "bid_price", "trade_volume", "acc_volume",
  "acc_value", "open_price", "high_price", "low_price", "open_interest",
  "theory_price", "theory_basis", "market_basis", "disparity_rate", "open_interest_diff",
  "disparity", "ask_trade_volume", "bid_trade_volume", "trade_strength_3m", "ask_trade_sum",
  "bid_trade_sum", "trade_strength", "open_interest_chg", "prev_day_volume_ratio", "kospi200",
  "futures_latest_price", "theory_diff", "rt_upper_limit", "rt_lower_limit", "block_acc_volume",
  "upper_step_width", "lower_step_width",
}

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

-- Split a tab-separated TYPE='K' body into a record keyed by FIELD_NAMES.
-- Returns nil if field count != 37. `rec.__offsets[name] = {off, len}` gives each
-- field's own byte range within the wire body.
-- `body` is expected to already be UTF-8 (EUC-KR fields are transcoded by the
-- caller; tab never occurs inside a multibyte sequence). `raw_body`, if given,
-- is the untranscoded wire bytes, used only for the byte offsets.
function K.decode(body, raw_body)
  body = body
  local fields, offsets = split_with_offsets(body)
  if #fields ~= #K.FIELD_NAMES then return nil end

  local rec = { __offsets = {} }
  for k = 1, #K.FIELD_NAMES do
    rec[K.FIELD_NAMES[k]] = fields[k]
    rec.__offsets[K.FIELD_NAMES[k]] = offsets[k]
  end

  if raw_body then
    local _, raw_offsets = split_with_offsets(raw_body)
    if #raw_offsets == #K.FIELD_NAMES then
      for k = 1, #K.FIELD_NAMES do
        rec.__offsets[K.FIELD_NAMES[k]] = raw_offsets[k]
      end
    end
  end
  return rec
end

-- Spec code + detail-pane label per field, from design/field_spec.md:
-- FIELD_SPEC[name] = { filter suffix (mas.rts.K.<suffix>), label }. The wire's
-- leading key (not in the spec) is "key"; `type_echo` (000) is never displayed.
K.FIELD_SPEC = {
  key = { "key", "key" }, trade_time = { "034", "(034)체결시간" },
  price = { "023", "(023)현재가" }, change = { "024", "(024)전일대비" },
  change_rate = { "033", "(033)등락율" }, ask_price = { "025", "(025)매도호가" },
  bid_price = { "026", "(026)매수호가" }, trade_volume = { "032", "(032)체결량" },
  acc_volume = { "027", "(027)거래량" }, acc_value = { "028", "(028)거래대금" },
  open_price = { "029", "(029)시가" }, high_price = { "030", "(030)고가" },
  low_price = { "031", "(031)저가" }, open_interest = { "201", "(201)미결약정" },
  theory_price = { "202", "(202)이론가" }, theory_basis = { "203", "(203)이론BASIS" },
  market_basis = { "204", "(204)시장BASIS" }, disparity_rate = { "205", "(205)괴리율" },
  open_interest_diff = { "206", "(206)미결대비" }, disparity = { "207", "(207)괴리치" },
  ask_trade_volume = { "037", "(037)도-체결량" }, bid_trade_volume = { "038", "(038)수-체결량" },
  trade_strength_3m = { "388", "(388)3분체결강도" }, ask_trade_sum = { "193", "(193)도-체결합" },
  bid_trade_sum = { "194", "(194)수-체결합" }, trade_strength = { "387", "(387)체결강도" },
  open_interest_chg = { "448", "(448)미결증감" }, prev_day_volume_ratio = { "249", "(249)전일거래량비" },
  kospi200 = { "462", "(462)KP200" }, futures_latest_price = { "200", "(200)선물최근현재" },
  theory_diff = { "358", "(358)이론대비" }, rt_upper_limit = { "411", "(411)실시간상한가" },
  rt_lower_limit = { "412", "(412)실시간하한가" }, block_acc_volume = { "414", "(414)협의대량누적체결량" },
  upper_step_width = { "415", "(415)상한가단계폭" }, lower_step_width = { "416", "(416)하한가단계폭" },
}

if _G.Proto then
  -- No dedicated Proto here — `mas` is the only registered protocol (§4.7).
  -- Fields are appended to the shared mas.proto (cumulative; see PROTOCOL.md §6).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  local pf = {}
  for _, name in ipairs(K.FIELD_NAMES) do
    if K.FIELD_SPEC[name] then  -- RTS-TYPE(000) is never displayed
      pf[name] = ProtoField.string("mas.rts.K." .. K.FIELD_SPEC[name][1], K.FIELD_SPEC[name][2])
    end
  end

  local fields = {}
  for _, f in pairs(pf) do fields[#fields + 1] = f end
  mas.proto.fields = fields

  local expert_badfields =
    ProtoExpert.new("mas.rts.K.expert.fields", "Unexpected TYPE K field count",
      expert.group.MALFORMED, expert.severity.WARN)
  mas.proto.experts = { expert_badfields }

  -- Decode a TYPE='K' record body into the tree. The subtree is always tagged
  -- with the umbrella `mas` proto (see PROTOCOL.md §4.7); a wrong field count is
  -- flagged via expert_badfields instead.
  local function add_record(tree, tvb, poff, r, pinfo, msg_index)
    local base = poff + r.off + 6   -- body start within tvb
    local raw = (r.len > 0) and tvb(base, r.len):raw() or ""
    local utf8 = (r.len > 0) and tvb(base, r.len):string(ENC_EUC_KR) or ""
    local rec = K.decode(utf8, raw)
    local sub = tree:add(mas.proto, tvb(poff + r.off, 6 + r.len),
      "type: " .. K.TYPE_K .. " (" .. r.len .. " bytes)")
    mas.rts_add_header(sub, tvb, poff, r)
    if not rec then
      sub:add_proto_expert_info(expert_badfields)
      return false
    end
    for _, name in ipairs(K.FIELD_NAMES) do
      if pf[name] then
        local o = rec.__offsets[name]
        sub:add(pf[name], tvb(base + o.off, o.len), rec[name])
      end
    end
    return true
  end

  -- Register as the TYPE='K' decoder; mas_rts.lua's generic dispatcher calls
  -- this for every such record.
  mas.by_rts_type[K.TYPE_K] = { add = add_record }
end

return K