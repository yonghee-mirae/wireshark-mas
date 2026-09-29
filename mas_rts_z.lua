-- MAS RTS TYPE='Z' (투자자AMT, Investor Type Amount) decoder.
--
-- One RTS-DATA record's DATA (see mas_rts.lua for RTS-HEADER framing) is a
-- 51-field tab-separated body: the same 16 investor-type categories as
-- mas_rts_y.lua (TYPE='Y'), each with sell/buy/net-buy AMOUNT instead of
-- quantity (spec codes are TYPE='Y''s codes + 400 — e.g. Y's sell code 101 ->
-- Z's 501 — confirming both types share the same 16-category breakdown).
-- This is the only RTS TYPE this module decodes; every other TYPE is left to
-- mas_rts.lua's generic "type: <TYPE>"-only handling.
--
-- Field order/names are the spec given in design/field_spec.md, confirmed
-- against samples/20260921_nana.pcapng (33 sampled records) and
-- samples/20260915_0809_RTS2.pcapng (52 sampled records) — both always
-- exactly 51 tab-separated fields.
--
-- Pure helpers (decode, required by tests) + Wireshark registration.
-- Coordinates with core via _G.mas.

local mas = _G.mas or {}
_G.mas = mas
mas.by_rts_type = mas.by_rts_type or {}

local Z = {}   -- module table: pure helpers (returned for tests)

Z.TYPE_INVESTOR_AMT = "Z"   -- the only RTS TYPE this module decodes

-- The spec's 16 investor-category codes (매도AMT base code; 매수AMT = base+100,
-- 순매수A = base+200) — see mas_rts_y.lua for why these are used directly
-- instead of a guessed investor-type name.
local CATEGORY_CODES = { 501, 502, 503, 504, 505, 506, 507, 508, 509, 510, 530, 531, 560, 570, 571, 590 }

-- Field order (0-based index 0..50), for RTS TYPE='Z' (Investor Amount).
Z.FIELD_NAMES = {}
local function append(t) for _, v in ipairs(t) do Z.FIELD_NAMES[#Z.FIELD_NAMES + 1] = v end end
append({ "key", "sep", "trade_time" })
for _, c in ipairs(CATEGORY_CODES) do
  append({ "sell_amt_" .. c, "buy_amt_" .. (c + 100), "net_buy_amt_" .. (c + 200) })
end

-- Split a tab-separated string into fields, stripping trailing NUL bytes from
-- each (see mas_rts_b for the version note). Also returns each field's own
-- 0-based byte range within `s` (post-NUL-strip length) so the detail pane
-- can highlight just that field's bytes instead of the whole record (see
-- add_investor_amt).
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

-- Split a tab-separated TYPE='Z' body into a record keyed by FIELD_NAMES.
-- Returns nil if field count != 51. Trailing NULs are stripped. Unlike
-- TYPE='B'/'C'/'F', `key` here is a market key, not a stock issue code, so
-- no market-prefix split is applied (see mas_rts_u.lua for the same "key"
-- convention). `rec.__offsets[name] = {off, len}` gives each field's own
-- byte range within `body`.
function Z.decode(body)
  local fields, offsets = split_with_offsets(body)
  if #fields ~= #Z.FIELD_NAMES then return nil end

  local rec = { __offsets = {} }
  for k = 1, #Z.FIELD_NAMES do
    rec[Z.FIELD_NAMES[k]] = fields[k]
    rec.__offsets[Z.FIELD_NAMES[k]] = offsets[k]
  end
  return rec
end

-- Spec code + detail-pane label per field, from design/field_spec.md:
-- FIELD_SPEC[name] = { filter suffix (mas.rts.Z.<suffix>), label }. The wire's
-- leading key (not in the spec) is "key"; `sep` is never displayed.
Z.FIELD_SPEC = {
  key = { "key", "key" }, trade_time = { "034", "(034)처리시간" },
  sell_amt_501 = { "501", "(501)매도AMT" }, buy_amt_601 = { "601", "(601)매수AMT" },
  net_buy_amt_701 = { "701", "(701)순매수A" }, sell_amt_502 = { "502", "(502)매도AMT" },
  buy_amt_602 = { "602", "(602)매수AMT" }, net_buy_amt_702 = { "702", "(702)순매수A" },
  sell_amt_503 = { "503", "(503)매도AMT" }, buy_amt_603 = { "603", "(603)매수AMT" },
  net_buy_amt_703 = { "703", "(703)순매수A" }, sell_amt_504 = { "504", "(504)매도AMT" },
  buy_amt_604 = { "604", "(604)매수AMT" }, net_buy_amt_704 = { "704", "(704)순매수A" },
  sell_amt_505 = { "505", "(505)매도AMT" }, buy_amt_605 = { "605", "(605)매수AMT" },
  net_buy_amt_705 = { "705", "(705)순매수A" }, sell_amt_506 = { "506", "(506)매도AMT" },
  buy_amt_606 = { "606", "(606)매수AMT" }, net_buy_amt_706 = { "706", "(706)순매수A" },
  sell_amt_507 = { "507", "(507)매도AMT" }, buy_amt_607 = { "607", "(607)매수AMT" },
  net_buy_amt_707 = { "707", "(707)순매수A" }, sell_amt_508 = { "508", "(508)매도AMT" },
  buy_amt_608 = { "608", "(608)매수AMT" }, net_buy_amt_708 = { "708", "(708)순매수A" },
  sell_amt_509 = { "509", "(509)매도AMT" }, buy_amt_609 = { "609", "(609)매수AMT" },
  net_buy_amt_709 = { "709", "(709)순매수A" }, sell_amt_510 = { "510", "(510)매도AMT" },
  buy_amt_610 = { "610", "(610)매수AMT" }, net_buy_amt_710 = { "710", "(710)순매수A" },
  sell_amt_530 = { "530", "(530)매도AMT" }, buy_amt_630 = { "630", "(630)매수AMT" },
  net_buy_amt_730 = { "730", "(730)순매수A" }, sell_amt_531 = { "531", "(531)매도AMT" },
  buy_amt_631 = { "631", "(631)매수AMT" }, net_buy_amt_731 = { "731", "(731)순매수A" },
  sell_amt_560 = { "560", "(560)매도AMT" }, buy_amt_660 = { "660", "(660)매수AMT" },
  net_buy_amt_760 = { "760", "(760)순매수A" }, sell_amt_570 = { "570", "(570)매도AMT" },
  buy_amt_670 = { "670", "(670)매수AMT" }, net_buy_amt_770 = { "770", "(770)순매수A" },
  sell_amt_571 = { "571", "(571)매도AMT" }, buy_amt_671 = { "671", "(671)매수AMT" },
  net_buy_amt_771 = { "771", "(771)순매수A" }, sell_amt_590 = { "590", "(590)매도AMT" },
  buy_amt_690 = { "690", "(690)매수AMT" }, net_buy_amt_790 = { "790", "(790)순매수A" },
}

if _G.Proto then
  -- No dedicated Proto here — `mas` is the only registered protocol (§4.7).
  -- Fields are appended to the shared mas.proto (cumulative; see PROTOCOL.md §6).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  -- Register a string field per FIELD_NAMES entry (sep omitted).
  local pf = {}
  for _, name in ipairs(Z.FIELD_NAMES) do
    if name ~= "sep" then  -- separator field: kept in FIELD_NAMES for decode, not displayed
      pf[name] = ProtoField.string("mas.rts.Z." .. Z.FIELD_SPEC[name][1], Z.FIELD_SPEC[name][2])
    end
  end

  local fields = {}
  for _, f in pairs(pf) do fields[#fields + 1] = f end
  mas.proto.fields = fields

  local expert_badfields =
    ProtoExpert.new("mas.rts.Z.expert.fields", "Unexpected investor-amt field count",
      expert.group.MALFORMED, expert.severity.WARN)
  mas.proto.experts = { expert_badfields }

  -- Decode a TYPE='Z' investor-amt record body into the tree. The subtree
  -- is always tagged with the umbrella `mas` proto (see PROTOCOL.md §4.7) —
  -- a malformed TYPE='Z' body (wrong field count) is flagged via
  -- expert_badfields instead; "did this decode?" is a field-value question,
  -- not a presence-filter one (mirrors add_breadth/add_broker).
  local function add_investor_amt(tree, tvb, poff, r, pinfo, msg_index)
    local rec = Z.decode(r.body)
    local sub = tree:add(mas.proto, tvb(poff + r.off, 6 + r.len),
      "type: " .. Z.TYPE_INVESTOR_AMT .. " (" .. r.len .. " bytes)")
    mas.rts_add_header(sub, tvb, poff, r)
    if not rec then
      sub:add_proto_expert_info(expert_badfields)
      return false
    end
    local base = poff + r.off + 6   -- body start within tvb
    for _, name in ipairs(Z.FIELD_NAMES) do
      if pf[name] then
        local o = rec.__offsets[name]
        sub:add(pf[name], tvb(base + o.off, o.len), rec[name])
      end
    end
    return true
  end

  -- Register as the TYPE='Z' decoder; mas_rts.lua's generic dispatcher calls
  -- this for every TYPE='Z' record and falls back to a bare "type: <TYPE>"
  -- label itself for any other TYPE.
  mas.by_rts_type[Z.TYPE_INVESTOR_AMT] = { add = add_investor_amt }
end

return Z
