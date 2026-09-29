-- MAS RTS TYPE='c' (통합시세 11~20 호가 (Quote levels 11-20)) decoder.
--
-- Filename `mas_rts_lc.lua`: the leading "l" marks a lowercase TYPE (see mas_rts_lm.lua); the
-- registration key and the Wireshark FILTER prefix (`mas.rts.c.*`) use the literal wire byte.
--
-- One RTS-DATA record's DATA (see mas_rts.lua for RTS-HEADER framing) is a 102-field
-- tab-separated body: key, the hidden record-type marker (000), then the spec
-- fields (design/field_spec.md).
-- Field layout confirmed against samples/20260915_0809_RTS.pcap (280 records).
--
-- Pure helpers (decode, required by tests) + Wireshark registration.
-- Coordinates with core via _G.mas.

local mas = _G.mas or {}
_G.mas = mas
mas.by_rts_type = mas.by_rts_type or {}

local LC = {}   -- module table: pure helpers (returned for tests)

LC.TYPE_LC = "c"   -- the only RTS TYPE this module decodes

-- key prefix -> market. No dot means KRX(K). Same convention as mas_rts_c.lua.
local MARKET = { M = "M", N = "N" }

function LC.split_market(key)
  local prefix, base = key:match("^([^.]*)%.(.*)$")
  if base then
    return MARKET[prefix] or prefix, base
  end
  return "K", key
end

-- Field order (0-based index 0..101).
LC.FIELD_NAMES = {
  "key", "type_echo", "ask_price11", "ask_price12", "ask_price13",
  "ask_price14", "ask_price15", "ask_price16", "ask_price17", "ask_price18",
  "ask_price19", "ask_price20", "ask_qty11", "ask_qty12", "ask_qty13",
  "ask_qty14", "ask_qty15", "ask_qty16", "ask_qty17", "ask_qty18",
  "ask_qty19", "ask_qty20", "ask_qty_chg11", "ask_qty_chg12", "ask_qty_chg13",
  "ask_qty_chg14", "ask_qty_chg15", "ask_qty_chg16", "ask_qty_chg17", "ask_qty_chg18",
  "ask_qty_chg19", "ask_qty_chg20", "krx_ask_qty11", "krx_ask_qty12", "krx_ask_qty13",
  "krx_ask_qty14", "krx_ask_qty15", "krx_ask_qty16", "krx_ask_qty17", "krx_ask_qty18",
  "krx_ask_qty19", "krx_ask_qty20", "nxt_ask_qty11", "nxt_ask_qty12", "nxt_ask_qty13",
  "nxt_ask_qty14", "nxt_ask_qty15", "nxt_ask_qty16", "nxt_ask_qty17", "nxt_ask_qty18",
  "nxt_ask_qty19", "nxt_ask_qty20", "bid_price11", "bid_price12", "bid_price13",
  "bid_price14", "bid_price15", "bid_price16", "bid_price17", "bid_price18",
  "bid_price19", "bid_price20", "bid_qty11", "bid_qty12", "bid_qty13",
  "bid_qty14", "bid_qty15", "bid_qty16", "bid_qty17", "bid_qty18",
  "bid_qty19", "bid_qty20", "bid_qty_chg11", "bid_qty_chg12", "bid_qty_chg13",
  "bid_qty_chg14", "bid_qty_chg15", "bid_qty_chg16", "bid_qty_chg17", "bid_qty_chg18",
  "bid_qty_chg19", "bid_qty_chg20", "krx_bid_qty11", "krx_bid_qty12", "krx_bid_qty13",
  "krx_bid_qty14", "krx_bid_qty15", "krx_bid_qty16", "krx_bid_qty17", "krx_bid_qty18",
  "krx_bid_qty19", "krx_bid_qty20", "nxt_bid_qty11", "nxt_bid_qty12", "nxt_bid_qty13",
  "nxt_bid_qty14", "nxt_bid_qty15", "nxt_bid_qty16", "nxt_bid_qty17", "nxt_bid_qty18",
  "nxt_bid_qty19", "nxt_bid_qty20",
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

-- Split a tab-separated TYPE='c' body into a record keyed by FIELD_NAMES.
-- Returns nil if field count != 102. `rec.__offsets[name] = {off, len}` gives each
-- field's own byte range within the wire body.
function LC.decode(body)
  body = body
  local fields, offsets = split_with_offsets(body)
  if #fields ~= #LC.FIELD_NAMES then return nil end

  local rec = { __offsets = {} }
  for k = 1, #LC.FIELD_NAMES do
    rec[LC.FIELD_NAMES[k]] = fields[k]
    rec.__offsets[LC.FIELD_NAMES[k]] = offsets[k]
  end
  rec.market, rec.key = LC.split_market(rec.key)
  return rec
end

-- Spec code + detail-pane label per field, from design/field_spec.md:
-- FIELD_SPEC[name] = { filter suffix (mas.rts.c.<suffix>), label }. The wire's
-- leading key (not in the spec) is "key"; `type_echo` (000) is never displayed.
LC.FIELD_SPEC = {
  key = { "key", "key" }, ask_price11 = { "1651", "(1651)매도가11" },
  ask_price12 = { "1652", "(1652)매도가12" }, ask_price13 = { "1653", "(1653)매도가13" },
  ask_price14 = { "1654", "(1654)매도가14" }, ask_price15 = { "1655", "(1655)매도가15" },
  ask_price16 = { "1656", "(1656)매도가16" }, ask_price17 = { "1657", "(1657)매도가17" },
  ask_price18 = { "1658", "(1658)매도가18" }, ask_price19 = { "1659", "(1659)매도가19" },
  ask_price20 = { "1660", "(1660)매도가20" }, ask_qty11 = { "1641", "(1641)매도량11" },
  ask_qty12 = { "1642", "(1642)매도량12" }, ask_qty13 = { "1643", "(1643)매도량13" },
  ask_qty14 = { "1644", "(1644)매도량14" }, ask_qty15 = { "1645", "(1645)매도량15" },
  ask_qty16 = { "1646", "(1646)매도량16" }, ask_qty17 = { "1647", "(1647)매도량17" },
  ask_qty18 = { "1648", "(1648)매도량18" }, ask_qty19 = { "1649", "(1649)매도량19" },
  ask_qty20 = { "1650", "(1650)매도량20" }, ask_qty_chg11 = { "1681", "(1681)매도비11" },
  ask_qty_chg12 = { "1682", "(1682)매도비12" }, ask_qty_chg13 = { "1683", "(1683)매도비13" },
  ask_qty_chg14 = { "1684", "(1684)매도비14" }, ask_qty_chg15 = { "1685", "(1685)매도비15" },
  ask_qty_chg16 = { "1686", "(1686)매도비16" }, ask_qty_chg17 = { "1687", "(1687)매도비17" },
  ask_qty_chg18 = { "1688", "(1688)매도비18" }, ask_qty_chg19 = { "1689", "(1689)매도비19" },
  ask_qty_chg20 = { "1690", "(1690)매도비20" }, krx_ask_qty11 = { "1341", "(1341)K매도량11" },
  krx_ask_qty12 = { "1342", "(1342)K매도량12" }, krx_ask_qty13 = { "1343", "(1343)K매도량13" },
  krx_ask_qty14 = { "1344", "(1344)K매도량14" }, krx_ask_qty15 = { "1345", "(1345)K매도량15" },
  krx_ask_qty16 = { "1346", "(1346)K매도량16" }, krx_ask_qty17 = { "1347", "(1347)K매도량17" },
  krx_ask_qty18 = { "1348", "(1348)K매도량18" }, krx_ask_qty19 = { "1349", "(1349)K매도량19" },
  krx_ask_qty20 = { "1350", "(1350)K매도량20" }, nxt_ask_qty11 = { "1541", "(1541)N매도량11" },
  nxt_ask_qty12 = { "1542", "(1542)N매도량12" }, nxt_ask_qty13 = { "1543", "(1543)N매도량13" },
  nxt_ask_qty14 = { "1544", "(1544)N매도량14" }, nxt_ask_qty15 = { "1545", "(1545)N매도량15" },
  nxt_ask_qty16 = { "1546", "(1546)N매도량16" }, nxt_ask_qty17 = { "1547", "(1547)N매도량17" },
  nxt_ask_qty18 = { "1548", "(1548)N매도량18" }, nxt_ask_qty19 = { "1549", "(1549)N매도량19" },
  nxt_ask_qty20 = { "1550", "(1550)N매도량20" }, bid_price11 = { "1671", "(1671)매수가11" },
  bid_price12 = { "1672", "(1672)매수가12" }, bid_price13 = { "1673", "(1673)매수가13" },
  bid_price14 = { "1674", "(1674)매수가14" }, bid_price15 = { "1675", "(1675)매수가15" },
  bid_price16 = { "1676", "(1676)매수가16" }, bid_price17 = { "1677", "(1677)매수가17" },
  bid_price18 = { "1678", "(1678)매수가18" }, bid_price19 = { "1679", "(1679)매수가19" },
  bid_price20 = { "1680", "(1680)매수가20" }, bid_qty11 = { "1661", "(1661)매수량11" },
  bid_qty12 = { "1662", "(1662)매수량12" }, bid_qty13 = { "1663", "(1663)매수량13" },
  bid_qty14 = { "1664", "(1664)매수량14" }, bid_qty15 = { "1665", "(1665)매수량15" },
  bid_qty16 = { "1666", "(1666)매수량16" }, bid_qty17 = { "1667", "(1667)매수량17" },
  bid_qty18 = { "1668", "(1668)매수량18" }, bid_qty19 = { "1669", "(1669)매수량19" },
  bid_qty20 = { "1670", "(1670)매수량20" }, bid_qty_chg11 = { "1691", "(1691)매수비11" },
  bid_qty_chg12 = { "1692", "(1692)매수비12" }, bid_qty_chg13 = { "1693", "(1693)매수비13" },
  bid_qty_chg14 = { "1694", "(1694)매수비14" }, bid_qty_chg15 = { "1695", "(1695)매수비15" },
  bid_qty_chg16 = { "1696", "(1696)매수비16" }, bid_qty_chg17 = { "1697", "(1697)매수비17" },
  bid_qty_chg18 = { "1698", "(1698)매수비18" }, bid_qty_chg19 = { "1699", "(1699)매수비19" },
  bid_qty_chg20 = { "1700", "(1700)매수비20" }, krx_bid_qty11 = { "1361", "(1361)K매수량11" },
  krx_bid_qty12 = { "1362", "(1362)K매수량12" }, krx_bid_qty13 = { "1363", "(1363)K매수량13" },
  krx_bid_qty14 = { "1364", "(1364)K매수량14" }, krx_bid_qty15 = { "1365", "(1365)K매수량15" },
  krx_bid_qty16 = { "1366", "(1366)K매수량16" }, krx_bid_qty17 = { "1367", "(1367)K매수량17" },
  krx_bid_qty18 = { "1368", "(1368)K매수량18" }, krx_bid_qty19 = { "1369", "(1369)K매수량19" },
  krx_bid_qty20 = { "1370", "(1370)K매수량20" }, nxt_bid_qty11 = { "1561", "(1561)N매수량11" },
  nxt_bid_qty12 = { "1562", "(1562)N매수량12" }, nxt_bid_qty13 = { "1563", "(1563)N매수량13" },
  nxt_bid_qty14 = { "1564", "(1564)N매수량14" }, nxt_bid_qty15 = { "1565", "(1565)N매수량15" },
  nxt_bid_qty16 = { "1566", "(1566)N매수량16" }, nxt_bid_qty17 = { "1567", "(1567)N매수량17" },
  nxt_bid_qty18 = { "1568", "(1568)N매수량18" }, nxt_bid_qty19 = { "1569", "(1569)N매수량19" },
  nxt_bid_qty20 = { "1570", "(1570)N매수량20" },
}

if _G.Proto then
  -- No dedicated Proto here — `mas` is the only registered protocol (§4.7).
  -- Fields are appended to the shared mas.proto (cumulative; see PROTOCOL.md §6).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  local pf = {}
  for _, name in ipairs(LC.FIELD_NAMES) do
    if LC.FIELD_SPEC[name] then  -- RTS-TYPE(000) is never displayed
      pf[name] = ProtoField.string("mas.rts.c." .. LC.FIELD_SPEC[name][1], LC.FIELD_SPEC[name][2])
    end
  end
  pf.market = ProtoField.string("mas.rts.c.market", "거래소")

  local fields = {}
  for _, f in pairs(pf) do fields[#fields + 1] = f end
  mas.proto.fields = fields

  local expert_badfields =
    ProtoExpert.new("mas.rts.c.expert.fields", "Unexpected TYPE c field count",
      expert.group.MALFORMED, expert.severity.WARN)
  mas.proto.experts = { expert_badfields }

  -- Decode a TYPE='c' record body into the tree. The subtree is always tagged
  -- with the umbrella `mas` proto (see PROTOCOL.md §4.7); a wrong field count is
  -- flagged via expert_badfields instead.
  local function add_record(tree, tvb, poff, r, pinfo, msg_index)
    local base = poff + r.off + 6   -- body start within tvb
    local rec = LC.decode(r.body)
    local sub = tree:add(mas.proto, tvb(poff + r.off, 6 + r.len),
      "type: " .. LC.TYPE_LC .. " (" .. r.len .. " bytes)")
    mas.rts_add_header(sub, tvb, poff, r)
    if not rec then
      sub:add_proto_expert_info(expert_badfields)
      return false
    end
    local k_off = rec.__offsets.key
    sub:add(pf.market, tvb(base + k_off.off, k_off.len), rec.market)   -- shown before key
    for _, name in ipairs(LC.FIELD_NAMES) do
      if pf[name] then
        local o = rec.__offsets[name]
        sub:add(pf[name], tvb(base + o.off, o.len), rec[name])
      end
    end
    return true
  end

  -- Register as the TYPE='c' decoder; mas_rts.lua's generic dispatcher calls
  -- this for every such record.
  mas.by_rts_type[LC.TYPE_LC] = { add = add_record }
end

return LC