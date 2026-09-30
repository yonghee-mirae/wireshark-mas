-- RTS TYPE='Y' (투자자QTY, Investor Type Quantity): 16 investor categories x sell/buy/net-buy quantity.

local mas = _G.mas or {}
_G.mas = mas
mas.rts_defs = mas.rts_defs or {}

-- 16 investor categories with no names in the spec, identified by code only
-- (매도QTY = base, 매수QTY = base+100, 순매수Q = base+200).
-- `key` is a market key (e.g. "0500000000"), not a stock code: no exchange split.
mas.rts_defs[#mas.rts_defs + 1] = {
  type = "Y",
  fields = {
    { "034", "처리시간" }, { "101", "매도QTY" }, { "201", "매수QTY" }, { "301", "순매수Q" },
    { "102", "매도QTY" }, { "202", "매수QTY" }, { "302", "순매수Q" }, { "103", "매도QTY" },
    { "203", "매수QTY" }, { "303", "순매수Q" }, { "104", "매도QTY" }, { "204", "매수QTY" },
    { "304", "순매수Q" }, { "105", "매도QTY" }, { "205", "매수QTY" }, { "305", "순매수Q" },
    { "106", "매도QTY" }, { "206", "매수QTY" }, { "306", "순매수Q" }, { "107", "매도QTY" },
    { "207", "매수QTY" }, { "307", "순매수Q" }, { "108", "매도QTY" }, { "208", "매수QTY" },
    { "308", "순매수Q" }, { "109", "매도QTY" }, { "209", "매수QTY" }, { "309", "순매수Q" },
    { "110", "매도QTY" }, { "210", "매수QTY" }, { "310", "순매수Q" }, { "130", "매도QTY" },
    { "230", "매수QTY" }, { "330", "순매수Q" }, { "131", "매도QTY" }, { "231", "매수QTY" },
    { "331", "순매수Q" }, { "160", "매도QTY" }, { "260", "매수QTY" }, { "360", "순매수Q" },
    { "170", "매도QTY" }, { "270", "매수QTY" }, { "370", "순매수Q" }, { "171", "매도QTY" },
    { "271", "매수QTY" }, { "371", "순매수Q" }, { "190", "매도QTY" }, { "290", "매수QTY" },
    { "390", "순매수Q" },
  },
}
