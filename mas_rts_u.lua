-- RTS TYPE='U' (업종:등락, Sector Breadth): market-wide advance/decline counts, not a per-stock quote.
-- f252+f251+f253+f255+f254 is constant per key (801 for "K0001", ~1522 for "KQ001"), plausibly the KOSPI/KOSDAQ
-- listed-company counts.

local mas = _G.mas or {}
_G.mas = mas
mas.rts_defs = mas.rts_defs or {}

-- `key` is a market/sector key (e.g. "KQ001"), not a stock code: no exchange split.
mas.rts_defs[#mas.rts_defs + 1] = {
  type = "U",
  fields = {
    { "034", "시간" }, { "252", "상승종목" }, { "251", "상한종목" }, { "253", "보합종목" },
    { "255", "하락종목" }, { "254", "하한종목" }, { "027", "거래량" }, { "028", "거래대금" },
  },
}
