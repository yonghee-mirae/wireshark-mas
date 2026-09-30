-- RTS TYPE='N' (해외:지수(TICKER-LINE의 NASDAQ-100, S&P-500)). UNVERIFIED: no samples; the layout, framing (key + hidden marker + spec fields) and
-- plain char-array values are assumed from the protocol spec.

local mas = _G.mas or {}
_G.mas = mas
mas.rts_defs = mas.rts_defs or {}

mas.rts_defs[#mas.rts_defs + 1] = {
  type = "N", strip = "retry", euckr = true,
  fields = {
    { "034", "거래시간" }, { "023", "현재가" }, { "024", "전일대비" }, { "033", "등락률" },
  },
}
