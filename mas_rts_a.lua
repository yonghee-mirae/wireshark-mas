-- RTS TYPE='A' (주식:시세). UNVERIFIED: no samples; the layout, framing (key + hidden marker + spec fields) and
-- plain char-array values are assumed from the protocol spec.

local mas = _G.mas or {}
_G.mas = mas
mas.rts_defs = mas.rts_defs or {}

mas.rts_defs[#mas.rts_defs + 1] = {
  type = "A", strip = "retry", euckr = true,
  fields = {
    { "023", "현재가" }, { "024", "전일대비" }, { "033", "등락율" }, { "025", "매도호가" },
    { "026", "매수호가" }, { "027", "거래량" }, { "028", "거래대금" }, { "029", "시가" },
    { "030", "고가" }, { "031", "저가" }, { "251", "전대비율(량)" }, { "264", "전대비율(금)" },
  },
}
