-- RTS TYPE='W' (투자자매매). UNVERIFIED: no samples; the layout, framing (key + hidden marker + spec fields) and
-- plain char-array values are assumed from the protocol spec.

local mas = _G.mas or {}
_G.mas = mas
mas.rts_defs = mas.rts_defs or {}

mas.rts_defs[#mas.rts_defs + 1] = {
  type = "W", strip = "retry", euckr = true,
  fields = {
    { "034", "처리시간" }, { "333", "매도수량" }, { "334", "매수수량" }, { "335", "전매수량" },
    { "336", "환매수량" }, { "337", "매도미결" }, { "338", "매수미결" }, { "339", "매도대금" },
    { "340", "매수대금" }, { "341", "전매대금" }, { "342", "환매대금" }, { "343", "순매수수량" },
    { "344", "순매수금액" },
  },
}
