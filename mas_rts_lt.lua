-- RTS TYPE='t' (거래원). UNVERIFIED: no samples; the layout, framing (key + hidden marker + spec fields) and
-- plain char-array values are assumed from the protocol spec.

local mas = _G.mas or {}
_G.mas = mas
mas.rts_defs = mas.rts_defs or {}

mas.rts_defs[#mas.rts_defs + 1] = {
  type = "t", strip = "retry", euckr = true,
  fields = {
    { "190", "회원사코드" }, { "191", "회원사명" }, { "192", "종목코드" }, { "193", "종목명" },
    { "194", "시간" }, { "195", "매수수량" }, { "196", "매도수량" }, { "197", "순매수" },
    { "198", "누적매수수량" }, { "199", "누적매도수량" }, { "200", "누적순매수" },
    { "201", "누적순매수대비" }, { "202", "비중" },
  },
}
