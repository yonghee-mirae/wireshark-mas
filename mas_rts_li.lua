-- RTS TYPE='i' (주식:예상 체결). UNVERIFIED: no samples; the layout, framing (key + hidden marker + spec fields) and
-- plain char-array values are assumed from the protocol spec.

local mas = _G.mas or {}
_G.mas = mas
mas.rts_defs = mas.rts_defs or {}

mas.rts_defs[#mas.rts_defs + 1] = {
  type = "i", strip = "retry", euckr = true,
  fields = {
    { "034", "체결시간" }, { "023", "예상체결가" }, { "024", "전일대비" }, { "033", "등락율" },
    { "025", "매도호가" }, { "026", "매수호가" }, { "032", "예상체결량" }, { "490", "장상태구분" },
    { "036", "매도총량" }, { "039", "매수총량" },
  },
}
