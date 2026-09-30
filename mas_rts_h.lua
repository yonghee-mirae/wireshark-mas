-- RTS TYPE='H' (시장변동상황). UNVERIFIED: no samples; the layout, framing (key + hidden marker + spec fields) and
-- plain char-array values are assumed from the protocol spec.

local mas = _G.mas or {}
_G.mas = mas
mas.rts_defs = mas.rts_defs or {}

mas.rts_defs[#mas.rts_defs + 1] = {
  type = "H", strip = "retry", euckr = true,
  fields = {
    { "379", "단일가매매연장" }, { "385", "조기종료발생" }, { "839", "VI발동시각" },
    { "840", "VI시장구분" }, { "841", "VI발동시장매도호가" }, { "842", "VI발동시장매수호가" },
    { "843", "KRX예상체결가" }, { "963", "단일가여부" }, { "844", "NXT예상체결가" },
    { "845", "KRX예상체결수량" }, { "846", "NXT예상체결수량" },
  },
}
