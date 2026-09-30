-- RTS TYPE='w' (해외주식:중국외국인매매한도). UNVERIFIED: no samples; the layout, framing (key + hidden marker + spec fields) and
-- plain char-array values are assumed from the protocol spec.

local mas = _G.mas or {}
_G.mas = mas
mas.rts_defs = mas.rts_defs or {}

mas.rts_defs[#mas.rts_defs + 1] = {
  type = "w", strip = "retry", euckr = true,
  fields = {
    { "888", "실시간구분" }, { "647", "자료일자(한국)" }, { "034", "자료시간(한국시간)" },
    { "475", "금액단위" }, { "503", "잔여비율" }, { "502", "외국인일일한도" },
    { "511", "외국인일일잔여금" },
  },
}
