-- RTS TYPE='5' (기준가변경시 기준가/상/하한가 전송). UNVERIFIED: no samples; the layout, framing (key + hidden marker + spec fields) and
-- plain char-array values are assumed from the protocol spec.

local mas = _G.mas or {}
_G.mas = mas
mas.rts_defs = mas.rts_defs or {}

mas.rts_defs[#mas.rts_defs + 1] = {
  type = "5", strip = "retry", euckr = true,
  fields = {
    { "635", "기준가" }, { "311", "상한가" }, { "312", "하한가" },
  },
}
