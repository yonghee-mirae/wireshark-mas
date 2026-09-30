-- RTS TYPE='j' (장운용정보). UNVERIFIED: no samples; the layout, framing (key + hidden marker + spec fields) and
-- plain char-array values are assumed from the protocol spec.

local mas = _G.mas or {}
_G.mas = mas
mas.rts_defs = mas.rts_defs or {}

mas.rts_defs[#mas.rts_defs + 1] = {
  type = "j", strip = "retry", euckr = true,
  fields = {
    { "034", "시간" }, { "023", "메시지" }, { "024", "NXT장운영구분값" },
  },
}
