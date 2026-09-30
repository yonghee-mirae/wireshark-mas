-- RTS TYPE='4' (단말 메시지 전송 (2024.07 add)). UNVERIFIED: no samples; the layout, framing (key + hidden marker + spec fields) and
-- plain char-array values are assumed from the protocol spec.

local mas = _G.mas or {}
_G.mas = mas
mas.rts_defs = mas.rts_defs or {}

mas.rts_defs[#mas.rts_defs + 1] = {
  type = "4", strip = "retry", euckr = true,
  fields = {
    { "001", "업무구분" }, { "002", "서브구분" }, { "003", "메시지" }, { "004", "예비" },
  },
}
