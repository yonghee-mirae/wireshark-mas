-- RTS TYPE='v' (마켓레이더). UNVERIFIED: no samples; the layout, framing (key + hidden marker + spec fields) and
-- plain char-array values are assumed from the protocol spec.

local mas = _G.mas or {}
_G.mas = mas
mas.rts_defs = mas.rts_defs or {}

mas.rts_defs[#mas.rts_defs + 1] = {
  type = "v", strip = "retry", euckr = true,
  fields = {
    { "201", "종목코드" }, { "801", "발생 해지 구분" }, { "802", "시간" }, { "803", "가격" },
    { "804", "시스템ID" }, { "805", "제목" },
  },
}
