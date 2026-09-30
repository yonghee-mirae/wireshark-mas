-- RTS TYPE='x' (DRFN종목검색 해외주식 실시간 신호). UNVERIFIED: no samples; the layout, framing (key + hidden marker + spec fields) and
-- plain char-array values are assumed from the protocol spec.

local mas = _G.mas or {}
_G.mas = mas
mas.rts_defs = mas.rts_defs or {}

mas.rts_defs[#mas.rts_defs + 1] = {
  type = "x", strip = "retry", euckr = true,
  fields = {
    { "600", "HEAD+DATA" },
  },
}
