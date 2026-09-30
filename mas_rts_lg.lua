-- RTS TYPE='g' (ELW:LP잔량). UNVERIFIED: no samples; the layout, framing (key + hidden marker + spec fields) and
-- plain char-array values are assumed from the protocol spec.

local mas = _G.mas or {}
_G.mas = mas
mas.rts_defs = mas.rts_defs or {}

mas.rts_defs[#mas.rts_defs + 1] = {
  type = "g", strip = "retry", euckr = true,
  fields = {
    { "421", "매도LP잔량1" }, { "422", "매도LP잔량2" }, { "423", "매도LP잔량3" },
    { "424", "매도LP잔량4" }, { "425", "매도LP잔량5" }, { "426", "매도LP잔량6" },
    { "427", "매도LP잔량7" }, { "428", "매도LP잔량8" }, { "429", "매도LP잔량9" },
    { "430", "매도LP잔량10" }, { "431", "매수LP잔량1" }, { "432", "매수LP잔량2" },
    { "433", "매수LP잔량3" }, { "434", "매수LP잔량4" }, { "435", "매수LP잔량5" },
    { "436", "매수LP잔량6" }, { "437", "매수LP잔량7" }, { "438", "매수LP잔량8" },
    { "439", "매수LP잔량9" }, { "440", "매수LP잔량10" }, { "441", "LP총매도잔량" },
    { "442", "LP총매수잔량" },
  },
}
