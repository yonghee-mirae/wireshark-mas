-- RTS TYPE='S' (선물 투자자별순매수). The spec's (260)종목코드 is the wire's leading key, not a separate field.

local mas = _G.mas or {}
_G.mas = mas
mas.rts_defs = mas.rts_defs or {}

mas.rts_defs[#mas.rts_defs + 1] = {
  type = "S",
  fields = {
    { "261", "투자자구분" }, { "262", "투자자계약수" }, { "263", "투자자계약금" },
  },
}
