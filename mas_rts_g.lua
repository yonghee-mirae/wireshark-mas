-- RTS TYPE='G' (ETF:NAV).

local mas = _G.mas or {}
_G.mas = mas
mas.rts_defs = mas.rts_defs or {}

mas.rts_defs[#mas.rts_defs + 1] = {
  type = "G", strip = "retry",
  fields = {
    { "934", "나브시간" }, { "940", "나브시세" }, { "941", "나브대비" }, { "942", "나브등락율" },
    { "943", "NAV괴리도" }, { "944", "NAV괴리율" }, { "747", "ETF추적지수" },
    { "748", "ETF추적대비" }, { "749", "ETF추적등락" }, { "746", "ETF추적오차율" },
    { "923", "ETF현재가" }, { "924", "ETF대비" }, { "933", "ETF등락율" },
  },
}
