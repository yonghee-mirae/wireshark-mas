-- RTS TYPE='J' (업종:시세/지수, Sector Index).

local mas = _G.mas or {}
_G.mas = mas
mas.rts_defs = mas.rts_defs or {}

-- `key` is a sector/index code (e.g. "K2001"), not a stock code: no exchange split.

mas.rts_defs[#mas.rts_defs + 1] = {
  type = "J",
  fields = {
    { "034", "시간" }, { "023", "지수" }, { "024", "전일대비" }, { "033", "등락율" },
    { "032", "체결량" }, { "027", "거래량" }, { "028", "거래대금" }, { "029", "시가" },
    { "030", "고가" }, { "031", "저가" }, { "490", "장상태구분" },
  },
}
