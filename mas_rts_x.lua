-- RTS TYPE='X' (업종:예상지수, Expected Sector Index): like 'J' without open/high/low. UNVERIFIED: no samples; only
-- the spec's example row matches.

local mas = _G.mas or {}
_G.mas = mas
mas.rts_defs = mas.rts_defs or {}

-- `key` is a sector/index code (e.g. "X0001"), not a stock code: no exchange split.

mas.rts_defs[#mas.rts_defs + 1] = {
  type = "X",
  fields = {
    { "034", "시간" }, { "023", "지수" }, { "024", "전일대비" }, { "033", "등락율" },
    { "032", "체결량" }, { "027", "거래량" }, { "028", "거래대금" }, { "490", "장상태구분" },
  },
}
