-- RTS TYPE='8' (52주 고가/저가).

local mas = _G.mas or {}
_G.mas = mas
mas.rts_defs = mas.rts_defs or {}

mas.rts_defs[#mas.rts_defs + 1] = {
  type = "8",
  fields = {
    { "530", "52주 최고가" }, { "531", "52주 최저가" }, { "538", "52주 최고일자" },
    { "539", "52주 최저일자" },
  },
}
