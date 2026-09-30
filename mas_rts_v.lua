-- RTS TYPE='V' (해외:지수, Overseas Index).

local mas = _G.mas or {}
_G.mas = mas
mas.rts_defs = mas.rts_defs or {}

-- `key` is a foreign symbol (e.g. "CME@NQ"), not a KRX stock code: no exchange split.

mas.rts_defs[#mas.rts_defs + 1] = {
  type = "V",
  fields = {
    { "034", "거래시간" }, { "023", "현재가" }, { "024", "전일대비" }, { "033", "등락률" },
    { "027", "거래량" }, { "029", "시가" }, { "030", "고가" }, { "031", "저가" }, { "047", "일자" },
  },
}
