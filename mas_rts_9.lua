-- RTS TYPE='9' (접속자수 2초 실시간 데이터). UNVERIFIED: no samples; the layout, framing (key + hidden marker + spec fields) and
-- plain char-array values are assumed from the protocol spec.

local mas = _G.mas or {}
_G.mas = mas
mas.rts_defs = mas.rts_defs or {}

mas.rts_defs[#mas.rts_defs + 1] = {
  type = "9", strip = "retry", euckr = true,
  fields = {
    { "047", "일자" }, { "043", "시간" }, { "900", "HTS" }, { "901", "PTS" }, { "902", "WTS" },
    { "903", "FX" }, { "904", "MTS" }, { "905", "HOMEPAGE" }, { "906", "OBT" }, { "907", "MAPIS" },
    { "908", "BR" }, { "909", "REALTEST" }, { "910", "VTS" }, { "911", "ODS" },
    { "912", "NAVER-WTSBP" }, { "913", "-" }, { "914", "-" }, { "915", "-" }, { "916", "-" },
    { "917", "-" }, { "918", "-" }, { "919", "-" }, { "920", "TOTAL" },
  },
}
