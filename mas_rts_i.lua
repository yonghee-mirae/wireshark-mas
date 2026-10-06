-- RTS TYPE='I' (ELW:지표). The 20-field layout is UNVERIFIED.

local mas = _G.mas or {}
_G.mas = mas
mas.rts_defs = mas.rts_defs or {}

mas.rts_defs[#mas.rts_defs + 1] = {
  type = "I", strip = "retry", base_count = 10,   -- 10 = key + marker + the first 8 fields (some symbols)
  fields = {
    { "890", "ELW시간" }, { "891", "ELW패러티" }, { "892", "프리미엄" }, { "893", "기어링비율" },
    { "894", "손일분기율" }, { "895", "자본지지점" }, { "896", "손익분기점" },
    { "898", "바스켓주가" }, { "202", "이론가" }, { "205", "괴리율" }, { "243", "델타" },
    { "244", "감마" }, { "245", "세타" }, { "246", "베가" }, { "247", "로" }, { "354", "내재변동" },
    { "203", "이론BASIS" }, { "204", "차익BASIS" }, { "897", "레버리지" }, { "207", "괴리" },
  },
}
