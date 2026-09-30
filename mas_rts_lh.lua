-- RTS TYPE='h' (해외주식:홍콩(VCM/CAS/IEP),호치민외국인매매한도,장운영). UNVERIFIED: no samples; the layout, framing (key + hidden marker + spec fields) and
-- plain char-array values are assumed from the protocol spec.

local mas = _G.mas or {}
_G.mas = mas
mas.rts_defs = mas.rts_defs or {}

mas.rts_defs[#mas.rts_defs + 1] = {
  type = "h", strip = "retry", euckr = true,
  fields = {
    { "888", "실시간구분" }, { "837", "정보구분" }, { "480", "가격소수점자리수" },
    { "838", "시간1" }, { "839", "시간2" }, { "840", "가격1" }, { "841", "가격2" },
    { "842", "가격3" }, { "508", "가격4" }, { "401", "가격5" },
  },
}
