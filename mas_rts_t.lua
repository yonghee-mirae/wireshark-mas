-- RTS TYPE='T' (시황제목). UNVERIFIED: no samples; the layout, framing (key + hidden marker + spec fields) and
-- plain char-array values are assumed from the protocol spec.

local mas = _G.mas or {}
_G.mas = mas
mas.rts_defs = mas.rts_defs or {}

mas.rts_defs[#mas.rts_defs + 1] = {
  type = "T", strip = "retry", euckr = true,
  fields = {
    { "015", "T_내용" }, { "014", "T_KEY" }, { "301", "코드" }, { "022", "종목명" },
    { "041", "KEY1" }, { "042", "KEY2" }, { "043", "시간" }, { "044", "분류" }, { "045", "분류2" },
    { "046", "XFLG" }, { "047", "일자" }, { "048", "현재가" }, { "049", "거래량" },
    { "024", "대비기호" }, { "099", "TEST" }, { "371", "장구분" },
  },
}
