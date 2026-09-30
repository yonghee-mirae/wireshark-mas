-- RTS TYPE='m' (시황제목/통합뉴스, Market Commentary Headline). f044/f045 look like a news provider's short
-- code/full name (e.g. "한차"/"한경차이나"): semantics not fully confirmed.

local mas = _G.mas or {}
_G.mas = mas
mas.rts_defs = mas.rts_defs or {}

mas.rts_defs[#mas.rts_defs + 1] = {
  type = "m", euckr = true,
  fields = {
    { "015", "내용" }, { "301", "종목코드" }, { "022", "종목명" }, { "041", "KEY1" },
    { "042", "KEY2" }, { "043", "시간" }, { "044", "분류" }, { "045", "분류2" },
    { "046", "제공처" }, { "047", "일자" }, { "048", "현재가" }, { "049", "거래량" },
    { "024", "대비기호" }, { "050", "KEY3" },
  },
}
