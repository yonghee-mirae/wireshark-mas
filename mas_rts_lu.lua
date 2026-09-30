-- RTS TYPE='u' (해외주식 체결, After Market): the layout of TYPE 's' with the after-market price block. f724 is a
-- 코드+수치 field (see mas_rts_ls.lua): f635 + signed(f724) == f723. The body ends with one stray tab before the NUL.

local mas = _G.mas or {}
_G.mas = mas
mas.rts_defs = mas.rts_defs or {}

mas.rts_defs[#mas.rts_defs + 1] = {
  type = "u", strip = "always", coded = { f724 = true },
  fields = {
    { "888", "실시간구분" }, { "480", "가격소수점자리수" }, { "310", "영업일자" },
    { "146", "자료일자(한국)" }, { "034", "자료시간(한국)" }, { "672", "장구분" },
    { "735", "After전일대비구분" }, { "387", "체결량구분" }, { "035", "체결구분" },
    { "635", "기준가" }, { "723", "After현재가" }, { "724", "After전일대비" },
    { "733", "After등락율" }, { "029", "시가" }, { "030", "고가" }, { "031", "저가" },
    { "026", "매수호가" }, { "025", "매도호가" }, { "032", "단위거래량" },
    { "722", "단위거래대금(천)" }, { "027", "누적거래량" }, { "028", "누적거래대금(천)" },
    { "488", "시가대비등락율" }, { "487", "고가대비등락율" }, { "489", "저가대비등락율" },
    { "252", "가중평균가" }, { "251", "전일거래비" }, { "388", "체결강도" },
    { "676", "차트 Tick,N분 SKIP구분" },
  },
}
