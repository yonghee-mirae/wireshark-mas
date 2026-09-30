-- RTS TYPE='r'/'e' (해외선물옵션 체결, Overseas Futures/Options Execution). 'e' is the snapshot-filter variant with
-- the same layout, never seen on the wire (unverified); each TYPE keeps its own filter prefix (mas.rts.r.* / .e.*).
--   f024 is a 코드+수치 field (as in mas_rts_ls.lua); |f023| - signed(f024) is constant (= 기준가).
--   f023/f025/f026/f029/f030/f031 are sign+magnitude: the leading +/-/space flags magnitude >= / < 기준가, not the
--   price's own sign.
--   f033 is a sign plus a value that may carry its own sign ("--0.93").
-- All are shown as-is.

local mas = _G.mas or {}
_G.mas = mas
mas.rts_defs = mas.rts_defs or {}

-- 'r' is observed on the wire; 'e' is the spec-only variant with the same layout.
mas.rts_defs[#mas.rts_defs + 1] = {
  type = "r", types = { "r", "e" }, expert_id = "re", coded = { f024 = true },
  fields = {
    { "034", "처리시간" }, { "023", "현재가" }, { "024", "전일대비" }, { "033", "등락율" },
    { "025", "매도호가" }, { "026", "매수호가" }, { "032", "체결량" }, { "027", "거래량" },
    { "029", "시가" }, { "030", "고가" }, { "031", "저가" }, { "619", "거래일자" },
    { "618", "영업일" },
  },
}
