-- RTS TYPE='6' (NXT종가매매/KRX종가 (2024.12.12 add)). UNVERIFIED: no samples; the layout, framing (key + hidden marker + spec fields) and
-- plain char-array values are assumed from the protocol spec.

local mas = _G.mas or {}
_G.mas = mas
mas.rts_defs = mas.rts_defs or {}

mas.rts_defs[#mas.rts_defs + 1] = {
  type = "6", strip = "retry", euckr = true,
  fields = {
    { "924", "KRX종가" }, { "928", "KRX종가전일대비(부호포함)" }, { "929", "KRX종가등락률" },
    { "925", "NXT종가매매매도잔량" }, { "926", "NXT종가매매매수잔량" },
    { "927", "NXT종가매매순매수잔량" },
  },
}
