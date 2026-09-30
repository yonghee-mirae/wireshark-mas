-- RTS TYPE='Z' (투자자AMT, Investor Type Amount): the same 16 categories as 'Y' with amounts (spec codes = Y's + 400).

local mas = _G.mas or {}
_G.mas = mas
mas.rts_defs = mas.rts_defs or {}

-- 16 investor categories identified by code only, as in mas_rts_y.lua
-- (매도AMT = base, 매수AMT = base+100, 순매수A = base+200).
-- `key` is a market key, not a stock code: no exchange split.
mas.rts_defs[#mas.rts_defs + 1] = {
  type = "Z",
  fields = {
    { "034", "처리시간" }, { "501", "매도AMT" }, { "601", "매수AMT" }, { "701", "순매수A" },
    { "502", "매도AMT" }, { "602", "매수AMT" }, { "702", "순매수A" }, { "503", "매도AMT" },
    { "603", "매수AMT" }, { "703", "순매수A" }, { "504", "매도AMT" }, { "604", "매수AMT" },
    { "704", "순매수A" }, { "505", "매도AMT" }, { "605", "매수AMT" }, { "705", "순매수A" },
    { "506", "매도AMT" }, { "606", "매수AMT" }, { "706", "순매수A" }, { "507", "매도AMT" },
    { "607", "매수AMT" }, { "707", "순매수A" }, { "508", "매도AMT" }, { "608", "매수AMT" },
    { "708", "순매수A" }, { "509", "매도AMT" }, { "609", "매수AMT" }, { "709", "순매수A" },
    { "510", "매도AMT" }, { "610", "매수AMT" }, { "710", "순매수A" }, { "530", "매도AMT" },
    { "630", "매수AMT" }, { "730", "순매수A" }, { "531", "매도AMT" }, { "631", "매수AMT" },
    { "731", "순매수A" }, { "560", "매도AMT" }, { "660", "매수AMT" }, { "760", "순매수A" },
    { "570", "매도AMT" }, { "670", "매수AMT" }, { "770", "순매수A" }, { "571", "매도AMT" },
    { "671", "매수AMT" }, { "771", "순매수A" }, { "590", "매도AMT" }, { "690", "매수AMT" },
    { "790", "순매수A" },
  },
}
