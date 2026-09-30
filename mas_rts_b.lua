-- RTS TYPE='B' (체결, Execution Price).

local mas = _G.mas or {}
_G.mas = mas
mas.rts_defs = mas.rts_defs or {}

-- The last 3 fields (f820, f718, f719) are NXT-only: issues without an exchange prefix (KRX only) have
-- exactly 36 fields, "M."/"N." ones exactly 39. The 3 fields are absent from `rec` (nil) in the 36-field case.

-- Reversal detector: is f027 lower than the previous record of the same (flow, exchange, key)?
-- eval() is idempotent per seq_index (Wireshark dissects in several passes): the result is cached,
-- as the frame number of the preceding higher-f027 record if reversed, else false.
-- Returns (reversed, that frame number).
local function new_reversal()
  local last, last_frame, cache = {}, {}, {}
  local flow_frame, flow   -- flow string of the frame being dissected, built once per frame
  local self = {}

  function self:eval(seq_index, pinfo, exchange, rec_key, acc_str)
    local c = cache[seq_index]
    if c ~= nil then return c ~= false, c or nil end
    if pinfo.number ~= flow_frame then flow_frame, flow = pinfo.number, mas.stream_key(pinfo) end
    local key = flow .. "\0" .. exchange .. "\0" .. rec_key
    local acc = tonumber(acc_str)
    local prev = last[key]
    local rev = prev ~= nil and acc ~= nil and acc < prev
    local prev_frame = rev and last_frame[key]
    if acc ~= nil then
      last[key] = acc
      last_frame[key] = pinfo.number
    end
    cache[seq_index] = prev_frame
    return rev, prev_frame or nil
  end

  function self:reset()
    last, last_frame, cache, flow_frame = {}, {}, {}, nil
  end

  return self
end

local reversal = new_reversal()

-- `f024` is a 코드+수치 field: a leading 1..5 전일대비구분 code, then the magnitude
-- (e.g. "212900" = 상승 12900); `|f023| - signed(f024)` equals `|f023|/(1+f033/100)` (기준가).
mas.rts_defs[#mas.rts_defs + 1] = {
  type = "B", exchange = true, base_count = 36, coded = { f024 = true },
  fields = {
    { "034", "체결시간" }, { "023", "현재가" }, { "024", "전일대비" }, { "033", "등락율" },
    { "025", "매도호가" }, { "026", "매수호가" }, { "032", "체결량" }, { "027", "거래량" },
    { "028", "거래대금" }, { "029", "시가" }, { "030", "고가" }, { "031", "저가" },
    { "251", "전대비율" }, { "252", "가중평균" }, { "355", "PER" }, { "273", "LP잔량" },
    { "274", "LP비율" }, { "299", "시가총액" }, { "387", "체결강도" }, { "388", "3M체결강도" },
    { "270", "10M체결강도" }, { "271", "30M체결강도" }, { "272", "60M체결강도" },
    { "266", "5일평균체강" }, { "267", "10일평균체강" }, { "268", "20일평균체강" },
    { "269", "60일평균체강" }, { "036", "매도총량" }, { "039", "매수총량" }, { "241", "매도량1" },
    { "242", "매수량1" }, { "275", "LP잔량대비" }, { "720", "정적VI예상상한가" },
    { "721", "정적VI예상하한가" }, { "820", "체결시장구분" }, { "718", "NXT VI예상상한가" },
    { "719", "NXT 정적VI예상하한가" },
  },
  init = function() reversal:reset() end,
  extra_fields = function(pf) pf.reversed = ProtoField.bool("mas.rts.B.reversed", "역전") end,
  after = function(sub, tvb, base, rec, pinfo, msg_index, pf, def)
    -- flag a record whose 누적거래량 (f027) went backwards
    local k = def.index.f027
    local rev, prev_frame = reversal:eval(
      pinfo.number * 1000 + msg_index, pinfo, rec.exchange, rec.key, rec.f027)
    local ti = sub:add(pf.reversed, tvb(base + rec.__off[k], rec.__len[k]), rev)
    if rev and prev_frame then ti:append_text(string.format(" (#%d)", prev_frame)) end
  end,
}
