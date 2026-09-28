-- MAS RTS TYPE='r'/'e'(소문자) 필드 레이아웃 — 해외선물옵션 체결
-- (Overseas Futures/Options Execution), incl. 'e' (SnapShot Filter variant).
--
-- Filename note: both TYPEs are already-lowercase letters. The FILENAME
-- convention lowercases the TYPE letter (e.g. TYPE='B' -> mas_rts_b.lua),
-- which would collide with a hypothetical future TYPE='R'/'E' (uppercase;
-- 'R' already exists, see mas_rts_r.lua's reservation note in
-- PROTOCOL.md/memory) — so this module is named `mas_rts_lre.lua`
-- ("lower r/e") instead of `mas_rts_r.lua`/`mas_rts_e.lua`, reserving those
-- plain names for hypothetical future TYPE='R'-family/'E' uppercase letters
-- (same reasoning as mas_rts_lm.lua/mas_rts_ls.lua/mas_rts_lq.lua). This is
-- filename-only: the registration keys (mas.by_rts_type["r"],
-- mas.by_rts_type["e"]) and the Wireshark FILTER prefixes (`mas.rts.r.*`,
-- `mas.rts.e.*`) both use the literal wire byte as-is.
--
-- protocols/해외.txt: "type e / 해외선물옵션 체결(SnapShot Filter) ... type r와
-- 동일" — 'r' and 'e' share the exact same 15-field layout, differing only
-- in which RTS-DATA TYPE byte selects them on the wire (a snapshot-filtered
-- subscription vs the regular stream). Both are registered here against the
-- same decode()/add() so there's exactly one implementation to maintain, but
-- **each gets its own ProtoField prefix** (`mas.rts.r.<field>` vs
-- `mas.rts.e.<field>`) rather than a merged `mas.rts.re.<field>` — this
-- matches every other TYPE's "the field prefix alone identifies which TYPE
-- produced it" convention (§4.7: e.g. `mas.rts.B.price` implies TYPE='B'),
-- so a filter like `mas.rts.r.price` only ever matches TYPE='r' records,
-- with no need to additionally check `mas.rts.type`. Only `r` has ever been
-- observed on the wire so far (samples/GlobalPart_RTS.pcapng, 340 records,
-- 'e' never seen) — `e`'s field set is registered from the same spec/code
-- path but is unverified against real capture data.
--
-- One RTS-DATA record's DATA (see mas_rts.lua for RTS-HEADER framing) is a
-- 15-field tab-separated body (spec: protocols/해외.txt). This is the only
-- pair of RTS TYPEs this module decodes; every other TYPE is left to
-- mas_rts.lua's generic "type: <TYPE>"-only handling.
--
-- `024`(change/전일대비) is a **코드+수치** field, same convention as
-- mas_rts_ls.lua's `change`/`regular_change`/`day_regular_diff`: leading
-- char is the 전일대비구분 code (1=상한/2=상승/3=보합/4=하한/5=하락), rest is
-- the ASCII decimal magnitude. Confirmed (samples/GlobalPart_RTS.pcapng, 340
-- real 'r' records, symbol CLX26): `|price| - decode_coded(change)` is
-- exactly constant (90.52) across all 340 records — the implied 기준가.
--
-- `price`/`ask_price`/`bid_price`/`open_price`/`high_price`/`low_price` are
-- **sign+magnitude** fields whose leading character (`+`/`-`/`' '`=보합) is
-- NOT the price's own math sign (a real price is never negative) — it's an
-- informational flag meaning "this field's magnitude is >= (`+`) or <
-- (`-`) 기준가". Confirmed via an unrelated, much larger, diverse real
-- dataset: TYPE='B' (mas_rts_b.lua, samples/tcp_capture.cap, 1777 domestic
-- execution records) has the identical field family/sign convention, and
-- checking `magnitude >= |price|/(1+change_rate%)` against every
-- open/high/low_price gave 0 mismatches across 5327 checks, including 8
-- records with a within-record sign split (proving it's not a shared
-- per-record direction flag). Re-ran the same check against 'r's own 340
-- records (base=90.52 from the `change` decode above) for
-- ask/bid/open/high/low_price: 0/340 mismatches too. Displayed as-is
-- (plain string, exact wire bytes) — no derived/stripped numeric field is
-- registered, since Wireshark showing the literal wire value is correct
-- here and no specific display format was requested (unlike `change`'s
-- 코드+수치 convention, which design/field_spec.md does specify).
-- `change_rate`(033/등락율) is sign(+/-/' ')+value where `value` itself can
-- carry its own sign (down days: "--0.93" double-dash) — shown as-is, plain.
--
-- Pure helpers (decode/decode_coded, required by tests) + Wireshark registration.
-- Coordinates with core via _G.mas.

local mas = _G.mas or {}
_G.mas = mas
mas.by_rts_type = mas.by_rts_type or {}

local LRE = {}   -- module table: pure helpers (returned for tests)

LRE.TYPE_OVERSEAS_FUT_EXEC = "r"       -- observed on the wire
LRE.TYPE_OVERSEAS_FUT_EXEC_SNAPSHOT = "e"   -- spec-only variant, same layout

-- 전일대비구분 code -> sign, same 1..5 dictionary as mas_rts_ls.lua's
-- S.CHANGE_SIGN (duplicated locally per this project's per-file convention).
LRE.CHANGE_SIGN = { ["1"] = 1, ["2"] = 1, ["3"] = 0, ["4"] = -1, ["5"] = -1 }

-- 전일대비구분 code -> Korean meaning, for detail-pane annotation.
LRE.CHANGE_LABEL = { ["1"] = "상한", ["2"] = "상승", ["3"] = "보합", ["4"] = "하한", ["5"] = "하락" }

-- Field order (0-based index 0..14), for RTS TYPE='r'/'e' (Overseas
-- Futures/Options Execution).
LRE.FIELD_NAMES = {
  "key", "type_echo", "trade_time", "price", "change", "change_rate",
  "ask_price", "bid_price", "trade_volume", "acc_volume",
  "open_price", "high_price", "low_price", "trade_date", "business_date",
}

-- Decode a 코드+수치 field ("50.84" -> -0.84 하락, "22.67" -> 2.67 상승).
-- Returns nil if the leading character isn't a known 전일대비구분 code or the
-- remainder isn't numeric. Same convention as mas_rts_ls.lua's S.decode_coded.
function LRE.decode_coded(tok)
  if not tok or #tok < 1 then return nil end
  local sign = LRE.CHANGE_SIGN[tok:sub(1, 1)]
  if not sign then return nil end
  local mag = tonumber(tok:sub(2))
  if not mag then return nil end
  return sign * mag
end

-- Split a tab-separated string into fields, stripping trailing NUL bytes from
-- each (see mas_rts_b for the version note). Also returns each field's own
-- 0-based byte range within `s` (post-NUL-strip length) so the detail pane
-- can highlight just that field's bytes instead of the whole record.
local function split_with_offsets(s)
  local fields, offsets = {}, {}
  local start = 1
  while true do
    local sep = s:find("\t", start, true)
    local e = sep and (sep - 1) or #s
    local raw = s:sub(start, e)
    local se = #raw
    while se > 0 and raw:byte(se) == 0 do se = se - 1 end
    fields[#fields + 1] = raw:sub(1, se)
    offsets[#offsets + 1] = { off = start - 1, len = se }
    if not sep then break end
    start = sep + 1
  end
  return fields, offsets
end

-- Split a tab-separated TYPE='r'/'e' body into a record keyed by
-- FIELD_NAMES. Returns nil if field count != 15. `rec.__offsets[name] =
-- {off, len}` gives each field's own byte range within `body`.
function LRE.decode(body)
  local fields, offsets = split_with_offsets(body)
  if #fields ~= #LRE.FIELD_NAMES then return nil end

  local rec = { __offsets = {} }
  for k = 1, #LRE.FIELD_NAMES do
    local name = LRE.FIELD_NAMES[k]
    rec[name] = fields[k]
    rec.__offsets[name] = offsets[k]
  end
  return rec
end

if _G.Proto then
  -- No dedicated Proto here — `mas` is the only registered protocol (§4.7).
  -- Fields are appended to the shared mas.proto (cumulative; see PROTOCOL.md §6).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  -- One field set per wire TYPE letter (see module note above for why).
  local function make_pf(prefix)
    local pf = {}
    for _, name in ipairs(LRE.FIELD_NAMES) do
      pf[name] = ProtoField.string("mas.rts." .. prefix .. "." .. name, name)
    end
    return pf
  end
  local pf_by_type = {
    [LRE.TYPE_OVERSEAS_FUT_EXEC] = make_pf(LRE.TYPE_OVERSEAS_FUT_EXEC),
    [LRE.TYPE_OVERSEAS_FUT_EXEC_SNAPSHOT] = make_pf(LRE.TYPE_OVERSEAS_FUT_EXEC_SNAPSHOT),
  }

  local fields = {}
  for _, pf in pairs(pf_by_type) do
    for _, f in pairs(pf) do fields[#fields + 1] = f end
  end
  mas.proto.fields = fields

  local expert_badfields =
    ProtoExpert.new("mas.rts.re.expert.fields", "Unexpected overseas-futures-execution field count",
      expert.group.MALFORMED, expert.severity.WARN)
  mas.proto.experts = { expert_badfields }

  -- Decode a TYPE='r'/'e' overseas-futures-execution record body into the
  -- tree. The subtree is always tagged with the umbrella `mas` proto (see
  -- PROTOCOL.md §4.7) — a malformed body (wrong field count) is flagged via
  -- expert_badfields instead; "did this decode?" is a field-value question,
  -- not a presence-filter one. `r.type` (the record's actual wire byte, 'r'
  -- or 'e') picks both the label and the field-prefix set, since one add()
  -- function serves both TYPEs.
  local function add_overseas_fut_exec(tree, tvb, poff, r, pinfo, msg_index)
    local rec = LRE.decode(r.body)
    local sub = tree:add(mas.proto, tvb(poff + r.off, 6 + r.len),
      "type: " .. r.type .. " (" .. r.len .. " bytes)")
    mas.rts_add_header(sub, tvb, poff, r)
    if not rec then
      sub:add_proto_expert_info(expert_badfields)
      return false
    end
    local pf = pf_by_type[r.type]
    local base = poff + r.off + 6   -- body start within tvb
    for _, name in ipairs(LRE.FIELD_NAMES) do
      local o = rec.__offsets[name]
      if name == "change" then
        -- 코드&수치 필드: 값에서 코드를 떼어 수치만 보여주고, "값(코드;의미)",
        -- e.g. "0.84 (5;하락)". 코드가 알려지지 않은 값이면 원본 그대로.
        local code = rec[name]:sub(1, 1)
        local label = LRE.CHANGE_LABEL[code]
        if label then
          local ti = sub:add(pf[name], tvb(base + o.off, o.len), rec[name]:sub(2))
          ti:append_text(" (" .. code .. ";" .. label .. ")")
        else
          sub:add(pf[name], tvb(base + o.off, o.len), rec[name])
        end
      else
        sub:add(pf[name], tvb(base + o.off, o.len), rec[name])
      end
    end
    return true
  end

  -- Register for both TYPE='r' and TYPE='e'; mas_rts.lua's generic
  -- dispatcher calls this for every 'r'/'e' record and falls back to a bare
  -- "type: <TYPE>" label itself for any other TYPE.
  mas.by_rts_type[LRE.TYPE_OVERSEAS_FUT_EXEC] = { add = add_overseas_fut_exec }
  mas.by_rts_type[LRE.TYPE_OVERSEAS_FUT_EXEC_SNAPSHOT] = { add = add_overseas_fut_exec }
end

return LRE
