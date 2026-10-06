-- MAS RTS layer (G/W SESS=0x08): RTS-HEADER framing, TYPE dispatch and the helpers shared by the TYPE decoders.
--
-- The payload is a repeated RTS-DATA record: KIND(1) DUMY(1) TYPE(1) LENGTH(3 ASCII) DATA(LENGTH, NUL included).
-- Each TYPE decoder (mas_rts_<t>.lua) registers a def in mas.rts_defs (see define_rts_type); a TYPE without one,
-- and KIND='I' (RTS-Symbol list), get a bare label plus raw `mas.data`. Records are tagged with the umbrella `mas`
-- proto and filtered by field value, e.g. `mas.rts.type == "B"`.

local mas = _G.mas or {}
_G.mas = mas
mas.by_sess = mas.by_sess or {}
mas.by_rts_type = mas.by_rts_type or {}

local R = {}   -- module table: pure helpers (returned for tests)

-- Split an RTS payload into { kind, dumy, type, len, body, off } records (off is 0-based);
-- stops at the first malformed one. Returns the records and the bytes consumed.
function R.split_records(payload)
  local recs = {}
  local i, n = 0, #payload
  while i + 6 <= n do
    local ls = payload:sub(i + 4, i + 6)
    if not ls:match("^%d%d%d$") then break end
    local L = tonumber(ls)
    if i + 6 + L > n then break end
    recs[#recs + 1] = {
      kind = payload:sub(i + 1, i + 1), dumy = payload:sub(i + 2, i + 2),
      type = payload:sub(i + 3, i + 3), len = L,
      body = payload:sub(i + 7, i + 6 + L), off = i,
    }
    i = i + 6 + L
  end
  return recs, i
end

-- "M.A035420" -> ("M","A035420"); "A009150" -> ("K","A009150") (no prefix = KRX).
function mas.split_exchange(key)
  local prefix, base = key:match("^([^.]*)%.(.*)$")
  if base then return prefix, base end
  return "K", key
end

-- Split on tabs, stripping trailing NULs from each field. Returns parallel arrays:
-- fields and their 0-based byte offsets/lengths within `s` (no table per field: faster).
local find, sub, byte = string.find, string.sub, string.byte
function mas.split_with_offsets(s)
  local fields, offs, lens, n = {}, {}, {}, 0
  local start = 1
  while true do
    local sep = find(s, "\t", start, true)
    local e = sep and (sep - 1) or #s
    local se = e
    while se >= start and byte(s, se) == 0 do se = se - 1 end
    n = n + 1
    fields[n] = sub(s, start, se)
    offs[n] = start - 1
    lens[n] = se - start + 1
    if not sep then break end
    start = sep + 1
  end
  return fields, offs, lens
end

-- Strip trailing NULs, then one stray tab.
local function rstrip_nul_and_tab(s)
  local e = #s
  while e > 0 and s:byte(e) == 0 do e = e - 1 end
  if e > 0 and s:byte(e) == 9 then e = e - 1 end
  return s:sub(1, e)
end

-- Map of 1-based tab-separated field index of `raw` -> number of NULs in it (the final byte, the
-- record terminator, is ignored).
local function nul_fields(raw)
  local last = (raw:byte(-1) == 0) and #raw - 1 or #raw
  local set, s, k = {}, 1, 1
  while true do
    local t = raw:find("\t", s, true)
    local n = select(2, raw:sub(s, math.min(t and t - 1 or last, last)):gsub("%z", ""))
    if n > 0 then set[k] = n end
    if not t then break end
    s, k = t + 1, k + 1
  end
  return set
end

-- Split an RTS-DATA body into rec[name] = value plus rec.__off[k] / rec.__len[k] (byte range of
-- the k-th field); nil if the field count is wrong. `body` is UTF-8 text; `raw_body` (the
-- untranscoded wire bytes, if different) is used only for the offsets. opts:
--   strip       "retry": drop a stray tab before the NUL if the count is off; "always": up front
--   base_count  a second accepted field count (trailing fields absent)
--   exchange    split the exchange prefix off `key` into rec.exchange
function mas.decode_record(names, body, raw_body, opts)
  opts = opts or {}
  if opts.strip == "always" then
    body = rstrip_nul_and_tab(body)
    raw_body = raw_body and rstrip_nul_and_tab(raw_body)
  end
  local fields, offs, lens = mas.split_with_offsets(body)
  if #fields ~= #names and #fields ~= opts.base_count then
    if opts.strip ~= "retry" then return nil end
    body = rstrip_nul_and_tab(body)
    raw_body = raw_body and rstrip_nul_and_tab(raw_body)
    fields, offs, lens = mas.split_with_offsets(body)
    if #fields ~= #names then return nil end
  end

  if raw_body then
    local _, raw_offs, raw_lens = mas.split_with_offsets(raw_body)
    if #raw_offs == #names then offs, lens = raw_offs, raw_lens end
  end
  local rec = { __off = offs, __len = lens }
  for k = 1, #fields do rec[names[k]] = fields[k] end
  if opts.exchange then rec.exchange, rec.key = mas.split_exchange(rec.key) end
  return rec
end

-- Build FIELD_NAMES and FIELD_SPEC (name -> { filter suffix, label }) from a wire-ordered list:
--   { "023", "현재가" }  name "f023", suffix "023", label "(023)현재가"
--   "key" / "extra"      suffix and label are the name itself
--   "type_echo"          the hidden (000) marker: no spec, never displayed
local function field_tables(list)
  local names, spec = {}, {}
  for i, e in ipairs(list) do
    if type(e) == "table" then
      names[i] = "f" .. e[1]
      spec[names[i]] = { e[1], "(" .. e[1] .. ")" .. e[2] }
    else
      names[i] = e
      if e ~= "type_echo" then spec[e] = { e, e } end
    end
  end
  return names, spec
end

-- 전일대비구분 code -> meaning.
local CHANGE_LABEL = { ["1"] = "상한", ["2"] = "상승", ["3"] = "보합", ["4"] = "하한", ["5"] = "하락" }

-- 코드+수치 field: the value without its leading code plus "code;meaning", e.g.
-- "22.6700" -> "2.6700", "2;상승"; nil for an unknown code (the raw value is shown).
function mas.split_coded(tok)
  local label = CHANGE_LABEL[tok:sub(1, 1)]
  if label then return tok:sub(2), tok:sub(1, 1) .. ";" .. label end
end

-- Define one RTS TYPE decoder from `def`: builds def.names/spec/index/decode, the detail-pane
-- fields, the field-count expert and mas.by_rts_type[TYPE]. Keys:
--   type, fields         TYPE letter; spec fields in wire order (after the implicit "key", "type_echo")
--   strip, base_count    see mas.decode_record
--   exchange             also split the exchange prefix (rec.exchange, field mas.rts.<T>.exchange)
--   euckr                body has EUC-KR text: transcoded before splitting, raw bytes give the offsets
--   coded                set of 코드+수치 field names (mas.split_coded)
--   types, expert_id     several TYPE letters sharing one layout / expert id (default: type)
--   alt                  { when = function(rec) -> bool, labels = { name -> label } }: detail-pane label override
--                        for records where `when` holds (the field and its filter name are unchanged)
--   extra_fields(pf), after(sub, tvb, base, rec, pinfo, msg_index, pf, def), init()   hooks
local function define_rts_type(def)
  local list = { "key", "type_echo" }
  for _, e in ipairs(def.fields) do list[#list + 1] = e end
  def.names, def.spec = field_tables(list)
  def.index = {}   -- name -> wire position (index into rec.__off / rec.__len)
  for k, name in ipairs(def.names) do def.index[name] = k end
  def.decode = function(body, raw_body) return mas.decode_record(def.names, body, raw_body, def) end
  if not _G.Proto then return end

  local types = def.types or { def.type }
  local coded = def.coded or {}
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")   -- the only protocol

  local pf_by_type, fields = {}, {}
  for _, t in ipairs(types) do
    local pf = {}
    for _, name in ipairs(def.names) do
      local sp = def.spec[name]
      if sp then  -- type_echo has no spec
        pf[name] = ProtoField.string("mas.rts." .. t .. "." .. sp[1], sp[2])
      end
    end
    if def.exchange then pf.exchange = ProtoField.string("mas.rts." .. t .. ".exchange", "거래소") end
    if def.extra_fields then def.extra_fields(pf) end
    pf_by_type[t] = pf
    for _, f in pairs(pf) do fields[#fields + 1] = f end
  end
  mas.proto.fields = fields

  local expert_badfields =
    ProtoExpert.new("mas.rts." .. (def.expert_id or types[1]) .. ".expert.fields",
      "Unexpected TYPE " .. table.concat(types, "/") .. " field count",
      expert.group.MALFORMED, expert.severity.WARN)
  mas.proto.experts = { expert_badfields }

  local function add_record(tree, tvb, poff, r, pinfo, msg_index)
    local base = poff + r.off + 6   -- body start within tvb
    local raw = def.euckr and ((r.len > 0) and tvb(base, r.len):raw() or "") or r.body
    -- A NUL anywhere but the final record terminator is a sender bug: drop it from the values, flag it below.
    local bad = raw:find("\0", 1, true)
    bad = bad and bad < #raw
    local rec, nul
    if bad then
      nul = nul_fields(raw)
      local clean
      if def.euckr then   -- tvb:string() stops at a NUL, so convert the NUL-free chunks
        clean = ""
        local s = 1
        while s <= #raw do
          local e = raw:find("\0", s, true) or (#raw + 1)
          if e > s then clean = clean .. tvb(base + s - 1, e - s):string(ENC_EUC_KR) end
          s = e + 1
        end
      else
        clean = raw:gsub("%z", "")
      end
      rec = def.decode(clean, raw)
    elseif def.euckr then
      rec = def.decode((r.len > 0) and tvb(base, r.len):string(ENC_EUC_KR) or "", raw)
    else
      rec = def.decode(r.body)
    end
    local sub = tree:add(mas.proto, tvb(poff + r.off, 6 + r.len),
      "type: " .. r.type .. " (" .. r.len .. " bytes)")
    mas.rts_add_header(sub, tvb, poff, r)
    if not rec then
      sub:add_proto_expert_info(expert_badfields)
      return false
    end
    if mas.collect then mas.collect(pinfo, r, poff, def, rec) end   -- set only while mas_stat_rts.lua collects
    local pf = pf_by_type[r.type]
    local offs, lens = rec.__off, rec.__len
    if def.exchange then
      sub:add(pf.exchange, tvb(base + offs[1], lens[1]), rec.exchange)   -- shown before key
    end
    for k, name in ipairs(def.names) do
      -- Skip fields a shorter record omits (e.g. TYPE B's NXT-only tail): TreeItem:add
      -- would otherwise show the whole tvbrange under them.
      if pf[name] and rec[name] then
        local shown, note = rec[name]
        if coded[name] then shown, note = mas.split_coded(rec[name]) end
        local ti = sub:add(pf[name], tvb(base + offs[k], lens[k]), shown or rec[name])
        if def.alt and def.alt.labels[name] and def.alt.when(rec) then
          ti:set_text(def.alt.labels[name] .. ": " .. (shown or rec[name]))
        end
        if note then ti:append_text(" (" .. note .. ")") end
        if nul and nul[k] then ti:append_text((" (NUL)"):rep(nul[k])) end
      end
    end
    if def.after then def.after(sub, tvb, base, rec, pinfo, msg_index, pf, def) end
    return true
  end

  for _, t in ipairs(types) do
    mas.by_rts_type[t] = { add = add_record, init = def.init, def = def }
  end
end

-- Modules append their def to mas.rts_defs; this works in either load order (Wireshark's
-- plugin order is not guaranteed): queued defs are defined here, later ones on append.
mas.rts_defs = mas.rts_defs or {}
for _, def in ipairs(mas.rts_defs) do define_rts_type(def) end
setmetatable(mas.rts_defs, { __newindex = function(t, k, def)
  rawset(t, k, def)
  define_rts_type(def)
end })

if _G.Proto then
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")   -- the only protocol

  -- RTS-HEADER fields (any TYPE).
  local pf = {
    kind = ProtoField.string("mas.rts.kind", "kind"),
    type = ProtoField.string("mas.rts.type", "type"),
    reclen = ProtoField.uint32("mas.rts.reclen", "length"),
  }
  mas.proto.fields = { pf.kind, pf.type, pf.reclen }

  -- Add the RTS-HEADER fields (KIND/TYPE/LENGTH) under `sub`; shared by all TYPE decoders.
  function mas.rts_add_header(sub, tvb, poff, r)
    sub:add(pf.kind, tvb(poff + r.off, 1))
    sub:add(pf.type, tvb(poff + r.off + 2, 1))
    sub:add(pf.reclen, tvb(poff + r.off + 3, 3), r.len)
  end

  -- Add a record with no TYPE-specific fields under `gw` (KIND='I' and unregistered TYPEs).
  local function add_raw_record(gw, tvb, poff, r, label)
    local sub = gw:add(mas.proto, tvb(poff + r.off, 6 + r.len),
      label .. " (" .. r.len .. " bytes)")
    mas.rts_add_header(sub, tvb, poff, r)
    if r.len > 0 then sub:add(mas.pf_data, tvb(poff + r.off + 6, r.len)) end
  end

  -- SESS=0x08 handler: split the payload into RTS-DATA records and dispatch each by TYPE.
  -- Returns the record count (shown in the Info column as "RTS:n").
  local function add_rts(gw, tvb, poff, plen, payload, pinfo)
    local recs, consumed = R.split_records(payload)
    for idx, r in ipairs(recs) do
      if r.kind == "I" then
        -- KIND='I' (RTS-Symbol list) is not the KIND='D' layout TYPE dispatch assumes.
        add_raw_record(gw, tvb, poff, r, "kind: I")
      else
        local h = mas.by_rts_type[r.type]
        if h then
          h.add(gw, tvb, poff, r, pinfo, idx)
        else
          add_raw_record(gw, tvb, poff, r, "type: " .. r.type)
        end
      end
    end
    if consumed < plen then gw:add(mas.pf_data, tvb(poff + consumed, plen - consumed)) end
    return #recs
  end

  mas.by_sess[mas.SESS_RTS] = {
    add = add_rts,
    init = function()
      for _, h in pairs(mas.by_rts_type) do
        if h.init then h.init() end
      end
    end,
  }
end

return R
