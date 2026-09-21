-- MAS RTS layer (G/W SESS=0x08) — generic RTS-HEADER framing + TYPE dispatch.
--
-- RTS payload (the G/W frame's LENGTH-bytes body) is a repeated RTS-DATA record:
--   KIND(1) DUMY(1) TYPE(1) LENGTH(3 ASCII) DATA(LENGTH, trailing NUL included)
-- TYPE selects the record layout. This module owns only the generic framing and
-- dispatch; each TYPE's actual decoder lives in its own file (e.g.
-- mas_rts_b.lua for TYPE='B') and registers itself into
-- `mas.by_rts_type[TYPE] = { add = function(gw, tvb, poff, r, pinfo, idx) ... end,
--                             init = function() ... end }` (init optional).
-- Every RTS-DATA record's subtree label is the generic "type: <TYPE>" (TYPE is
-- always readable from the RTS-HEADER regardless of decode success) — a TYPE
-- with no registered decoder gets the same label, just without any
-- TYPE-specific fields underneath (raw `mas.data` instead). The one exception
-- is KIND='I' (RTS-Symbol list, a different record kind from KIND='D'/Data):
-- those are labeled "kind: I" instead and never reach TYPE dispatch at all,
-- since TYPE dispatch assumes the KIND='D' layout. Every record —
-- decoded or not — is tagged with the umbrella `mas` proto, never a per-TYPE
-- child proto (see PROTOCOL.md §4.7): existence filters on a child
-- proto/wrapper item turned out to diverge from field-value filters in
-- confusing ways, so specific filtering is field-value-only (e.g.
-- `mas.rts.type == "B"`, or a TYPE-specific field like `mas.rts.B.price`).
--
-- Pure helper (split_records, required by tests) + Wireshark registration.
-- Coordinates with core via _G.mas.

local mas = _G.mas or {}
_G.mas = mas
mas.by_sess = mas.by_sess or {}
mas.by_rts_type = mas.by_rts_type or {}

local R = {}   -- module table: pure helpers (returned for tests)

-- Split an RTS payload into RTS-DATA records: { {kind,dumy,type,len,body,off}, ... }.
-- `off` is the 0-based offset of the record within the payload. Stops (without
-- error) at the first malformed record; callers show the remainder as raw data.
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
  return recs, i   -- i = bytes consumed; payload:sub(i+1) is any unparsed tail
end

if _G.Proto then
  -- No dedicated Proto here — `mas` is the only registered protocol (§4.7).
  -- Fields are appended to the shared mas.proto (cumulative; see PROTOCOL.md §6).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  -- RTS-HEADER fields (common to every RTS-DATA record, any TYPE).
  local pf = {
    kind = ProtoField.string("mas.rts.kind", "kind"),
    type = ProtoField.string("mas.rts.type", "type"),
    reclen = ProtoField.uint32("mas.rts.reclen", "length"),
  }
  mas.proto.fields = { pf.kind, pf.type, pf.reclen }

  -- Add one RTS-DATA record's header fields (KIND/TYPE/LENGTH) under `sub`.
  -- Shared by every TYPE decoder so header display stays identical across types.
  function mas.rts_add_header(sub, tvb, poff, r)
    sub:add(pf.kind, tvb(poff + r.off, 1))
    sub:add(pf.type, tvb(poff + r.off + 2, 1))
    sub:add(pf.reclen, tvb(poff + r.off + 3, 3), r.len)
  end

  -- SESS=0x08 (RTS) handler: split the payload into RTS-DATA records and dispatch
  -- each to its registered TYPE decoder. Returns the number of RTS-DATA records
  -- contained (decoded and unspecified both count) — a single RTS G/W frame's
  -- payload is a repeated RTS-HEADER+RTS-DATA, so this is what mas.lua's Info
  -- column reports for "RTS:n", not a flat 1-per-frame.
  -- Add a raw (no TYPE-specific fields) RTS-DATA record under `gw`, labeled
  -- `label` — shared by the KIND='I' and unregistered-TYPE fallbacks below.
  local function add_raw_record(gw, tvb, poff, r, label)
    local sub = gw:add(mas.proto, tvb(poff + r.off, 6 + r.len),
      label .. " (" .. r.len .. " bytes)")
    mas.rts_add_header(sub, tvb, poff, r)
    if r.len > 0 then sub:add(mas.pf_data, tvb(poff + r.off + 6, r.len)) end
  end

  local function add_rts(gw, tvb, poff, plen, payload, pinfo)
    local recs, consumed = R.split_records(payload)
    for idx, r in ipairs(recs) do
      if r.kind == "I" then
        -- KIND='I' (RTS-Symbol list) is a fundamentally different record kind
        -- from KIND='D' (Data) — TYPE dispatch assumes the KIND='D' layout, so
        -- it's never applied here; labeled by KIND instead of TYPE.
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
