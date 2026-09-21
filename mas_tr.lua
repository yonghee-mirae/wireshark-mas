-- MAS Transaction layer (G/W SESS=0x01) — generic AXIS-HEADER framing + MSGK dispatch.
--
-- Transaction payload (the G/W frame's LENGTH-bytes body) is:
--   AXIS-HEADER(24) + TR-DATA
--     MSGK(1) ACTF(1) CHKF(1) XWIN(1) YWIN(1) KEYV(2) SVCC(4) TRNM(8) LENGTH(5 ASCII)
-- MSGK selects the transaction kind. This module owns only the generic framing
-- and dispatch; each MSGK's actual decoder lives in its own file (e.g.
-- mas_tr_90.lua for MSGK=0x90/UMP) and registers itself into
-- `mas.by_msgk[MSGK] = { add = function(sub, tvb, poff, plen, pinfo) ... end }`.
-- Every Transaction's subtree label is the generic "msgk: <name> (0x<hex>)"
-- (MSGK is always readable from AXIS-HEADER regardless of decode success) —
-- an unregistered MSGK, or an encrypted one (ACTF encryption bit set), gets
-- the same label, just without any MSGK-specific fields underneath (raw
-- `mas.data` instead). Every Transaction — decoded or not — is tagged
-- with the umbrella `mas` proto, never a per-MSGK child proto (see PROTOCOL.md
-- §4.7): existence filters on a child proto turned out to diverge from
-- field-value filters in confusing ways, so specific filtering is
-- field-value-only (e.g. `mas.tr.msgk == 0x90`, or a MSGK-specific field like
-- `mas.tr.90.950`).
--
-- Wireshark registration only (no pure helpers needed by tests). Coordinates
-- with core via _G.mas.

local mas = _G.mas or {}
_G.mas = mas
mas.by_sess = mas.by_sess or {}
mas.by_msgk = mas.by_msgk or {}

mas.MSGK_NAMES = {
  [0x20] = "Normal", [0x50] = "RTS", [0x80] = "Key Exchange", [0x81] = "Cert Key",
  [0x90] = "UMP", [0x91] = "Dialog Popup", [0x92] = "Error",
  [0x5f] = "RTS On/Off",
}

if _G.Proto then
  -- No dedicated Proto here — `mas` is the only registered protocol (§4.7).
  -- Fields are appended to the shared mas.proto (cumulative; see PROTOCOL.md §6).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")

  -- AXIS-HEADER fields (common to every SESS=0x01 Transaction frame, any MSGK).
  local pf = {
    msgk = ProtoField.uint8("mas.tr.msgk", "msgk", base.HEX, mas.MSGK_NAMES),
    actf = ProtoField.uint8("mas.tr.actf", "actf", base.HEX),
    encrypted = ProtoField.bool("mas.tr.encrypted", "encrypted"),
    svcc = ProtoField.string("mas.tr.svcc", "svcc"),
    trnm = ProtoField.string("mas.tr.trnm", "trnm"),
    length = ProtoField.uint32("mas.tr.length", "length"),
  }
  mas.proto.fields = { pf.msgk, pf.actf, pf.encrypted, pf.svcc, pf.trnm, pf.length }

  -- Add the AXIS-HEADER fields under `sub`. LENGTH is a 5-digit ASCII char array
  -- (e.g. "00672"), not a 4-byte binary uint32, so its value is parsed from the
  -- digit characters and passed explicitly — the tvbrange is only for
  -- highlighting the underlying bytes in the packet view.
  local function add_axis_header(sub, tvb, poff)
    local actf = tvb(poff + 1, 1):uint()
    sub:add(pf.msgk, tvb(poff, 1))
    sub:add(pf.actf, tvb(poff + 1, 1))
    sub:add(pf.encrypted, tvb(poff + 1, 1), mas.hasbit(actf, 0x02))
    sub:add(pf.svcc, tvb(poff + 7, 4))
    sub:add(pf.trnm, tvb(poff + 11, 8))
    local lenv = tonumber(tvb(poff + 19, 5):string()) or 0
    sub:add(pf.length, tvb(poff + 19, 5), lenv)
  end

  -- SESS=0x01 (Transaction) handler: peek MSGK/ACTF, dispatch to the registered
  -- decoder. A Transaction G/W frame always holds exactly one AXIS-HEADER+TR-DATA
  -- message, so no count is returned (mas.lua defaults to 1).
  local function add_transaction(gw, tvb, poff, plen, payload, pinfo)
    if plen < 24 then
      if plen > 0 then gw:add(mas.pf_data, tvb(poff, plen)) end
      return
    end
    local msgk_byte, actf_byte = payload:byte(1), payload:byte(2)
    local h = mas.by_msgk[msgk_byte]
    local will_decode = h ~= nil and not mas.hasbit(actf_byte, 0x02)
    local title = string.format("msgk: %s (0x%02x)", mas.MSGK_NAMES[msgk_byte] or "?", msgk_byte)
    local sub = gw:add(mas.proto, tvb(poff, plen),
      title .. " (" .. (plen - 24) .. " bytes)")
    add_axis_header(sub, tvb, poff)

    if will_decode then
      h.add(sub, tvb, poff, plen, pinfo)
      return
    end
    if plen - 24 > 0 then sub:add(mas.pf_data, tvb(poff + 24, plen - 24)) end
  end

  mas.by_sess[mas.SESS_TRAN] = { add = add_transaction }
end

return {}
