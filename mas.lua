-- MAS Wireshark plugin core: AXIS gateway transport (G/W frames).
--
-- G/W HEADER (12 bytes): SOF(0xFE 0xFE) CTRL(1) SESS(1) CHCK(1) RSVD(2) LENGTH(5 ASCII); LENGTH counts the payload,
-- NUL padding follows to the next frame.
--   CTRL  0x01 Normal, 0x02 ACK, 0x03 NAK, 0x04 POLL, 0x05 CheckSession
--   SESS  0x01 Transaction, 0x08 RTS, 0x99 SessionEnd
--   CHCK  0x20 always set, 0x02 compressed (LZO), 0x08 continuation, 0x01 ACK request, 0x80 error
-- SESS handlers: mas_rts.lua (RTS) and mas_tr.lua (Transaction). Message decoders, one file per TYPE/MSGK:
-- mas_rts_<t>.lua (register in mas.rts_defs) and mas_tr_90.lua (mas.by_msgk). A lowercase TYPE gets an "l" prefix
-- (mas_rts_lm.lua for 'm') so it cannot collide with an uppercase twin; the filter prefix and registration key
-- stay the literal wire byte.
--
-- Copy ALL files into the plugins dir. They share the global `_G.mas`; load order is not relied upon.

local mas = _G.mas or {}
_G.mas = mas
mas.by_sess = mas.by_sess or {}   -- SESS value -> { label, add(gw,tvb,poff,plen,payload,pinfo) }

-- CTRL / SESS constants and names.
mas.CTRL_POLL = 0x04
mas.SESS_RTS  = 0x08
mas.SESS_TRAN = 0x01
mas.CTRL_NAMES = { [0x01]="Normal", [0x02]="ACK", [0x03]="NAK",
                   [0x04]="POLL", [0x05]="CheckSession" }
mas.SESS_NAMES = { [0x01]="Transaction", [0x08]="RTS", [0x99]="SessionEnd" }

-- Single-bit test (avoids relying on Lua 5.3 bitwise operators).
function mas.hasbit(v, mask) return v % (mask + mask) >= mask end

-- 5-tuple key for a packet: used by reassembly (here) and B's reversal detection.
function mas.stream_key(pinfo)
  return tostring(pinfo.src) .. ":" .. pinfo.src_port .. "->" ..
         tostring(pinfo.dst) .. ":" .. pinfo.dst_port
end

local SOF2 = string.char(0xFE, 0xFE)

-- Scan a byte string into ordered items. Returns (items, pending):
--   item {t="mas", off, total, ctrl, sess, chck, len, payload}  -- one G/W frame
--   item {t="data", off, len}                                   -- junk / non-frame bytes
-- `pending` = {offset, needed} for a truncated G/W frame at the tail (reassembly).
-- Offsets are 0-based. NUL padding between frames is skipped.
function mas.scan(buf)
  local items, pending = {}, nil
  local n = #buf
  local i = 0
  while i < n do
    while i < n and buf:byte(i + 1) == 0 do i = i + 1 end   -- skip NUL padding
    if i >= n then break end
    local avail = n - i
    if avail < 2 then
      -- Too little left to be the 2-byte SOF: junk unless it could be the start of one
      -- (a lone trailing 0xFE), in which case wait for more bytes.
      if buf:sub(i + 1, n) == SOF2:sub(1, avail) then
        pending = { offset = i, needed = 2 - avail }
      else
        items[#items + 1] = { t = "data", off = i, len = avail }
      end
      break
    end
    if buf:sub(i + 1, i + 2) == SOF2 then
      if avail < 12 then                                     -- header incomplete
        pending = { offset = i, needed = 12 - avail }
        break
      end
      local lens = buf:sub(i + 8, i + 12)                    -- LENGTH: 5 ASCII digits
      if not lens:match("^%d%d%d%d%d$") then
        items[#items + 1] = { t = "data", off = i, len = 2 } -- bogus header, resync
        i = i + 2
      else
        local L = tonumber(lens)
        local total = 12 + L
        if i + total > n then                                -- payload truncated
          pending = { offset = i, needed = (i + total) - n }
          break
        end
        items[#items + 1] = {
          t = "mas", off = i, total = total,
          ctrl = buf:byte(i + 3), sess = buf:byte(i + 4), chck = buf:byte(i + 5),
          len = L, payload = buf:sub(i + 13, i + total),
        }
        i = i + total
      end
    else                                                     -- junk until next FE FE
      local nxt = buf:find(SOF2, i + 1, true)
      local endp
      if nxt then
        endp = nxt - 1
      else
        -- No full SOF2 ahead; keep a lone trailing 0xFE out of the junk run.
        endp = (buf:byte(n) == 0xFE) and (n - 1) or n
      end
      items[#items + 1] = { t = "data", off = i, len = endp - i }
      i = endp
    end
  end
  return items, pending
end

if _G.Proto then
  -- `mas` is the only registered protocol; every other file appends its fields to it.
  -- `or` because another file may create it first (load order is not relied on).
  mas.proto = mas.proto or Proto("mas", "Mirae Asset Securities")
  local proto = mas.proto

  -- G/W header fields (common to every MAS frame).
  local pf = {
    ctrl       = ProtoField.uint8("mas.ctrl", "ctrl", base.HEX, mas.CTRL_NAMES),
    sess       = ProtoField.uint8("mas.sess", "sess", base.HEX, mas.SESS_NAMES),
    chck       = ProtoField.uint8("mas.chck", "chck", base.HEX),
    compressed = ProtoField.bool("mas.compressed", "compressed"),
    continued  = ProtoField.bool("mas.continued", "continuation"),
    length     = ProtoField.uint32("mas.length", "length"),
    data       = ProtoField.bytes("mas.data", "data"),
  }
  proto.fields = { pf.ctrl, pf.sess, pf.chck, pf.compressed, pf.continued, pf.length, pf.data }
  mas.pf_data = pf.data   -- stream modules reuse this for undecodable bodies

  proto.prefs.port = Pref.uint("TCP port", 15201, "TCP port to auto-bind MAS to (either direction); irrelevant when manually applied via Decode As")
  local bound_port

  -- Reassembly continuation tracking.
  local carry = {}       -- [stream key] = frame number that left an incomplete tail
  local cont_from = {}   -- [frame number] = earlier frame this one continues from
  local info_frame       -- last frame whose Info column we took over

  function proto.init()
    carry = {}; cont_from = {}; info_frame = nil
    for _, h in pairs(mas.by_sess) do if h.init then h.init() end end
  end

  local function gw_label(item)
    if item.ctrl == mas.CTRL_POLL then return "POLL" end
    local name = mas.SESS_NAMES[item.sess] or string.format("SESS 0x%02x", item.sess)
    local tag = mas.hasbit(item.chck, 0x02) and " [compressed]" or ""
    return string.format("%s%s (%d bytes)", name, tag, item.len)
  end

  -- Add the G/W header fields under a frame subtree.
  local function add_gw_header(gw, tvb, item)
    gw:add(pf.ctrl, tvb(item.off + 2, 1))
    gw:add(pf.sess, tvb(item.off + 3, 1))
    gw:add(pf.chck, tvb(item.off + 4, 1))
    gw:add(pf.compressed, tvb(item.off + 4, 1), mas.hasbit(item.chck, 0x02))
    gw:add(pf.continued,  tvb(item.off + 4, 1), mas.hasbit(item.chck, 0x08))
    gw:add(pf.length, tvb(item.off + 7, 5), item.len)
  end

  function proto.dissector(tvb, pinfo, tree)
    -- No src_port re-check: recognition is by content (does mas.scan find a G/W frame?), so a
    -- manual "Decode As" on any port works; non-MAS bytes show up as "Unspecified".
    local buf = tvb:raw()
    if not buf or #buf == 0 then return 0 end

    local items, pending = mas.scan(buf)
    pinfo.cols.protocol = "MAS"
    local tree_root = tree:add(proto, tvb())

    -- Info column counts by CTRL/SESS, not decode success: RTS, Transaction, POLL, then
    -- Unspecified (other CTRL/SESS such as ACK/NAK/SessionEnd, plus junk bytes), in that order.
    -- RTS/Transaction count the messages actually contained (an RTS frame holds several
    -- records, a Transaction frame exactly one); a compressed payload or missing handler
    -- counts the frame itself as 1. E.g. "RTS:2 Transaction:1 POLL Unspecified".
    local cnt = { RTS = 0, Transaction = 0, POLL = 0, Unspecified = 0 }

    local nmsg = 0
    for _, it in ipairs(items) do
      if it.t == "data" then
        tree_root:add(pf.data, tvb(it.off, it.len))
        cnt.Unspecified = cnt.Unspecified + 1
      else
        nmsg = nmsg + 1
        local gw = tree_root:add(proto, tvb(it.off, it.total), gw_label(it))
        add_gw_header(gw, tvb, it)
        local poff, plen = it.off + 12, it.len
        if it.ctrl == mas.CTRL_POLL then
          cnt.POLL = cnt.POLL + 1
          if plen > 0 then gw:add(pf.data, tvb(poff, plen)) end
        else
          local label = (it.sess == mas.SESS_RTS) and "RTS"
                     or (it.sess == mas.SESS_TRAN) and "Transaction"
                     or "Unspecified"
          local n = 1   -- default: this frame is one unit (compressed / no handler / unclassified SESS)
          if mas.hasbit(it.chck, 0x02) then               -- compressed (LZO) -> raw, contents unknowable
            if plen > 0 then gw:add(pf.data, tvb(poff, plen)) end
          else
            local h = mas.by_sess[it.sess]
            if h and plen > 0 then
              n = h.add(gw, tvb, poff, plen, it.payload, pinfo) or 1
            elseif plen > 0 then
              gw:add(pf.data, tvb(poff, plen))
            end
          end
          cnt[label] = cnt[label] + n
        end
      end
    end

    -- Continuation marker: which earlier frame this frame's first bytes continue.
    local from
    if not pinfo.visited and cont_from[pinfo.number] == nil then
      local key = mas.stream_key(pinfo)
      from = carry[key]
      cont_from[pinfo.number] = from or false
      carry[key] = pending and pinfo.number or nil
    else
      from = cont_from[pinfo.number] or nil
    end

    -- RTS/Transaction always show ":count" (even 1); POLL/Unspecified show the bare word.
    -- No items at all (e.g. a lone 0xFE awaiting reassembly) falls back to "Unspecified".
    local ALWAYS_COUNT = { RTS = true, Transaction = true }
    local parts = {}
    for _, lbl in ipairs({ "RTS", "Transaction", "POLL", "Unspecified" }) do
      local c = cnt[lbl]
      if c > 0 then
        parts[#parts + 1] = ALWAYS_COUNT[lbl] and (lbl .. ":" .. c) or lbl
      end
    end
    local info = table.concat(parts, " ")
    if info == "" then info = "Unspecified" end
    info = info .. " "
    -- Own the whole Info column: clear on the first call for this frame, append on later ones
    -- (reassembly can call several times).
    if info_frame ~= pinfo.number then
      info_frame = pinfo.number
      if from then info = string.format("(#%d)", from) .. info end
      pinfo.cols.info:clear()
      pinfo.cols.info:append(info)
    elseif nmsg > 0 then
      pinfo.cols.info:append(info)
    end

    if pending then
      pinfo.desegment_offset = pending.offset
      pinfo.desegment_len = pending.needed
    end
    return #buf
  end

  local function apply_port()
    local tcp = DissectorTable.get("tcp.port")
    if bound_port then tcp:remove(bound_port, proto) end
    bound_port = proto.prefs.port
    tcp:add(bound_port, proto)
  end
  apply_port()
  function proto.prefs_changed() apply_port() end
end

return mas
