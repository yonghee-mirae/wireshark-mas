-- MAS Wireshark plugin — core (AXIS gateway transport + shared GUI).
--
-- Wire format (AXIS 4.x, cross-checked with the protocol doc):
--   Layer 1  G/W HEADER (12 bytes):
--     SOF(0xFE) SOF(0xFE) CTRL(1) SESS(1) CHCK(1) RSVD(2) LENGTH(5 ASCII)
--       CTRL  0x01 Normal, 0x02 ACK, 0x03 NAK, 0x04 POLL(heartbeat), 0x05 CheckSession
--       SESS  0x01 Transaction, 0x08 RTS(realtime), 0x99 SessionEnd
--       CHCK  bit 0x20 always, 0x02 compressed(LZO), 0x08 continuation, 0x01 ACK-req, 0x80 error
--       LENGTH payload length (bytes after the G/W header); NUL padding follows to the next frame
--   Layer 2  depends on SESS (parsed by the stream modules):
--     SESS 0x08 RTS         -> [ RTS-HEADER(6) + RTS-DATA ] repeated   (mas_execution_price.lua)
--     SESS 0x01 Transaction -> AXIS-HEADER(24) + TR-DATA               (mas_order_report.lua)
--
-- Multi-file plugin (copy ALL into the plugins dir): mas.lua (this),
-- mas_execution_price.lua, mas_order_report.lua. They coordinate through the
-- shared global `_G.mas`; each stream module registers a handler by SESS value.
-- Only the two supported inner protocols are decoded; everything else (other
-- SESS, compressed, heartbeat, junk) is shown as raw data with the header info.

local mas = _G.mas or {}
_G.mas = mas
mas.by_sess = mas.by_sess or {}   -- SESS value -> { label, add(gw,tvb,poff,plen,payload,pinfo) }

-- CTRL / SESS constants and names.
mas.CTRL_POLL = 0x04
mas.SESS_RTS  = 0x08
mas.SESS_TRAN = 0x01
mas.CTRL_NAMES = { [0x01]="Normal", [0x02]="ACK", [0x03]="NAK",
                   [0x04]="POLL (heartbeat)", [0x05]="CheckSession" }
mas.SESS_NAMES = { [0x01]="Transaction", [0x08]="RTS", [0x99]="SessionEnd" }

-- Single-bit test (avoids relying on Lua 5.3 bitwise operators).
function mas.hasbit(v, mask) return v % (mask + mask) >= mask end

-- 5-tuple key for a packet. Shared by reassembly (here) and per-stream analysis.
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
      -- Too little left to know whether this is the 2-byte SOF marker. A lone
      -- trailing 0xFE could be its first byte, so this is only "data" (junk) if
      -- it definitely isn't; otherwise wait for more bytes (reassembly).
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
        -- No full SOF2 ahead; a lone trailing 0xFE could start one once more
        -- bytes arrive, so exclude it from this junk run.
        endp = (buf:byte(n) == 0xFE) and (n - 1) or n
      end
      items[#items + 1] = { t = "data", off = i, len = endp - i }
      i = endp
    end
  end
  return items, pending
end

if _G.Proto then
  local proto = Proto("mas", "Mirae Asset Securities")   -- umbrella / gateway (filter: mas)
  mas.proto = proto   -- stream modules use this for undecoded/unspecified content, so
                       -- their own child protocol (mas.ep/mas.or) only claims presence
                       -- when content was actually decoded as that protocol

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

  proto.prefs.port = Pref.uint("TCP port", 15201, "MAS server source port")
  local bound_port

  -- Reassembly continuation tracking (see notes below).
  local carry = {}       -- [stream key] = frame number that left an incomplete tail
  local cont_from = {}   -- [frame number] = earlier frame this one continues from
  local info_frame       -- last frame whose Info column we took over

  function proto.init()
    carry = {}; cont_from = {}; info_frame = nil
    for _, h in pairs(mas.by_sess) do if h.init then h.init() end end
  end

  local function gw_label(item)
    if item.ctrl == mas.CTRL_POLL then return "Heartbeat" end
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
    if pinfo.src_port ~= bound_port then return 0 end     -- MAS = traffic from the server port
    local buf = tvb:raw()
    if not buf or #buf == 0 then return 0 end

    local items, pending = mas.scan(buf)
    pinfo.cols.protocol = "MAS"
    local tree_root = tree:add(proto, tvb())

    -- Info column is driven purely by CTRL/SESS (not decode success): every RTS
    -- frame counts toward "RTS", every Transaction frame toward "Transaction"
    -- (compressed or not, decoded or not), CTRL=POLL toward "Heartbeat" — always
    -- in that fixed order. RTS/Transaction's count is the number of MESSAGES
    -- actually CONTAINED, not the number of G/W frames: a single RTS G/W frame's
    -- payload is a repeated RTS-HEADER+RTS-DATA, so it can hold several records
    -- (Execution Price and Unspecified RTS both count); a Transaction G/W frame
    -- always holds exactly one AXIS-HEADER+TR-DATA, so it always counts as 1.
    -- When the payload is compressed (or a handler otherwise isn't invoked), the
    -- contained count can't be determined, so the frame itself counts as 1.
    -- CTRL/SESS combinations outside these three ARE valid per spec (e.g. ACK/NAK/
    -- CheckSession, or SESS=SessionEnd) and, along with plain junk bytes, all count
    -- as "Unspecified" — its own bucket that coexists with the other three, always
    -- listed last (e.g. "RTS:2 Transaction:1 Heartbeat Unspecified").
    local cnt = { RTS = 0, Transaction = 0, Heartbeat = 0, Unspecified = 0 }

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
          cnt.Heartbeat = cnt.Heartbeat + 1
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

    -- Build the Info text in fixed order. RTS/Transaction ALWAYS show a ":count"
    -- suffix, even for exactly 1 (it's a contained-message count, not a frame
    -- count, so it's informative even at 1). Heartbeat/Unspecified never show a
    -- count, just the bare word. The items==0 edge case (e.g. a single
    -- unconfirmed 0xFE awaiting reassembly) still falls back to "Unspecified".
    local ALWAYS_COUNT = { RTS = true, Transaction = true }
    local parts = {}
    for _, lbl in ipairs({ "RTS", "Transaction", "Heartbeat", "Unspecified" }) do
      local c = cnt[lbl]
      if c > 0 then
        parts[#parts + 1] = ALWAYS_COUNT[lbl] and (lbl .. ":" .. c) or lbl
      end
    end
    local info = table.concat(parts, " ")
    if info == "" then info = "Unspecified" end
    info = info .. " "
    -- Own the whole Info column so no TCP note leaks in: clear on the first (of
    -- possibly several, under reassembly) calls for this frame; later calls append.
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

-- ---------------------------------------------------------------------------
-- Shared GUI: a Statistics stream-list window. Stream modules register their own
-- Statistics menu whose callback calls mas.open_stream_window at click time.
-- ---------------------------------------------------------------------------
if gui_enabled() then
  local function current_filter(proto_filter)
    local df = get_filter()
    if df and df ~= "" then return "(" .. df .. ") and " .. proto_filter end
    return proto_filter
  end
  local function flow_key(pinfo)
    return tostring(pinfo.src) .. ":" .. pinfo.src_port .. "->" ..
           tostring(pinfo.dst) .. ":" .. pinfo.dst_port
  end

  function mas.open_stream_window(title, proto_filter, columns, extractors)
    local rows, flows, sel = {}, {}, nil

    local function collect()
      rows, flows = {}, {}
      local seen = {}
      local ok, tap = pcall(Listener.new, nil, current_filter(proto_filter))
      if not ok then tap = Listener.new(nil, proto_filter) end
      function tap.packet(pinfo)
        local flow = flow_key(pinfo)
        local cols, count = {}, 0
        for i, ex in ipairs(extractors) do
          cols[i] = { ex() }
          if #cols[i] > count then count = #cols[i] end
        end
        for m = 1, count do
          local vals = {}
          for i, c in ipairs(columns) do
            local fi = cols[i][m]
            local v = fi and fi.value
            if c.map then v = c.map(v) end
            vals[i] = (v == nil) and "" or tostring(v)
          end
          rows[#rows + 1] = { frame = pinfo.number, flow = flow, vals = vals }
          if not seen[flow] then seen[flow] = true; flows[#flows + 1] = flow end
        end
      end
      retap_packets()
      tap:remove()
      if sel and not seen[sel] then sel = nil end
    end

    local tw = TextWindow.new(title)
    local function render()
      local out = {}
      local df = get_filter()
      out[#out + 1] = "Filter: " .. ((df and df ~= "") and df or "(none)")
      out[#out + 1] = "Flow:   " .. (sel or ("all (" .. #flows .. " flows)"))
      out[#out + 1] = ""
      local hdr = { string.format("%-7s", "No.") }
      for _, c in ipairs(columns) do hdr[#hdr + 1] = string.format("%-" .. c.width .. "s", c.header) end
      out[#out + 1] = table.concat(hdr, " ")
      local n = 0
      for _, r in ipairs(rows) do
        if (not sel) or r.flow == sel then
          local line = { string.format("%-7d", r.frame) }
          for i, c in ipairs(columns) do line[#line + 1] = string.format("%-" .. c.width .. "s", r.vals[i]) end
          out[#out + 1] = table.concat(line, " ")
          n = n + 1
        end
      end
      out[#out + 1] = ""
      out[#out + 1] = n .. " messages"
      tw:set(table.concat(out, "\n"))
    end

    tw:add_button("Refresh", function() collect(); render() end)
    tw:add_button("Flow", function()
      if #flows == 0 then return end
      local idx = 0
      for i, f in ipairs(flows) do if f == sel then idx = i break end end
      idx = idx + 1
      sel = (idx > #flows) and nil or flows[idx]
      render()
    end)

    collect(); render()
  end
end

return mas
