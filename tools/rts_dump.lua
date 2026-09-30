-- Regression dump for the RTS TYPE decoders (no Wireshark needed).
--
-- Loads each given mas_rts_<t>.lua (a definition registered in mas.rts_defs) under a stubbed Wireshark API, feeds every
-- registered TYPE synthetic bodies (field values derived from the field index)
-- and prints what the decoder would add to the detail pane:
-- registered filters/labels plus, per body, (filter, label, offset, length, value).
-- Field names never appear in the output, so a pure internal rename must
-- produce an identical dump.
--
-- Usage (run from anywhere; <repo> is the directory holding mas_rts*.lua):
--   lua tools/rts_dump.lua <repo> <pattern 1|2|3> mas_rts_b.lua mas_rts_c.lua ...
--   lua tools/rts_dump.lua . 1 $(cd . && ls mas_rts_*.lua | grep -v '^mas_rts.lua$')
-- Compare before/after a change: dump an earlier checkout (e.g. `git archive <rev>`; it must
-- already use mas.rts_defs) and the working tree, then `diff` the two outputs.
--   pattern 1: values "2<1000+k>" (leading 1..5 exercises the code+value path),
--              key "N.A005930" (exchange prefix).
--   pattern 2: values "v<k>", key "K1" (no exchange prefix).
--   pattern 3: values are EUC-KR "가"+k (0xB0 0xA1); the string(ENC_EUC_KR) stub
--              converts them to 3-byte UTF-8, so per-field offsets taken from the
--              raw bytes differ from offsets in the converted text.
--   RTS_LOAD_ORDER=late  load each module before mas_rts.lua instead of after (must give the same
--                        dump, apart from the 3 REG lines of the shared mas.rts.kind/type/length).
-- Synthetic bodies only: this does not replace checking real captures in Wireshark.

local repo, pat = arg[1], tonumber(arg[2])
local out = {}
local function emit(s) out[#out + 1] = s end

-- Wireshark API stubs
-- proto.fields = {...} appends to the protocol's registered fields (as in Wireshark).
Proto = function()
  local p = { all = {}, experts = {} }
  return setmetatable(p, {
    __index = function(t, k) if k == "fields" then return t.all end end,
    __newindex = function(t, k, v)
      if k == "fields" then for _, f in ipairs(v) do t.all[#t.all + 1] = f end else rawset(t, k, v) end
    end })
end
ProtoField = setmetatable({}, { __index = function(_, kind)
  return function(abbrev, label) return { abbrev = abbrev, label = label, kind = kind } end
end })
ProtoExpert = { new = function(a, l) return { abbrev = a, label = l } end }
expert = { group = { MALFORMED = 1 }, severity = { WARN = 1 } }
ENC_EUC_KR = 0

local CUR_BODY = ""
local function tvb_new()
  return setmetatable({}, { __call = function(_, off, l)
    local sub = CUR_BODY:sub(off - 6 + 1, off - 6 + l)   -- body starts after the 6-byte RTS-HEADER
    return { off = off, len = l,
      string = function(_, enc)
        if enc ~= nil then return (sub:gsub("\xB0\xA1", "\xEA\xB0\x80")) end   -- EUC-KR -> UTF-8
        return sub
      end,
      raw = function() return sub end }
  end })
end

local mktree
function mktree()
  local tree = {}
  function tree:add(pf, rng, val)
    local item = mktree()
    if type(pf) == "table" and pf.abbrev then
      emit("add " .. pf.abbrev .. " [" .. pf.label .. "] off=" .. tostring(rng and rng.off) ..
           " len=" .. tostring(rng and rng.len) .. " val=" .. tostring(val))
    else
      emit("add-proto off=" .. tostring(rng and rng.off) .. " len=" .. tostring(rng and rng.len) ..
           " val=" .. tostring(val))
    end
    function item:append_text(s) emit("  append " .. s) end
    return item
  end
  function tree:add_proto_expert_info(e) emit("expert " .. tostring(e.abbrev)) end
  return tree
end

_G.mas = { by_rts_type = {} }
-- mas_rts.lua provides the shared helpers and the mas.rts_defs queue.
pcall(dofile, repo .. "/mas_rts.lua")
mas.rts_add_header = function() emit("header") end   -- replace the real one
mas.stream_key = function() return "S" end
mas.proto = nil

local late = os.getenv("RTS_LOAD_ORDER") == "late"

local function run(modfile)
  if late then
    -- load the module BEFORE mas_rts.lua: its def is queued and defined when that loads
    _G.mas = { by_rts_type = {}, stream_key = function() return "S" end }
    dofile(repo .. "/" .. modfile)
    pcall(dofile, repo .. "/mas_rts.lua")
    mas.rts_add_header = function() emit("header") end
  else
    mas.by_rts_type = {}
    dofile(repo .. "/" .. modfile)
  end
  local def = mas.rts_defs[#mas.rts_defs]   -- the definition this module just registered
  local abbs = {}
  for _, f in ipairs(mas.proto.fields) do abbs[#abbs + 1] = f.abbrev .. "|" .. f.label end
  table.sort(abbs)
  for _, a in ipairs(abbs) do emit("REG " .. a) end
  mas.proto.all = {}

  local types = {}
  for t in pairs(mas.by_rts_type) do types[#types + 1] = t end
  table.sort(types)
  local n = #def.names
  for _, typ in ipairs(types) do
    emit("-- type " .. typ)
    -- exact count, then one/three fewer (optional trailing fields), then one extra
    for _, cnt in ipairs({ n, n - 1, n - 3, n + 1 }) do
      if cnt > 0 then
        local parts = {}
        for k = 1, cnt do
          parts[k] = (pat == 1) and ("2" .. (1000 + k)) or (pat == 3 and ("\xB0\xA1" .. k) or ("v" .. k))
        end
        parts[1] = (pat ~= 2) and "N.A005930" or "K1"
        local body = table.concat(parts, "\t") .. "\0"
        emit("BODY cnt=" .. cnt)
        CUR_BODY = body
        local r = { off = 0, len = #body, body = body, raw_body = body, type = typ, kind = "D" }
        local ok, err = pcall(mas.by_rts_type[typ].add, mktree(), tvb_new(), 0, r, { number = 7 }, 1)
        emit("  ok=" .. tostring(ok) .. (ok and "" or (" err=" .. tostring(err))))
      end
    end
  end
end

for i = 3, #arg do
  emit("== " .. arg[i])
  local ok, err = pcall(run, arg[i])
  if not ok then emit("LOADERR " .. tostring(err)) end
  mas.proto = nil
end
io.write(table.concat(out, "\n"), "\n")
