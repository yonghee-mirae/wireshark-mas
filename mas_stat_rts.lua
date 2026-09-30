-- Statistics > MAS > RTS: a table (CSV text) of the records of ONE RTS TYPE selected by the main display filter,
-- with a Copy to clipboard button.
--
-- A display filter works per frame but a frame holds several RTS records, so the filter text is parsed here and
-- evaluated per record: mas.rts.* terms against the decoded record, every other term (ip.addr, mas.tr.*, ...) by
-- one Listener each (frame-level truth), combined with not/and/or. Supported terms:
--   <field>                        existence
--   <field> ==|!=|<|>|<=|>= "str"  (also eq ne lt gt le ge; string comparison)
--   <field> contains "str"         <field> in {"a" "b"}
-- Not supported (reported, never silently ignored): matches/~, functions, slices, arithmetic, unquoted or numeric
-- values on mas.rts.* fields, mas.rts.<T>.reversed and mas.rts.reclen (neither is part of the decoded record).
-- mas.rts.* values are compared as Wireshark shows them (a 코드+수치 field without its leading code); the CSV has the
-- wire value. A record-level term on an absent field (e.g. B's NXT-only tail) is false, `!=` included.

local mas = _G.mas or {}
_G.mas = mas

local S = {}   -- module table: pure helpers (returned for tests)

local OPS = {
  ["=="] = "==", ["!="] = "!=", ["<="] = "<=", [">="] = ">=", ["<"] = "<", [">"] = ">",
  eq = "==", ne = "!=", le = "<=", ge = ">=", lt = "<", gt = ">", contains = "contains",
}

-- Tokens: { t = "(" | ")" | "{" | "}" | "op" | "str" | "word", v }. Strings understand only \\ and \".
local function tokenize(s)
  local toks, i, n = {}, 1, #s
  while i <= n do
    local c = s:sub(i, i)
    local two = s:sub(i, i + 1)
    if c:match("%s") then
      i = i + 1
    elseif c == "(" or c == ")" or c == "{" or c == "}" then
      toks[#toks + 1] = { t = c, v = c }; i = i + 1
    elseif c == '"' then
      local j, buf = i + 1, {}
      while true do
        local d = s:sub(j, j)
        if d == "" then error("unterminated string", 0) end
        if d == "\\" then buf[#buf + 1] = s:sub(j + 1, j + 1); j = j + 2
        elseif d == '"' then break
        else buf[#buf + 1] = d; j = j + 1 end
      end
      toks[#toks + 1] = { t = "str", v = table.concat(buf) }; i = j + 1
    elseif two == "&&" or two == "||" or two == "==" or two == "!=" or two == "<=" or two == ">=" then
      toks[#toks + 1] = { t = "op", v = two }; i = i + 2
    elseif c == "!" or c == "<" or c == ">" then
      toks[#toks + 1] = { t = "op", v = c }; i = i + 1
    else
      local w = s:match('^[^%s(){}<>=!&|"]+', i)
      if not w then error("unexpected '" .. c .. "'", 0) end
      toks[#toks + 1] = { t = "word", v = w }; i = i + #w
    end
  end
  return toks
end

local function quote(v) return '"' .. (v:gsub('[\\"]', "\\%0")) .. '"' end

-- Is token `tk` the keyword `kw` (any case) or the symbol `sym`?
local function is(tk, kw, sym)
  return tk ~= nil and ((tk.t == "word" and tk.v:lower() == kw) or (tk.t == "op" and tk.v == sym))
end

-- Fill in how an atom is evaluated: a.frame (Wireshark per-frame term, re-sent as a.text), a.hdr ("type"/"kind")
-- or a.rtype/a.suffix (field of TYPE rtype).
local function classify(a)
  local rest = a.field:match("^mas%.rts%.(.+)$")
  if not rest then a.frame = true; return end
  for _, q in ipairs(a.quoted) do
    if not q then error("value of " .. a.field .. " must be a quoted string", 0) end
  end
  if rest == "type" or rest == "kind" then
    a.hdr = rest
    if rest == "type" and a.op ~= "==" and a.op ~= "in" then error("mas.rts.type supports only == and in", 0) end
  else
    local t, suf = rest:match("^(.)%.([^.]+)$")
    if not t or suf == "reversed" then error("unsupported field " .. a.field, 0) end
    a.rtype, a.suffix = t, suf
  end
end

-- Parse `text` into (ast, atoms) or (nil, error message). ast: { "and"|"or", l, r }, { "not", x }, { "atom", a }.
function S.parse(text)
  local ok, ast, atoms = pcall(function()
    local toks, pos, atoms = tokenize(text), 1, {}
    local parse_or

    local function parse_atom()
      local tk = toks[pos]
      if not tk then error("unexpected end of filter", 0) end
      if tk.t ~= "word" then error("unexpected '" .. tk.v .. "'", 0) end
      pos = pos + 1
      local a = { field = tk.v, quoted = {} }
      local nx = toks[pos]
      if nx and nx.t == "(" then error("functions are not supported: " .. tk.v .. "()", 0) end
      local op = nx and ((nx.t == "op" and OPS[nx.v]) or (nx.t == "word" and OPS[nx.v:lower()]))
      if op then
        local val = toks[pos + 1]
        if not val or (val.t ~= "str" and val.t ~= "word") then error("missing value after " .. nx.v, 0) end
        pos = pos + 2
        a.op, a.values, a.quoted = op, { val.v }, { val.t == "str" }
        a.text = tk.v .. " " .. op .. " " .. (val.t == "str" and quote(val.v) or val.v)
      elseif is(nx, "in", "") then
        pos = pos + 1
        if not toks[pos] or toks[pos].t ~= "{" then error("expected '{' after in", 0) end
        pos = pos + 1
        a.op, a.values, a.quoted = "in", {}, {}
        local parts = {}
        while toks[pos] and toks[pos].t ~= "}" do
          local m = toks[pos]
          if m.t ~= "str" and m.t ~= "word" then error("unexpected '" .. m.v .. "' in set", 0) end
          a.values[#a.values + 1], a.quoted[#a.quoted + 1] = m.v, m.t == "str"
          parts[#parts + 1] = m.t == "str" and quote(m.v) or m.v
          pos = pos + 1
        end
        if not toks[pos] then error("missing '}'", 0) end
        pos = pos + 1
        a.text = tk.v .. " in {" .. table.concat(parts, " ") .. "}"
      else
        if nx and nx.t == "word" and not is(nx, "and", "") and not is(nx, "or", "") then
          error("unsupported operator '" .. nx.v .. "'", 0)
        end
        a.text = tk.v
      end
      classify(a)
      atoms[#atoms + 1] = a
      return { "atom", a }
    end

    local function parse_not()
      local tk = toks[pos]
      if is(tk, "not", "!") then pos = pos + 1; return { "not", parse_not() } end
      if tk and tk.t == "(" then
        pos = pos + 1
        local e = parse_or()
        if not toks[pos] or toks[pos].t ~= ")" then error("missing ')'", 0) end
        pos = pos + 1
        return e
      end
      return parse_atom()
    end

    local function parse_and()
      local l = parse_not()
      while is(toks[pos], "and", "&&") do pos = pos + 1; l = { "and", l, parse_not() } end
      return l
    end

    function parse_or()
      local l = parse_and()
      while is(toks[pos], "or", "||") do pos = pos + 1; l = { "or", l, parse_and() } end
      return l
    end

    local e = parse_or()
    if toks[pos] then error("unexpected '" .. toks[pos].v .. "'", 0) end
    return e, atoms
  end)
  if not ok then return nil, ast end
  return ast, atoms
end

-- Sorted list of the RTS TYPE letters the filter refers to (mas.rts.<T>.* fields, mas.rts.type == / in).
function S.types(atoms)
  local set, list = {}, {}
  local function add(t) if not set[t] then set[t] = true; list[#list + 1] = t end end
  for _, a in ipairs(atoms) do
    if a.rtype then add(a.rtype)
    elseif a.hdr == "type" then for _, v in ipairs(a.values) do add(v) end end
  end
  table.sort(list)
  return list
end

-- suffix ("key", "023", "exchange") -> field name, for a def.
function S.suffix_map(def)
  local m = {}
  for name, sp in pairs(def.spec) do m[sp[1]] = name end
  if def.exchange then m.exchange = "exchange" end
  return m
end

-- Error message for a mas.rts.<T>.<suffix> term that names no field of `def`, else nil.
function S.check_fields(atoms, def, sfx)
  for _, a in ipairs(atoms) do
    if a.suffix and not sfx[a.suffix] then return "unknown field " .. a.field end
  end
end

local function compare(op, v, vals)
  if op == "==" then return v == vals[1]
  elseif op == "!=" then return v ~= vals[1]
  elseif op == "<" then return v < vals[1]
  elseif op == ">" then return v > vals[1]
  elseif op == "<=" then return v <= vals[1]
  elseif op == ">=" then return v >= vals[1]
  elseif op == "contains" then return v:find(vals[1], 1, true) ~= nil
  end
  for _, x in ipairs(vals) do if v == x then return true end end   -- in
  return false
end

-- Value of record-level atom `a` in `row` ({ type, kind, def, rec }); nil if the record has no such field.
local function record_value(a, row, sfx)
  if a.hdr then return row[a.hdr] end
  if a.rtype ~= row.type then return nil end
  local name = sfx[a.suffix]
  local v = row.rec[name]
  if v ~= nil and row.def.coded and row.def.coded[name] then v = (mas.split_coded(v)) or v end
  return v
end

-- Does the filter hold for `row`? frame_truth(atom, frame) answers the frame-level terms.
function S.matches(ast, row, sfx, frame_truth)
  local function ev(node)
    local k = node[1]
    if k == "and" then return ev(node[2]) and ev(node[3])
    elseif k == "or" then return ev(node[2]) or ev(node[3])
    elseif k == "not" then return not ev(node[2]) end
    local a = node[2]
    if a.frame then return frame_truth(a, row.frame) end
    local v = record_value(a, row, sfx)
    if v == nil then return false end
    if not a.op then return true end
    return compare(a.op, v, a.values)
  end
  return ev(ast)
end

local function csv_field(v)
  if v:find('[,"\r\n]') then return '"' .. (v:gsub('"', '""')) .. '"' end
  return v
end

-- Capture time (epoch seconds) as local "YYYY-MM-DD HH:MM:SS.uuuuuu".
local function fmt_time(ts)
  if not ts then return "" end
  local sec = math.floor(ts)
  local us = math.floor((ts - sec) * 1e6 + 0.5)
  if us >= 1000000 then sec, us = sec + 1, 0 end
  return os.date("%Y-%m-%d %H:%M:%S", sec) .. string.format(".%06d", us)
end

-- CSV text: frame, time, [거래소], then the spec fields in wire order with their detail-pane labels (wire values).
function S.csv(def, rows)
  local names, head = {}, { "frame", "time" }
  if def.exchange then head[#head + 1] = "거래소" end
  for _, name in ipairs(def.names) do
    if def.spec[name] then names[#names + 1] = name; head[#head + 1] = def.spec[name][2] end
  end
  local out = {}
  for i, h in ipairs(head) do head[i] = csv_field(h) end
  out[1] = table.concat(head, ",")
  for _, row in ipairs(rows) do
    local line = { tostring(row.frame), fmt_time(row.time) }
    if def.exchange then line[#line + 1] = csv_field(row.rec.exchange or "") end
    for _, name in ipairs(names) do line[#line + 1] = csv_field(row.rec[name] or "") end
    out[#out + 1] = table.concat(line, ",")
  end
  return table.concat(out, "\n") .. "\n"
end

-- Build the window text for filter `text` from `rows` (every collected record: { frame, type, kind, def, rec }),
-- `frame_sets[atom text][frame]` (frame-level term truth) and `flows[frame]` (5-tuple). Returns (csv, nil) or
-- (nil, message); `ast`/`atoms`/`def` are the parse and the TYPE's def. Split from the GUI glue so it can be tested.
function S.select(ast, atoms, def, typ, rows, frame_sets, flows)
  local sfx = S.suffix_map(def)
  local function truth(a, frame) return frame_sets[a.text][frame] == true end
  local hit, seen, nflow, flow_list = {}, {}, 0, {}
  for _, row in ipairs(rows) do
    if row.type == typ and S.matches(ast, row, sfx, truth) then
      hit[#hit + 1] = row
      local f = flows[row.frame]
      if not seen[f] then seen[f] = true; nflow = nflow + 1; flow_list[#flow_list + 1] = f end
    end
  end
  if #hit == 0 then return nil, "No TYPE " .. typ .. " record matches the filter." end
  if nflow > 1 then
    table.sort(flow_list)
    local shown = {}
    for i = 1, math.min(#flow_list, 5) do shown[i] = flow_list[i] end
    return nil, "The matching TYPE " .. typ .. " records span " .. nflow .. " 5-tuples; filter on one of them (e.g. ip.addr, tcp.port):\n  "
      .. table.concat(shown, "\n  ") .. (#flow_list > 5 and "\n  ..." or "")
  end
  return S.csv(def, hit)
end

if _G.gui_enabled and gui_enabled() then
  -- Collect every record of every frame the data tap sees, plus the frames each frame-level term matches.
  -- Wireshark dissects a frame before calling the tap for it, and may dissect it more than once: dedup by offset.
  local function collect(atoms)
    local rows, flows, frame_sets, taps = {}, {}, {}, {}
    local buf = { frame = nil, recs = {}, seen = {} }
    mas.collect = function(pinfo, r, poff, def, rec)
      if buf.frame ~= pinfo.number then buf.frame, buf.recs, buf.seen = pinfo.number, {}, {} end
      local off = poff + r.off
      if not buf.seen[off] then
        buf.seen[off] = true
        buf.recs[#buf.recs + 1] = { frame = pinfo.number, type = r.type, kind = r.kind, def = def, rec = rec }
      end
    end
    local function cleanup()
      mas.collect = nil
      for _, t in ipairs(taps) do t:remove() end
    end

    local ok, err = pcall(function()
      local data = Listener.new(nil, "mas.rts.kind")
      taps[#taps + 1] = data
      function data.packet(pinfo)
        if buf.frame ~= pinfo.number then return end
        flows[pinfo.number] = mas.stream_key(pinfo)
        for _, row in ipairs(buf.recs) do row.time = pinfo.abs_ts; rows[#rows + 1] = row end
        buf.recs = {}
      end
      for _, a in ipairs(atoms) do
        if a.frame and not frame_sets[a.text] then
          local set = {}
          frame_sets[a.text] = set
          local ok2, tap = pcall(Listener.new, nil, a.text)
          if not ok2 then error("invalid filter term: " .. a.text, 0) end
          taps[#taps + 1] = tap
          function tap.packet(pinfo) set[pinfo.number] = true end
        end
      end
      retap_packets()
    end)
    cleanup()
    if not ok then return nil, tostring(err) end
    return rows, nil, frame_sets, flows
  end

  -- Window text for the current main display filter: (csv, nil) or (nil, message).
  local function build()
    local text = get_filter() or ""
    local ast, atoms = S.parse(text)
    if not ast then
      if text == "" then return nil, "Set a display filter that names one RTS TYPE, e.g. mas.rts.type == \"B\"." end
      return nil, "Unsupported filter: " .. atoms
    end
    local types = S.types(atoms)
    if #types == 0 then return nil, "The filter names no RTS TYPE: use mas.rts.type == \"B\" or a mas.rts.B.<field> term." end
    if #types > 1 then
      return nil, "The filter names several RTS TYPEs (" .. table.concat(types, ", ") .. "): specify exactly one."
    end
    local typ = types[1]
    local h = mas.by_rts_type[typ]
    if not (h and h.def) then return nil, "No decoder for RTS TYPE " .. typ .. "." end
    local bad = S.check_fields(atoms, h.def, S.suffix_map(h.def))
    if bad then return nil, bad end
    local rows, err, frame_sets, flows = collect(atoms)
    if not rows then return nil, err end
    return S.select(ast, atoms, h.def, typ, rows, frame_sets, flows)
  end

  register_menu("MAS/RTS", function()
    local tw = TextWindow.new("MAS - RTS")
    local csv
    local function refresh()
      local msg
      csv, msg = build()
      tw:set(csv or msg)
    end
    tw:add_button("Refresh", refresh)
    tw:add_button("Copy to clipboard", function()
      if not csv then report_failure("Nothing to copy: the window shows no table."); return end
      copy_to_clipboard(csv)
    end)
    refresh()
  end, MENU_STAT_UNSORTED)
end

return S
