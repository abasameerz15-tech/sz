--
-- ultralight webframework for [Redbean web server](https://redbean.dev/)
-- Copyright 2021-23 Paul Kulchenko
--

local NAME, VERSION = "fullmoon", "0.384"

--[[-- support functions --]]--

local unpack = table.unpack or unpack
local load = load or loadstring
if not setfenv then -- Lua 5.2+; this assumes f is a function
  -- based on http://lua-users.org/lists/lua-l/2010-06/msg00314.html
  -- and https://leafo.net/guides/setfenv-in-lua52-and-above.html
  local function findenv(f)
    local idx = 1
    repeat
      local name, value = debug.getupvalue(f, idx)
      if name == '_ENV' then return idx, value end
      idx = idx + 1
    until not name
  end
  getfenv = function (f)
    -- if the function is not provided, use the caller
    return(select(2, findenv(f or debug.getinfo(2,"f").func)) or _G)
  end
  setfenv = function (f, t)
    local level = findenv(f)
    if level then debug.upvaluejoin(f, level, function() return t end, 1) end
    return f
  end
end
local function loadsafe(data)
  local f, err = load(data)
  if not f then return f, err end
  local c = -2
  local hf, hm, hc = debug.gethook()
  debug.sethook(function() c=c+1; if c>0 then error("failed safety check") end end, "c")
  local ok, res = pcall(f)
  c = -1
  debug.sethook(hf, hm, hc)
  return ok, res
end
local function argerror(cond, narg, extramsg, name)
  if cond then return cond end
  name = name or debug.getinfo(2, "n").name or "?"
  local msg = ("bad argument #%d to %s%s"):format(narg, name, extramsg and " "..extramsg or  "")
  return error(msg, 3)
end
local function logFormat(fmt, ...)
  argerror(type(fmt) == "string", 1, "(string expected)")
  return "(fm) "..(select('#', ...) == 0 and fmt or (fmt or ""):format(...))
end
local function quote(s) return s:gsub('([%(%)%.%%%+%-%*%?%[%^%$%]])','%%%1') end
local function getRBVersion()
  local v = GetRedbeanVersion()
  local major = math.floor(v / 2^16)
  local minor = math.floor((v / 2^16 - major) * 2^8)
  return ("%d.%d.%d"):format(major, minor, v % 2^8)
end
local LogDebug = function(...) return Log(kLogDebug, logFormat(...)) end
local LogVerbose = function(...) return Log(kLogVerbose, logFormat(...)) end
local LogInfo = function(...) return Log(kLogInfo, logFormat(...)) end
local LogWarn = function(...) return Log(kLogWarn, logFormat(...)) end
local istype = function(b)
  return function(mode) return math.floor((mode % (2*b)) / b) == 1 end end
local isregfile = unix and unix.S_ISREG or istype(2^15)
local function reg(func, v)
  local t = {n = 1,
    x2 = function(t, v) t[v] = t.n; t.n = t.n * 2 end,
    p1 = function(t, v) t[v] = t.n; t.n = t.n + 1 end,
  }
  for _, p in ipairs(v) do t[func](t, p) end
  return t
end
local function reg2x(v) return reg("x2", v) end
local function reg1p(v) return reg("p1", v) end
local getTimeNano = (unix
  and function() return {unix.clock_gettime()} end
  or function() return {GetTime(), 0} end)
local function getTimeDiff(st, et)
  if not et then et = getTimeNano() end
  return et[1] - st[1] + (et[2] - st[2]) * 1e-9
end
local function obsolete(obj, old, new, ver)
  obj[old] = VERSION < ver and function(...)
    LogWarn(("method %s has been replaced by %s and will be removed in v%s.")
      :format(old, new, ver))
    obj[old] = obj[new]
    return obj[new](...)
  end or nil
end

-- headers that are not allowed to be set, as Redbean may
-- also set them, leading to conflicts and improper handling
local noHeaderMap = {
  ["content-length"] = true,
  ["transfer-encoding"] = true,
  ["content-encoding"] = true,
  date = true,
  -- "close" is the only value that is allowed for "Connection",
  -- but only in Redbean before v2.2
  connection = GetRedbeanVersion() < 0x20200 and "close" or nil,
}
-- request headers based on https://datatracker.ietf.org/doc/html/rfc7231#section-5
-- response headers based on https://datatracker.ietf.org/doc/html/rfc7231#section-7
-- this allows the user to use `.ContentType` instead of `["Content-Type"]`
-- Host is listed to allow retrieving Host header even in the presence of host attribute
local headerMap = {}
(function(s) for h in s:gmatch("[%w%-]+") do headerMap[h:gsub("-","")] = h end end)([[
  Cache-Control Host Max-Forwards Proxy-Authorization User-Agent
  Accept-Charset Accept-Encoding Accept-Language Content-Disposition
  If-Match If-None-Match If-Modified-Since If-Unmodified-Since If-Range
  Content-Type Content-Encoding Content-Language Content-Location
  Retry-After Last-Modified WWW-Authenticate Proxy-Authenticate Accept-Ranges
  Content-Length Transfer-Encoding
]])
local htmlVoidTags = {} -- from https://html.spec.whatwg.org/#void-elements
(function(s) for h in s:gmatch("%w+") do htmlVoidTags[h] = true end end)([[
  area base br col embed hr img input link meta param source track wbr
]])
local default500 = [[<!doctype html><title>{%& status %} {%& reason %}</title>
<h1>{%& status %} {%& reason %}</h1>
{% if message then %}<pre>{%& message %}</pre>{% end %}]]

--[[-- route path generation --]]--

local PARAM = "([:*])([%w_]*)"
local routes = {}
local function makePath(name, params)
  argerror(type(name) == "string", 1, "(string expected)")
  params = params or {}
  -- name can be the name or the route itself (even not registered)
  local pos = routes[name]
  local route = pos and routes[pos].route or name
  -- replace :foo and *splat with provided parameters
  route = route:gsub(PARAM.."([^(*:]*)", function(sigil, param, rest)
      if sigil == "*" and param == "" then param = "splat" end
      -- ignore everything that doesn't match `:%w` pattern
      if sigil == ":" and param == "" then return sigil..param..rest end
      -- if the parameter value is `false`, replace it with an empty string
      return ((params[param] or (params[param] == false and "" or sigil..param))
        ..rest:gsub("^%b[]",""))
    end)
  -- remove all optional groups
  local function findopt(route)
    return route:gsub("(%b())", function(optroute)
        optroute = optroute:sub(2, -2)
        local s = optroute:find("[:*]")
        if s then
          local p = optroute:find("%b()")
          if not p or s < p then return "" end
        end
        return findopt(optroute)
      end)
  end
  route = findopt(route)
  local param = route:match(":(%a[%w_]*)") or route:match("*([%w_]*)")
  argerror(not param, 2, "(missing required parameter "
    ..(param and #param > 0 and param or "splat")..")")
  return route
end
local function makeUrl(url, opts)
  if type(url) == "table" and opts == nil then url, opts = nil, url end
  if not url then url = GetUrl() end
  if not opts then opts = {} end
  argerror(type(url) == "string", 1, "(string expected)")
  argerror(type(opts) == "table", 2, "(table expected)")
  -- check if params are in the hash table format and
  -- convert to the array format that Redbean expects
  if opts.params and not opts.params[1] and next(opts.params) then
    local tbl = {}
    for k, v in pairs(opts.params) do
      table.insert(tbl, v == true and {k} or {k, v})
    end
    table.sort(tbl, function(a, b) return a[1] < b[1] end)
    opts.params = tbl
  end
  local parts = ParseUrl(url)
  -- copy options, but remove those that have `false` values
  for k, v in pairs(opts) do parts[k] = v or nil end
  return EncodeUrl(parts)
end

local org, ref = {}, {} -- some unique key values to index template parameters
-- request functions (`request.write()`)
local reqenv = {
  escapeHtml = EscapeHtml, escapePath = EscapePath,
  formatIp = FormatIp, formatHttpDateTime = FormatHttpDateTime,
  makePath = makePath, makeUrl = makeUrl, }
-- request properties (`request.authority`)
local reqapi = { authority = function()
    local parts = ParseUrl(GetUrl())
    return EncodeUrl({scheme = parts.scheme, host = parts.host, port = parts.port})
  end, }
local function genEnv(opt)
  opt = opt or {}
  return function(t, key)
    local val = reqenv[key] or rawget(t, ref) and rawget(t, ref)[key]
    -- can cache the value, since it's not passed as a parameter
    local cancache = val == nil
    if not opt.request and val == nil then val = _G[key] end
    if opt.request and val == nil and type(key) == "string" then
      local func = reqapi[key] or _G["Get"..key:sub(1,1):upper()..key:sub(2)]
      -- map a property (like `.host`) to a function call (`GetHost()`)
      if type(func) == "function" then val = func() else val = func end
    end
    -- allow pseudo-tags, but only if used in a template environment;
    -- provide fallback for `table` to make `table{}` and `table.concat` work
    local istable = key == "table"
    if opt.autotag and (val == nil or istable) then
      -- nothing was resolved; this is either undefined value or
      -- a pseudo-tag (like `div{}` or `span{}`), so add support for them
      val = setmetatable({key}, {
          -- support the case of printing/concatenating undefined values
          -- tostring handles conversion to a string
          __tostring = function() return "" end,
          -- concat handles concatenation with a string
          __concat = function(a, _) return a end,
          __index = (istable and table or nil),
          __call = function(t, v, ...)
            if type(v) == "table" then
              table.insert(v, 1, key)
              return v
            end
            return {t[1], v, ...}
          end})
    elseif cancache then
      t[key] = val -- cache the calculated value for future use
    end
    return val
  end
end
local tmplTagHandlerEnv = {__index = genEnv({autotag = true}) }
local tmplRegHandlerEnv = {__index = genEnv() }
local tmplReqHandlerEnv = {__index = genEnv({request = true}) }
local req
local function getRequest() return req end
local function detectType(s)
  local ch = s:match("^%s*(%S)")
  return ch and (ch == "<" and "text/html" or ch == "{" and "application/json") or "text/plain"
end

local function serveResponse(status, headers, body)
  -- since headers is optional, handle the case when headers are not present
  if type(headers) == "string" and body == nil then
    body, headers = headers, nil
  end
  if type(status) == "string" and body == nil and headers == nil then
    body, status = status, 200
  end
  argerror(type(status) == "number", 1, "(number expected)")
  argerror(not headers or type(headers) == "table", 2, "(table expected)")
  argerror(not body or type(body) == "string", 3, "(string expected)")
  return function()
    SetStatus(status)
    if headers then
      -- make sure that the metatable gets transferred as well
      local r = getRequest()
      r.headers = setmetatable(headers, getmetatable(r.headers))
    end
    if body then Write(body) end
    return true
  end
end

--[[-- multipart parsing --]]--

local patts = {}
local function getParameter(header, name)
  local function optignorecase(s)
    if not patts[s] then
      patts[s] = (";%s*"
        ..s:gsub("%w", function(s) return ("[%s%s]"):format(s:upper(), s:lower()) end)
        ..[[=["']?([^;"']*)["']?]])
    end
    return patts[s]
  end
  return header:match(optignorecase(name))
end
local CRLF, TAIL = "\r\n", "--"
local CRLFlen = #CRLF
local MULTIVAL = "%[%]$"
local function parseMultipart(body, ctype)
  argerror(type(ctype) == "string", 2, "(string expected)")
  local parts = {
    boundary = getParameter(ctype, "boundary"),
    start = getParameter(ctype, "start"),
  }
  local boundary = "--"..argerror(parts.boundary, 2, "(boundary expected in Content-Type)")
  local bol, eol, eob = 1
  while true do
    repeat
      eol, eob = string.find(body, boundary, bol, true)
      if not eol then return nil, "missing expected boundary at position "..bol end
    until eol == 1 or eol > CRLFlen and body:sub(eol-CRLFlen, eol-1) == CRLF
    if eol > CRLFlen then eol = eol - CRLFlen end
    local headers, name, filename = {}
    if bol > 1 then
      -- find the header (if any)
      if string.sub(body, bol, bol+CRLFlen-1) == CRLF then -- no headers
        bol = bol + CRLFlen
      else -- headers
        -- find the end of headers (CRLF+CRLF)
        local boh, eoh = 1, string.find(body, CRLF..CRLF, bol, true)
        if not eoh then return nil, "missing expected end of headers at position "..bol end
        -- join multi-line header values back if present
        local head = string.sub(body, bol, eoh+1):gsub(CRLF.."%s+", " ")
        while (string.find(head, CRLF, boh, true) or 0) > boh do
          local p, e, header, value = head:find("([^:]+)%s*:%s*(.-)%s*\r\n", boh)
          if p ~= boh then return nil, "invalid header syntax at position "..bol+boh end
          header = header:lower()
          if header == "content-disposition" then
            name = getParameter(value, "name")
            filename = getParameter(value, "filename")
          end
          headers[header] = value
          boh = e + 1
        end
        bol = eoh + CRLFlen*2
      end
      -- epilogue is processed, but not returned
      local ct = headers["content-type"]
      local b, err = string.sub(body, bol, eol-1)
      if ct and ct:lower():find("^multipart/") then
        b, err = parseMultipart(b, ct) -- handle multipart/* recursively
        if not b then return b, err end
      end
      local first = parts.start and parts.start == headers["content-id"] and 1
      local v = {name = name, headers = headers, filename = filename, data = b}
      table.insert(parts, first or #parts+1, v)
      if name then
        if string.find(name, MULTIVAL) then
          parts[name] = parts[name] or {}
          table.insert(parts[name], first or #parts[name]+1, v)
        else
          parts[name] = parts[name] or v
        end
      end
    end
    local tail = body:sub(eob+1, eob+#TAIL)
    -- check if the encapsulation or regular boundary is present
    if tail == TAIL then break end
    if tail ~= CRLF then return nil, "missing closing boundary at position "..eol end
    bol = eob + #tail + 1
  end
  return parts
end

--[[-- template engine --]]--

local templates, vars = {}, {}
local stack, blocks = {}, {}
-- `blocks` is a table behind proxy tables indexed by actual `block` tables in each template
-- where the values are defined blocks and their functions
-- blocks are retrieved in the order in which templates are rendered
-- (first called is first used), as stored in `stack` during rendering.
-- the `stack` table also includes mapping from template names to their proxy tables
local metablock = {
  __newindex = function(t, k, v)
    if not blocks[t] then
      blocks[t] = {}
      stack[t[blocks]] = blocks[t]
    end
    blocks[t][k] = v
  end,
  __index = function(t, k)
    if not blocks[t] then
      blocks[t] = {}
      stack[t[blocks]] = blocks[t]
    end
    -- use the "earliest" template after the one signified with `t`
    for _, name in ipairs(stack) do
      -- if a template name is requested, then return its table
      -- this is needed for direct access to template blocks to simulate `super()`
      local tbl = stack[name]
      -- don't look beyond the template that made this call
      if name == k then return tbl end
      local blk = name and tbl and tbl[k]
      if blk then return blk end
    end
  end,
}
local function render(name, opt)
  argerror(type(name) == "string", 1, "(string expected)")
  argerror(templates[name], 1, "(unknown template name '"..tostring(name).."')")
  argerror(not opt or type(opt) == "table", 2, "(table expected)")
  -- assign default parameters, but allow to overwrite
  local params = {vars = vars, block = setmetatable({[blocks] = name}, metablock)}
  local env = getfenv(templates[name].handler)
  -- add "original" template parameters
  for k, v in pairs(rawget(env, org) or {}) do params[k] = v end
  -- add "passed" template parameters
  for k, v in pairs(opt or {}) do params[k] = v end
  LogDebug("render template '%s'", name)
  env[ref] = params
  table.insert(stack, name)
  local res, more = templates[name].handler(opt)
  table.remove(stack)
  -- reset block cache when the render stack becomes empty
  if #stack == 0 then stack, blocks = {}, {} end
  -- return template results or an empty string to indicate completion
  -- this is useful when the template does direct write to the output buffer
  return res or "", more or {ContentType = templates[name].ContentType}
end

local function setTemplate(name, code, opt)
  -- name as a table designates a list of prefixes for assets paths
  -- to load templates from;
  -- its hash values provide mapping from extensions to template types
  if type(name) == "table" then
    local tmpls = {}
    for _, prefix in ipairs(name) do
      local paths = GetZipPaths(prefix)
      for _, path in ipairs(paths) do
        local tmplname, ext = path:gsub("^"..prefix.."/?",""):match("(.+)%.(%w+)$")
        if ext and name[ext] then
          local asset = LoadAsset(path) or error("Can't load asset: "..path)
          setTemplate(tmplname, {asset, type = name[ext], path = path}, opt)
          tmpls[tmplname] = true
        end
      end
    end
    return tmpls
  end
  argerror(type(name) == "string", 1, "(string or table expected)")
  local params = {}
  if type(code) == "table" then params, code = code, table.remove(code, 1) end
  local ctype = type(code)
  argerror(ctype == "string" or ctype == "function", 2, "(string, table or function expected)")
  LogVerbose("set template '%s'", name)
  local tmpl = templates[params.type or "fmt"]
  local env = setmetatable({render = render, [org] = opt},
    -- get the metatable from the template that this one is based on,
    -- to make sure the correct environment is being served
    tmpl and getmetatable(getfenv(tmpl.handler)) or
    params.autotag and tmplTagHandlerEnv or tmplRegHandlerEnv)
  if ctype == "string" then
    argerror(tmpl ~= nil, 2, "(unknown template type/name)")
    argerror(tmpl.parser ~= nil, 2, "(referenced template doesn't have a parser)")
    local path = "@" .. (params.path or name)
    -- assign proper environment in case parser needs it
    if tmpl.autotag then tmpl.parser = setfenv(tmpl.parser, env) end
    local func = tmpl.parser(code, path)
    -- if the parser returns function, use it as is
    -- if it returns some code, then load and use it
    code = type(func) == "function" and func or assert(load(func, path))
  end
  params.handler = setfenv(code, env)
  templates[name] = params
  return {name = true}
end

local function setTemplateVar(name, value) vars[name] = value end

--[[-- routing engine --]]--

local setmap = {}
(function(s) for pat, reg in s:gmatch("(%S+)=([^%s,]+),?") do setmap[pat] = reg end end)([[
  d=0-9, ]=[.].], -=[.-.], a=[:alpha:], l=[:lower:], u=[:upper:], w=[:alnum:], x=[:xdigit:],
]])
local function findset(s)
  return setmap[s] or s:match("%p") and s or error("Invalid escape sequence %"..s)
end
local function route2regex(route)
  -- foo/bar, foo/*, foo/:bar, foo/:bar[%d], foo(/:bar(/:more))(.:ext)
  local params = {}
  local regex = route:gsub("%)", "%1?") -- update optional groups from () to ()?
    :gsub("%.", "\\.") -- escape dots (.)
    :gsub(PARAM, function(sigil, param)
        if sigil == "*" and param == "" then param = "splat" end
        -- ignore everything that doesn't match `:%w` pattern
        if sigil == ":" and param == "" then return sigil..param end
        table.insert(params, param)
        return sigil == "*" and "(.*)" or "([^/]+)"
      end)
    :gsub("%b[](%+%))(%b[])([^/:*%[]*)", function(sep, pat, rest)
        local leftover, more = rest:match("(.-])(.*)")
        if leftover then pat = pat..leftover; rest = more end
        -- replace Lua character classes with regex ones
        return pat:gsub("%%(.)", findset)..sep..rest end)
  -- mark optional captures, as they are going to be returned during match
  local subnum = 1
  local s, _, capture = 0
  while true do
    s, _, capture = regex:find("%b()([?]?)", s+1)
    if not s then break end
    if capture > "" then table.insert(params, subnum, false) end
    subnum = subnum + 1
  end
  return "^"..regex.."$", params
end

local function findRoute(route, opts)
  for i, r in ipairs(routes) do
    local ometh = opts.method
    local rmeth = (r.options or {}).method
    if route == r.route and
      (type(ometh) == "table" and table.concat(ometh, ",") or ometh) ==
      (type(rmeth) == "table" and table.concat(rmeth, ",") or rmeth) then
      return i
    end
  end
end
local function setRoute(opts, ...)
  local ot = type(opts)
  if ot == "string" then
    opts = {opts}
  elseif ot == "table" then
    argerror(#opts > 0, 1, "(one or more routes expected)", "setRoute")
  else
    argerror(false, 1, "(string or table expected)", "setRoute")
  end
  -- as the handler is optional, allow it to be skipped
  local pnum, handler = select('#', ...), ...
  local ht = type(handler)
  -- allow empty, but not `nil` handler (so `setRoute('foo')`, but not `setRoute('foo', nil)`)
  -- this protects against typos in handler names being silently accepted
  argerror(ht == "function" or ht == "string" or (ht == "nil" and pnum == 0),
    2, "(function or string expected)", "setRoute")
  if ht == "string" then
    -- if `handler` is a string, then turn it into a handler that does
    -- internal redirect (to an existing path), but not a directory.
    -- This is to avoid failing on a missing directory index.
    -- If directory index is still desired, then use `serveIndex()`.
    local newroute = handler
    handler = function(r)
      local path = r.makePath(newroute, r.params)
      local mode = GetAssetMode(path)
      return mode and isregfile(mode) and RoutePath(path)
    end
  end
  if ot == "table" then
    -- remap filters to hash if presented as an (array) table
    for k, v in pairs(opts) do
      if type(v) == "table" then
        -- {"POST", "PUT"} => {"POST", "PUT", PUT = true, POST = true}
        for i = 1, #v do v[v[i]] = true end
        -- if GET is allowed, then also allow HEAD, unless `HEAD=false` exists
        if k == "method" and v.GET and v.HEAD == nil then
          table.insert(v, "HEAD") -- add to the list to generate a proper list of methods
          v.HEAD = v.GET
        end
        if v.regex then
          v.regex = argerror(re.compile(v.regex),
            1, ("(valid regex expected for '%s')"):format(k), "setRoute")
        end
      elseif headerMap[k] then
        opts[k] = {pattern = "%f[%w]"..quote(v).."%f[%W]"}
      end
    end
  end
  -- process 1+ routes as specified
  while true do
    local route = table.remove(opts, 1)
    if not route then break end
    argerror(type(route) == "string", 1, "(route string expected)", "setRoute")
    local pos = findRoute(route, opts) or #routes+1
    if opts.routeName then
      if routes[opts.routeName] then LogWarn("route '%s' already registered", opts.routeName) end
      routes[opts.routeName], opts.routeName = pos, nil
    end
    local regex, params = route2regex(route)
    local tmethod = type(opts.method)
    local methods = tmethod == "table" and opts.method or tmethod == "string" and {opts.method} or {'ANY'}
    LogVerbose("set route '%s' (%s) at index %d", route, table.concat(methods,','), pos)
    routes[pos] = {route = route, handler = handler, options = opts, comp = re.compile(regex), params = params}
    routes[route] = pos
  end
end

local function matchCondition(value, cond)
  if type(cond) == "function" then return cond(value) end
  if type(cond) ~= "table" then return value == cond end
  -- allow `{function() end, otherwise = ...}` as well
  if type(cond[1]) == "function" then return cond[1](value) end
  if value == nil or cond[value] then return true end
  if cond.regex then return cond.regex:search(value) ~= nil end
  if cond.pattern then return value:match(cond.pattern) ~= nil end
  return false
end

local function getAllowedMethod(matchedRoutes)
  local methods = {}
  for _, idx in ipairs(matchedRoutes) do
    local routeMethod = routes[idx].options and routes[idx].options.method
    if routeMethod then
      for _, method in ipairs(type(routeMethod) == "table" and routeMethod or {routeMethod}) do
        if not methods[method] then
          methods[method] = true
          table.insert(methods, method)
        end
      end
    end
  end
  table.sort(methods)
  return (#methods > 0
    and table.concat(methods, ", ")..(methods.OPTIONS == nil and ", OPTIONS" or "")
    or "GET, HEAD, POST, PUT, DELETE, OPTIONS")
end

local function matchRoute(path, req)
  assert(type(req) == "table", "bad argument #2 to match (table expected)")
  LogDebug("match %d route(s) against '%s'", #routes, path)
  local matchedRoutes = {}
  for idx, route in ipairs(routes) do
    -- skip static routes that are only used for path generation
    local opts = route.options
    if route.handler or opts and opts.otherwise then
      local res = {route.comp:search(path)}
      local matched = table.remove(res, 1)
      LogDebug("route '%s' %smatched", route.route, matched and "" or "not ")
      if matched then -- path matched
        table.insert(matchedRoutes, idx)
        for ind, val in ipairs(route.params) do
          if val and res[ind] then req.params[val] = res[ind] > "" and res[ind] or false end
        end
        -- check if there are any additional options to filter by
        local otherwise
        matched = true
        if opts and next(opts) then
          for filter, cond in pairs(opts) do
            if filter ~= "otherwise" then
              local header = headerMap[filter]
              -- check "dashed" headers, params, properties (method, port, host, etc.), and then headers again
              local value = (filter == "r" and req  -- special request value
                or header and req.headers[header]  -- an existing header
                or req.params[filter] or req[filter] or req.headers[filter])
              -- condition can be a value (to compare with) or a table/hash with multiple values
              local resCond, err = matchCondition(value, cond)
              if not resCond then
                otherwise = type(cond) == "table" and cond.otherwise or opts.otherwise
                LogDebug("route '%s' filter '%s%s' didn't match value '%s'%s",
                  route.route, filter, type(cond) == "string" and "="..cond or "",
                  value, tonumber(otherwise) and " and returned "..otherwise or "")
                if otherwise then
                  if type(otherwise) == "function" then
                    return otherwise(err, value)
                  else
                    if otherwise == 405 and not req.headers.Allow then
                      req.headers.Allow = getAllowedMethod(matchedRoutes)
                    end
                    return serveResponse(otherwise)
                  end
                end
                matched = false
                break
              end
            end
          end
        end
        if matched and route.handler then
          local res, more = route.handler(req)
          if res then return res, more end
          path = rawget(req, "path") or path  -- assign path for subsequent checks
        end
      end
    end
  end
end

--[[-- storage engine --]]--

local sqlite3
local NONE = {}
local dbmt = { -- share one metatable among all DBM objects
  -- simple __index = db doesn't work, as it gets `dbm` passed instead of `db`,
  -- so remapping is needed to proxy this to `t.db` instead
  __index = function(t,k)
    if sqlite3[k] then return sqlite3[k] end
    local db = rawget(t, "db")
    return db and db[k] and function(self,...) return db[k](db,...) end or nil
  end,
  __gc = function(t) return t:close() end,
  __close = function(t) return t:close() end
}
local function makeStorage(dbname, sqlsetup, opts)
  sqlite3 = sqlite3 or require "lsqlite3"
  if type(sqlsetup) == "table" and opts == nil then
    sqlsetup, opts = nil, sqlsetup
  end
  local flags = 0
  for flagname, val in pairs(opts or {}) do
    local flagcode = flagname:find("^OPEN_") and (
      sqlite3[flagname] or error("unknown option "..flagname))
    flags = flags | (val and flagcode or 0)
  end
  argerror(not opts or not opts.trace or type(opts.trace) == "function",
    3 , "(function expected as trace option value)")
  -- check if any of the required flags are set; set defaults if not
  if flags & (sqlite3.OPEN_READWRITE + sqlite3.OPEN_READONLY) == 0 then
    flags = flags | (sqlite3.OPEN_READWRITE + sqlite3.OPEN_CREATE)
  end
  local dbm = {NONE = NONE, prepcache = {}, pragmas = {},
    name = dbname, sql = sqlsetup, opts = opts or {}}
  local msgdelete = "use delete option to force"
  local function getPragmas(sql)
    local pragmas = {}
    for p in (sql or ""):gmatch("%s*([^;]+)") do
      if not p:lower():find("pragma ") then break end
      table.insert(pragmas, p)
    end
    return table.concat(pragmas, ";")
  end
  function dbm:init(reopen)
    local db = self.db
    -- if this is a forked process with a connection opened elsewhere,
    -- then need to re-open the connection to avoid bad things:
    -- https://sqlite.org/howtocorrupt.html#_carrying_an_open_database_connection_across_a_fork_
    -- (but don't re-open temp/inmemory and read-only DBs, as it's not needed)
    if db and reopen then
      -- reset the pid even when re-opening is skipped, so that it's not repeated
      self.pid = unix.getpid()
      if db:db_filename("main") ~= "" and (not db.readonly or not db:readonly()) then
        db = false
      end
    end
    if db then return self end

    local skipexec = db == false
    local code, msg
    db, code, msg = sqlite3.open(self.name, flags)
    if not db then error(("%s (code: %d)"):format(msg, code)) end
    -- __gc handler on the DB object will close it, which can happen multiple times
    -- for forked connections and needs to be prevented, as closing one may affect
    -- the others due to the way POSIX advisory locks behave on file handlers):
    -- https://sqlite.org/howtocorrupt.html#_posix_advisory_locks_canceled_by_a_separate_thread_doing_close_
    if debug.getmetatable(db) then debug.getmetatable(db).__gc = nil end
    db:busy_timeout(1000) -- configure wait on busy DB to allow serialized writes
    -- skipexec indicates that a shortcut can be taken to set up the DB,
    -- but the pragmas still need to be processed to have the correct configuration
    local pragmas = skipexec and self.sql and getPragmas(self.sql)
    if pragmas and db:exec(pragmas) > 0
    or not skipexec and self.sql and db:exec(self.sql) > 0 then
      error("can't setup db: "..db:errmsg())
    end
    self.db = db
    self.prepcache = {}
    self.pid = unix.getpid()
    return setmetatable(self, dbmt)
  end
  local function norm(sql)
    return (sql:gsub("%-%-[^\n]*\n?",""):gsub("^%s+",""):gsub("%s+$",""):gsub("%s+"," ")
      :gsub("%s*([(),])%s*","%1"):gsub('"(%w+)"',"%1"))
  end
  local function prepstmt(dbm, stmt)
    if not dbm.prepcache[stmt] then
      assert(dbm.db)
      local st, tail = dbm.db:prepare(stmt)
      -- if there is tail, then return as is, don't cache
      if st and tail and #tail > 0 then return st, tail end
      dbm.prepcache[stmt] = st
    end
    return dbm.prepcache[stmt]
  end
  function dbm:close()
    -- only close the DB when done from the same process that opened it
    -- to avoid closing the DB from a forked process,
    -- which is likely to mess up POSIX locks
    local db = self.db
    if db and self.pid == unix.getpid() then
      self.db = false -- mark it as re-openable
      return db:close()
    end
  end
  local function fetch(self, query, one, ...)
    -- re-open the connection if this is a forked process; see comment in `dbm:init()`
    if self.pid ~= unix.getpid() then self:init(true) end
    if not self.db then self:init() end
    local trace = self.opts.trace
    local start = trace and getTimeNano()
    local rows = {}
    local stmt, tail = query, nil
    repeat
      if type(stmt) == "string" then
        stmt, tail = prepstmt(self, stmt)
      end
      if not stmt then return nil, "can't prepare: "..self.db:errmsg() end
      -- if the last statement is incomplete
      if not stmt:isopen() then break end
      -- if the first parameter is a table, then use it to bind parameters by name
      local tbl = select(1, ...)
      if (type(tbl) == "table" and stmt:bind_names(tbl) or stmt:bind_values(...)) ~= sqlite3.OK then
        return nil, "can't bind values: "..self.db:errmsg()
      end
      for row in stmt:nrows() do
        table.insert(rows, row)
        if one then break end
      end
      stmt:reset()
      stmt = tail  -- get multi-statement ready for processing
    until (one or not tail)
    if trace then trace(self, query, {...}, getTimeDiff(start)) end
    if one == nil then return self.db:changes() end  -- return execute results
    -- return self.NONE instead of an empty table to indicate no rows
    return not one and (rows[1] and rows or self.NONE) or rows[1] or self.NONE
  end
  local function exec(self, stmt, ...) return fetch(self, stmt, nil, ...) end
  local function dberr(db) return nil, db:errmsg() end
  function dbm:execute(list, ...)
    -- if the first parameter is not table, use regular `exec`
    if type(list) ~= "table" then return exec(self, list, ...) end
    -- re-open the connection if this is a forked process; see comment in `dbm:init()`
    if self.pid ~= unix.getpid() then self:init(true) end
    if not self.db then self:init() end
    local db = self.db
    local changes = 0
    if db:exec("savepoint execute") ~= sqlite3.OK then return dberr(db) end
    for _, sql in ipairs(list) do
      if type(sql) ~= "table" then sql = {sql} end
      local ok, err = exec(self, unpack(sql))
      if not ok then
        if db:exec("rollback to execute") ~= sqlite3.OK then return dberr(db) end
        return nil, err
      end
      changes = changes + ok
    end
    if db:exec("release execute") ~= sqlite3.OK then return dberr(db) end
    return changes
  end
  function dbm:fetchAll(stmt, ...) return fetch(dbm, stmt, false, ...) end
  function dbm:fetchOne(stmt, ...) return fetch(dbm, stmt, true, ...) end
  function dbm:pragma(stmt)
    local pragma = stmt:match("[_%w]+")
    if not self.pragmas[pragma] then
      if self:fetchOne("select * from pragma_pragma_list() where name = ?",
        pragma or "") == self.NONE then return nil, "missing or invalid pragma name" end
      self.pragmas[pragma] = true
    end
    local row = self:fetchOne("PRAGMA "..stmt)
    if not row then return nil, self.db:errmsg() end
    return select(2, next(row)) or self.NONE
  end
  obsolete(dbm, "fetchone", "fetchOne", "0.40")
  obsolete(dbm, "fetchall", "fetchAll", "0.40")

  --[[-- dbm upgrade --]]--

  function dbm:upgrade(opts)
    opts = opts or {}
    local actual = self.db and self or error("can't upgrade non initialized db")
    local pristine = makeStorage(":memory:", self.sql)
    local sqltbl = [[SELECT name, sql FROM sqlite_schema
      WHERE type = 'table' AND name not like 'sqlite_%']]
    local ok, err
    local changes, legacyalter = {}, false
    local actbl, prtbl = {}, {}
    for r in pristine:nrows(sqltbl) do prtbl[r.name] = r.sql end
    for r in actual:nrows(sqltbl) do
      actbl[r.name] = true
      if prtbl[r.name] then
        if norm(r.sql) ~= norm(prtbl[r.name]) then
          local namepatt = '%f[^%s"]'..r.name:gsub("%p","%%%1")..'%f[%s"(]'
          local tmpname = r.name.."__new"
          local createtbl = prtbl[r.name]:gsub(namepatt, tmpname, 1)
          table.insert(changes, createtbl)

          local sqlcol = ("PRAGMA table_info(%s)"):format(r.name)
          local common, prcol = {}, {}
          for c in pristine:nrows(sqlcol) do prcol[c.name] = true end
          for c in actual:nrows(sqlcol) do
            if prcol[c.name] then
              table.insert(common, c.name)
            elseif not opts.delete then
              err = err or ("Not allowed to remove '%s' from '%s'; %s"
                ):format(c.name, r.name, msgdelete)
            end
          end
          local cols = table.concat(common, ",")
          table.insert(changes, ("INSERT INTO %s (%s) SELECT %s FROM %s")
            :format(tmpname, cols, cols, r.name))
          table.insert(changes, ("DROP TABLE %s"):format(r.name))
          table.insert(changes, ("ALTER TABLE %s RENAME TO %s"):format(tmpname, r.name))
          legacyalter = true
        end
      else
        if opts.delete == nil then
          err = err or ("Not allowed to drop table '%s'; %s"
            ):format(r.name, msgdelete)
        end
        if opts.delete == true then
          table.insert(changes, ("DROP table %s"):format(r.name))
        end
      end
    end
    if err then return nil, err end
    -- `alter table` may require legacy_alter_table pragma
    -- if depending triggers/views exist
    -- see https://sqlite.org/forum/forumpost/0e2390093fbb8fd6
    -- and https://www.sqlite.org/pragma.html#pragma_legacy_alter_table
    if legacyalter then
      table.insert(changes, 1, "PRAGMA legacy_alter_table=1")
      table.insert(changes, "PRAGMA legacy_alter_table=0")
    end
    for k in pairs(prtbl) do
      if not actbl[k] then table.insert(changes, prtbl[k]) end
    end

    local sqlidx = [[SELECT name, sql, type FROM sqlite_schema
      WHERE type in ('index', 'trigger', 'view')
        AND name not like 'sqlite_%']]
    actbl, prtbl = {}, {}
    for r in pristine:nrows(sqlidx) do
      prtbl[r.type..r.name] = r.sql end
    for r in actual:nrows(sqlidx) do
      actbl[r.type..r.name] = true
      if prtbl[r.type..r.name] then
        if r.sql ~= prtbl[r.type..r.name] then
          table.insert(changes, ("DROP %s IF EXISTS %s"):format(r.type, r.name))
          table.insert(changes, prtbl[r.type..r.name])
        end
      else
        table.insert(changes, ("DROP %s IF EXISTS %s"):format(r.type, r.name))
      end
    end
    for k in pairs(prtbl) do
      if not actbl[k] then table.insert(changes, prtbl[k]) end
    end

    -- get the current value of `PRAGMA foreign_keys` to restore if needed
    local acpfk = assert(actual:pragma"foreign_keys")
    -- get the pristine value of `PRAGMA foreign_keys` to set later
    local prpfk = assert(pristine:pragma"foreign_keys")

    if opts.integritycheck ~= false then
      local ic = self:pragma"integrity_check(1)"
      if ic ~= "ok" then return nil, ic end
      -- check existing foreign key violations if the foreign key setting is enabled
      local fkc = prpfk ~= "0" and self:pragma"foreign_key_check"
      if fkc and fkc ~= self.NONE then return nil, "foreign key check failed" end
    end
    if opts.dryrun then return changes end
    if #changes == 0 then return changes end

    -- disable `pragma foreign_keys`, to avoid triggerring cascading deletes
    ok, err = self:pragma"foreign_keys=0"
    if not ok then return ok, err end

    -- execute the changes (within a savepoint)
    ok, err = self:execute(changes)
    -- restore `PRAGMA foreign_keys` value:
    -- (1) to the original value after failure
    -- (2) to the "pristine" value after normal execution
    local pfk = "foreign_keys="..(ok and prpfk or acpfk)
    if self:pragma(pfk) and ok then table.insert(changes, "PRAGMA "..pfk) end
    if not ok then return ok, err end

    -- clean up the database
    ok, err = self:execute("VACUUM")
    if not ok then return ok, err end
    return changes
  end

  return dbm:init()
end

--[[-- hook management --]]--

local hooks = {}
local function onHook(hookName, ...)
  for _, v in ipairs(hooks[hookName]) do
    local res = v[1](...)
    if res ~= nil then return res end
  end
end
local function findHook(hookName, suffix)
  for i, v in ipairs(hooks[hookName]) do
    if v[2] == suffix then return i, v end
  end
end
local function setHook(name, func)
  -- name: OnWorkerStart[.suffix]
  argerror(type(name) == "string", 1, "(string expected)")
  local main, suffix = name:match("([^.]+)%.?(.*)")
  -- register redbean hook even without handler;
  -- this is needed to set up a handler later, as for some
  -- hooks redbean only checks before the main loop is started
  if not hooks[main] then
    hooks[main] = {}
    local orig = _G[main]
    _G[main] = function(...)
      if orig then orig() end
      return onHook(main, ...)
    end
  end
  local idx, val = findHook(main, suffix)
  local res = val and val[1]
  local isQualified = #suffix > 0
  if not func then
    -- remove the current hook if it's a fully qualified hook
    if idx and isQualified then table.remove(hooks[main], idx) end
  else  -- set the new function
    local hook = {func, suffix}
    if idx and isQualified then  -- update existing qualified hook
      hooks[main][idx] = hook
    else  -- add a new one
      table.insert(hooks[main], hook)
    end
  end
  return res  -- return the old hook value (if any)
end

--[[-- scheduling engine --]]--

local function expand(min, max, vals)
  local tbl = {MIN = min, MAX = max, ['*'] = min.."-"..max}
  for i = min, max do
    tbl[i] = vals and vals[i] or ("%02d"):format(i)
  end
  for k, v in pairs(vals or {}) do tbl[v] = k end
  return tbl
end
local expressions = { expand(0,59), expand(0,23), expand(1,31),
  expand(1,12, {"jan","feb","mar","apr","may","jun","jul","aug","sep","oct","nov","dec"}),
  expand(0,7, {[0]="sun","mon","tue","wed","thu","fri","sat","sun"}),
}
local function cron2hash(rec)
  local cronrec = {rec:lower():match("%s*(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s*")}
  local tbl = {{},{},{},{},{}}
  if #cronrec ~= #tbl then return nil, "invalid format" end
  for exppos, exps in ipairs(cronrec) do
    local map = expressions[exppos]
    for e in exps:gmatch("([^,]+)") do
      local exp = e:gsub("[^%d%-/]+", map)
      local min, rng, max, step = exp:match("^(%d+)(%-?)(%d*)/?(%d*)$")
      if not min then max, step = exp:match("^%-(%d+)/?(%d*)$") end
      if not min and not max then return nil, "invalid expression: "..e end
      min = math.max(map.MIN, tonumber(min) or map.MIN)
      max = math.min(map.MAX, tonumber(max) or #rng==0 and min or map.MAX)
      step = tonumber(step) or 1
      for i = min, max, step do tbl[exppos][map[i]] = true end
    end
  end
  return tbl
end

local schedules, lasttime = {}, 0
local scheduleHook = "OnServerHeartbeat.fm-setSchedule"
local function checkSchedule(time)
  local times = FormatHttpDateTime(time)
  local dow, dom, mon, h, m = times:lower():match("^(%S+), (%S+) (%S+) %S+ (%S+):(%S+):")
  for _, v in pairs(schedules) do
    local cront, func, sameproc = v[1], v[2], v[3]
    if cront[1][m] and cront[2][h] and cront[3][dom] and cront[4][mon] and cront[5][dow] then
      if sameproc or assert(unix.fork()) == 0 then
        local ok, err = pcall(func)
        if not ok then LogWarn("scheduled task failed: "..err) end
        if not sameproc then unix.exit(0) end
      end
    end
  end
end
local function scheduler()
  local time = math.floor(GetTime()/60)*60
  if time == lasttime then return else lasttime = time end
  checkSchedule(time)
end
local function setSchedule(exp, func, opts)
  if type(exp) == "table" then opts, exp, func = exp, unpack(exp) end
  opts = opts or {}
  argerror(type(opts) == "table", 3, "(table expected)")
  local res, err = cron2hash(exp)
  argerror(res ~= nil, 1, err)
  schedules[exp] = {res, func, opts.sameProc}
  if not setHook(scheduleHook, scheduler) then  -- first schedule hook
    if ProgramHeartbeatInterval then
      local min = 60*1000
      if ProgramHeartbeatInterval() > min then ProgramHeartbeatInterval(min) end
    else
      LogWarn("OnServerHeartbeat is required for setSchedule to work,"..
        " but may not be available; you need redbean v2.0.16+.")
    end
  end
end

--[[-- filters --]]--

local function makeLastModified(asset)
  argerror(type(asset) == "string", 1, "(string expected)")
  local lastModified = GetLastModifiedTime(asset)
  return {
    function(ifModifiedSince)
      local isModified = (not ifModifiedSince or
        ParseHttpDateTime(ifModifiedSince) < lastModified)
      if isModified then
        getRequest().headers.LastModified = FormatHttpDateTime(lastModified)
      end
      return isModified
    end,
    otherwise = 304,  -- serve 304 if not modified
  }
end

local trueval = function() return true end
local validators = { msg = trueval, optional = trueval,
  minlen = function(s, num) return #tostring(s or "") >= num, "%s is shorter than "..num.." chars" end,
  maxlen = function(s, num) return #tostring(s or "") <= num, "%s is longer than "..num.." chars" end,
  pattern = function(s, pat) return tostring(s or ""):match(pat), "invalid %s format" end,
  test = function(s, fun) return fun(s) end,
  oneof = function(s, list)
    if type(list) ~= "table" then list = {list} end
    for _, v in ipairs(list) do if s == v then return true end end
    return nil, "%s must be one of: "..EncodeLua(list):sub(2, -2)
  end,
}
local function makeValidator(rules)
  argerror(type(rules) == "table", 1, "(table expected)")
  for i, rule in ipairs(rules) do
    argerror(type(rule) == "table", 1, "(table expected at position "..i..")")
    argerror(type(rule[1]) == "string", 1, "(rule with name expected at position "..i..")")
    argerror(not rule.test or type(rule.test) == "function", 1, "(rule with test as function expected at position "..i..")")
  end
  return setmetatable({
      function(val)
        -- validator can be called in three ways:
        -- (1) directly with a params-like table passed
        -- (2) as a filter on an existing (scalar) field
        -- (3) as a filter on an non-existing field (to get request.params table)
        if val == nil then val = getRequest().params end  -- case (3)
        if type(val) ~= "table" and #rules > 0 then  -- case (2)
          -- convert the passed value into a hash based on the name in the first rule
          val = {[rules[1][1]] = val}
        end
        local errors = {}
        for _, rule in ipairs(rules) do repeat
          local param, err = rule[1], rule.msg
          local value = val[param]
          if value == nil and rule.optional == true then break end  -- continue
          for checkname, checkval in pairs(rule) do
            if type(checkname) == "string" then
              local validator = validators[checkname]
              if not validator then argerror(false, 1, "unknown validator "..checkname) end
              local success, msg = validator(value, checkval)
              if not success then
                local key = rules.key and param or #errors+1
                local errmsg = (err or msg or "%s check failed"):format(param)
                errors[key] = errors[key] or errmsg
                if not rules.all then
                  -- report an error as a single message, unless key is asked for
                  return nil, rules.key and errors or errmsg
                end
              end
            end
          end
        until true end
        if #errors > 0 or next(errors) then return nil, errors end
        return true
      end,
      otherwise = rules.otherwise,
      }, {__call = function(t, r) return t[1](r) end})
  end

--[[-- security --]]--

local function makeBasicAuth(authtable, opts)
  argerror(type(authtable) == "table", 1, "(table expected)")
  argerror(opts == nil or type(opts) == "table", 2, "(table expected)")
  opts = opts or {}
  local realm = opts.realm and (" Realm=%q"):format(opts.realm) or ""
  local hash, key = opts.hash, opts.key
  return {
    function(authorization)
      if not authorization then return false end
      local pass, user = GetPass(), GetUser()
      if not pass or not user or not authtable[user] then return false end
      if hash:upper() == "ARGON2" then return argon2.verify(authtable[user], pass) end
      return authtable[user] == (hash and GetCryptoHash(hash:upper(), pass, key) or pass)
    end,
    -- if authentication is not present or fails, return 401
    otherwise = serveResponse(401, {WWWAuthenticate = "Basic" .. realm}),
  }
end

local function makeIpMatcher(list)
  if type(list) == "string" then list = {list} end
  argerror(type(list) == "table", 1, "(table or string expected)")
  local subnets = {}
  for _, ip in ipairs(list) do
    local v, neg = ip:gsub("^!","")
    local addr, mask = v:match("^(%d+%.%d+%.%d+%.%d+)/(%d+)$")
    if not addr then addr, mask = v, 32 end
    addr = ParseIp(addr)
    argerror(addr ~= -1, 1, ("(invalid IP address %s)"):format(ip))
    mask = tonumber(mask)
    argerror(mask and mask >= 0 and mask <=32, 1, ("invalid mask in %s"):format(ip))
    mask = ~0 << (32 - mask)
    -- apply mask to addr in case addr/subnet is not properly aligned
    table.insert(subnets, {addr & mask, mask, neg > 0})
  end
  return function(ip)
    if ip == -1 then return false end -- fail the check on invalid IP
    for _, v in ipairs(subnets) do
      local match = v[1] == (ip & v[2])
      if match then return not v[3] end
    end
    return false
  end
end

--[[-- core engine --]]--

local function error2tmpl(status, reason, message)
  if not reason then reason = GetHttpReason(status) end
  SetStatus(status, reason) -- set status, but allow template handlers to overwrite it
  local ok, res = pcall(render, tostring(status),
    {status = status, reason = reason, message = message})
  if not ok and status ~= 500 and not res:find("unknown template name") then
    error(res)
  end
  return ok and res or ServeError(status, reason) or true
end
local function checkPath(path) return type(path) == "string" and path or GetPath() end
local fm = setmetatable({ _VERSION = VERSION, _NAME = NAME, _COPYRIGHT = "Paul Kulchenko",
  reg2x = reg2x, reg1p = reg1p,
  getBrand = function() return ("%s/%s %s/%s"):format("redbean", getRBVersion(), NAME, VERSION) end,
  setTemplate = setTemplate, setTemplateVar = setTemplateVar,
  setRoute = setRoute, setSchedule = setSchedule, setHook = setHook,
  parseMultipart = parseMultipart,
  makeStorage = makeStorage,
  makePath = makePath, makeUrl = makeUrl,
  makeBasicAuth = makeBasicAuth, makeIpMatcher = makeIpMatcher,
  makeLastModified = makeLastModified, makeValidator = makeValidator,
  getAsset = LoadAsset, getReq