--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
--
-- This configuration file does nothing.  The event functions are all empty
-- stubs.  Maybe a good starting point for building your own config from
-- scratch.
--

-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

local jsenc = require("json.encode")
local ltn12 = require("ltn12")
local http = require("socket.http")
local mime = require("mime")

local id = 1

local default_ttl = "60s"

local b64 = function(x)
  local a, b = mime.b64(x)
  return a
end

observer.get_address = function(context, is_src)
  local par = context:get_parent()
  local addrs

  if par then
    if is_src then
      addrs = observer.get_address(par, true)
    else
      addrs = observer.get_address(par, false)
    end
  else
    addrs = {}
  end

  local cls, addr
  if is_src then
    cls, addr = context:get_src_addr()
  else
    cls, addr = context:get_dest_addr()
  end

  if not (addr == "") then
    addrs[#addrs + 1] = { protocol = cls, address = addr }
  end

  return addrs
end

local http_req = function(u, meth, reqbody)

  local r, c, rg
  r, c, rg = http.request {
    url = u;
    method = meth;
    headers = {["Content-Length"] = #reqbody};
    source = ltn12.source.string(reqbody);
  }

  return c

end

local observation = function(request)

  local u = string.format("http://localhost:9200/cybermon/observation/%d", id)
  request["observation"]["oid"] = id
  request["observation"]["time"] = os.time()

--  print(jsenc.encode(request))

  print(string.format("Observation %d", id))
  id = id + 1

  local c = http_req(u, "PUT", jsenc.encode(request))

  if not (c == 201) then
    io.write(string.format("Elasticsearch index failed: %s\n", c))
  end

end

-- Elasticsearch init

print("Deleting index...")
local c = http_req("http://localhost:9200/cybermon/observation/", "DELETE", "")

print("Create mapping...")
local request = {}
request["observation"] = {}
request["observation"]["_ttl"] = {}
request["observation"]["_ttl"]["enabled"] = "true"
request["observation"]["properties"] = {}
request["observation"]["properties"]["body"] = {}
request["observation"]["properties"]["body"]["type"] = "binary"
request["observation"]["properties"]["data"] = {}
request["observation"]["properties"]["data"]["type"] = "binary"
request["observation"]["properties"]["time"] = {}
request["observation"]["properties"]["time"]["type"] = "integer"

local c = http_req("http://localhost:9200/cybermon",
  "PUT", jsenc(request))

local c = http_req("http://localhost:9200/cybermon/observation/_mapping",
  "PUT", jsenc(request))

-- The table should contain functions.

-- This function is called when a trigger events starts collection of an
-- attacker. liid=the trigger ID, addr=trigger address
observer.trigger_up = function(liid, addr)
end

-- This function is called when an attacker goes off the air
observer.trigger_down = function(liid)
end

-- This function is called when a stream-orientated connection is made
-- (e.g. TCP)
observer.connection_up = function(context)
  local request = {}
  request["observation"] = {}
  request["observation"]["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = observer.get_address(context, true)
  request["observation"]["dest"] = observer.get_address(context, false)
  request["observation"]["action"] = "connected_up"
  observation(request)
end

-- This function is called when a stream-orientated connection is closed
observer.connection_down = function(context)
  local request = {}
  request["observation"] = {}
  request["observation"]["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = observer.get_address(context, true)
  request["observation"]["dest"] = observer.get_address(context, false)
  request["observation"]["action"] = "connected_down"
  observation(request)
end

-- This function is called when a datagram is observed, but the protocol
-- is not recognised.
observer.unrecognised_datagram = function(context, data)
  local request = {}
  request["observation"] = {}
  request["observation"]["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = observer.get_address(context, true)
  request["observation"]["dest"] = observer.get_address(context, false)
  request["observation"]["action"] = "datagram"
  request["observation"]["data"] = b64(data)
  observation(request)
end

-- This function is called when stream data  is observed, but the protocol
-- is not recognised.
observer.unrecognised_stream = function(context, data)
  local request = {}
  request["observation"] = {}
  request["observation"]["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = observer.get_address(context, true)
  request["observation"]["dest"] = observer.get_address(context, false)
  request["observation"]["action"] = "unrecognised_stream"
  request["observation"]["data"] = b64(data)
  observation(request)
end

-- This function is called when an ICMP message is observed.
observer.icmp = function(context, data)
  local request = {}
  request["observation"] = {}
  request["observation"]["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = observer.get_address(context, true)
  request["observation"]["dest"] = observer.get_address(context, false)
  request["observation"]["action"] = "icmp"
  request["observation"]["data"] = b64(data)
  observation(request)
end

-- This function is called when an HTTP request is observed.
observer.http_request = function(context, method, url, header, body)
  local request = {}
  request["observation"] = {}
  request["observation"]["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = observer.get_address(context, true)
  request["observation"]["dest"] = observer.get_address(context, false)
  request["observation"]["action"] = "http_request"
  request["observation"]["method"] = method
  request["observation"]["url"] = url
  request["observation"]["header"] = header
  request["observation"]["body"] = b64(body)
  observation(request)
end

-- This function is called when an HTTP response is observed.
observer.http_response = function(context, code, status, header, url, body)
  local request = {}
  request["observation"] = {}
  request["observation"]["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = observer.get_address(context, true)
  request["observation"]["dest"] = observer.get_address(context, false)
  request["observation"]["action"] = "http_response"
  request["observation"]["code"] = code
  request["observation"]["status"] = status
  request["observation"]["header"] = header
  request["observation"]["url"] = url
  request["observation"]["body"] = b64(body)
  observation(request)
end

-- This function is called when a DNS message is observed.
observer.dns_message = function(context, header, queries, answers, auth, add)
  local request = {}
  request["observation"] = {}
  request["observation"]["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = observer.get_address(context, true)
  request["observation"]["dest"] = observer.get_address(context, false)
  request["observation"]["action"] = "dns_message"

  if header.qr == 0 then
    request["observation"]["type"] = "query"
  else
    request["observation"]["type"] = "response"
  end

  local q = {}
  for key, value in pairs(queries) do
    q[#q + 1] = value.name
  end
  request["observation"]["queries"] = q

  q = {}
  for key, value in pairs(answers) do
    local a = {}
    a["name"] = value.name
    if value.rdaddress then
       a["address"] = value.rdaddress
    end
    if value.rdname then
       a["name"] = value.rdname
    end
    q[#q + 1] = a
  end
  request["observation"]["answers"] = q
  observation(request)
end


-- This function is called when an FTP command is observed.
observer.ftp_command = function(context, command)
  local request = {}
  request["observation"] = {}
  request["observation"]["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = observer.get_address(context, true)
  request["observation"]["dest"] = observer.get_address(context, false)
  request["observation"]["action"] = "ftp_command"
  request["observation"]["command"] = command
  observation(request)
end

-- This function is called when an FTP response is observed.
observer.ftp_response = function(context, status, text)
  local request = {}
  request["observation"] = {}
  request["observation"]["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = observer.get_address(context, true)
  request["observation"]["dest"] = observer.get_address(context, false)
  request["observation"]["action"] = "ftp_response"
--  request["observation"]["status"] = status
  request["observation"]["text"] = text
  observation(request)
end

-- Return the table
return observer

