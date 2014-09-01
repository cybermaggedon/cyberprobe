--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
--
-- This configuration file uses data from a STIX server stored locally in
-- JSON format.  Triggers when STIX Indicators are detected to hit.
--

-- Load JSON decode, and filesystem module.
local jsdec = require("json.decode")
local lfs = require("lfs")
local jsenc = require("json.encode")
local ltn12 = require("ltn12")
local http = require("socket.http")
local mime = require("mime")

-- Object ID counter
local id = 1

-- Default TTL on objects.
local default_ttl = "5m"

-- Base64 encoder.
local b64 = function(x)
  local a, b = mime.b64(x)
  return a
end

-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

-- Gets the stack of addresses on the src/dest side of a context.
observer.get_stack = function(context, is_src)
  local par = context:get_parent()
  local addrs

  if par then
    if is_src then
      addrs = observer.get_stack(par, true)
    else
      addrs = observer.get_stack(par, false)
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

-- Make an HTTP request
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

-- Create an observation object in ElasticSearch
local observation = function(request)

  local u = string.format("http://localhost:9200/cybermon/observation/%d", id)
  request["observation"]["oid"] = id
  request["observation"]["time"] = os.time()

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

-- Last mod time of the configuration file.  This helps us work out when to
-- reload.
local cur_mtime = 0

-- Configuration file.
local config_file = "stix-default-combined.json"

-- STIX information gets stored here.
local stix = {}

-- This stores the JSON decode.
stix.configuration = {}

-- This stores an index, from various address information to the STIX
-- Indicators.
stix.index = {}

-- Function, checks the modification time of the configuration file, and
-- if it's changed, reloads and regenerates the index.
stix.check_config = function(file)

  -- Get file mod time.
  local mtime = lfs.attributes(file, "modification")

  -- If modtime is the same, nothing to do.
  if mtime == last_mtime then return end

  -- Read file
  local f = io.open(file, "r")
  stix.configuration = jsdec(f:read("*a"))
  f:close()

  -- Initialise the STIX indexes.
  stix.index = {}
  stix.index.email = {}
  stix.index.user_account = {}
  stix.index.hostname = {}
  stix.index.port = {}
  stix.index.url = {}
  stix.index.ipv4 = {}
  stix.index.mac = {}
  stix.index.file = {}
  stix.index.hash = {}

  -- Loop through indicators.
  for key, value in pairs(stix.configuration.indicators) do

    -- Get indicator object
    local object = value.observable.object.properties

    -- Pull out different interesting things for the index.

    -- Address type
    if object["xsi:type"] == "AddressObjectType" then

      -- Index email address
      if object.category == "e-mail" then
	stix.index.email[object.address_value] = value
      end

      -- Index IPv4 address
      if object.category == "ipv4-addr" then
	stix.index.ipv4[object.address_value] = value
      end

      -- Index MAC address
      if object.category == "mac" then
	stix.index.mac[object.address_value] = value
      end

    -- UserAccount type
    elseif object["xsi:type"] == "UserAccountObjectType" then

      -- Index on concatenation of domain and username.
      if object.domain and object.username then
	ix = object.domain .. "|" .. object.username
	stix.index.user_account[ix] = value
      end

    -- Hostname
    elseif object["xsi:type"] == "HostnameObjectType" then

      -- Index on hostname value
      stix.index.hostname[object.hostname_value] = value

    -- Port
    elseif object["xsi:type"] == "PortObjectType" then

      -- Index on concatenation of layer 4 protocol, and port number.
      if object.port_value and object.layer4_protocol then
	ix = object.layer4_protocol.value .. ":" .. object.port_value
	stix.index.port[ix] = value
      end

    -- URI
    elseif object["xsi:type"] == "URIObjectType" then

      -- Index on the URI itself.
      stix.index.url[object.value] = value

    -- File
    elseif object["xsi:type"] == "FileObjectType" then

      -- Index on pathname
      if object.full_path ~= nil then
	stix.index.file[object.full_path] = value
      end

      -- Index on hash values
      if object.hashes then
	for k2, v2 in pairs(object.hashes) do
	  if v2.type and v2.simple_hash_value then
	    ix = v2.type .. ":" .. v2.simple_hash_value
	    stix.index.hash[ix] = value
	  end
	end
      end
    end
  end

  io.write("Reloaded configuration file.\n")

  -- Update file modification time to modtime of this file.
  last_mtime = mtime

end

-- This function is called when a trigger events starts collection of an
-- attacker. liid=the trigger ID, addr=trigger address
observer.trigger_up = function(liid, addr)
end

-- This function is called when an attacker goes off the air
observer.trigger_down = function(liid)
end

observer.get_address = function(context, lst, cls, is_src)

  local par = context:get_parent()
  if par then
    observer.get_address(par, lst, cls, is_src)
  end

  if is_src then
    tcls, addr = context:get_src_addr()
  else
    tcls, addr = context:get_dest_addr()
  end

  if tcls == cls then
    table.insert(lst, addr)
  end

end

-- This function is called when a stream-orientated connection is made
-- (e.g. TCP)
observer.connection_up = function(context)

  observer.check_config()

  lst = {}
  indicators = {}

  -- Source and destination addresses
  observer.get_address(context, lst, "ipv4", true)
  observer.get_address(context, lst, "ipv4", false)

  for k, v in pairs(lst) do
    check = stix.index.ipv4[v]
    if check then
      print(string.format("Connection with address %s, hits %s (%s)", v,
        check.id, check.description))
      local indicator = {}
      indicator["on"] = "ipv4"
      indicator["value"] = v
      indicator["id"] = check.id
      indicator["description"] = check.description
      indicators[#indicators + 1] = indicator
    end
  end

  lst = {}

  -- Source and destination addresses
  observer.get_address(context, lst, "tcp", true)
  observer.get_address(context, lst, "tcp", false)

  for k, v in pairs(lst) do
    check = stix.index.port["tcp:" .. v]
    if check then
      print(string.format("Connection with TCP port %s, hits %s (%s)", v,
        check.id, check.description))
      local indicator = {}
      indicator["on"] = "tcp"
      indicator["value"] = v
      indicator["id"] = check.id
      indicator["description"] = check.description
      indicators[#indicators + 1] = indicator
    end
  end

  local request = {}
  request["observation"] = {}
  request["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = observer.get_stack(context, true)
  request["observation"]["dest"] = observer.get_stack(context, false)
  request["observation"]["action"] = "connected_up"
  request["observation"]["indicators"] = indicators
  observation(request)

end

-- This function is called when a stream-orientated connection is closed
observer.connection_down = function(context)

  local request = {}
  request["observation"] = {}
  request["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = observer.get_stack(context, true)
  request["observation"]["dest"] = observer.get_stack(context, false)
  request["observation"]["action"] = "connected_down"
  observation(request)

end

-- This function is called when a datagram is observed, but the protocol
-- is not recognised.
observer.unrecognised_datagram = function(context, data)

  observer.check_config()

  lst = {}
  indicators = {}

  -- Source and destination addresses
  observer.get_address(context, lst, "ipv4", true)
  observer.get_address(context, lst, "ipv4", false)

  for k, v in pairs(lst) do
    check = stix.index.ipv4[v]
    if check then
      print(string.format("Datagram with address %s, hits %s (%s)", v,
        check.id, check.description))
      local indicator = {}
      indicator["on"] = "ipv4"
      indicator["value"] = v
      indicator["id"] = check.id
      indicator["description"] = check.description
      indicators[#indicators + 1] = indicator
    end
  end

  local request = {}
  request["observation"] = {}
  request["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = observer.get_stack(context, true)
  request["observation"]["dest"] = observer.get_stack(context, false)
  request["observation"]["action"] = "datagram"
  request["observation"]["data"] = b64(data)
  request["observation"]["indicators"] = indicators
  observation(request)

end

-- This function is called when stream data  is observed, but the protocol
-- is not recognised.
observer.unrecognised_stream = function(context, data)

  lst = {}
  indicators = {}

  -- Source and destination addresses
  observer.get_address(context, lst, "ipv4", true)
  observer.get_address(context, lst, "ipv4", false)

  for k, v in pairs(lst) do
    check = stix.index.ipv4[v]
    if check then
      print(string.format("Datagram with address %s, hits %s (%s)", v,
        check.id, check.description))
      local indicator = {}
      indicator["on"] = "ipv4"
      indicator["value"] = v
      indicator["id"] = check.id
      indicator["description"] = check.description
      indicators[#indicators + 1] = indicator
    end
  end

  lst = {}

  -- Source and destination addresses
  observer.get_address(context, lst, "tcp", true)
  observer.get_address(context, lst, "tcp", false)

  for k, v in pairs(lst) do
    check = stix.index.port["tcp:" .. v]
    if check then
      print(string.format("Connection with TCP port %s, hits %s (%s)", v,
        check.id, check.description))
      local indicator = {}
      indicator["on"] = "tcp"
      indicator["value"] = v
      indicator["id"] = check.id
      indicator["description"] = check.description
      indicators[#indicators + 1] = indicator
    end
  end

  local request = {}
  request["observation"] = {}
  request["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = observer.get_stack(context, true)
  request["observation"]["dest"] = observer.get_stack(context, false)
  request["observation"]["action"] = "unrecognised_stream"
  request["observation"]["data"] = b64(data)
  request["observation"]["indicators"] = indicators
  observation(request)

end

-- This function is called when an ICMP message is observed.
observer.icmp = function(context, data)

  observer.check_config()

  lst = {}
  indicators = {}

  -- Source and destination addresses
  observer.get_address(context, lst, "ipv4", true)
  observer.get_address(context, lst, "ipv4", false)

  for k, v in pairs(lst) do
    check = stix.index.ipv4[v]
    if check then
      print(string.format("ICMP with address %s, hits %s (%s)", v,
        check.id, check.description))
      local indicator = {}
      indicator["on"] = "ipv4"
      indicator["value"] = v
      indicator["id"] = check.id
      indicator["description"] = check.description
      indicators[#indicators + 1] = indicator
    end
  end

  local request = {}
  request["observation"] = {}
  request["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = observer.get_stack(context, true)
  request["observation"]["dest"] = observer.get_stack(context, false)
  request["observation"]["action"] = "icmp"
  request["observation"]["data"] = b64(data)
  request["observation"]["indicators"] = indicators
  observation(request)

end

-- Call this to check, and if appropriate, update the configuration file
observer.check_config = function()
  stix.check_config(config_file)
end

-- This function is called when an HTTP request is observed.
observer.http_request = function(context, method, url, header, body)

  observer.check_config()

  indicators = {}

  -- Hacky.  Construct the URL from bits of stuff we know.
  -- FIXME: URL may already by correct.
  url = "http://" .. header['Host'] .. url

  check = stix.index.url[url]
  if check then
    print(string.format("HTTP request to %s, hits %s (%s)", url,
        check.id, check.description))
      local indicator = {}
      indicator["on"] = "ipv4"
      indicator["value"] = v
      indicator["id"] = check.id
      indicator["description"] = check.description
      indicators[#indicators + 1] = indicator
  end

  check = stix.index.hostname[header['Host']]
  if check then
    print(string.format("HTTP request to %s, hits %s (%s)", header["Host"],
        check.id, check.description))
      local indicator = {}
      indicator["on"] = "ipv4"
      indicator["value"] = v
      indicator["id"] = check.id
      indicator["description"] = check.description
      indicators[#indicators + 1] = indicator
  end

  local request = {}
  request["observation"] = {}
  request["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = observer.get_stack(context, true)
  request["observation"]["dest"] = observer.get_stack(context, false)
  request["observation"]["action"] = "http_request"
  request["observation"]["method"] = method
  request["observation"]["url"] = url
  request["observation"]["header"] = header
  request["observation"]["body"] = b64(body)
  request["observation"]["indicators"] = indicators
  observation(request)

end

-- This function is called when an HTTP response is observed.
observer.http_response = function(context, code, status, header, url, body)

  observer.check_config()

  indicators = {}

  check = stix.index.url[url]
  if check then
    print(string.format("HTTP response from %s, hits %s (%s)", url,
        check.id, check.description))
      local indicator = {}
      indicator["on"] = "ipv4"
      indicator["value"] = v
      indicator["id"] = check.id
      indicator["description"] = check.description
      indicators[#indicators + 1] = indicator
  end

  local request = {}
  request["observation"] = {}
  request["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = observer.get_stack(context, true)
  request["observation"]["dest"] = observer.get_stack(context, false)
  request["observation"]["action"] = "http_response"
  request["observation"]["code"] = code
  request["observation"]["status"] = status
  request["observation"]["header"] = header
  request["observation"]["url"] = url
  request["observation"]["body"] = b64(body)
  request["observation"]["indicators"] = indicators
  observation(request)

end

-- This function is called when an SMTP command is observed.
observer.smtp_command = function(context, command)
  -- FIXME Make observation!
end

-- This function is called when an SMTP response is observed.
observer.smtp_response = function(context, status, text)
  -- FIXME: Make observation
end

-- This function is called when an SMTP response is observed.
observer.smtp_data = function(context, from, to, data)

  -- FIXME: Make observation

  check = stix.index.email[from]
  if check then
    print(string.format("SMTP email from %s, hits %s (%s)", from,
        check.id, check.description))
  end

  for k, v in pairs(to) do
    check = stix.index.email[v]
    if check then
      print(string.format("SMTP email to %s, hits %s (%s)", to,
          check.id, check.description))
    end
  end

end

-- This function is called when a DNS message is observed.
observer.dns_message = function(context, header, queries, answers, auth, add)

  indicators = {}

  observer.check_config()

  if header.qr == 0 and #queries == 1 then

    check = stix.index.hostname[queries[1].name]
    if check then
      print(string.format("DNS query for %s, hits %s (%s)", queries[1].name,
          check.id, check.description))
      local indicator = {}
      indicator["on"] = "hostname"
      indicator["value"] = v
      indicator["id"] = check.id
      indicator["description"] = check.description
      indicators[#indicators + 1] = indicator
    end

  end

  if header.qr == 1 and #queries == 1 then

    check = stix.index.hostname[queries[1].name]
    if check then
      print(string.format("DNS response for %s, hits %s (%s)", queries[1].name,
          check.id, check.description))
      local indicator = {}
      indicator["on"] = "hostname"
      indicator["value"] = v
      indicator["id"] = check.id
      indicator["description"] = check.description
      indicators[#indicators + 1] = indicator
    end

  end
  local request = {}
  request["observation"] = {}
  request["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = observer.get_stack(context, true)
  request["observation"]["dest"] = observer.get_stack(context, false)
  request["observation"]["action"] = "dns_message"
  request["observation"]["indicators"] = indicators

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

  observer.check_config()

  lst = {}
  indicators = {}

  -- Source and destination addresses
  observer.get_address(context, lst, "ipv4", true)
  observer.get_address(context, lst, "ipv4", false)

  for k, v in pairs(lst) do
    check = stix.index.ipv4[v]
    if check then
      print(string.format("Connection with address %s, hits %s (%s)", v,
        check.id, check.description))
      local indicator = {}
      indicator["on"] = "ipv4"
      indicator["value"] = v
      indicator["id"] = check.id
      indicator["description"] = check.description
      indicators[#indicators + 1] = indicator
    end
  end

  lst = {}

  -- Source and destination addresses
  observer.get_address(context, lst, "tcp", true)
  observer.get_address(context, lst, "tcp", false)

  for k, v in pairs(lst) do
    check = stix.index.port["tcp:" .. v]
    if check then
      print(string.format("Connection with TCP port %s, hits %s (%s)", v,
        check.id, check.description))
      local indicator = {}
      indicator["on"] = "tcp"
      indicator["value"] = v
      indicator["id"] = check.id
      indicator["description"] = check.description
      indicators[#indicators + 1] = indicator
    end
  end

  local request = {}
  request["observation"] = {}
  request["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = observer.get_stack(context, true)
  request["observation"]["dest"] = observer.get_stack(context, false)
  request["observation"]["action"] = "ftp_command"
  request["observation"]["command"] = command
  observation(request)

end

-- This function is called when an FTP response is observed.
observer.ftp_response = function(context, status, text)

  observer.check_config()

  lst = {}
  indicators = {}

  -- Source and destination addresses
  observer.get_address(context, lst, "ipv4", true)
  observer.get_address(context, lst, "ipv4", false)

  for k, v in pairs(lst) do
    check = stix.index.ipv4[v]
    if check then
      print(string.format("Connection with address %s, hits %s (%s)", v,
        check.id, check.description))
      local indicator = {}
      indicator["on"] = "ipv4"
      indicator["value"] = v
      indicator["id"] = check.id
      indicator["description"] = check.description
      indicators[#indicators + 1] = indicator
    end
  end

  lst = {}

  -- Source and destination addresses
  observer.get_address(context, lst, "tcp", true)
  observer.get_address(context, lst, "tcp", false)

  for k, v in pairs(lst) do
    check = stix.index.port["tcp:" .. v]
    if check then
      print(string.format("Connection with TCP port %s, hits %s (%s)", v,
        check.id, check.description))
      local indicator = {}
      indicator["on"] = "tcp"
      indicator["value"] = v
      indicator["id"] = check.id
      indicator["description"] = check.description
      indicators[#indicators + 1] = indicator
    end
  end

  local request = {}
  request["observation"] = {}
  request["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = observer.get_stack(context, true)
  request["observation"]["dest"] = observer.get_stack(context, false)
  request["observation"]["action"] = "ftp_response"
--  request["observation"]["status"] = status
  request["observation"]["text"] = text
  observation(request)

end

-- Return the table
return observer

