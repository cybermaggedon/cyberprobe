--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
--
-- This configuration file uses data from a STIX server stored locally in
-- JSON format.  Triggers when STIX Indicators are detected to hit.
--

-- Load JSON decode, and filesystem module.
local mime = require("mime")
local stix = require("stix")
local util = require("util")
local elastic = require("elastic")

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

-- Elasticsearch init
elastic.init()

-- Last mod time of the configuration file.  This helps us work out when to
-- reload.
local cur_mtime = 0

-- Configuration file.
local config_file = "stix-default-combined.json"

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

  observer.check_config()

  lst = {}
  indicators = {}

  -- Source and destination addresses
  util.get_address(context, lst, "ipv4", true)
  util.get_address(context, lst, "ipv4", false)

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
  util.get_address(context, lst, "tcp", true)
  util.get_address(context, lst, "tcp", false)

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
  request["observation"]["src"] = util.get_stack(context, true)
  request["observation"]["dest"] = util.get_stack(context, false)
  request["observation"]["action"] = "connected_up"
  request["observation"]["indicators"] = indicators
  elastic.create_observation(request)

end

-- This function is called when a stream-orientated connection is closed
observer.connection_down = function(context)

  local request = {}
  request["observation"] = {}
  request["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = util.get_stack(context, true)
  request["observation"]["dest"] = util.get_stack(context, false)
  request["observation"]["action"] = "connected_down"
  elastic.create_observation(request)

end

-- This function is called when a datagram is observed, but the protocol
-- is not recognised.
observer.unrecognised_datagram = function(context, data)

  observer.check_config()

  lst = {}
  indicators = {}

  -- Source and destination addresses
  util.get_address(context, lst, "ipv4", true)
  util.get_address(context, lst, "ipv4", false)

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
  request["observation"]["src"] = util.get_stack(context, true)
  request["observation"]["dest"] = util.get_stack(context, false)
  request["observation"]["action"] = "datagram"
  request["observation"]["data"] = b64(data)
  request["observation"]["indicators"] = indicators
  elastic.create_observation(request)

end

-- This function is called when stream data  is observed, but the protocol
-- is not recognised.
observer.unrecognised_stream = function(context, data)

  lst = {}
  indicators = {}

  -- Source and destination addresses
  util.get_address(context, lst, "ipv4", true)
  util.get_address(context, lst, "ipv4", false)

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
  util.get_address(context, lst, "tcp", true)
  util.get_address(context, lst, "tcp", false)

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
  request["observation"]["src"] = util.get_stack(context, true)
  request["observation"]["dest"] = util.get_stack(context, false)
  request["observation"]["action"] = "unrecognised_stream"
  request["observation"]["data"] = b64(data)
  request["observation"]["indicators"] = indicators
  elastic.create_observation(request)

end

-- This function is called when an ICMP message is observed.
observer.icmp = function(context, data)

  observer.check_config()

  lst = {}
  indicators = {}

  -- Source and destination addresses
  util.get_address(context, lst, "ipv4", true)
  util.get_address(context, lst, "ipv4", false)

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
  request["observation"]["src"] = util.get_stack(context, true)
  request["observation"]["dest"] = util.get_stack(context, false)
  request["observation"]["action"] = "icmp"
  request["observation"]["data"] = b64(data)
  request["observation"]["indicators"] = indicators
  elastic.create_observation(request)

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
  request["observation"]["src"] = util.get_stack(context, true)
  request["observation"]["dest"] = util.get_stack(context, false)
  request["observation"]["action"] = "http_request"
  request["observation"]["method"] = method
  request["observation"]["url"] = url
  request["observation"]["header"] = header
  request["observation"]["body"] = b64(body)
  request["observation"]["indicators"] = indicators
  elastic.create_observation(request)

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
  request["observation"]["src"] = util.get_stack(context, true)
  request["observation"]["dest"] = util.get_stack(context, false)
  request["observation"]["action"] = "http_response"
  request["observation"]["code"] = code
  request["observation"]["status"] = status
  request["observation"]["header"] = header
  request["observation"]["url"] = url
  request["observation"]["body"] = b64(body)
  request["observation"]["indicators"] = indicators
  elastic.create_observation(request)

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
  request["observation"]["src"] = util.get_stack(context, true)
  request["observation"]["dest"] = util.get_stack(context, false)
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
  elastic.create_observation(request)

end

-- This function is called when an FTP command is observed.
observer.ftp_command = function(context, command)

  observer.check_config()

  lst = {}
  indicators = {}

  -- Source and destination addresses
  util.get_address(context, lst, "ipv4", true)
  util.get_address(context, lst, "ipv4", false)

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
  util.get_address(context, lst, "tcp", true)
  util.get_address(context, lst, "tcp", false)

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
  request["observation"]["src"] = util.get_stack(context, true)
  request["observation"]["dest"] = util.get_stack(context, false)
  request["observation"]["action"] = "ftp_command"
  request["observation"]["command"] = command
  elastic.create_observation(request)

end

-- This function is called when an FTP response is observed.
observer.ftp_response = function(context, status, text)

  observer.check_config()

  lst = {}
  indicators = {}

  -- Source and destination addresses
  util.get_address(context, lst, "ipv4", true)
  util.get_address(context, lst, "ipv4", false)

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
  util.get_address(context, lst, "tcp", true)
  util.get_address(context, lst, "tcp", false)

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
  request["observation"]["src"] = util.get_stack(context, true)
  request["observation"]["dest"] = util.get_stack(context, false)
  request["observation"]["action"] = "ftp_response"
--  request["observation"]["status"] = status
  request["observation"]["text"] = text
  elastic.create_observation(request)

end

-- Return the table
return observer

