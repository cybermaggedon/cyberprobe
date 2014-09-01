--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
--
-- This configuration file uses data from a STIX server stored locally in
-- JSON format.  Triggers when STIX Indicators are detected to hit.
--

-- Load JSON decode, and filesystem module.
local mime = require("mime")
local stix = require("util.stix")
local addr = require("util.addresses")
local elastic = require("util.elastic")

-- Default TTL on objects.
local default_ttl = "1h"

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

  indicators = {}
  stix.check_addresses(context, indicators)

  for k, v in pairs(indicators) do
    print(string.format("Connection opened to address %s, hits %s (%s)", 
      v.value, v.id, v.description))
  end

  local request = {}
  request["observation"] = {}
  request["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = addr.get_stack(context, true)
  request["observation"]["dest"] = addr.get_stack(context, false)
  request["observation"]["action"] = "connection_up"
  request["observation"]["data"] = b64(data)
  request["observation"]["indicators"] = indicators
  elastic.create_observation(request)

end

-- This function is called when a stream-orientated connection is closed
observer.connection_down = function(context)

-- No indicators reported on connection down

  local request = {}
  request["observation"] = {}
  request["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = addr.get_stack(context, true)
  request["observation"]["dest"] = addr.get_stack(context, false)
  request["observation"]["action"] = "connection_down"
  request["observation"]["data"] = b64(data)
  elastic.create_observation(request)

end

-- This function is called when a datagram is observed, but the protocol
-- is not recognised.
observer.unrecognised_datagram = function(context, data)

  indicators = {}
  stix.check_addresses(context, indicators)

  for k, v in pairs(indicators) do
    print(string.format("Unrecognised datagram with address %s, hits %s (%s)", 
      v.value, v.id, v.description))
  end

  local request = {}
  request["observation"] = {}
  request["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = addr.get_stack(context, true)
  request["observation"]["dest"] = addr.get_stack(context, false)
  request["observation"]["action"] = "unrecognised_datagram"
  request["observation"]["data"] = b64(data)
  request["observation"]["indicators"] = indicators
  elastic.create_observation(request)

end

-- This function is called when stream data  is observed, but the protocol
-- is not recognised.
observer.unrecognised_stream = function(context, data)

  indicators = {}
  stix.check_addresses(context, indicators)

  for k, v in pairs(indicators) do
    print(string.format("Connection with address %s, hits %s (%s)", v.value,
      v.id, v.description))
  end

  local request = {}
  request["observation"] = {}
  request["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = addr.get_stack(context, true)
  request["observation"]["dest"] = addr.get_stack(context, false)
  request["observation"]["action"] = "unrecognised_stream"
  request["observation"]["data"] = b64(data)
  request["observation"]["indicators"] = indicators
  elastic.create_observation(request)

end

-- This function is called when an ICMP message is observed.
observer.icmp = function(context, data)

  indicators = {}
  stix.check_addresses(context, indicators)

  for k, v in pairs(indicators) do
    print(string.format("ICMP with address %s, hits %s (%s)", v.value,
      v.id, v.description))
  end

  local request = {}
  request["observation"] = {}
  request["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = addr.get_stack(context, true)
  request["observation"]["dest"] = addr.get_stack(context, false)
  request["observation"]["action"] = "icmp"
  request["observation"]["data"] = b64(data)
  request["observation"]["indicators"] = indicators
  elastic.create_observation(request)

end

-- This function is called when an HTTP request is observed.
observer.http_request = function(context, method, url, header, body)

  -- Hacky.  Construct the URL from bits of stuff we know.
  -- FIXME: URL may already by correct.
  url = "http://" .. header['Host'] .. url

  indicators = {}
  stix.check_url(url, indicators)
  stix.check_dns(header['Host'], indicators)

  for k, v in pairs(indicators) do
    print(string.format("HTTP request to %s, hits %s (%s)", v.value,
        v.id, v.description))
  end

  local request = {}
  request["observation"] = {}
  request["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = addr.get_stack(context, true)
  request["observation"]["dest"] = addr.get_stack(context, false)
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

  indicators = {}
  stix.check_url(url, indicators)

  for k, v in pairs(indicators) do
    print(string.format("HTTP response from %s, hits %s (%s)", v.value,
        v.id, v.description))
  end

  local request = {}
  request["observation"] = {}
  request["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = addr.get_stack(context, true)
  request["observation"]["dest"] = addr.get_stack(context, false)
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

  indicators = {}
  stix.check_addresses(context, indicators)

  for k, v in pairs(indicators) do
    print(string.format("SMTP command with address %s, hits %s (%s)", v.value,
      v.id, v.description))
  end

  local request = {}
  request["observation"] = {}
  request["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = addr.get_stack(context, true)
  request["observation"]["dest"] = addr.get_stack(context, false)
  request["observation"]["action"] = "smtp_command"
  request["observation"]["command"] = command
  request["observation"]["indicators"] = indicators
  elastic.create_observation(request)

end

-- This function is called when an SMTP response is observed.
observer.smtp_response = function(context, status, text)

  indicators = {}
  stix.check_addresses(context, indicators)

  for k, v in pairs(indicators) do
    print(string.format("SMTP response with address %s, hits %s (%s)", v.value,
      v.id, v.description))
  end

  local request = {}
  request["observation"] = {}
  request["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = addr.get_stack(context, true)
  request["observation"]["dest"] = addr.get_stack(context, false)
  request["observation"]["action"] = "smtp_response"
  request["observation"]["status"] = status
  request["observation"]["text"] = text
  request["observation"]["indicators"] = indicators
  elastic.create_observation(request)

end

-- This function is called when an SMTP response is observed.
observer.smtp_data = function(context, from, to, data)

  indicators = {}
  stix.check_email(from)

  for k, v in pairs(to) do
    stix.check_email(v)
  end

  for k, v in pairs(indicators) do
    print(string.format("SMTP email from/to %s, hits %s (%s)", v.value,
        v.id, v.description))
  end

  local request = {}
  request["observation"] = {}
  request["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = addr.get_stack(context, true)
  request["observation"]["dest"] = addr.get_stack(context, false)
  request["observation"]["action"] = "smtp_data"
  request["observation"]["from"] = from
  request["observation"]["to"] = to
  request["observation"]["data"] = b64(data)
  request["observation"]["indicators"] = indicators
  elastic.create_observation(request)

end

-- This function is called when a DNS message is observed.
observer.dns_message = function(context, header, queries, answers, auth, add)

  local trans = "query"
  if header.qr == 1 then
    trans = "response"
  end

  if not(#queries == 1) then
    return
  end

  indicators = {}

  stix.check_dns(queries[1].name, indicators)

  for k, v in pairs(indicators) do
    print(string.format("DNS %s for %s, hits %s (%s)", trans, queries[1].name,
        v.id, v.description))
  end

  local request = {}
  request["observation"] = {}
  request["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = addr.get_stack(context, true)
  request["observation"]["dest"] = addr.get_stack(context, false)
  request["observation"]["action"] = "dns_message"
  request["observation"]["indicators"] = indicators
  request["observation"]["type"] = trans

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

  indicators = {}
  stix.check_addresses(context, indicators)

  for k, v in pairs(indicators) do
    print(string.format("FTP response with address %s, hits %s (%s)", v.value,
      v.id, v.description))
  end

  local request = {}
  request["observation"] = {}
  request["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = addr.get_stack(context, true)
  request["observation"]["dest"] = addr.get_stack(context, false)
  request["observation"]["action"] = "ftp_command"
  request["observation"]["command"] = command
  request["observation"]["indicators"] = indicators
  elastic.create_observation(request)

end

-- This function is called when an FTP response is observed.
observer.ftp_response = function(context, status, text)

  indicators = {}
  stix.check_addresses(context, indicators)

  for k, v in pairs(indicators) do
    print(string.format("FTP response with address %s, hits %s (%s)", v.value,
      v.id, v.description))
  end

  local request = {}
  request["observation"] = {}
  request["_ttl"] = default_ttl
  request["observation"]["liid"] = context:get_liid()
  request["observation"]["src"] = addr.get_stack(context, true)
  request["observation"]["dest"] = addr.get_stack(context, false)
  request["observation"]["action"] = "ftp_response"
  request["observation"]["status"] = status
  request["observation"]["text"] = text
  request["observation"]["indicators"] = indicators
  elastic.create_observation(request)

end

-- Return the table
return observer

