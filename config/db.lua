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

local mime = require("mime")
local elastic = require("util.elastic")

local b64 = function(x)
  local a, b = mime.b64(x)
  return a
end

-- Elasticsearch init
elastic.init()

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
  local obs = elastic.initialise_observation(context)
  obs["observation"]["action"] = "connected_up"
  elastic.submit_observation(obs)
end

-- This function is called when a stream-orientated connection is closed
observer.connection_down = function(context)
  local obs = elastic.initialise_observation(context)
  obs["observation"]["action"] = "connected_down"
  elastic.submit_observation(obs)
end

-- This function is called when a datagram is observed, but the protocol
-- is not recognised.
observer.unrecognised_datagram = function(context, data)
  local obs = elastic.initialise_observation(context)
  obs["observation"]["action"] = "unrecognised_datagram"
  obs["observation"]["data"] = b64(data)
  elastic.submit_observation(obs)
end

-- This function is called when stream data  is observed, but the protocol
-- is not recognised.
observer.unrecognised_stream = function(context, data)
  local obs = elastic.initialise_observation(context)
  obs["observation"]["action"] = "unrecognised_stream"
  obs["observation"]["data"] = b64(data)
  elastic.submit_observation(obs)
end

-- This function is called when an ICMP message is observed.
observer.icmp = function(context, data)
  local obs = elastic.initialise_observation(context)
  obs["observation"]["action"] = "icmp"
  obs["observation"]["data"] = b64(data)
  elastic.submit_observation(obs)
end

-- This function is called when an HTTP request is observed.
observer.http_request = function(context, method, url, header, body)
  local obs = elastic.initialise_observation(context)
  obs["observation"]["action"] = "http_request"
  obs["observation"]["method"] = method
  obs["observation"]["url"] = url
  obs["observation"]["header"] = header
  obs["observation"]["body"] = b64(body)
  elastic.submit_observation(obs)
end

-- This function is called when an HTTP response is observed.
observer.http_response = function(context, code, status, header, url, body)
  local obs = elastic.initialise_observation(context)
  obs["observation"]["action"] = "http_response"
  obs["observation"]["code"] = code
  obs["observation"]["status"] = status
  obs["observation"]["header"] = header
  obs["observation"]["url"] = url
  obs["observation"]["body"] = b64(body)
  elastic.submit_observation(obs)
end

-- This function is called when a DNS message is observed.
observer.dns_message = function(context, header, queries, answers, auth, add)
  local obs = elastic.initialise_observation(context)

  obs["observation"]["action"] = "dns_message"

  if header.qr == 0 then
    obs["observation"]["type"] = "query"
  else
    obs["observation"]["type"] = "response"
  end

  local q = {}
  for key, value in pairs(queries) do
    q[#q + 1] = value.name
  end
  obs["observation"]["queries"] = q

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
  obs["observation"]["answers"] = q
  elastic.submit_observation(obs)
end


-- This function is called when an FTP command is observed.
observer.ftp_command = function(context, command)
  local obs = elastic.initialise_observation(context)
  obs["observation"]["action"] = "ftp_command"
  obs["observation"]["command"] = command
  elastic.submit_observation(obs)
end

-- This function is called when an FTP response is observed.
observer.ftp_response = function(context, status, text)
  local obs = elastic.initialise_observation(context)
  obs["observation"]["action"] = "ftp_response"
  obs["observation"]["status"] = status
  obs["observation"]["text"] = text
  elastic.submit_observation(obs)
end

-- Return the table
return observer

