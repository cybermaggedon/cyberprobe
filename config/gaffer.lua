--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
--
-- This configuration file stores events in ElasticSearch.  The event
-- functions are all empty stubs.  Maybe a good starting point for building
-- your own config from scratch.
--

-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

local mime = require("mime")
local jsenc = require("json.encode")
local addr = require("util.addresses")

local b64 = function(x)
  local a, b = mime.b64(x)
  return a
end

-- Elasticsearch init
-- gaffer.init()

-- The table should contain functions.

-- Add edge to observation
observer.add_edge = function(obs, pred, object)
  if not obs[pred] then
    obs[pred] = {}
  end
  obs[pred][#obs[pred] + 1] = object
end

-- Initialise a basic observation
observer.initialise_observation = function(obs, context, action)

  observer.add_edge(obs, "pred:liid", context:get_liid())

  observer.add_edge(obs, "pred:action", action)
  
  for key, value in pairs(addr.get_stack(context, true)) do
    observer.add_edge(obs, "pred:src:" .. key, value)
  end
  for key, value in pairs(addr.get_stack(context, false)) do
    observer.add_edge(obs, "pred:dest:" .. key, value)
  end

  local tm = context:get_event_time()
  local tmstr = os.date("!%Y%m%dT%H%M%S", math.floor(tm))
  local millis = 1000 * (tm - math.floor(tm))

  tmstr = tmstr .. "." .. string.format("%03dZ", math.floor(millis))

  observer.add_edge(obs, "pred:time", tmstr)

end

observer.submit_observation = function(obs)
  str = jsenc(obs)
  print(str)
end

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
  local obs = {}
  observer.initialise_observation(obs, context, "connection_up")
  observer.submit_observation(obs)
end

-- This function is called when a stream-orientated connection is closed
observer.connection_down = function(context)
  local obs = {}
  observer.initialise_observation(obs, context, "connection_down")
  observer.submit_observation(obs)
end

-- This function is called when a datagram is observed, but the protocol
-- is not recognised.
observer.unrecognised_datagram = function(context, data)
  local obs = {}
  observer.initialise_observation(obs, context, "unrecognised_datagram")
  observer.add_edge(obs, "pred:data", b64(data))
  observer.submit_observation(obs)
end

-- This function is called when stream data  is observed, but the protocol
-- is not recognised.
observer.unrecognised_stream = function(context, data)
  local obs = {}
  observer.initialise_observation(obs, context, "unrecognised_stream")
  observer.add_edge(obs, "pred:data", b64(data))
  observer.submit_observation(obs)
end

-- This function is called when an ICMP message is observed.
observer.icmp = function(context, data)
  local obs = {}
  observer.initialise_observation(obs, context, "icmp")
  observer.add_edge(obs, "pred:data", b64(data))
  observer.submit_observation(obs)
end

-- This function is called when an HTTP request is observed.
observer.http_request = function(context, method, url, header, body)
  local obs = {}
  observer.initialise_observation(obs, context, "http_request")
  observer.add_edge(obs, "pred:method", method)
  observer.add_edge(obs, "pred:url", url)
  for key, value in pairs(header) do
    observer.add_edge(obs, "pred:header:" .. key, value)
  end
  observer.add_edge(obs, "pred:body", b64(body))
  observer.submit_observation(obs)
end

-- This function is called when an HTTP response is observed.
observer.http_response = function(context, code, status, header, url, body)
  local obs = {}
  observer.initialise_observation(obs, context, "http_response")
  observer.add_edge(obs, "pred:code", code)
  observer.add_edge(obs, "pred:status", status)
  observer.add_edge(obs, "pred:url", url)
  for key, value in pairs(header) do
    observer.add_edge(obs, "pred:header:" .. key, value)
  end
  observer.add_edge(obs, "pred:body", b64(body))
  observer.submit_observation(obs)
end


-- This function is called when a DNS message is observed.
observer.dns_message = function(context, header, queries, answers, auth, add)
  local obs = {}
  observer.initialise_observation(obs, context, "dns_message")

  if header.qr == 0 then
    observer.add_edge(obs, "pred:dns_type", "query")
  else
    observer.add_edge(obs, "pred:dns_type", "response")
  end

  for key, value in pairs(queries) do
    observer.add_edge(obs, "pred:query", value.name)
  end

  for key, value in pairs(answers) do
    observer.add_edge(obs, "pred:answer_name", value.name)
    if value.rdaddress then
       observer.add_edge(obs, "pred:answer:address", value.rdaddress)
    end
    if value.rdname then
       observer.add_edge(obs, "pred:answer:name", value.rdname)
    end
  end
  observer.submit_observation(obs)
end


-- This function is called when an FTP command is observed.
observer.ftp_command = function(context, command)
  local obs = {}
  observer.initialise_observation(obs, context, "ftp_command")
  observer.add_edge(obs, "pred:command", command)
  observer.submit_observation(obs)
end

-- This function is called when an FTP response is observed.
observer.ftp_response = function(context, status, text)
  local obs = {}
  observer.initialise_observation(obs, context, "ftp_response")
  observer.add_edge(obs, "pred:status", status)
  observer.add_edge(obs, "pred:text", text)
  elastic.submit_observation(obs)
end

-- Return the table
return observer

