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
local http = require("util.http")
local jsenc = require("json.encode")

local b64 = function(x)
  local a, b = mime.b64(x)
  return a
end

observer.base = "http://localhost:8080/example-rest/v1"

-- Elasticsearch init
-- gaffer.init()

-- The table should contain functions.

-- Add edge to observation

local add_edge = function(obs, subject, pred, object)

  if not obs["elements"] then
    obs["elements"] = {}
  end

  local elt = {}
  elt["directed"] = true
  elt["class"] = "gaffer.data.element.Edge"
  elt["group"] = "BasicEdge"
  elt["source"] = "n:u:" .. subject
  elt["destination"] = "n:u:" .. object
  elt["properties"] = {}
  elt["properties"]["name"] = {}
  elt["properties"]["name"]["gaffer.function.simple.types.FreqMap"] = {}
  elt["properties"]["name"]["gaffer.function.simple.types.FreqMap"]["@r"] = 1
  elt["properties"]["name"]["gaffer.function.simple.types.FreqMap"]["r:u:" .. pred] = 1

  obs["elements"][#obs["elements"] + 1] = elt

  local elt = {}
  elt["directed"] = true
  elt["class"] = "gaffer.data.element.Edge"
  elt["group"] = "BasicEdge"
  elt["source"] = "n:u:" .. subject
  elt["destination"] = "r:u:" .. pred
  elt["properties"] = {}
  elt["properties"]["name"] = {}
  elt["properties"]["name"]["gaffer.function.simple.types.FreqMap"] = {}
  elt["properties"]["name"]["gaffer.function.simple.types.FreqMap"]["@n"] = 1
  elt["properties"]["name"]["gaffer.function.simple.types.FreqMap"]["n:u:" .. object] = 1

  obs["elements"][#obs["elements"] + 1] = elt

end

local next_id = 0

local get_next_id = function()
  local id = "http://cyberprobe.sf.net/obs/" .. next_id
  next_id = next_id + 1
  return id
end

-- Initialise a basic observation
local initialise_observation = function(obs, context, id, action)

  add_edge(obs, id, "http://www.w3.org/1999/02/22-rdf-syntax-ns#type",
  			 "http://cyberprobe.sf.net/type/observation")

  add_edge(obs, id, "http://cyberprobe.sf.net/prop/liid",
  			 context:get_liid())

  add_edge(obs, id, "http://cyberprobe.sf.net/prop/action", action)
  
  for key, value in pairs(addr.get_stack(context, true)) do
    for i = 1, #value do
      add_edge(obs, id, "http://cyberprobe.sf.net/prop/src:" .. key,
                        value[i])
    end
  end
  
  for key, value in pairs(addr.get_stack(context, false)) do
    for i = 1, #value do
      add_edge(obs, id, "http://cyberprobe.sf.net/prop/dest:" .. key,
                        value[i])
    end
  end

  local tm = context:get_event_time()
  local tmstr = os.date("!%Y%m%dT%H%M%S", math.floor(tm))
  local millis = 1000 * (tm - math.floor(tm))

  tmstr = tmstr .. "." .. string.format("%03dZ", math.floor(millis))

  add_edge(obs, id, "http://cyberprobe.sf.net/prop/time", tmstr)

end

observer.submit_observation = function(obs)
  local c = http.http_req(observer.base .. "/graph/doOperation/add/elements",
  	                  "PUT", jsenc.encode(obs),
			  "application/json")
  print(c)
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
  local id = get_next_id()
  initialise_observation(obs, context, id, "connection_up")
  observer.submit_observation(obs)
end

-- This function is called when a stream-orientated connection is closed
observer.connection_down = function(context)
  local obs = {}
  local id = get_next_id()
  initialise_observation(obs, context, id, "connection_down")
  observer.submit_observation(obs)
end

-- This function is called when a datagram is observed, but the protocol
-- is not recognised.
observer.unrecognised_datagram = function(context, data)
  local obs = {}
  local id = get_next_id()
  initialise_observation(obs, context, id, "unrecognised_datagram")
  add_edge(obs, id, "http://cyberprobe.sf.net/prop/data", b64(data))
  observer.submit_observation(obs)
end

-- This function is called when stream data  is observed, but the protocol
-- is not recognised.
observer.unrecognised_stream = function(context, data)
  local obs = {}
  local id = get_next_id()
  initialise_observation(obs, context, id, "unrecognised_stream")
  add_edge(obs, id, "http://cyberprobe.sf.net/prop/data", b64(data))
  observer.submit_observation(obs)
end

-- This function is called when an ICMP message is observed.
observer.icmp = function(context, data)
  local obs = {}
  local id = get_next_id()
  initialise_observation(obs, context, id, "icmp")
  add_edge(obs, id, "http://cyberprobe.sf.net/prop/data", b64(data))
  observer.submit_observation(obs)
end

-- This function is called when an HTTP request is observed.
observer.http_request = function(context, method, url, header, body)
  local obs = {}
  local id = get_next_id()
  initialise_observation(obs, context, id, "http_request")
  add_edge(obs, id, "http://cyberprobe.sf.net/prop/method", method)
  add_edge(obs, id, "http://cyberprobe.sf.net/prop/url", url)
  for key, value in pairs(header) do
    add_edge(obs, id, "http://cyberprobe.sf.net/prop/header:" .. key,
                      value)
  end
  add_edge(obs, id, "http://cyberprobe.sf.net/prop/body", b64(body))
  observer.submit_observation(obs)
end

-- This function is called when an HTTP response is observed.
observer.http_response = function(context, code, status, header, url, body)
  local obs = {}
  local id = get_next_id()
  initialise_observation(obs, context, id, "http_response")
  add_edge(obs, id, "http://cyberprobe.sf.net/prop/code", code)
  add_edge(obs, id, "http://cyberprobe.sf.net/prop/status", status)
  add_edge(obs, id, "http://cyberprobe.sf.net/prop/url", url)
  for key, value in pairs(header) do
    add_edge(obs, id, "http://cyberprobe.sf.net/prop/header:" .. key,
                      value)
  end
  add_edge(obs, id, "http://cyberprobe.sf.net/prop/body", b64(body))
  observer.submit_observation(obs)
end


-- This function is called when a DNS message is observed.
observer.dns_message = function(context, header, queries, answers, auth, add)
  local obs = {}
  local id = get_next_id()
  initialise_observation(obs, context, id, "dns_message")

  if header.qr == 0 then
    add_edge(obs, id, "http://cyberprobe.sf.net/prop/dns_type", "query")
  else
    add_edge(obs, id, "http://cyberprobe.sf.net/prop/dns_type", "response")
  end

  for key, value in pairs(queries) do
    add_edge(obs, id, "http://cyberprobe.sf.net/prop/query", value.name)
  end

  for key, value in pairs(answers) do
    add_edge(obs, id, "http://cyberprobe.sf.net/prop/answer_name", value.name)
    if value.rdaddress then
       add_edge(obs, id, "http://cyberprobe.sf.net/prop/answer:address", value.rdaddress)
    end
    if value.rdname then
       add_edge(obs, id, "http://cyberprobe.sf.net/prop/answer:name",
                         value.rdname)
    end
  end
  observer.submit_observation(obs)
end


-- This function is called when an FTP command is observed.
observer.ftp_command = function(context, command)
  local obs = {}
  local id = get_next_id()
  initialise_observation(obs, context, id, "ftp_command")
  add_edge(obs, id, "http://cyberprobe.sf.net/prop/command", command)
  observer.submit_observation(obs)
end

-- This function is called when an FTP response is observed.
observer.ftp_response = function(context, status, text)
  local obs = {}
  local id = get_next_id()
  initialise_observation(obs, context, id, "ftp_response")
  add_edge(obs, id, "http://cyberprobe.sf.net/prop/status", status)
  add_edge(obs, id, "http://cyberprobe.sf.net/prop/text", text)
  elastic.submit_observation(obs)
end

-- Return the table
return observer

