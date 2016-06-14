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

-- Common data type URI
local cybtype = "http://cyberprobe.sf.net/type/"
local cybprop = "http://cyberprobe.sf.net/prop/"
local cybobj = "http://cyberprobe.sf.net/obj/"

local rdfschema = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
local dubcore = "http://purl.org/dc/elements/1.1/"

local b64 = function(x)
  local a, b = mime.b64(x)
  if (a == nil) then
    return ""
  end
  return a
end

observer.base = "http://localhost:8080/example-rest/v1"

-- Add edge to observation
local add_edge_basic = function(edges, s, e, d, tp)

  if not edges["elements"] then
    edges["elements"] = {}
  end

  local elt = {}
  elt["directed"] = true
  elt["class"] = "gaffer.data.element.Edge"
  elt["group"] = "BasicEdge"
  elt["source"] = s
  elt["destination"] = d
  elt["properties"] = {}
  elt["properties"]["name"] = {}
  elt["properties"]["name"]["gaffer.function.simple.types.FreqMap"] = {}
  elt["properties"]["name"]["gaffer.function.simple.types.FreqMap"][tp] = 1
  elt["properties"]["name"]["gaffer.function.simple.types.FreqMap"][e] = 1

  edges["elements"][#edges["elements"] + 1] = elt

end

local add_edge_u = function(edges, s, p, o)
  add_edge_basic(edges, "n:u:" .. s, "r:u:" .. p, "n:u:" .. o, "@r")
  add_edge_basic(edges, "n:u:" .. s, "n:u:" .. o, "r:u:" .. p, "@n")
end

local add_edge_s = function(edges, s, p, o)
  add_edge_basic(edges, "n:u:" .. s, "r:u:" .. p, "n:s:" .. o, "@r")
  add_edge_basic(edges, "n:u:" .. s, "n:s:" .. o, "r:u:" .. p, "@n")
end

local add_edge_i = function(edges, s, p, o)
  add_edge_basic(edges, "n:u:" .. s, "r:u:" .. p, "n:i:" .. math.floor(o), "@r")
  add_edge_basic(edges, "n:u:" .. s, "n:i:" .. math.floor(o), "r:u:" .. p, "@n")
end

local add_edge_dt = function(edges, s, p, o)
  add_edge_basic(edges, "n:u:" .. s, "r:u:" .. p, "n:d:" .. o, "@r")
  add_edge_basic(edges, "n:u:" .. s, "n:d:" .. o, "r:u:" .. p, "@n")
end

local submit_edges = function(edges)
  local c = http.http_req(observer.base .. "/graph/doOperation/add/elements",
  	                  "PUT", jsenc.encode(edges),
			  "application/json")
  print(c)
end

local init = function()

  edges = {}

  add_edge_u(edges, cybtype .. "observation", rdfschema .. "type",
             rdfschema .. "Resource")
  add_edge_s(edges, cybtype .. "observation", dubcore .. "title",
             "Observation")

  add_edge_u(edges, cybtype .. "liid", rdfschema .. "type",
             rdfschema .. "Resource")
  add_edge_s(edges, cybtype .. "liid", dubcore .. "title",
             "LIID")

  add_edge_u(edges, cybprop .. "method", rdfschema .. "type",
             rdfschema .. "Property")
  add_edge_s(edges, cybprop .. "method", dubcore .. "title",
             "Method")

  add_edge_u(edges, cybprop .. "action", rdfschema .. "type",
             rdfschema .. "Property")
  add_edge_s(edges, cybprop .. "action", dubcore .. "title",
             "Action")

  add_edge_u(edges, cybprop .. "code", rdfschema .. "type",
             rdfschema .. "Property")
  add_edge_s(edges, cybprop .. "code", dubcore .. "title",
             "Response code")

  add_edge_u(edges, cybprop .. "status", rdfschema .. "type",
             rdfschema .. "Property")
  add_edge_s(edges, cybprop .. "status", dubcore .. "title",
             "Response status")

  add_edge_u(edges, cybprop .. "url", rdfschema .. "type",
             rdfschema .. "Property")
  add_edge_s(edges, cybprop .. "url", dubcore .. "title",
             "URL")

  add_edge_u(edges, cybtype .. "time", rdfschema .. "type",
             rdfschema .. "Resource")
  add_edge_s(edges, cybtype .. "time", dubcore .. "title",
             "Time of observation")

  -- For DNS

  add_edge_u(edges, cybprop .. "dns_type", rdfschema .. "type",
             rdfschema .. "Property")
  add_edge_s(edges, cybprop .. "dns_type", dubcore .. "title",
             "DNS type")

  add_edge_u(edges, cybprop .. "query", rdfschema .. "type",
             rdfschema .. "Property")
  add_edge_s(edges, cybprop .. "query", dubcore .. "title",
             "DNS query")

  add_edge_u(edges, cybprop .. "answer_name", rdfschema .. "type",
             rdfschema .. "Property")
  add_edge_s(edges, cybprop .. "answer_name", dubcore .. "title",
             "Answer (name)")

  add_edge_u(edges, cybprop .. "answer_address", rdfschema .. "type",
             rdfschema .. "Property")
  add_edge_s(edges, cybprop .. "answer_address", dubcore .. "title",
             "Answer (address)")

  -- Addresses

  add_edge_u(edges, cybprop .. "source", rdfschema .. "type",
             rdfschema .. "Property")
  add_edge_s(edges, cybprop .. "source", dubcore .. "title",
             "Source address")

  add_edge_u(edges, cybprop .. "dest", rdfschema .. "type",
             rdfschema .. "Property")
  add_edge_s(edges, cybprop .. "dest", dubcore .. "title",
             "Destination address")

  add_edge_u(edges, cybtype .. "ipv4", rdfschema .. "type",
             rdfschema .. "Resource")
  add_edge_s(edges, cybtype .. "ipv4", dubcore .. "title",
             "IPv4 address")

  add_edge_u(edges, cybtype .. "tcp", rdfschema .. "type",
             rdfschema .. "Resource")
  add_edge_s(edges, cybtype .. "tcp", dubcore .. "title",
             "TCP port")

  add_edge_u(edges, cybtype .. "udp", rdfschema .. "type",
             rdfschema .. "Resource")
  add_edge_s(edges, cybtype .. "udp", dubcore .. "title",
             "UDP port")

  submit_edges(edges)

end

local next_id = 0

local get_next_id = function()
  local id = next_id
  next_id = next_id + 1
  return id
end

-- Initialise a basic observation
local create_basic = function(edges, context, action)

  local id = get_next_id()
  local uri = cybobj .. "obs/" .. id
  add_edge_u(edges, uri, rdfschema .. "type", cybtype .. "observation")
  add_edge_s(edges, uri, dubcore .. "title", "Observation " .. id)

  local liid = cybobj .. "liid/" .. context:get_liid()
  add_edge_u(edges, uri, cybprop .. "liid", liid)
  add_edge_u(edges, liid, rdfschema .. "type", cybtype .. "liid")
  add_edge_s(edges, liid, dubcore .. "title", "LIID " .. context:get_liid())

  add_edge_s(edges, uri, cybprop .. "action", action)
  
  for key, value in pairs(addr.get_stack(context, true)) do
    for i = 1, #value do
      if key == "ipv4" or key == "tcp" or key == "udp" then
        add_edge_u(edges, uri, cybprop .. "source",
	           cybobj .. key .. "/" .. value[i])
        add_edge_u(edges, cybobj .. key .. "/" .. value[i], rdfschema .. "type",
	           cybtype .. key)
        add_edge_s(edges, cybobj .. key .. "/" .. value[i], dubcore .. "title",
	           value[i] .. " (" .. key .. ")")
      end
    end
  end

  for key, value in pairs(addr.get_stack(context, false)) do
    for i = 1, #value do
      if key == "ipv4" or key == "tcp" or key == "udp" then
        add_edge_u(edges, uri, cybprop .. "dest",
	           cybobj .. key .. "/" .. value[i])
        add_edge_u(edges, cybobj .. key .. "/" .. value[i], rdfschema .. "type",
	           cybtype .. key)
        add_edge_s(edges, cybobj .. key .. "/" .. value[i], dubcore .. "title",
	           value[i] .. " (" .. key .. ")")
      end		    
    end
  end
  
  local tm = context:get_event_time()
  local tmstr = os.date("!%Y%m%dT%H%M%S", math.floor(tm))
  local millis = 1000 * (tm - math.floor(tm))

  tmstr = tmstr .. "." .. string.format("%03dZ", math.floor(millis))

  add_edge_dt(edges, uri, cybprop .. "time", tmstr)

  return uri

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
  local edges = {}
  local id = create_basic(edges, context, "connection_up")
  submit_edges(edges)
end

-- This function is called when a stream-orientated connection is closed
observer.connection_down = function(context)
  local edges = {}
  local id = create_basic(edges, context, "connection_down")
  submit_edges(edges)
end

-- This function is called when a datagram is observed, but the protocol
-- is not recognised.
observer.unrecognised_datagram = function(context, data)
  local edges = {}
  local id = create_basic(edges, context, "unrecognised_datagram")
  add_edge_s(edges, id, cybprop .. "data", b64(data))
  submit_edges(edges)
end

-- This function is called when stream data  is observed, but the protocol
-- is not recognised.
observer.unrecognised_stream = function(context, data)
  local edges = {}
  local id = create_basic(edges, context, "unrecognised_stream")
  add_edge_s(edges, id, cybprop .. "data", b64(data))
  submit_edges(edges)
end

-- This function is called when an ICMP message is observed.
observer.icmp = function(context, data)
  local edges = {}
  local id = create_basic(edges, context, "icmp")
  add_edge_s(edges, id, cybprop .. "data", b64(data))
  submit_edges(edges)
end

-- This function is called when an HTTP request is observed.
observer.http_request = function(context, method, url, header, body)
  local edges = {}
  local id = create_basic(edges, context, "http_request")
  add_edge_s(edges, id, cybprop .. "method", method)
  add_edge_u(edges, id, cybprop .. "url", url)
  for key, value in pairs(header) do
    add_edge_s(edges, id, cybprop .. "header:" .. key, value)
  end
  if (body and not body == "") then
    add_edge_s(edges, id, cybprop .. "body", b64(body))
  end
  submit_edges(edges)
end

-- This function is called when an HTTP response is observed.
observer.http_response = function(context, code, status, header, url, body)
  local edges = {}
  local id = create_basic(edges, context, "http_response")
  add_edge_s(edges, id, cybprop .. "code", code)
  add_edge_s(edges, id, cybprop .. "status", status)
  add_edge_u(edges, id, cybprop .. "url", url)
  for key, value in pairs(header) do
    add_edge_s(edges, id, cybprop .. "header:" .. key, value)
  end
  if (body) then
    add_edge_s(edges, id, cybprop .. "body", b64(body))
  end
  submit_edges(edges)
end


-- This function is called when a DNS message is observed.
observer.dns_message = function(context, header, queries, answers, auth, add)
  local edges = {}
  local id = create_basic(edges, context, "dns_message")

  if header.qr == 0 then
    add_edge_s(edges, id, cybprop .. "dns_type", "query")
  else
    add_edge_s(edges, id, cybprop .. "dns_type", "answer")
  end

  for key, value in pairs(queries) do
    add_edge_s(edges, id, cybprop .. "query", value.name)
  end

  for key, value in pairs(answers) do
    add_edge_s(edges, id, cybprop .. "answer_name", value.name)
    if value.rdaddress then
       add_edge_s(edges, id, cybprop .. "answer_address",
                  value.rdaddress)
    end
    if value.rdname then
       add_edge_s(edges, id, cybprop .. "answer_name",
                            value.rdname)
    end
  end
  submit_edges(edges)
end


-- This function is called when an FTP command is observed.
observer.ftp_command = function(context, command)
  local edges = {}
  local id = create_basic(edges, context, "ftp_command")
  add_edge_s(edges, id, cybprop .. "command", command)
  submit_edges(edges)
end

-- This function is called when an FTP response is observed.
observer.ftp_response = function(context, status, text)
  local edges = {}
  local id = create_basic(edges, context, "ftp_response")
  add_edge_s(edges, id, cybprop .. "status", status)
  add_edge_s(edges, id, cybprop .. "text", text)
  submit_edges(edges)
end

-- Initialise
init()

-- Return the table
return observer

