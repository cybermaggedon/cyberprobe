
local module = {}

local http = require("util.http")
local addr = require("util.addresses")

local jsenc = require("json.encode")

-- Object ID counter
local id = 1

-- Time-to-live
local default_ttl = "1h"

-- Points to an ElasticSearch instance.
module.base = "http://localhost:9200/"

-- Initialise a basic observation
module.initialise_observation = function(context)

  local obs = {}
  obs["_ttl"] = default_ttl
  obs["observation"] = {}
  obs["observation"]["liid"] = context:get_liid()
  obs["observation"]["src"] = addr.get_stack(context, true)
  obs["observation"]["dest"] = addr.get_stack(context, false)

  local tm = context:get_event_time()
  local tmtab = os.date("*t", tm)
  local tmstr = os.date("%Y%m%dT%H%M", tm)
  local secs = (tm - math.floor(tm)) + tmtab.sec

  tmstr = tmstr .. string.format("%02.3fZ", secs)

  obs["observation"]["time"] = tmstr  

  return obs

end



-- Create an observation object in ElasticSearch
module.submit_observation = function(request)

  local u = string.format(module.base .. "cybermon/observation/%d", id)
  request["observation"]["oid"] = id

  print(string.format("Observation %d", id))
  id = id + 1

  local c = http.http_req(u, "PUT", jsenc.encode(request))

  if not (c == 201) then
    io.write(string.format("Elasticsearch index failed: %s\n", c))
  end

end

-- Initialise elasticsearch
module.init = function()

  print("Deleting index...")
  local c = http.http_req(module.base .. "cybermon/observation/", "DELETE", "")

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
  request["observation"]["properties"]["time"]["type"] = "time"
  request["observation"]["properties"]["time"]["format"] = "basic_date_time"
  request["observation"]["properties"]["header.Content-Type"] = {}
  request["observation"]["properties"]["header.Content-Type"]["type"] = "string"
  request["observation"]["properties"]["header.Content-Type"]["index"] = "not_analyzed"
  request["observation"]["properties"]["header.Host"] = {}
  request["observation"]["properties"]["header.Host"]["type"] = "string"
  request["observation"]["properties"]["header.Host"]["index"] = "not_analyzed"
  request["observation"]["properties"]["dest.ipv4"] = {}
  request["observation"]["properties"]["dest.ipv4"]["type"] = "ip"
  request["observation"]["properties"]["src.ipv4"] = {}
  request["observation"]["properties"]["src.ipv4"]["type"] = "ip"

  local c = http.http_req(module.base .. "cybermon", "PUT", "")

  local c = http.http_req(module.base .. "cybermon/observation/_mapping", 
      "PUT", jsenc(request))

end

return module

