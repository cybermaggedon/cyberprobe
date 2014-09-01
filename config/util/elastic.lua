
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
  obs["observation"]["time"] = context:get_event_time()

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
  request["observation"]["properties"]["time"]["type"] = "integer"

  local c = http.http_req(module.base .. "cybermon", "PUT", jsenc(request))

  local c = http.http_req(module.base .. "cybermon/observation/_mapping", 
      "PUT", jsenc(request))

end

return module

