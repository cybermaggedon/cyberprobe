
local module = {}

local http = require("http")

local jsenc = require("json.encode")

-- Object ID counter
local id = 1

-- Points to an ElasticSearch instance.
module.base = "http://localhost:9200/"

-- Create an observation object in ElasticSearch
module.create_observation = function(request)

  local u = string.format(module.base .. "cybermon/observation/%d", id)
  request["observation"]["oid"] = id
  request["observation"]["time"] = os.time()

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

