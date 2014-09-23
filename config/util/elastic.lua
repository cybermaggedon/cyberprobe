
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
  local tmstr = os.date("%Y%m%dT%H%M%S", tm)
  local millis = 1000 * (tm - math.floor(tm))

  tmstr = tmstr .. "." .. string.format("%03dZ", millis)

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

  if not (c == 201 or c == 200) then
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
  request["observation"]["properties"]["time"]["type"] = "date"
  request["observation"]["properties"]["time"]["format"] = "basic_date_time"
  request["observation"]["properties"]["url"] = {}
  request["observation"]["properties"]["url"]["type"] = "string"
  request["observation"]["properties"]["url"]["analyzer"] = "keyword"
  request["observation"]["properties"]["header"] = {}
  request["observation"]["properties"]["header"]["type"] = "object"
  request["observation"]["properties"]["header"]["properties"] = {}
  request["observation"]["properties"]["header"]["properties"]["Content-Type"] = {}
  request["observation"]["properties"]["header"]["properties"]["Content-Type"]["type"] = "string"
  request["observation"]["properties"]["header"]["properties"]["Content-Type"]["index"] = "analyzed"
  request["observation"]["properties"]["header"]["properties"]["Content-Type"]["analyzer"] = "keyword"
  request["observation"]["properties"]["header"]["properties"]["User-Agent"] = {}
  request["observation"]["properties"]["header"]["properties"]["User-Agent"]["type"] = "string"
  request["observation"]["properties"]["header"]["properties"]["User-Agent"]["index"] = "analyzed"
  request["observation"]["properties"]["header"]["properties"]["User-Agent"]["analyzer"] = "keyword"
  request["observation"]["properties"]["header"]["properties"]["Host"] = {}
  request["observation"]["properties"]["header"]["properties"]["Host"]["type"] = "string"
  request["observation"]["properties"]["header"]["properties"]["Host"]["index"] = "analyzed"
  request["observation"]["properties"]["header"]["properties"]["Host"]["analyzer"] = "keyword"
  request["observation"]["properties"]["indicators"] = {}
  request["observation"]["properties"]["indicators"]["type"] = "object"
  request["observation"]["properties"]["src"] = {}
  request["observation"]["properties"]["src"]["type"] = "object"
  request["observation"]["properties"]["src"]["properties"] = {}
  request["observation"]["properties"]["src"]["properties"]["ipv4"] = {}
  request["observation"]["properties"]["src"]["properties"]["ipv4"]["type"] = "string"
  request["observation"]["properties"]["src"]["properties"]["ipv4"]["analyzer"] = "keyword"
  request["observation"]["properties"]["dest"] = {}
  request["observation"]["properties"]["dest"]["type"] = "object"
  request["observation"]["properties"]["dest"]["properties"] = {}
  request["observation"]["properties"]["dest"]["properties"]["ipv4"] = {}
  request["observation"]["properties"]["dest"]["properties"]["ipv4"]["type"] = "string"
  request["observation"]["properties"]["dest"]["properties"]["ipv4"]["analyzer"] = "keyword"
  request["observation"]["properties"]["indicators"] = {}
  request["observation"]["properties"]["indicators"]["properties"] = {}
  request["observation"]["properties"]["indicators"]["properties"]["id"] = {}
  request["observation"]["properties"]["indicators"]["properties"]["id"]["type"] = "string"
  request["observation"]["properties"]["indicators"]["properties"]["id"]["analyzer"] = "keyword"
  request["observation"]["properties"]["indicators"]["properties"]["description"] = {}
  request["observation"]["properties"]["indicators"]["properties"]["description"]["type"] = "string"
  request["observation"]["properties"]["indicators"]["properties"]["description"]["analyzer"] = "keyword"
  request["observation"]["properties"]["indicators"]["properties"]["value"] = {}
  request["observation"]["properties"]["indicators"]["properties"]["value"]["type"] = "string"
  request["observation"]["properties"]["indicators"]["properties"]["value"]["analyzer"] = "keyword"
  request["observation"]["properties"]["indicators"]["properties"]["on"] = {}
  request["observation"]["properties"]["indicators"]["properties"]["on"]["type"] = "string"
  request["observation"]["properties"]["indicators"]["properties"]["on"]["analyzer"] = "keyword"

  req = {}
  req["observation"] = {}
  req["observation"]["properties"] = request

  request = req

  local c = http.http_req(module.base .. "cybermon", "PUT", "")

  print(jsenc(request))

  local c = http.http_req(module.base .. "cybermon/observation/_mapping", 
      "PUT", jsenc(request))

  print(c)

end

return module

