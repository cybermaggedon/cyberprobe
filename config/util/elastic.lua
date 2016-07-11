
local module = {}

local http = require("util.http")
local addr = require("util.addresses")

local jsenc = require("json.encode")

-- Object ID counter
local id = 1

-- Time-to-live
local default_ttl = "1h"

-- Index
local index = "cyberprobe"
local object = "observation"

-- Points to an ElasticSearch instance.
module.base = "http://localhost:9200/"

-- Initialise a basic observation
module.initialise_observation = function(context, indicators)

  local obs = {}
  obs[object] = {}
  obs[object]["liid"] = context:get_liid()
  obs[object]["src"] = addr.get_stack(context, true)
  obs[object]["dest"] = addr.get_stack(context, false)

  if indicators and not(#indicators == 0) then
    obs[object]["indicators"] = {}
    obs[object]["indicators"]["on"] = {}
    obs[object]["indicators"]["description"] = {}
    obs[object]["indicators"]["value"] = {}
    obs[object]["indicators"]["id"] = {}
    for key, value in pairs(indicators) do
      table.insert(obs[object]["indicators"]["on"], value["on"])
      table.insert(obs[object]["indicators"]["description"], value["description"])
      table.insert(obs[object]["indicators"]["value"], value["value"])
      table.insert(obs[object]["indicators"]["id"], value["id"])
    end
  end

  local tm = context:get_event_time()
  local tmstr = os.date("!%Y%m%dT%H%M%S", math.floor(tm))
  local millis = 1000 * (tm - math.floor(tm))

  tmstr = tmstr .. "." .. string.format("%03dZ", math.floor(millis))

  obs[object]["time"] = tmstr

  return obs

end


-- Create an observation object in ElasticSearch
module.submit_observation = function(request)

  local u = string.format("%s%s/%s/%d?ttl=%s", module.base, index, object, id,
  	default_ttl)
print(u)
  request[object]["oid"] = id

  print(string.format("Observation %d", id))
  id = id + 1

  local c = http.http_req(u, "PUT", jsenc.encode(request), "application/json")

  if not (c == 201 or c == 200) then
    io.write(string.format("Elasticsearch index failed: %s\n", c))
  end

end

-- Initialise elasticsearch
module.init = function()

  -- Look for mapping.
  local c = http.http_req(module.base .. index .. "/" .. object .. "/_mapping",
  	    	          "GET", "", "application/json")
  
  -- If mapping already exists, move on.
  if c == 200 then
    print("Index already exists.")
    return
  end

  print("Create index...")
  local c = http.http_req(module.base .. index, "PUT", "", "application/json")

  if not(c == 200) then
    print("ERROR: Index creation failed")
  end

  print("Create mapping...")
  local request = {}
  request[object] = {}
  request[object]["properties"] = {}
  request[object]["properties"]["body"] = {}
  request[object]["properties"]["body"]["type"] = "binary"
  request[object]["properties"]["data"] = {}
  request[object]["properties"]["data"]["type"] = "binary"
  request[object]["properties"]["time"] = {}
  request[object]["properties"]["time"]["type"] = "date"
  request[object]["properties"]["time"]["format"] = "basic_date_time"
  request[object]["properties"]["url"] = {}
  request[object]["properties"]["url"]["type"] = "string"
  request[object]["properties"]["url"]["analyzer"] = "keyword"
  request[object]["properties"]["queries"] = {}
  request[object]["properties"]["queries"]["type"] = "string"
  request[object]["properties"]["queries"]["analyzer"] = "keyword"
  request[object]["properties"]["header"] = {}
  request[object]["properties"]["header"]["type"] = "object"
  request[object]["properties"]["header"]["properties"] = {}
  request[object]["properties"]["header"]["properties"]["Content-Type"] = {}
  request[object]["properties"]["header"]["properties"]["Content-Type"]["type"] = "string"
  request[object]["properties"]["header"]["properties"]["Content-Type"]["index"] = "analyzed"
  request[object]["properties"]["header"]["properties"]["Content-Type"]["analyzer"] = "keyword"
  request[object]["properties"]["header"]["properties"]["User-Agent"] = {}
  request[object]["properties"]["header"]["properties"]["User-Agent"]["type"] = "string"
  request[object]["properties"]["header"]["properties"]["User-Agent"]["index"] = "analyzed"
  request[object]["properties"]["header"]["properties"]["User-Agent"]["analyzer"] = "keyword"
  request[object]["properties"]["header"]["properties"]["Host"] = {}
  request[object]["properties"]["header"]["properties"]["Host"]["type"] = "string"
  request[object]["properties"]["header"]["properties"]["Host"]["index"] = "analyzed"
  request[object]["properties"]["header"]["properties"]["Host"]["analyzer"] = "keyword"
  request[object]["properties"]["src"] = {}
  request[object]["properties"]["src"]["type"] = "object"
  request[object]["properties"]["src"]["properties"] = {}
  request[object]["properties"]["src"]["properties"]["ipv4"] = {}
  request[object]["properties"]["src"]["properties"]["ipv4"]["type"] = "string"
  request[object]["properties"]["src"]["properties"]["ipv4"]["analyzer"] = "keyword"
  request[object]["properties"]["dest"] = {}
  request[object]["properties"]["dest"]["type"] = "object"
  request[object]["properties"]["dest"]["properties"] = {}
  request[object]["properties"]["dest"]["properties"]["ipv4"] = {}
  request[object]["properties"]["dest"]["properties"]["ipv4"]["type"] = "string"
  request[object]["properties"]["dest"]["properties"]["ipv4"]["analyzer"] = "keyword"
  request[object]["properties"]["indicators"] = {}
  request[object]["properties"]["indicators"]["properties"] = {}
  request[object]["properties"]["indicators"]["properties"]["id"] = {}
  request[object]["properties"]["indicators"]["properties"]["id"]["type"] = "string"
  request[object]["properties"]["indicators"]["properties"]["id"]["analyzer"] = "keyword"
  request[object]["properties"]["indicators"]["properties"]["description"] = {}
  request[object]["properties"]["indicators"]["properties"]["description"]["type"] = "string"
  request[object]["properties"]["indicators"]["properties"]["description"]["analyzer"] = "keyword"
  request[object]["properties"]["indicators"]["properties"]["value"] = {}
  request[object]["properties"]["indicators"]["properties"]["value"]["type"] = "string"
  request[object]["properties"]["indicators"]["properties"]["value"]["analyzer"] = "keyword"
  request[object]["properties"]["indicators"]["properties"]["on"] = {}
  request[object]["properties"]["indicators"]["properties"]["on"]["type"] = "string"
  request[object]["properties"]["indicators"]["properties"]["on"]["analyzer"] = "keyword"

  req = {}
  req[object] = {}
  req[object]["_ttl"] = {}
  req[object]["_ttl"]["enabled"] = "true"
  req[object]["properties"] = request

  request = req

  local c = http.http_req(module.base .. index .. "/" .. object .. "/_mapping", 
      "PUT", jsenc(request), "application/json")

  if not(c == 200) then
    print("ERROR: Mapping creation failed")
  end

end

return module

