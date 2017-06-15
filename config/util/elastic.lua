
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
  request[object]["properties"]["id"] = {}
  request[object]["properties"]["id"]["type"] = "keyword"
  request[object]["properties"]["time"] = {}
  request[object]["properties"]["time"]["type"] = "date"
  request[object]["properties"]["url"] = {}
  request[object]["properties"]["url"]["type"] = "keyword"
  request[object]["properties"]["queries"] = {}
  request[object]["properties"]["queries"]["type"] = "keyword"
  request[object]["properties"]["action"] = {}
  request[object]["properties"]["action"]["type"] = "keyword"
  request[object]["properties"]["device"] = {}
  request[object]["properties"]["device"]["type"] = "keyword"
  request[object]["properties"]["type"] = {}
  request[object]["properties"]["type"]["type"] = "keyword"
  request[object]["properties"]["method"] = {}
  request[object]["properties"]["method"]["type"] = "keyword"
  request[object]["properties"]["src"] = {}
  request[object]["properties"]["src"]["properties"] = {}
  request[object]["properties"]["src"]["properties"]["ipv4"] = {}
  request[object]["properties"]["src"]["properties"]["ipv4"]["type"] = "ip"
  request[object]["properties"]["src"]["properties"]["tcp"] = {}
  request[object]["properties"]["src"]["properties"]["tcp"]["type"] = "integer"
  request[object]["properties"]["src"]["properties"]["udp"] = {}
  request[object]["properties"]["src"]["properties"]["udp"]["type"] = "integer"
  request[object]["properties"]["dst"] = {}
  request[object]["properties"]["dst"]["properties"] = {}
  request[object]["properties"]["dst"]["properties"]["ipv4"] = {}
  request[object]["properties"]["dst"]["properties"]["ipv4"]["type"] = "ip"
  request[object]["properties"]["dst"]["properties"]["tcp"] = {}
  request[object]["properties"]["dst"]["properties"]["tcp"]["type"] = "integer"
  request[object]["properties"]["dst"]["properties"]["udp"] = {}
  request[object]["properties"]["dst"]["properties"]["udp"]["type"] = "integer"
  request[object]["properties"]["queries"] = {}
  request[object]["properties"]["queries"]["properties"] = {}
  request[object]["properties"]["queries"]["properties"]["name"] = {}
  request[object]["properties"]["queries"]["properties"]["name"]["type"] = "keyword"
  request[object]["properties"]["answers"] = {}
  request[object]["properties"]["answers"]["properties"] = {}
  request[object]["properties"]["answers"]["properties"]["name"] = {}
  request[object]["properties"]["answers"]["properties"]["name"]["type"] = "keyword"
  request[object]["properties"]["answers"]["properties"]["address"] = {}
  request[object]["properties"]["answers"]["properties"]["address"]["type"] = "keyword"
  request[object]["properties"]["header"] = {}
  request[object]["properties"]["header"]["properties"] = {}
  request[object]["properties"]["header"]["properties"]["User-Agent"] = {}
  request[object]["properties"]["header"]["properties"]["User-Agent"]["type"] = "keyword"
  request[object]["properties"]["header"]["properties"]["Host"] = {}
  request[object]["properties"]["header"]["properties"]["Host"]["type"] = "keyword"
  request[object]["properties"]["header"]["properties"]["Content-Type"] = {}
  request[object]["properties"]["header"]["properties"]["Content-Type"]["type"] = "keyword"
  request[object]["properties"]["header"]["properties"]["Server"] = {}
  request[object]["properties"]["header"]["properties"]["Server"]["type"] = "keyword"
  request[object]["properties"]["header"]["properties"]["Connection"] = {}
  request[object]["properties"]["header"]["properties"]["Connection"]["type"] = "keyword"

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


-- Create an observation object in ElasticSearch
module.submit_observation = function(request)

  local u = string.format("%s%s/%s/%d?ttl=%s", module.base, index, object, id,
  	default_ttl)
print(u)
  id = id + 1

  local c = http.http_req(u, "PUT", jsenc.encode(request), "application/json")

  if not (c == 201 or c == 200) then
    io.write(string.format("Elasticsearch index failed: %s\n", c))
  end

end


return module

