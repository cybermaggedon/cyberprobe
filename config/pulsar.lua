--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
-- This one integrates cybermon with a Pulsar through the websocket API.
--

-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

-- Other modules -----------------------------------------------------------
local os = require("os")
local json = require("json")
local string = require("string")
local socket = require("socket")
local websocket = require("http.websocket")
local mime = require("mime")

-- Config ------------------------------------------------------------------

local default_broker = "ws://localhost:8080"
if os.getenv("PULSAR_BROKER") then
  broker = os.getenv("PULSAR_BROKER")
else
  broker = default_broker
end

if os.getenv("PULSAR_TENANT") then
  tenant = os.getenv("PULSAR_TENANT")
else
  tenant = 'public'
end

if os.getenv("PULSAR_PERSISTENCY") then
  pers = os.getenv("PULSAR_PERSISTENCY")
else
  pers = 'persistent'
end

if os.getenv("PULSAR_NAMESPACE") then
  ns = os.getenv("PULSAR_NAMESPACE")
else
  ns = 'default'
end

if os.getenv("PULSAR_TOPIC") then
  topic = os.getenv("PULSAR_TOPIC")
else
  topic = 'cyberprobe'
end

print("Broker: " .. broker)
print("Tenant: " .. tenant)
print("Persistency: " .. pers)
print("Namespace: " .. ns)
print("Topic: " .. topic)

url = string.format("%s/ws/v2/producer/persistent/%s/%s/%s", broker, tenant, ns, topic)

-- Initialise.
local init = function()

  while true do

    if not pcall(function() ws = websocket.new_from_uri(url) end) then

      print("Pulsar connection failed, will retry...")
      socket.select(nil, nil, 5)

    else

      ok = ws:connect()

      if not ok then
        print("Pulsar connection failed, will retry...")
        ws:close()
        socket.select(nil, nil, 5)
      else

        print("Pulsar connection created.")
        return

      end

    end

  end

end

-- Base64 encoding
local b64 = function(x)
  local a, b = mime.b64(x)
  if (a == nil) then
    return ""
  end
  return a
end

-- Object submission function - just pushes the object onto the queue.
local submit = function(obs)
  pay = b64(obs)
  msg = json.encode({
    payload = pay,
    properties = { device = obs["device"], network = obs["network"] },
    context = "1"
  })
  while true do
    local ok, err = ws:send(msg)
    if not ok then
      ws:close()
      print("Pulsar delivery failed, will reconnect.")
      socket.select(nil, nil, 5)
      init()
    else
      -- Receive result and ignore.
      ws:receive()
      return
    end
  end
end

observer.event = function(e)
  submit(e:protobuf())
end

-- Initialise
init()

-- Return the table
return observer

