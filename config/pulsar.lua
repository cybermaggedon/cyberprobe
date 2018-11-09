--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
-- This one integrates cybermon with a Pulsar through the websocket API.
--

-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

-- Other modules -----------------------------------------------------------
local json = require("json")
local os = require("os")
local string = require("string")
local model = require("util.json")
local socket = require("socket")
local websocket = require "http.websocket"

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
  pay = b64(json.encode(obs))
  msg = json.encode({
    payload = pay,
    properties = { device = obs["device"], network = obs["network"] },
    context = "1"
  })
  while true do
    print("Attempting...")
    local ok, err = ws:send(msg)
    if not ok then
      ws:close()
      print("Pulsar delivery failed, will reconnect.")
      socket.select(nil, nil, 5)
      init()
    else
      -- Receive result and ignore.
      print("Sent.")
      ws:receive()
      print("Response received.")
      return
    end
  end
end

-- Call the JSON functions for all observer functions.
observer.trigger_up = model.trigger_up
observer.trigger_down = model.trigger_down
observer.connection_up = model.connection_up
observer.connection_down = model.connection_down
observer.unrecognised_datagram = model.unrecognised_datagram
observer.unrecognised_stream = model.unrecognised_stream
observer.icmp = model.icmp
observer.imap = model.imap
observer.imap_ssl = model.imap_ssl
observer.pop3 = model.pop3
observer.pop3_ssl = model.pop3_ssl
observer.http_request = model.http_request
observer.http_response = model.http_response
observer.sip_request = model.sip_request
observer.sip_response = model.sip_response
observer.sip_ssl = model.sip_ssl
observer.smtp_command = model.smtp_command
observer.smtp_response = model.smtp_response
observer.smtp_data = model.smtp_data
observer.dns_message = model.dns_message
observer.ftp_command = model.ftp_command
observer.ftp_response = model.ftp_response
observer.ntp_timestamp_message = model.ntp_timestamp_message
observer.ntp_control_message = model.ntp_control_message
observer.ntp_private_message = model.ntp_private_message

-- Initialise submission model.
model.init(submit)

-- Initialise
init()

-- Return the table
return observer

