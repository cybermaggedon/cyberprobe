--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
-- This one integrates cybermon with redis, so that network events are RPUSH'd
-- on a list to use as a queue.
--

-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

-- Other modules -----------------------------------------------------------
local json = require("json")
local redis = require("redis")
local os = require("os")
local string = require("string")
local model = require("util.json")
local socket = require("socket")

-- Config ------------------------------------------------------------------

local redist_host = "localhost"
local redis_port = 6379

if os.getenv("REDIS_SERVER") then
  local redis_server = os.getenv("REDIS_SERVER")
  local a, b = string.find(redis_server, ":")
  if a > 0 then
    redis_host = string.sub(redis_server, 1, a-1)
    redis_port = tonumber(string.sub(redis_server, b + 1, -1))
  end

  if os.getenv("QUEUE") then
    queue = os.getenv("QUEUE")
  else
    queue = 'input'
  end
  
end

-- Initialise.
local init = function()
  while true do
    if pcall(function() client = redis.connect(redis_host, redis_port) end ) then
      break
    else
      print("Redis connection failed, will retry...")
      socket.select(nil, nil, 5)
    end
  end
  print("Connected to redis.")
end

-- Redis object submission function - just pushes the object onto the queue.
local submit = function(obs)
  while true do
    if pcall(function() client:rpush(queue, json.encode(obs)) end) then
      break
    end
    print("Redis delivery failed, will reconnect.")
    -- Failed, so reconnect and retry...
    init()
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
observer.gre = model.gre
observer.grep_pptp = model.gre_pptp
observer.esp = model.esp
observer.unrecognised_ip_protocol = model.unrecognised_ip_protocol
observer.wlan = model.wlan

-- Register Redis submission.
model.init(submit)

-- Initialise
init()

-- Return the table
return observer

