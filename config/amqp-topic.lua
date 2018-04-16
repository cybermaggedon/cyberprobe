--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
-- This one integrates cybermon with an AMQP broker, so that network events are
-- published to an exchange.
--

-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

-- Other modules -----------------------------------------------------------
local json = require("json")
local amqp = require("amqp")
local os = require("os")
local string = require("string")
local model = require("util.json")
local socket = require("socket")

-- Config ------------------------------------------------------------------

local default_broker = "localhost:5672"
local amqp_port = 5672

if os.getenv("AMQP_BROKER") then
  broker = os.getenv("AMQP_BROKER")
else
  broker = default_broker
end

if os.getenv("EXCHANGE") then
  exch = os.getenv("EXCHANGE")
else
  exch = 'amq.topic'
end

if os.getenv("ROUTING_KEY") then
  rkey = os.getenv("ROUTING_KEY")
else
  rkey = 'cyberprobe'
end

-- Initialise.
local init = function()

  while true do

    if not pcall(function() ctx = amqp.new({role = "publisher", exchange = exch, routing_key = rkey}) end) then
 
      print("AMQP connection failed, will retry...")
      socket.select(nil, nil, 5)

    else

      ok = ctx:connect("127.0.0.1",5672)

      if not ok then
       print("AMQP connection failed, will retry...")
       ctx:close()
       socket.select(nil, nil, 5)
      else

       ok = ctx:setup()

       if not ok then
	 print("AMQP setup failed, will retry...")
	 ctx:close()
	 socket.select(nil, nil, 5)

       else

	 print("AMQP connection created.")
	 return

	end

      end

    end

  end

end

-- Object submission function - just pushes the object onto the queue.
local submit = function(obs)
  while true do
    local ok, err = ctx:publish(json.encode(obs))
    if not ok then
      ctx:close()
      print("AMQP delivery failed, will reconnect.")
      init()
    else
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

